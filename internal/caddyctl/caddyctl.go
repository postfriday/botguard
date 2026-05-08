// Package caddyctl writes the dynamic blocked.caddy snippet and triggers a
// graceful Caddy reload via its admin API.
package caddyctl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Controller renders the snippet and debounces reloads.
type Controller struct {
	snippetPath string
	caddyfile   string
	adminURL    string
	debounce    time.Duration
	reloadCmd   string // optional shell command override

	mu       sync.Mutex
	pending  bool
	timer    *time.Timer
	lastHash string
	log      *slog.Logger
}

// Options bundles configuration for New.
type Options struct {
	SnippetPath   string
	CaddyfilePath string
	AdminURL      string
	Debounce      time.Duration
	ReloadCommand string
	Logger        *slog.Logger
}

// New creates a Controller.
func New(o Options) *Controller {
	if o.Debounce <= 0 {
		o.Debounce = 30 * time.Second
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return &Controller{
		snippetPath: o.SnippetPath,
		caddyfile:   o.CaddyfilePath,
		adminURL:    o.AdminURL,
		debounce:    o.Debounce,
		reloadCmd:   o.ReloadCommand,
		log:         o.Logger,
	}
}

// Render writes the blocked.caddy snippet for the given IPs and schedules a
// debounced reload. Idempotent: if the file content hasn't changed, no reload
// is scheduled.
func (c *Controller) Render(ctx context.Context, ips []string) error {
	body := buildSnippet(ips)
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])

	c.mu.Lock()
	if hash == c.lastHash {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	if err := writeAtomic(c.snippetPath, body, 0o644); err != nil {
		return fmt.Errorf("caddyctl: write snippet: %w", err)
	}

	c.mu.Lock()
	c.lastHash = hash
	if c.timer != nil {
		c.timer.Stop()
	}
	c.timer = time.AfterFunc(c.debounce, func() {
		if err := c.Reload(context.Background()); err != nil {
			c.log.Error("caddyctl: reload failed", "err", err)
		}
	})
	c.pending = true
	c.mu.Unlock()
	c.log.Info("caddyctl: snippet updated", "ips", len(ips), "path", c.snippetPath)
	return nil
}

// Reload triggers a Caddy reload immediately.
func (c *Controller) Reload(ctx context.Context) error {
	c.mu.Lock()
	c.pending = false
	c.mu.Unlock()

	if c.reloadCmd != "" {
		return c.reloadShell(ctx)
	}
	return c.reloadAdminAPI(ctx)
}

// reloadAdminAPI POSTs the current Caddyfile (adapted to JSON via Caddy's
// /adapt endpoint) to /load. This avoids needing a Caddy CLI in the daemon
// container.
func (c *Controller) reloadAdminAPI(ctx context.Context) error {
	if c.caddyfile == "" {
		return errors.New("caddyctl: caddyfile path not set")
	}
	body, err := os.ReadFile(c.caddyfile)
	if err != nil {
		return fmt.Errorf("caddyctl: read caddyfile: %w", err)
	}
	// Adapt Caddyfile -> JSON
	adaptURL := strings.TrimRight(c.adminURL, "/") + "/adapt"
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, adaptURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "text/caddyfile")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("caddyctl: adapt: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("caddyctl: adapt status=%d body=%s", resp.StatusCode, truncate(string(b), 256))
	}
	adapted := struct {
		Result   any   `json:"result"`
		Warnings []any `json:"warnings"`
	}{}
	if err := jsonDecode(resp.Body, &adapted); err != nil {
		return fmt.Errorf("caddyctl: decode adapt: %w", err)
	}
	// Re-encode the result (which is the actual JSON config) and POST to /load
	cfgBytes, err := jsonEncode(adapted.Result)
	if err != nil {
		return fmt.Errorf("caddyctl: re-encode: %w", err)
	}
	loadURL := strings.TrimRight(c.adminURL, "/") + "/load"
	req2, _ := http.NewRequestWithContext(ctx, http.MethodPost, loadURL, bytes.NewReader(cfgBytes))
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		return fmt.Errorf("caddyctl: load: %w", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode/100 != 2 {
		b, _ := io.ReadAll(resp2.Body)
		return fmt.Errorf("caddyctl: load status=%d body=%s", resp2.StatusCode, truncate(string(b), 256))
	}
	c.log.Info("caddyctl: caddy reloaded via admin api")
	return nil
}

func (c *Controller) reloadShell(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "sh", "-c", c.reloadCmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("caddyctl: reload cmd: %w (output=%s)", err, truncate(string(out), 256))
	}
	return nil
}

// buildSnippet renders the dynamic blocklist as raw Caddyfile directives
// (matcher + respond). The file is meant to be imported INSIDE a site block
// via `import /etc/caddy/dynamic/*.caddy`, so we must NOT wrap it in
// a named snippet definition `(name) { ... }`.
func buildSnippet(ips []string) []byte {
	var buf bytes.Buffer
	buf.WriteString("# Generated by botguard. Do not edit by hand.\n")
	buf.WriteString("# Import inside a site block: `import /etc/caddy/dynamic/*.caddy`.\n")
	if len(ips) == 0 {
		buf.WriteString("# no blocked IPs\n")
		return buf.Bytes()
	}
	sorted := append([]string(nil), ips...)
	sort.Strings(sorted)

	buf.WriteString("@botguard_bad_ip remote_ip")
	for _, ip := range sorted {
		buf.WriteByte(' ')
		buf.WriteString(ip)
	}
	buf.WriteString("\n")
	buf.WriteString("respond @botguard_bad_ip 403\n")
	return buf.Bytes()
}

func writeAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".botguard.*")
	if err != nil {
		return err
	}
	defer func() {
		_ = os.Remove(tmp.Name())
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
