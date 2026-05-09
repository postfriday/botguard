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
	configPath  string // when set, Reload uses PATCH /config/<configPath>
	debounce    time.Duration
	reloadCmd   string // optional shell command override

	mu       sync.Mutex
	pending  bool
	timer    *time.Timer
	lastHash string
	lastIPs  []string // canonical IPs for the in-place PATCH path
	log      *slog.Logger
}

// Options bundles configuration for New.
type Options struct {
	SnippetPath   string
	CaddyfilePath string
	AdminURL      string
	Debounce      time.Duration
	ReloadCommand string
	// ConfigPath, when non-empty, switches Reload from adapt+/load to
	// PATCH /config/<ConfigPath> with the current IP list as a JSON array.
	// Use this to update only the blocked-IPs matcher in the running
	// Caddy config without re-loading everything. The path may also start
	// with "/id/<@id>/..." to address a node by its @id.
	// Example: "/id/botguard_blocked/match/0/remote_ip/ranges".
	ConfigPath string
	Logger     *slog.Logger
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
		configPath:  o.ConfigPath,
		debounce:    o.Debounce,
		reloadCmd:   o.ReloadCommand,
		log:         o.Logger,
	}
}

// Render persists the IP list and schedules a debounced reload. The IPs are
// always written to the blocked.caddy snippet (when SnippetPath is set) so
// /blocked and offline debugging keep working; in PATCH mode the snippet is
// kept in sync but is not what triggers Caddy — Reload pushes the same IPs
// directly into the running config via /config/. Idempotent: if the
// canonical IP set hasn't changed since the last call, no reload is
// scheduled.
func (c *Controller) Render(ctx context.Context, ips []string) error {
	sorted := canonicalIPs(ips)
	body := buildSnippet(sorted)
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])

	c.mu.Lock()
	if hash == c.lastHash {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	if c.snippetPath != "" {
		if err := writeAtomic(c.snippetPath, body, 0o644); err != nil {
			return fmt.Errorf("caddyctl: write snippet: %w", err)
		}
	}

	c.mu.Lock()
	c.lastHash = hash
	c.lastIPs = sorted
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
	c.log.Info("caddyctl: snippet updated", "ips", len(sorted), "path", c.snippetPath)
	return nil
}

// Reload triggers a Caddy reload immediately. Selection order:
//  1. ReloadCommand — shell override (used in dev/no-Caddy stands).
//  2. ConfigPath — PATCH /config/<path> with the current IP list.
//  3. Default — adapt the Caddyfile to JSON and POST to /load.
func (c *Controller) Reload(ctx context.Context) error {
	c.mu.Lock()
	c.pending = false
	ips := append([]string(nil), c.lastIPs...)
	c.mu.Unlock()

	if c.reloadCmd != "" {
		return c.reloadShell(ctx)
	}
	if c.configPath != "" {
		return c.reloadAdminAPIPatch(ctx, ips)
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
		return fmt.Errorf("caddyctl: adapt status=%d body=%s", resp.StatusCode, truncate(string(b)))
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
		return fmt.Errorf("caddyctl: load status=%d body=%s", resp2.StatusCode, truncate(string(b)))
	}
	c.log.Info("caddyctl: caddy reloaded via admin api")
	return nil
}

// reloadAdminAPIPatch sends PATCH /config/<configPath> with the canonical IP
// list as a JSON array, replacing the value at that node in the running
// Caddy config. The user is expected to wire the path to a slice-shaped
// node — typically a remote_ip matcher's "ranges" field — so Caddy can
// deserialize the body without re-validating the whole config.
//
// ConfigPath is normalised:
//   - "" is rejected
//   - leading "/" is added if missing
//   - paths that don't already start with /config/ or /id/ get the /config
//     prefix
func (c *Controller) reloadAdminAPIPatch(ctx context.Context, ips []string) error {
	if c.configPath == "" {
		return errors.New("caddyctl: config_path not set")
	}
	if c.adminURL == "" {
		return errors.New("caddyctl: admin_url not set")
	}
	if ips == nil {
		// Caddy expects a JSON array; nil would marshal to "null" and break the matcher.
		ips = []string{}
	}
	payload, err := jsonEncode(ips)
	if err != nil {
		return fmt.Errorf("caddyctl: encode patch payload: %w", err)
	}
	url := strings.TrimRight(c.adminURL, "/") + normalisePatchPath(c.configPath)

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("caddyctl: build patch request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("caddyctl: patch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("caddyctl: patch status=%d body=%s",
			resp.StatusCode, truncate(string(b)))
	}
	c.log.Info("caddyctl: caddy patched via admin api",
		"path", c.configPath, "ips", len(ips))
	return nil
}

// normalisePatchPath returns a leading-slash path under /config/ or /id/ as
// the Caddy admin API expects. Inputs like "apps/http/...", "/apps/http/..."
// and "/config/apps/http/..." all collapse to "/config/apps/http/...";
// "/id/foo" is preserved as-is.
func normalisePatchPath(p string) string {
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if strings.HasPrefix(p, "/config/") || p == "/config" ||
		strings.HasPrefix(p, "/id/") || p == "/id" {
		return p
	}
	return "/config" + p
}

func (c *Controller) reloadShell(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "sh", "-c", c.reloadCmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("caddyctl: reload cmd: %w (output=%s)", err, truncate(string(out)))
	}
	return nil
}

// canonicalIPs trims, dedupes and sorts an IP slice. Hashing/serializing the
// canonical form makes Render and the PATCH payload stable across input
// orderings — important for both idempotency and Caddy diffing.
func canonicalIPs(ips []string) []string {
	if len(ips) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(ips))
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		if _, dup := seen[ip]; dup {
			continue
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
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
	// Caller is expected to pass a canonical (sorted, deduped) slice; we sort
	// defensively so the snippet remains stable if it is ever invoked with a
	// raw list.
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

// maxErrBodySnippet caps how many bytes of an admin-API error body we splice
// into a returned error. 256 is enough to read Caddy's "msg"/"error" fields
// without dragging an entire JSON dump into logs.
const maxErrBodySnippet = 256

func truncate(s string) string {
	if len(s) <= maxErrBodySnippet {
		return s
	}
	return s[:maxErrBodySnippet] + "..."
}
