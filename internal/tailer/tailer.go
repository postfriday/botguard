// Package tailer follows a Caddy access log file (JSON lines), surviving log
// rotation by detecting inode/size changes via fsnotify with a polling fallback.
package tailer

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/postfriday/botguard/internal/model"
)

// Tailer streams parsed log events to its output channel.
type Tailer struct {
	path         string
	pollInterval time.Duration
	out          chan model.Event
	log          *slog.Logger
}

// New returns a Tailer that streams events from path. The output channel is
// closed when ctx is canceled.
func New(path string, pollInterval time.Duration, logger *slog.Logger) *Tailer {
	if pollInterval <= 0 {
		pollInterval = 250 * time.Millisecond
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Tailer{
		path:         path,
		pollInterval: pollInterval,
		out:          make(chan model.Event, 1024),
		log:          logger,
	}
}

// Events returns the read-only events channel.
func (t *Tailer) Events() <-chan model.Event { return t.out }

// Run blocks until ctx is canceled. It transparently re-opens the file when
// it gets rotated.
func (t *Tailer) Run(ctx context.Context) error {
	defer close(t.out)

	watcher, _ := fsnotify.NewWatcher() // best-effort
	if watcher != nil {
		defer func() { _ = watcher.Close() }()
		// watch the directory so we see CREATE on rotation (file may not exist yet)
		dir := filepath.Dir(t.path)
		_ = watcher.Add(dir)
	}

	var (
		f       *os.File
		reader  *bufio.Reader
		curStat os.FileInfo
		err     error
	)
	openFile := func() error {
		f, err = os.Open(t.path)
		if err != nil {
			return err
		}
		// Seek to end so we don't replay history on first start.
		// On rotation reopen we deliberately seek(0) so we capture the new file
		// from the very beginning.
		curStat, err = f.Stat()
		if err != nil {
			return err
		}
		_, _ = f.Seek(0, io.SeekEnd)
		reader = bufio.NewReaderSize(f, 64*1024)
		return nil
	}

	if err := openFile(); err != nil {
		t.log.Warn("tailer: log not yet present, will retry", "path", t.path, "err", err)
	}

	pollTimer := time.NewTicker(t.pollInterval)
	defer pollTimer.Stop()

	rotated := func() bool {
		if f == nil {
			return false
		}
		st, err := os.Stat(t.path)
		if err != nil {
			return false
		}
		// new inode -> file replaced
		if !sameFile(curStat, st) {
			return true
		}
		// file truncated (size went down)
		if st.Size() < curStat.Size() {
			return true
		}
		curStat = st
		return false
	}

	for {
		// Drain whatever's available
		if reader != nil {
			for {
				line, err := reader.ReadString('\n')
				if len(line) > 0 {
					if ev, ok := parseLine(line); ok {
						select {
						case t.out <- ev:
						case <-ctx.Done():
							return nil
						}
					}
				}
				if err != nil {
					if err != io.EOF {
						t.log.Warn("tailer: read error", "err", err)
					}
					break
				}
			}
		}

		// Check rotation / re-open
		if rotated() {
			t.log.Info("tailer: log rotated, re-opening", "path", t.path)
			_ = f.Close()
			f, reader = nil, nil
			_ = openFile() // will seek to end on the fresh file
			// after rotation we want to start from byte 0:
			if f != nil {
				_, _ = f.Seek(0, io.SeekStart)
				reader = bufio.NewReaderSize(f, 64*1024)
			}
		}
		if reader == nil {
			// retry-open
			_ = openFile()
		}

		// Wait for activity
		select {
		case <-ctx.Done():
			if f != nil {
				_ = f.Close()
			}
			return nil
		case <-pollTimer.C:
		case ev, ok := <-watcherEvents(watcher):
			if !ok {
				continue
			}
			// any event nudges another iteration
			_ = ev
		}
	}
}

// watcherEvents returns the watcher's Events channel, or nil so the select
// case blocks forever (we don't want a closed channel here, which would busy-
// loop the select alongside the poll timer).
func watcherEvents(w *fsnotify.Watcher) <-chan fsnotify.Event {
	if w == nil {
		return nil
	}
	return w.Events
}

func sameFile(a, b os.FileInfo) bool {
	if a == nil || b == nil {
		return false
	}
	sa, oka := a.Sys().(*syscall.Stat_t)
	sb, okb := b.Sys().(*syscall.Stat_t)
	if !oka || !okb {
		return os.SameFile(a, b)
	}
	return sa.Ino == sb.Ino && sa.Dev == sb.Dev
}

// caddyEntry is the relevant subset of Caddy's JSON access log format.
type caddyEntry struct {
	TS      float64      `json:"ts"`
	Request caddyRequest `json:"request"`
	Status  int          `json:"status"`
	Size    int          `json:"size"`
}

type caddyRequest struct {
	RemoteIP   string              `json:"remote_ip"`   // Caddy >=2.6
	RemoteAddr string              `json:"remote_addr"` // older / fallback
	ClientIP   string              `json:"client_ip"`   // when trusted_proxies is enabled
	Host       string              `json:"host"`
	URI        string              `json:"uri"`
	Method     string              `json:"method"`
	Headers    map[string][]string `json:"headers"`
}

func parseLine(line string) (model.Event, bool) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] != '{' {
		return model.Event{}, false
	}
	var c caddyEntry
	if err := json.Unmarshal([]byte(line), &c); err != nil {
		return model.Event{}, false
	}
	ip := pickIP(&c.Request)
	if ip == "" {
		return model.Event{}, false
	}
	ua := ""
	if v := c.Request.Headers["User-Agent"]; len(v) > 0 {
		ua = v[0]
	}
	ts := time.Now()
	if c.TS > 0 {
		sec, frac := splitFloatTime(c.TS)
		ts = time.Unix(sec, frac)
	}
	return model.Event{
		IP:       ip,
		UA:       ua,
		Path:     c.Request.URI,
		Status:   c.Status,
		Host:     c.Request.Host,
		TS:       ts,
		RawBytes: len(line),
	}, true
}

func pickIP(r *caddyRequest) string {
	cands := []string{r.ClientIP, r.RemoteIP, r.RemoteAddr}
	for _, raw := range cands {
		if raw == "" {
			continue
		}
		// strip :port if any
		host, _, err := net.SplitHostPort(raw)
		if err == nil {
			raw = host
		}
		if net.ParseIP(raw) != nil {
			return raw
		}
	}
	return ""
}

func splitFloatTime(f float64) (int64, int64) {
	sec := int64(f)
	frac := int64((f - float64(sec)) * 1e9)
	return sec, frac
}

// Sentinel errors for callers.
var (
	ErrPathEmpty = errors.New("tailer: empty path")
)
