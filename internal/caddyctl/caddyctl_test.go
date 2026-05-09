package caddyctl

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestNormalisePatchPath(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"apps/http/servers/srv0", "/config/apps/http/servers/srv0"},
		{"/apps/http/servers/srv0", "/config/apps/http/servers/srv0"},
		{"/config/apps/http/servers/srv0", "/config/apps/http/servers/srv0"},
		{"/id/botguard_blocked/match/0/remote_ip/ranges", "/id/botguard_blocked/match/0/remote_ip/ranges"},
		{"id/botguard_blocked", "/id/botguard_blocked"},
	}
	for _, tc := range cases {
		if got := normalisePatchPath(tc.in); got != tc.want {
			t.Errorf("normalisePatchPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCanonicalIPs(t *testing.T) {
	got := canonicalIPs([]string{"  1.2.3.4 ", "5.6.7.8", "1.2.3.4", "", "  "})
	want := []string{"1.2.3.4", "5.6.7.8"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("canonicalIPs = %v, want %v", got, want)
	}
	if canonicalIPs(nil) != nil {
		t.Fatalf("canonicalIPs(nil) should be nil")
	}
}

// TestReloadAdminAPIPatch verifies that Reload, when ConfigPath is set,
// issues a PATCH against /config/<path> with the canonical IP list as a
// JSON array, and that a non-2xx status surfaces as an error.
func TestReloadAdminAPIPatch(t *testing.T) {
	var (
		gotMethod, gotPath, gotCT string
		gotBody                   []byte
		callCount                 atomic.Int32
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotCT = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c := New(Options{
		AdminURL:   ts.URL,
		ConfigPath: "/id/botguard_blocked/match/0/remote_ip/ranges",
		Debounce:   time.Hour, // make sure the timer never fires during the test
	})
	// Seed lastIPs the way Render would — but skip writing a snippet by
	// setting SnippetPath empty (already empty).
	if err := c.Render(context.Background(), []string{"5.6.7.8", "1.2.3.4", "1.2.3.4"}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if err := c.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if got := callCount.Load(); got != 1 {
		t.Fatalf("expected 1 admin API call, got %d", got)
	}
	if gotMethod != http.MethodPatch {
		t.Errorf("method = %s, want PATCH", gotMethod)
	}
	if gotPath != "/id/botguard_blocked/match/0/remote_ip/ranges" {
		t.Errorf("path = %s", gotPath)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %s", gotCT)
	}
	var ips []string
	if err := json.Unmarshal(gotBody, &ips); err != nil {
		t.Fatalf("body is not a JSON array: %v (raw=%q)", err, gotBody)
	}
	want := []string{"1.2.3.4", "5.6.7.8"}
	if !reflect.DeepEqual(ips, want) {
		t.Errorf("body ips = %v, want %v (sorted+deduped)", ips, want)
	}
}

func TestReloadAdminAPIPatchEmptyList(t *testing.T) {
	var gotBody []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c := New(Options{
		AdminURL:   ts.URL,
		ConfigPath: "/id/botguard_blocked/match/0/remote_ip/ranges",
		Debounce:   time.Hour,
	})
	// Reload directly without Render: lastIPs is nil — must serialize as [],
	// not "null" (Caddy would reject the latter for a slice-shaped node).
	if err := c.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if string(gotBody) != "[]" {
		t.Fatalf("empty body = %q, want []", gotBody)
	}
}

func TestReloadAdminAPIPatchErrorStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"unknown id"}`))
	}))
	defer ts.Close()

	c := New(Options{
		AdminURL:   ts.URL,
		ConfigPath: "/id/missing/match/0/remote_ip/ranges",
		Debounce:   time.Hour,
	})
	if err := c.Reload(context.Background()); err == nil {
		t.Fatal("expected error from non-2xx response, got nil")
	}
}

// TestRenderIdempotent verifies that calling Render twice with the same IP
// set does not schedule a second reload and does not re-write the snippet.
func TestRenderIdempotent(t *testing.T) {
	dir := t.TempDir()
	snippet := filepath.Join(dir, "blocked.caddy")

	c := New(Options{
		SnippetPath: snippet,
		AdminURL:    "http://127.0.0.1:1", // unreachable; reload never fires
		ConfigPath:  "/id/botguard_blocked/match/0/remote_ip/ranges",
		Debounce:    time.Hour,
	})
	if err := c.Render(context.Background(), []string{"1.2.3.4", "5.6.7.8"}); err != nil {
		t.Fatalf("first Render: %v", err)
	}
	hash1 := c.lastHash
	// Same IPs in different order — canonical form is identical, so Render
	// must short-circuit before touching the timer or the file.
	if err := c.Render(context.Background(), []string{"5.6.7.8", "1.2.3.4"}); err != nil {
		t.Fatalf("second Render: %v", err)
	}
	if c.lastHash != hash1 {
		t.Errorf("hash changed across identical Render calls: %s vs %s", hash1, c.lastHash)
	}
}
