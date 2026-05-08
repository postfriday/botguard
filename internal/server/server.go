// Package server exposes a minimal HTTP read-only API: /healthz and /stats.
package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/postfriday/botguard/internal/store"
)

// Options for New.
type Options struct {
	Listen    string
	BasicUser string
	BasicPass string
	Store     *store.Store
	Logger    *slog.Logger
}

// Server is a tiny HTTP wrapper.
type Server struct {
	srv  *http.Server
	opts Options
}

// New builds a Server. If Listen is empty, Run is a no-op.
func New(o Options) *Server {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	mux := http.NewServeMux()
	s := &Server{opts: o}
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.Handle("/stats", s.auth(http.HandlerFunc(s.handleStats)))
	mux.Handle("/blocked", s.auth(http.HandlerFunc(s.handleBlocked)))
	if o.Listen != "" {
		s.srv = &http.Server{
			Addr:              o.Listen,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		}
	}
	return s
}

// Run blocks until ctx is canceled.
func (s *Server) Run(ctx context.Context) error {
	if s.srv == nil {
		<-ctx.Done()
		return nil
	}
	errCh := make(chan error, 1)
	go func() { errCh <- s.srv.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return s.srv.Shutdown(shutCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *Server) auth(h http.Handler) http.Handler {
	if s.opts.BasicUser == "" {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok ||
			subtle.ConstantTimeCompare([]byte(u), []byte(s.opts.BasicUser)) != 1 ||
			subtle.ConstantTimeCompare([]byte(p), []byte(s.opts.BasicPass)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="botguard"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

type statRow struct {
	Pattern   string `json:"pattern"`
	UniqueIPs int    `json:"unique_ips"`
	Hits      int    `json:"hits"`
	FirstSeen int64  `json:"first_seen"`
	LastSeen  int64  `json:"last_seen"`
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	since := r.URL.Query().Get("since")
	dur, err := time.ParseDuration(since)
	if err != nil || dur <= 0 {
		dur = 24 * time.Hour
	}
	cutoff := time.Now().Add(-dur).Unix()
	rows, err := s.opts.Store.DB().QueryContext(r.Context(), `
		SELECT COALESCE(rule_pattern,'') AS pattern,
		       COUNT(DISTINCT ip)        AS unique_ips,
		       COUNT(*)                  AS hits,
		       MIN(ts), MAX(ts)
		  FROM block_events WHERE ts >= ?
		 GROUP BY pattern
		 ORDER BY hits DESC`, cutoff)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer func() { _ = rows.Close() }()
	var out []statRow
	for rows.Next() {
		var row statRow
		if err := rows.Scan(&row.Pattern, &row.UniqueIPs, &row.Hits, &row.FirstSeen, &row.LastSeen); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		out = append(out, row)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (s *Server) handleBlocked(w http.ResponseWriter, r *http.Request) {
	rows, err := s.opts.Store.DB().QueryContext(r.Context(), `
		SELECT ip, hostname, decision, rule_pattern, hit_count, expires_at
		  FROM ip_cache WHERE decision='deny'
		 ORDER BY hit_count DESC LIMIT 500`)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer func() { _ = rows.Close() }()
	type row struct {
		IP, Hostname, Decision, Rule string
		HitCount                     int64
		ExpiresAt                    int64
	}
	var out []row
	for rows.Next() {
		var x row
		if err := rows.Scan(&x.IP, &x.Hostname, &x.Decision, &x.Rule, &x.HitCount, &x.ExpiresAt); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		out = append(out, x)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
