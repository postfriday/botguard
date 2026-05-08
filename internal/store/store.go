// Package store wraps SQLite as the persistent state for botguard.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/postfriday/botguard/internal/model"

	_ "modernc.org/sqlite"
)

// Store is a thin wrapper over *sql.DB.
type Store struct {
	db *sql.DB
}

// Open opens (or creates) the SQLite database at path with WAL mode.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("store: empty path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("store: mkdir: %w", err)
	}
	q := url.Values{}
	q.Set("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(ON)")
	dsn := "file:" + path + "?" + q.Encode()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	db.SetMaxOpenConns(1) // sqlite likes single writer; we keep it simple
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the underlying DB handle.
func (s *Store) Close() error { return s.db.Close() }

// DB exposes the raw handle (for read-only ad-hoc queries).
func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS ip_cache (
			ip            TEXT PRIMARY KEY,
			hostname      TEXT NOT NULL DEFAULT '',
			verification  TEXT NOT NULL DEFAULT 'unattempted',
			decision      TEXT NOT NULL DEFAULT 'pending',
			rule_pattern  TEXT NOT NULL DEFAULT '',
			ua            TEXT NOT NULL DEFAULT '',
			checked_at    INTEGER NOT NULL DEFAULT 0,
			expires_at    INTEGER NOT NULL DEFAULT 0,
			hit_count     INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_ip_cache_expires ON ip_cache(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_ip_cache_decision ON ip_cache(decision)`,

		`CREATE TABLE IF NOT EXISTS block_events (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			ip            TEXT NOT NULL,
			hostname      TEXT NOT NULL DEFAULT '',
			ua            TEXT NOT NULL DEFAULT '',
			path          TEXT NOT NULL DEFAULT '',
			host          TEXT NOT NULL DEFAULT '',
			rule_pattern  TEXT NOT NULL DEFAULT '',
			ts            INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_block_events_ts ON block_events(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_block_events_ip ON block_events(ip)`,
		`CREATE INDEX IF NOT EXISTS idx_block_events_pattern ON block_events(rule_pattern)`,

		`CREATE TABLE IF NOT EXISTS overrides (
			ip          TEXT PRIMARY KEY,
			action      TEXT NOT NULL,    -- allow|deny
			reason      TEXT NOT NULL DEFAULT '',
			created_at  INTEGER NOT NULL
		)`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("store: migrate: %w (%s)", err, q)
		}
	}
	return nil
}

// GetIP returns the cached record for ip, or nil if missing.
func (s *Store) GetIP(ctx context.Context, ip string) (*model.IPRecord, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT ip, hostname, verification, decision, rule_pattern, ua,
		        checked_at, expires_at, hit_count
		   FROM ip_cache WHERE ip = ?`, ip)
	var r model.IPRecord
	var checkedAt, expiresAt int64
	var verification, decision string
	if err := row.Scan(&r.IP, &r.Hostname, &verification, &decision,
		&r.RulePattern, &r.UA, &checkedAt, &expiresAt, &r.HitCount); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	r.Verification = model.Verification(verification)
	r.Decision = model.Decision(decision)
	r.CheckedAt = time.Unix(checkedAt, 0)
	r.ExpiresAt = time.Unix(expiresAt, 0)
	return &r, nil
}

// UpsertIP writes or updates the cache record.
func (s *Store) UpsertIP(ctx context.Context, r *model.IPRecord) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO ip_cache(ip, hostname, verification, decision, rule_pattern, ua,
		                    checked_at, expires_at, hit_count)
		VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(ip) DO UPDATE SET
		  hostname     = excluded.hostname,
		  verification = excluded.verification,
		  decision     = excluded.decision,
		  rule_pattern = excluded.rule_pattern,
		  ua           = excluded.ua,
		  checked_at   = excluded.checked_at,
		  expires_at   = excluded.expires_at
	`,
		r.IP, r.Hostname, string(r.Verification), string(r.Decision),
		r.RulePattern, r.UA, r.CheckedAt.Unix(), r.ExpiresAt.Unix(), r.HitCount)
	return err
}

// IncrementHit bumps hit_count for an existing IP and refreshes UA.
func (s *Store) IncrementHit(ctx context.Context, ip, ua string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE ip_cache SET hit_count = hit_count + 1, ua = ? WHERE ip = ?`, ua, ip)
	return err
}

// RecordBlockEvent inserts an entry in block_events.
func (s *Store) RecordBlockEvent(ctx context.Context, e *model.BlockEvent) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO block_events(ip, hostname, ua, path, host, rule_pattern, ts)
		VALUES(?,?,?,?,?,?,?)`,
		e.IP, e.Hostname, e.UA, e.Path, e.Host, e.RulePattern, e.TS.Unix())
	return err
}

// ActiveBlockedIPs returns IPs whose decision == "deny" and that have had a
// block event within the retention window. Manual allow-overrides are
// excluded; manual deny-overrides are always included regardless of recency.
func (s *Store) ActiveBlockedIPs(ctx context.Context, retention time.Duration) ([]string, error) {
	cutoff := time.Now().Add(-retention).Unix()
	rows, err := s.db.QueryContext(ctx, `
		WITH candidates AS (
		  SELECT DISTINCT ip FROM block_events WHERE ts >= ?
		  UNION
		  SELECT ip FROM overrides WHERE action = 'deny'
		)
		SELECT c.ip
		  FROM candidates c
		  LEFT JOIN overrides o ON o.ip = c.ip
		 WHERE COALESCE(o.action, '') <> 'allow'
		 ORDER BY c.ip`, cutoff)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, rows.Err()
}

// SetOverride forces a verdict for an IP regardless of resolver state.
func (s *Store) SetOverride(ctx context.Context, ip, action, reason string) error {
	if action != "allow" && action != "deny" {
		return fmt.Errorf("invalid override action %q", action)
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO overrides(ip,action,reason,created_at) VALUES(?,?,?,?)
		 ON CONFLICT(ip) DO UPDATE SET action=excluded.action, reason=excluded.reason`,
		ip, action, reason, time.Now().Unix())
	return err
}

// DropOverride removes any override for the given IP.
func (s *Store) DropOverride(ctx context.Context, ip string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM overrides WHERE ip=?`, ip)
	return err
}

// Override looks up a manual verdict.
func (s *Store) Override(ctx context.Context, ip string) (string, error) {
	var act string
	err := s.db.QueryRowContext(ctx, `SELECT action FROM overrides WHERE ip=?`, ip).Scan(&act)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return act, err
}

// PurgeExpired drops cache entries past their TTL.
func (s *Store) PurgeExpired(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM ip_cache WHERE expires_at > 0 AND expires_at < ?`, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
