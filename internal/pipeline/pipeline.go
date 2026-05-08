// Package pipeline glues the tailer, resolver, store, rules and caddyctl into
// a single goroutine-friendly processing loop.
package pipeline

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/postfriday/botguard/internal/caddyctl"
	"github.com/postfriday/botguard/internal/config"
	"github.com/postfriday/botguard/internal/model"
	"github.com/postfriday/botguard/internal/resolver"
	"github.com/postfriday/botguard/internal/rules"
	"github.com/postfriday/botguard/internal/store"
)

// Pipeline owns the long-running loop.
type Pipeline struct {
	cfg   *config.Config
	dur   *config.Durations
	store *store.Store
	res   *resolver.Resolver
	rs    *rules.Set
	cdy   *caddyctl.Controller
	log   *slog.Logger

	dirty chan struct{} // signals "blocklist changed, render snippet"
}

// New constructs a Pipeline. All dependencies must be non-nil.
func New(cfg *config.Config, dur *config.Durations, st *store.Store,
	res *resolver.Resolver, rs *rules.Set, cdy *caddyctl.Controller,
	logger *slog.Logger) *Pipeline {
	return &Pipeline{
		cfg:   cfg,
		dur:   dur,
		store: st,
		res:   res,
		rs:    rs,
		cdy:   cdy,
		log:   logger,
		dirty: make(chan struct{}, 1),
	}
}

// Run consumes events until ctx is canceled.
func (p *Pipeline) Run(ctx context.Context, events <-chan model.Event) error {
	var wg sync.WaitGroup

	// Renderer: redraws blocked.caddy when blocklist changes.
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.runRenderer(ctx)
	}()

	// Periodic cache cleanup.
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.runCleaner(ctx)
	}()

	// First render so an empty snippet exists at startup.
	p.markDirty()

	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return nil
		case ev, ok := <-events:
			if !ok {
				wg.Wait()
				return nil
			}
			p.handle(ctx, ev)
		}
	}
}

func (p *Pipeline) handle(ctx context.Context, ev model.Event) {
	if ev.IP == "" {
		return
	}

	// 0) Manual override always wins.
	if act, _ := p.store.Override(ctx, ev.IP); act != "" {
		switch act {
		case "deny":
			p.recordBlock(ctx, ev, "", "manual:deny")
			p.markDirty()
		}
		return
	}

	// 1) Cache hit?
	rec, _ := p.store.GetIP(ctx, ev.IP)
	if rec != nil && time.Now().Before(rec.ExpiresAt) {
		_ = p.store.IncrementHit(ctx, ev.IP, ev.UA)
		// Re-evaluate UA-only rules each request: a cached neutral IP that
		// suddenly sends a malicious UA must still be blocked.
		dec := p.rs.Evaluate(rec.Hostname, ev.UA, rec.Verification == model.VerifyConfirmed)
		if dec.Action == model.DecisionDeny {
			p.recordBlock(ctx, ev, rec.Hostname, dec.RulePattern)
			p.markDirty()
		}
		return
	}

	// 2) Fast path: UA-only rules can short-circuit before we spend a DNS lookup.
	dec := p.rs.Evaluate("", ev.UA, false)
	if dec.Action == model.DecisionDeny {
		p.upsert(ctx, &model.IPRecord{
			IP: ev.IP, UA: ev.UA, Verification: model.VerifyUnattempted,
			Decision:    model.DecisionDeny,
			RulePattern: dec.RulePattern,
			CheckedAt:   time.Now(),
			ExpiresAt:   time.Now().Add(p.dur.TTLDeny),
		})
		p.recordBlock(ctx, ev, "", dec.RulePattern)
		p.markDirty()
		return
	}
	if dec.Action == model.DecisionAllow {
		p.upsert(ctx, &model.IPRecord{
			IP: ev.IP, UA: ev.UA, Verification: model.VerifyUnattempted,
			Decision:    model.DecisionAllow,
			RulePattern: dec.RulePattern,
			CheckedAt:   time.Now(),
			ExpiresAt:   time.Now().Add(p.dur.TTLAllow),
		})
		return
	}

	// 3) Slow path: FCrDNS lookup.
	r := p.res.Lookup(ctx, ev.IP)
	verified := r.Verification == model.VerifyConfirmed
	host := r.Hostname
	if !verified {
		// keep raw PTR for diagnostics but never use it for allow decisions
		host = r.Hostname
	}
	finalDec := p.rs.Evaluate(host, ev.UA, verified)
	ttl := p.ttlFor(r.Verification, finalDec.Action)

	rec = &model.IPRecord{
		IP:           ev.IP,
		UA:           ev.UA,
		Hostname:     host,
		Verification: r.Verification,
		Decision:     finalDec.Action,
		RulePattern:  finalDec.RulePattern,
		CheckedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(ttl),
	}
	p.upsert(ctx, rec)

	if finalDec.Action == model.DecisionDeny {
		p.recordBlock(ctx, ev, host, finalDec.RulePattern)
		p.markDirty()
	}

	if r.Err != nil {
		p.log.Debug("resolver error", "ip", ev.IP, "err", r.Err)
	}
}

// ttlFor picks a cache TTL based on resolver state and final verdict.
func (p *Pipeline) ttlFor(v model.Verification, d model.Decision) time.Duration {
	switch v {
	case model.VerifyDNSError:
		return p.dur.TTLError
	case model.VerifyNoPTR:
		return p.dur.TTLNXDomain
	}
	switch d {
	case model.DecisionAllow:
		return p.dur.TTLAllow
	case model.DecisionDeny:
		return p.dur.TTLDeny
	}
	return p.dur.TTLNeutral
}

func (p *Pipeline) upsert(ctx context.Context, r *model.IPRecord) {
	if err := p.store.UpsertIP(ctx, r); err != nil {
		p.log.Error("upsert ip failed", "ip", r.IP, "err", err)
	}
}

func (p *Pipeline) recordBlock(ctx context.Context, ev model.Event, hostname, pattern string) {
	host := strings.TrimSpace(hostname)
	err := p.store.RecordBlockEvent(ctx, &model.BlockEvent{
		IP: ev.IP, Hostname: host, UA: ev.UA, Path: ev.Path,
		Host: ev.Host, RulePattern: pattern, TS: ev.TS,
	})
	if err != nil {
		p.log.Error("record block event failed", "err", err)
	}
}

func (p *Pipeline) markDirty() {
	select {
	case p.dirty <- struct{}{}:
	default:
	}
}

func (p *Pipeline) runRenderer(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.dirty:
		}
		ips, err := p.store.ActiveBlockedIPs(ctx, p.dur.BlockRetention)
		if err != nil {
			p.log.Error("blocklist query failed", "err", err)
			continue
		}
		if err := p.cdy.Render(ctx, ips); err != nil {
			p.log.Error("render snippet failed", "err", err)
		}
	}
}

func (p *Pipeline) runCleaner(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := p.store.PurgeExpired(ctx); err != nil {
				p.log.Warn("purge expired failed", "err", err)
			} else if n > 0 {
				p.log.Info("purged expired cache rows", "count", n)
			}
		}
	}
}
