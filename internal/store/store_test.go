package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/postfriday/botguard/internal/model"
)

func TestResolutionStatsGroupsVerificationOutcomes(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "botguard.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = st.Close() }()

	now := time.Now()
	records := []model.IPRecord{
		{IP: "203.0.113.1", Verification: model.VerifyConfirmed},
		{IP: "203.0.113.2", Verification: model.VerifyMismatch},
		{IP: "203.0.113.3", Verification: model.VerifyNoPTR},
		{IP: "203.0.113.4", Verification: model.VerifyForwardMissing},
		{IP: "203.0.113.5", Verification: model.VerifyDNSError},
		{IP: "203.0.113.6", Verification: model.VerifyUnattempted},
	}
	for _, rec := range records {
		rec.Decision = model.DecisionNeutral
		rec.CheckedAt = now
		rec.ExpiresAt = now.Add(time.Hour)
		if err := st.UpsertIP(ctx, &rec); err != nil {
			t.Fatalf("UpsertIP(%s): %v", rec.IP, err)
		}
	}

	got, err := st.ResolutionStats(ctx)
	if err != nil {
		t.Fatalf("ResolutionStats: %v", err)
	}
	if got.FCrDNSSuccesses != 1 {
		t.Fatalf("FCrDNSSuccesses = %d, want 1", got.FCrDNSSuccesses)
	}
	if got.FCrDNSFailures != 3 {
		t.Fatalf("FCrDNSFailures = %d, want 3", got.FCrDNSFailures)
	}
	if got.ResolverFailures != 1 {
		t.Fatalf("ResolverFailures = %d, want 1", got.ResolverFailures)
	}
	if got.Unattempted != 1 {
		t.Fatalf("Unattempted = %d, want 1", got.Unattempted)
	}
	if got.ByVerification[string(model.VerifyForwardMissing)] != 1 {
		t.Fatalf("forward_missing count = %d, want 1", got.ByVerification[string(model.VerifyForwardMissing)])
	}
}
