package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/postfriday/botguard/internal/model"
	"github.com/postfriday/botguard/internal/store"
)

func TestHandleMetricsReportsResolutionStats(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "botguard.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = st.Close() }()

	now := time.Now()
	for _, rec := range []model.IPRecord{
		{IP: "203.0.113.1", Verification: model.VerifyConfirmed},
		{IP: "203.0.113.2", Verification: model.VerifyForwardMissing},
		{IP: "203.0.113.3", Verification: model.VerifyDNSError},
	} {
		rec.Decision = model.DecisionNeutral
		rec.CheckedAt = now
		rec.ExpiresAt = now.Add(time.Hour)
		if err := st.UpsertIP(ctx, &rec); err != nil {
			t.Fatalf("UpsertIP(%s): %v", rec.IP, err)
		}
	}

	s := New(Options{Store: st})
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	s.handleMetrics(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var got store.ResolutionStats
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.FCrDNSSuccesses != 1 || got.FCrDNSFailures != 1 || got.ResolverFailures != 1 {
		t.Fatalf("metrics = %+v, want one success, one validation failure, one resolver failure", got)
	}
}
