package resolver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/postfriday/botguard/internal/model"
)

type stubLookupResolver struct {
	lookupAddr func(context.Context, string) ([]string, error)
	lookupHost func(context.Context, string) ([]string, error)
}

func (s stubLookupResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	return s.lookupAddr(ctx, addr)
}

func (s stubLookupResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return s.lookupHost(ctx, host)
}

func testResolver(stub stubLookupResolver) *Resolver {
	return &Resolver{
		rs:      stub,
		timeout: time.Second,
		sem:     make(chan struct{}, 1),
	}
}

func TestLookupClassifiesForwardNXDomainAsValidationFailure(t *testing.T) {
	r := testResolver(stubLookupResolver{
		lookupAddr: func(context.Context, string) ([]string, error) {
			return []string{"customer.bnssarg1.isp.starlink.com."}, nil
		},
		lookupHost: func(context.Context, string) ([]string, error) {
			return nil, &net.DNSError{
				Err:        "no such host",
				Name:       "customer.bnssarg1.isp.starlink.com",
				IsNotFound: true,
			}
		},
	})

	got := r.Lookup(context.Background(), "203.0.113.10")
	if got.Err != nil {
		t.Fatalf("Err = %v, want nil", got.Err)
	}
	if got.Verification != model.VerifyForwardMissing {
		t.Fatalf("Verification = %q, want %q", got.Verification, model.VerifyForwardMissing)
	}
	if got.Hostname != "customer.bnssarg1.isp.starlink.com" {
		t.Fatalf("Hostname = %q", got.Hostname)
	}
	if got.Reason != ReasonForwardNotFound {
		t.Fatalf("Reason = %q, want %q", got.Reason, ReasonForwardNotFound)
	}
}

func TestLookupClassifiesForwardTimeoutAsResolverError(t *testing.T) {
	timeoutErr := &net.DNSError{
		Err:         "i/o timeout",
		Name:        "crawl.example.net",
		IsTimeout:   true,
		IsTemporary: true,
	}
	r := testResolver(stubLookupResolver{
		lookupAddr: func(context.Context, string) ([]string, error) {
			return []string{"crawl.example.net."}, nil
		},
		lookupHost: func(context.Context, string) ([]string, error) {
			return nil, timeoutErr
		},
	})

	got := r.Lookup(context.Background(), "203.0.113.11")
	if got.Err != timeoutErr {
		t.Fatalf("Err = %v, want timeout error", got.Err)
	}
	if got.Verification != model.VerifyDNSError {
		t.Fatalf("Verification = %q, want %q", got.Verification, model.VerifyDNSError)
	}
	if got.Reason != "" {
		t.Fatalf("Reason = %q, want empty", got.Reason)
	}
}

func TestLookupClassifiesEmptyForwardResultAsValidationFailure(t *testing.T) {
	r := testResolver(stubLookupResolver{
		lookupAddr: func(context.Context, string) ([]string, error) {
			return []string{"crawl.example.net."}, nil
		},
		lookupHost: func(context.Context, string) ([]string, error) {
			return nil, nil
		},
	})

	got := r.Lookup(context.Background(), "203.0.113.12")
	if got.Err != nil {
		t.Fatalf("Err = %v, want nil", got.Err)
	}
	if got.Verification != model.VerifyForwardMissing {
		t.Fatalf("Verification = %q, want %q", got.Verification, model.VerifyForwardMissing)
	}
	if got.Reason != ReasonForwardNotFound {
		t.Fatalf("Reason = %q, want %q", got.Reason, ReasonForwardNotFound)
	}
}

func TestLookupClassifiesForwardMismatchAsValidationFailure(t *testing.T) {
	r := testResolver(stubLookupResolver{
		lookupAddr: func(context.Context, string) ([]string, error) {
			return []string{"crawl.example.net."}, nil
		},
		lookupHost: func(context.Context, string) ([]string, error) {
			return []string{"203.0.113.99"}, nil
		},
	})

	got := r.Lookup(context.Background(), "203.0.113.12")
	if got.Err != nil {
		t.Fatalf("Err = %v, want nil", got.Err)
	}
	if got.Verification != model.VerifyMismatch {
		t.Fatalf("Verification = %q, want %q", got.Verification, model.VerifyMismatch)
	}
	if got.Reason != ReasonForwardMismatch {
		t.Fatalf("Reason = %q, want %q", got.Reason, ReasonForwardMismatch)
	}
}

func TestLookupClassifiesConfirmedHost(t *testing.T) {
	r := testResolver(stubLookupResolver{
		lookupAddr: func(context.Context, string) ([]string, error) {
			return []string{"crawl.example.net."}, nil
		},
		lookupHost: func(context.Context, string) ([]string, error) {
			return []string{"203.0.113.13"}, nil
		},
	})

	got := r.Lookup(context.Background(), "203.0.113.13")
	if got.Err != nil {
		t.Fatalf("Err = %v, want nil", got.Err)
	}
	if got.Verification != model.VerifyConfirmed {
		t.Fatalf("Verification = %q, want %q", got.Verification, model.VerifyConfirmed)
	}
	if got.Reason != "" {
		t.Fatalf("Reason = %q, want empty", got.Reason)
	}
}
