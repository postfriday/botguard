// Package resolver performs Forward-Confirmed Reverse DNS (FCrDNS).
//
//	IP -> PTR -> hostname
//	hostname -> A/AAAA -> {IPs}
//	if IP ∈ {IPs}  => confirmed
//	otherwise      => mismatch  (PTR is spoofed or stale)
package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/postfriday/botguard/internal/model"
)

// Result is the outcome of a single FCrDNS lookup.
type Result struct {
	IP           string
	Hostname     string // canonical, lowercased, trailing dot stripped
	Verification model.Verification
	Reason       string // set for FCrDNS validation failures
	Err          error
}

const (
	ReasonNoPTR           = "ptr lookup returned NXDOMAIN"
	ReasonForwardNotFound = "forward lookup returned NXDOMAIN or no A/AAAA records"
	ReasonForwardMismatch = "forward lookup did not include original IP"
)

type lookupResolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// Resolver wraps a *net.Resolver with a worker pool and timeout.
type Resolver struct {
	rs      lookupResolver
	timeout time.Duration
	sem     chan struct{}
}

// New creates a Resolver with the given timeout, max in-flight lookups, and
// optional explicit DNS servers (host:port). When servers is empty, the
// system resolver is used.
func New(timeout time.Duration, maxInFlight int, servers []string) *Resolver {
	if maxInFlight <= 0 {
		maxInFlight = 32
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	r := &Resolver{
		timeout: timeout,
		sem:     make(chan struct{}, maxInFlight),
	}
	if len(servers) > 0 {
		r.rs = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				// round-robin: just pick first; net.Resolver retries on failure
				return d.DialContext(ctx, network, servers[0])
			},
		}
	} else {
		r.rs = net.DefaultResolver
	}
	return r
}

// Lookup performs FCrDNS for ip. Always returns a non-nil Result.
func (r *Resolver) Lookup(ctx context.Context, ip string) Result {
	res := Result{IP: ip}
	if net.ParseIP(ip) == nil {
		res.Verification = model.VerifyDNSError
		res.Err = fmt.Errorf("invalid ip %q", ip)
		return res
	}
	r.sem <- struct{}{}
	defer func() { <-r.sem }()

	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	names, err := r.rs.LookupAddr(ctx, ip)
	if err != nil {
		if isNXDomain(err) {
			res.Verification = model.VerifyNoPTR
			res.Reason = ReasonNoPTR
			return res
		}
		res.Verification = model.VerifyDNSError
		res.Err = err
		return res
	}
	if len(names) == 0 {
		res.Verification = model.VerifyNoPTR
		res.Reason = ReasonNoPTR
		return res
	}
	host := normalize(names[0])
	res.Hostname = host

	addrs, err := r.rs.LookupHost(ctx, host)
	if err != nil {
		if isNXDomain(err) {
			res.Verification = model.VerifyForwardMissing
			res.Reason = ReasonForwardNotFound
			return res
		}
		res.Verification = model.VerifyDNSError
		res.Err = err
		return res
	}
	if len(addrs) == 0 {
		res.Verification = model.VerifyForwardMissing
		res.Reason = ReasonForwardNotFound
		return res
	}
	for _, a := range addrs {
		if equalIP(a, ip) {
			res.Verification = model.VerifyConfirmed
			return res
		}
	}
	res.Verification = model.VerifyMismatch
	res.Reason = ReasonForwardMismatch
	return res
}

// isNXDomain returns true for NXDOMAIN-style errors.
func isNXDomain(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	return false
}

func normalize(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimSuffix(host, ".")
	return strings.ToLower(host)
}

func equalIP(a, b string) bool {
	ipA := net.ParseIP(a)
	ipB := net.ParseIP(b)
	if ipA == nil || ipB == nil {
		return strings.EqualFold(a, b)
	}
	return ipA.Equal(ipB)
}
