// Package model contains shared data structures used across botguard packages.
package model

import "time"

// Decision is the verdict botguard assigns to an IP after FCrDNS verification
// and rule evaluation.
type Decision string

const (
	DecisionAllow   Decision = "allow"   // explicit allow from a rule (whitelist)
	DecisionDeny    Decision = "deny"    // explicit deny — IP must be blocked
	DecisionNeutral Decision = "neutral" // no rule matched
	DecisionPending Decision = "pending" // resolution still in progress
	DecisionError   Decision = "error"   // resolver failed (SERVFAIL, timeout)
)

// Verification captures the FCrDNS state of a hostname.
type Verification string

const (
	VerifyConfirmed   Verification = "confirmed"   // PTR -> hostname, A -> IP matches
	VerifyMismatch    Verification = "mismatch"    // forward lookup did not include the IP
	VerifyNoPTR       Verification = "no_ptr"      // no PTR record
	VerifyDNSError    Verification = "dns_error"   // SERVFAIL/timeout/network
	VerifyUnattempted Verification = "unattempted" // not resolved yet
)

// IPRecord is a cached row about a single IP.
type IPRecord struct {
	IP           string
	Hostname     string
	Verification Verification
	Decision     Decision
	RulePattern  string // matched rule name (if any)
	UA           string // last seen user-agent
	CheckedAt    time.Time
	ExpiresAt    time.Time
	HitCount     int64
}

// Event is one log line of interest (request from Caddy access log).
type Event struct {
	IP       string
	UA       string
	Path     string
	Status   int
	Host     string
	TS       time.Time
	RawBytes int // size of source line, used to estimate budget
}

// BlockEvent is recorded each time a request was matched as deny.
type BlockEvent struct {
	IP          string
	Hostname    string
	UA          string
	Path        string
	Host        string
	RulePattern string
	TS          time.Time
}
