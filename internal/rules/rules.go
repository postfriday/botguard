// Package rules evaluates allow/deny verdicts against a (hostname, UA) pair.
//
// Rules are evaluated in order; first match wins. A rule may specify any of:
//
//   - ua_regex:        case-insensitive regex against the User-Agent
//   - hostname_suffix: list of DNS suffixes to match against the FCrDNS-verified hostname
//   - require_fcrdns:  if true, the rule only matches when the hostname is FCrDNS-confirmed
//
// Within one rule, all listed conditions must hold (AND).
package rules

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/postfriday/botguard/internal/model"

	"gopkg.in/yaml.v3"
)

// Rule is a single allow/deny clause.
type Rule struct {
	Name           string   `yaml:"name"`
	Action         string   `yaml:"action"` // "allow" | "deny"
	UARegex        string   `yaml:"ua_regex"`
	HostnameSuffix []string `yaml:"hostname_suffix"`
	RequireFCrDNS  bool     `yaml:"require_fcrdns"`

	uaCompiled *regexp.Regexp `yaml:"-"`
}

// Set is the parsed list of rules.
type Set struct {
	Rules []*Rule
}

// Decision returned by Evaluate.
type Decision struct {
	Action      model.Decision
	RulePattern string
}

// Load reads and validates a rules file.
func Load(path string) (*Set, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("rules: read %s: %w", path, err)
	}
	var doc struct {
		Rules []*Rule `yaml:"rules"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("rules: parse %s: %w", path, err)
	}
	for i, r := range doc.Rules {
		if r.Name == "" {
			r.Name = fmt.Sprintf("rule-%d", i)
		}
		switch r.Action {
		case "allow", "deny":
		default:
			return nil, fmt.Errorf("rules: %s: action must be allow|deny (got %q)", r.Name, r.Action)
		}
		if r.UARegex != "" {
			re, err := regexp.Compile("(?i)" + r.UARegex)
			if err != nil {
				return nil, fmt.Errorf("rules: %s: bad ua_regex: %w", r.Name, err)
			}
			r.uaCompiled = re
		}
		// normalize suffixes
		for j, s := range r.HostnameSuffix {
			s = strings.ToLower(strings.TrimSpace(s))
			s = strings.TrimPrefix(s, "*.")
			s = strings.TrimSuffix(s, ".")
			r.HostnameSuffix[j] = s
		}
	}
	return &Set{Rules: doc.Rules}, nil
}

// Evaluate finds the first rule matching (hostname, ua, verified). hostname
// should be the FCrDNS-confirmed name when verified is true; otherwise the
// raw PTR (used only for diagnostics).
func (s *Set) Evaluate(hostname, ua string, verified bool) Decision {
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
	for _, r := range s.Rules {
		if !ruleMatches(r, hostname, ua, verified) {
			continue
		}
		return Decision{
			Action:      model.Decision(r.Action),
			RulePattern: r.Name,
		}
	}
	return Decision{Action: model.DecisionNeutral}
}

func ruleMatches(r *Rule, hostname, ua string, verified bool) bool {
	if r.RequireFCrDNS && !verified {
		return false
	}
	if r.uaCompiled != nil {
		if ua == "" || !r.uaCompiled.MatchString(ua) {
			return false
		}
	}
	if len(r.HostnameSuffix) > 0 {
		if hostname == "" {
			return false
		}
		ok := false
		for _, s := range r.HostnameSuffix {
			if hostname == s || strings.HasSuffix(hostname, "."+s) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	// Reject empty rules (no conditions) to avoid catching everything by accident.
	if r.uaCompiled == nil && len(r.HostnameSuffix) == 0 {
		return false
	}
	return true
}

// HasUARule returns true when at least one rule mentions the given UA pattern;
// useful to decide if FCrDNS should be skipped for unknown UAs in fast-path.
func (s *Set) HasAnyUARule() bool {
	for _, r := range s.Rules {
		if r.uaCompiled != nil {
			return true
		}
	}
	return false
}
