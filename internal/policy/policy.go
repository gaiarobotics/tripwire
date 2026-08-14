// Package policy decides whether a reader of a decoy is benign (allowlisted) or
// hostile. Default-deny: anything not matched by an allow rule is hostile.
package policy

import (
	"strings"

	"github.com/mbarnathan/tripwire/internal/attrib"
	"github.com/mbarnathan/tripwire/internal/config"
)

// Verdict is the policy outcome.
type Verdict int

const (
	Hostile Verdict = iota
	Benign
)

func (v Verdict) String() string {
	if v == Benign {
		return "benign"
	}
	return "hostile"
}

// Ruleset is a compiled allowlist.
type Ruleset struct {
	rules []config.AllowRule
}

// Compile prepares an allowlist for evaluation.
func Compile(rules []config.AllowRule) *Ruleset {
	return &Ruleset{rules: rules}
}

// Evaluate returns Benign iff some rule matches; otherwise Hostile.
func (rs *Ruleset) Evaluate(id attrib.Identity) Verdict {
	for _, r := range rs.rules {
		if matches(r, id) {
			return Benign
		}
	}
	return Hostile
}

// matches is AND across all set fields; empty fields are wildcards.
func matches(r config.AllowRule, id attrib.Identity) bool {
	// A rule with no fields set matches nothing (guard against an empty rule
	// accidentally allowlisting the world).
	if r.Exe == "" && r.UID == nil && r.LoginUID == nil && r.Unit == "" && r.Ancestor == "" {
		return false
	}
	if r.Exe != "" && r.Exe != id.Exe {
		return false
	}
	if r.UID != nil && *r.UID != id.UID {
		return false
	}
	if r.LoginUID != nil && int64(*r.LoginUID) != id.LoginUID {
		return false
	}
	if r.Unit != "" && !strings.Contains(id.Cgroup, r.Unit) {
		return false
	}
	if r.Ancestor != "" && !hasAncestor(id, r.Ancestor) {
		return false
	}
	return true
}

func hasAncestor(id attrib.Identity, name string) bool {
	for _, a := range id.Ancestors {
		if a.Comm == name || a.Exe == name || strings.HasSuffix(a.Exe, "/"+name) {
			return true
		}
	}
	return false
}
