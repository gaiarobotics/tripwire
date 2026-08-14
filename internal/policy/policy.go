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

// rule is an allow rule with its capability mask pre-parsed, so evaluating an
// event never re-parses config while a reader is held.
type rule struct {
	config.AllowRule
	capEff    uint64
	hasCapEff bool
}

// Ruleset is a compiled allowlist.
type Ruleset struct {
	rules []rule
}

// Compile prepares an allowlist for evaluation. Rules whose capability mask does
// not parse are dropped rather than silently matching everything; config
// validation rejects them first, so this only guards a hand-edited struct.
func Compile(rules []config.AllowRule) *Ruleset {
	out := make([]rule, 0, len(rules))
	for _, r := range rules {
		mask, ok, err := r.CapEffMask()
		if err != nil {
			continue
		}
		out = append(out, rule{AllowRule: r, capEff: mask, hasCapEff: ok})
	}
	return &Ruleset{rules: out}
}

// Evaluate returns Benign iff some rule matches; otherwise Hostile.
func (rs *Ruleset) Evaluate(id attrib.Identity) Verdict {
	for _, r := range rs.rules {
		if r.matches(id) {
			return Benign
		}
	}
	return Hostile
}

// matches is AND across all set fields; empty fields are wildcards.
func (r rule) matches(id attrib.Identity) bool {
	// A rule with no fields set matches nothing (guard against an empty rule
	// accidentally allowlisting the world).
	if r.Exe == "" && r.UID == nil && r.LoginUID == nil && r.Unit == "" &&
		r.Ancestor == "" && !r.hasCapEff {
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
	// The reader must hold every capability named in the mask.
	if r.hasCapEff && id.CapEff&r.capEff != r.capEff {
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
