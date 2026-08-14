package policy

import (
	"testing"

	"github.com/mbarnathan/tripwire/internal/attrib"
	"github.com/mbarnathan/tripwire/internal/config"
)

func id(exe string, uid int, loginuid int64, ancestors ...string) attrib.Identity {
	var anc []attrib.Ancestor
	for i, a := range ancestors {
		anc = append(anc, attrib.Ancestor{PID: 100 + i, Comm: a, Exe: a})
	}
	return attrib.Identity{Exe: exe, UID: uid, LoginUID: loginuid, Ancestors: anc}
}

func TestUnmatchedIsHostile(t *testing.T) {
	rs := Compile(nil)
	if v := rs.Evaluate(id("/usr/bin/curl", 1000, 1000)); v != Hostile {
		t.Fatalf("verdict = %v, want Hostile", v)
	}
}

func TestExeAndLoginUIDMustBothMatch(t *testing.T) {
	uid := 0
	rules := []config.AllowRule{{Exe: "/usr/bin/updatedb", LoginUID: &uid}}
	rs := Compile(rules)

	// exe matches, loginuid matches -> benign
	if v := rs.Evaluate(id("/usr/bin/updatedb", 0, 0)); v != Benign {
		t.Fatalf("verdict = %v, want Benign", v)
	}
	// exe matches but loginuid differs -> hostile
	if v := rs.Evaluate(id("/usr/bin/updatedb", 0, 1000)); v != Hostile {
		t.Fatalf("verdict = %v, want Hostile (loginuid mismatch)", v)
	}
}

func TestAncestorMatch(t *testing.T) {
	rules := []config.AllowRule{{Ancestor: "backupd"}}
	rs := Compile(rules)
	if v := rs.Evaluate(id("/usr/bin/tar", 0, 1000, "sh", "backupd")); v != Benign {
		t.Fatalf("verdict = %v, want Benign via ancestor", v)
	}
	if v := rs.Evaluate(id("/usr/bin/tar", 0, 1000, "sh", "sshd")); v != Hostile {
		t.Fatalf("verdict = %v, want Hostile", v)
	}
}

// An ancestor rule naming a bare command must also match an absolute exe path
// ending in that command, but must not match a partial name.
func TestAncestorMatchesPathSuffixOnly(t *testing.T) {
	rs := Compile([]config.AllowRule{{Ancestor: "backupd"}})
	if v := rs.Evaluate(id("/usr/bin/tar", 0, 1000, "/usr/sbin/backupd")); v != Benign {
		t.Fatal("absolute ancestor exe ending in /backupd must match")
	}
	if v := rs.Evaluate(id("/usr/bin/tar", 0, 1000, "/usr/sbin/evilbackupd")); v != Hostile {
		t.Fatal("evilbackupd must not match a backupd rule")
	}
}

// A rule with no fields set would otherwise allowlist every reader, disabling
// the tripwire entirely. It must match nothing.
func TestEmptyRuleMatchesNothing(t *testing.T) {
	rs := Compile([]config.AllowRule{{Comment: "oops, forgot the fields"}})
	if v := rs.Evaluate(id("/usr/bin/curl", 1000, 1000)); v != Hostile {
		t.Fatalf("verdict = %v, want Hostile — an empty rule must not allowlist the world", v)
	}
}

func TestUIDAndUnitMatch(t *testing.T) {
	uid := 0
	rs := Compile([]config.AllowRule{{UID: &uid, Unit: "aide.service"}})
	benign := attrib.Identity{Exe: "/usr/bin/aide", UID: 0, Cgroup: "0::/system.slice/aide.service"}
	if v := rs.Evaluate(benign); v != Benign {
		t.Fatalf("verdict = %v, want Benign via uid+unit", v)
	}
	wrongUnit := attrib.Identity{Exe: "/usr/bin/aide", UID: 0, Cgroup: "0::/system.slice/sshd.service"}
	if v := rs.Evaluate(wrongUnit); v != Hostile {
		t.Fatalf("verdict = %v, want Hostile (unit mismatch)", v)
	}
	wrongUID := attrib.Identity{Exe: "/usr/bin/aide", UID: 1000, Cgroup: "0::/system.slice/aide.service"}
	if v := rs.Evaluate(wrongUID); v != Hostile {
		t.Fatalf("verdict = %v, want Hostile (uid mismatch)", v)
	}
}

// Any one matching rule in the list is enough; rules are ORed with each other
// while fields within a rule are ANDed.
func TestAnyRuleMayMatch(t *testing.T) {
	rs := Compile([]config.AllowRule{
		{Exe: "/usr/bin/updatedb"},
		{Exe: "/usr/bin/aide"},
	})
	if v := rs.Evaluate(id("/usr/bin/aide", 0, 0)); v != Benign {
		t.Fatalf("verdict = %v, want Benign via second rule", v)
	}
}

func TestVerdictString(t *testing.T) {
	if Benign.String() != "benign" || Hostile.String() != "hostile" {
		t.Fatalf("verdict strings = %q/%q", Benign, Hostile)
	}
}
