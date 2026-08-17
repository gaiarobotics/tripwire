package config

import (
	"gopkg.in/yaml.v3"

	"github.com/mbarnathan/tripwire/internal/bait"
	"strings"
	"testing"
	"time"
)

func TestLoadWorkstationDefaults(t *testing.T) {
	cfg, err := Parse([]byte(`profile: workstation`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Profile != "workstation" {
		t.Fatalf("profile = %q", cfg.Profile)
	}
	// Install default is alert-only regardless of profile.
	if got := cfg.Actions; len(got) != 1 || got[0] != "alert" {
		t.Fatalf("actions = %v, want [alert]", got)
	}
	if cfg.AlertTimeout != 10*time.Second {
		t.Fatalf("AlertTimeout = %v, want 10s", cfg.AlertTimeout)
	}
}

func TestHoldDefaultsFromLadder(t *testing.T) {
	// Destructive ladder -> 15s cap.
	cfg, err := Parse([]byte("actions: [alert, poweroff]"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EffectiveHold() != 15*time.Second {
		t.Fatalf("hold = %v, want 15s", cfg.EffectiveHold())
	}
	// Alert-only -> 3s.
	cfg2, _ := Parse([]byte("actions: [alert]"))
	if cfg2.EffectiveHold() != 3*time.Second {
		t.Fatalf("hold = %v, want 3s", cfg2.EffectiveHold())
	}
	// Explicit hold: 0 wins.
	cfg3, _ := Parse([]byte("actions: [alert, poweroff]\nhold: 0s"))
	if cfg3.EffectiveHold() != 0 {
		t.Fatalf("hold = %v, want 0", cfg3.EffectiveHold())
	}
}

func TestValidateRejectsUnknownAction(t *testing.T) {
	_, err := Parse([]byte("actions: [alert, nuke]"))
	if err == nil || !strings.Contains(err.Error(), "nuke") {
		t.Fatalf("err = %v, want mention of nuke", err)
	}
}

func TestValidateRejectsUnknownKillScope(t *testing.T) {
	_, err := Parse([]byte("actions: [kill]\nkill: {scope: galaxy}"))
	if err == nil || !strings.Contains(err.Error(), "galaxy") {
		t.Fatalf("err = %v, want mention of galaxy", err)
	}
}

func TestArmedFalseWhenAlertOnly(t *testing.T) {
	cfg, _ := Parse([]byte("actions: [alert]"))
	if cfg.HasDestructiveAction() {
		t.Fatal("alert-only must not be destructive")
	}
	cfg2, _ := Parse([]byte("actions: [alert, kill]"))
	if !cfg2.HasDestructiveAction() {
		t.Fatal("kill is destructive")
	}
}

func TestValidateRejectsBadCapEffMask(t *testing.T) {
	_, err := Parse([]byte("allow:\n  - {exe: /usr/bin/aide, cap_eff: zzz}"))
	if err == nil || !strings.Contains(err.Error(), "cap_eff") {
		t.Fatalf("err = %v, want a cap_eff parse error", err)
	}
}

func TestCapEffMaskAcceptsBareAndPrefixedHex(t *testing.T) {
	cfg, err := Parse([]byte("allow:\n  - {exe: /usr/bin/aide, cap_eff: \"0x200004\"}\n  - {exe: /usr/bin/dump, cap_eff: \"000001ffffffffff\"}"))
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []uint64{0x200004, 0x1ffffffffff} {
		got, ok, err := cfg.Allow[i].CapEffMask()
		if err != nil || !ok || got != want {
			t.Fatalf("allow[%d] mask = %#x (ok=%t, err=%v), want %#x", i, got, ok, err, want)
		}
	}
	// No mask set means no capability requirement.
	if _, ok, _ := (AllowRule{Exe: "/x"}).CapEffMask(); ok {
		t.Fatal("an unset cap_eff must not impose a requirement")
	}
}

// The journald record is never configurable — only the desktop notification is,
// and only the workstation profile has a desktop to notify.
func TestDesktopNotifyRules(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want bool
	}{
		{"workstation default", "profile: workstation", true},
		{"workstation opted out", "profile: workstation\nsinks: {journal: false}", false},
		{"workstation explicit", "profile: workstation\nsinks: {journal: true}", true},
		{"server default", "profile: server", false},
		{"server cannot opt in", "profile: server\nsinks: {journal: true}", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse([]byte(tc.yaml))
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.DesktopNotify(); got != tc.want {
				t.Fatalf("DesktopNotify() = %t, want %t", got, tc.want)
			}
		})
	}
}

// The plain list is the documented default and must keep working untouched.
func TestBaitAcceptsPlainStringList(t *testing.T) {
	cfg, err := Parse([]byte("bait:\n  - /etc/codex/auth.json\n  - /etc/claude-code/credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.BaitPaths(); len(got) != 2 || got[0] != "/etc/codex/auth.json" {
		t.Fatalf("paths = %v", got)
	}
	for i, b := range cfg.Bait {
		if b.Kind != "auto" {
			t.Fatalf("bait[%d].Kind = %q, want auto for a bare path", i, b.Kind)
		}
	}
	decoys, err := cfg.Decoys()
	if err != nil {
		t.Fatal(err)
	}
	if decoys[0].Kind != bait.KindCodex || decoys[1].Kind != bait.KindClaude {
		t.Fatalf("auto inference failed: %+v", decoys)
	}
}

// An explicit kind overrides what the filename suggests — the whole point of the
// long form.
func TestBaitKindOverridesInference(t *testing.T) {
	cfg, err := Parse([]byte(`
bait:
  - { path: /srv/app/codex-looking.json, kind: claude }
  - { path: /srv/app/anthropic-looking.json, kind: codex }
`))
	if err != nil {
		t.Fatal(err)
	}
	decoys, err := cfg.Decoys()
	if err != nil {
		t.Fatal(err)
	}
	if decoys[0].Kind != bait.KindClaude {
		t.Fatal("explicit kind: claude must beat the codex-looking filename")
	}
	if decoys[1].Kind != bait.KindCodex {
		t.Fatal("explicit kind: codex must beat the anthropic-looking filename")
	}
}

// Both forms in one list, which is what a config looks like mid-migration.
func TestBaitAcceptsMixedForms(t *testing.T) {
	cfg, err := Parse([]byte(`
bait:
  - /etc/codex/auth.json
  - { path: /srv/app/creds.json, kind: codex }
  - { path: /srv/app/other.json }
  - { path: /srv/app/explicit-auto.json, kind: auto }
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Bait) != 4 {
		t.Fatalf("got %d entries", len(cfg.Bait))
	}
	decoys, err := cfg.Decoys()
	if err != nil {
		t.Fatal(err)
	}
	want := []bait.Kind{bait.KindCodex, bait.KindCodex, bait.KindClaude, bait.KindClaude}
	for i, w := range want {
		if decoys[i].Kind != w {
			t.Fatalf("decoy %d (%s) kind = %v, want %v", i, decoys[i].Path, decoys[i].Kind, w)
		}
	}
	// An omitted kind and an explicit "auto" must mean the same thing.
	if cfg.Bait[2].Kind != "auto" || cfg.Bait[3].Kind != "auto" {
		t.Fatalf("kinds = %q, %q; both should normalise to auto", cfg.Bait[2].Kind, cfg.Bait[3].Kind)
	}
}

func TestBaitRejectsUnknownKind(t *testing.T) {
	_, err := Parse([]byte("bait:\n  - { path: /etc/codex/auth.json, kind: gemini }"))
	if err == nil || !strings.Contains(err.Error(), "gemini") {
		t.Fatalf("err = %v, want the bad kind named", err)
	}
	if err != nil && !strings.Contains(err.Error(), "auto, claude, codex") {
		t.Fatalf("err = %v, want the valid kinds listed", err)
	}
}

func TestBaitRejectsRelativeAndEmptyPaths(t *testing.T) {
	if _, err := Parse([]byte("bait:\n  - relative/auth.json")); err == nil {
		t.Fatal("a relative bait path must be rejected")
	}
	if _, err := Parse([]byte("bait:\n  - { kind: codex }")); err == nil {
		t.Fatal("a bait entry without a path must be rejected")
	}
}

// An absent bait list means the four shipped decoys, decided in one place.
func TestBaitDefaultsToTheShippedDecoys(t *testing.T) {
	cfg, err := Parse([]byte("profile: server"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(cfg.BaitPaths()), len(bait.DefaultPaths()); got != want {
		t.Fatalf("default bait count = %d, want %d", got, want)
	}
	decoys, err := cfg.Decoys()
	if err != nil {
		t.Fatal(err)
	}
	for i, d := range decoys {
		if d != bait.DefaultDecoys()[i] {
			t.Fatalf("default decoy %d = %+v, want %+v", i, d, bait.DefaultDecoys()[i])
		}
	}
}

// Writing a config back out must not convert a readable list of paths into a
// list of mappings.
func TestBaitMarshalsBackToTheShortForm(t *testing.T) {
	cfg, err := Parse([]byte("bait:\n  - /etc/codex/auth.json\n  - { path: /srv/app/creds.json, kind: codex }"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := yaml.Marshal(cfg.Bait)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "- /etc/codex/auth.json") {
		t.Fatalf("auto entries should round-trip as bare paths:\n%s", out)
	}
	if !strings.Contains(string(out), "kind: codex") {
		t.Fatalf("explicit kinds must survive the round trip:\n%s", out)
	}
	// And the round trip must parse back to the same decoys.
	var back []BaitEntry
	if err := yaml.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	if len(back) != 2 || back[0].Kind != "auto" || back[1].Kind != "codex" {
		t.Fatalf("round-tripped entries = %+v", back)
	}
}
