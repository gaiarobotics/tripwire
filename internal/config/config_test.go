package config

import (
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
