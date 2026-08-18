package action

import (
	"slices"
	"strings"
	"testing"
)

// The graceful poweroff must not broadcast. systemctl sends a wall message to
// every logged-in session by default, which would hand a hostile reader still
// holding a shell warning of the shutdown — exactly who this must stay silent
// from. --no-wall is what suppresses it, so it is load-bearing, not cosmetic.
func TestGracefulPoweroffIsSilent(t *testing.T) {
	args := poweroffCmd().Args
	if !slices.Contains(args, "--no-wall") {
		t.Fatalf("graceful poweroff = %q, missing --no-wall; the attacker would be warned", strings.Join(args, " "))
	}
	if !slices.Contains(args, "poweroff") {
		t.Fatalf("expected a poweroff command, got %q", strings.Join(args, " "))
	}
}
