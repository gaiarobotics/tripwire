package bait

import (
	"regexp"
	"testing"
)

func TestFingerprintFromSeedIsStable(t *testing.T) {
	a := FingerprintFromSeed("host-abc")
	b := FingerprintFromSeed("host-abc")
	if a != b {
		t.Fatalf("not stable: %q vs %q", a, b)
	}
	if FingerprintFromSeed("host-xyz") == a {
		t.Fatal("different seeds must differ")
	}
}

func TestFingerprintShape(t *testing.T) {
	fp := FingerprintFromSeed("host-abc")
	// tw- prefix + 16 lowercase hex chars: identifiable and greppable.
	if !regexp.MustCompile(`^tw-[0-9a-f]{16}$`).MatchString(fp) {
		t.Fatalf("bad shape: %q", fp)
	}
}
