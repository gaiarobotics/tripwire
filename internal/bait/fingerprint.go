package bait

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
)

// FingerprintFromSeed derives a stable, greppable per-install id from a seed.
func FingerprintFromSeed(seed string) string {
	sum := sha256.Sum256([]byte("tripwire\x00" + seed))
	return "tw-" + hex.EncodeToString(sum[:8])
}

// Fingerprint derives the install id from the host's machine-id, falling back
// to the hostname. The result is embedded in every bait token so a leaked
// token can be traced to the host that leaked it.
func Fingerprint() string {
	if b, err := os.ReadFile("/etc/machine-id"); err == nil && len(b) > 0 {
		return FingerprintFromSeed(string(b))
	}
	if h, err := os.Hostname(); err == nil {
		return FingerprintFromSeed(h)
	}
	return FingerprintFromSeed(fmt.Sprintf("pid-%d", os.Getpid()))
}
