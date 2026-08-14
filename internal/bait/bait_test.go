package bait

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultDecoysCoverBothTools(t *testing.T) {
	paths := DefaultPaths()
	joined := strings.Join(paths, " ")
	for _, want := range []string{"claude", "anthropic", "codex", "openai"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("default paths missing %q: %v", want, paths)
		}
	}
	for _, p := range paths {
		if !filepath.IsAbs(p) || !strings.HasPrefix(p, "/etc/") {
			t.Fatalf("decoy %q must be an absolute /etc path", p)
		}
	}
}

func TestPlaceWritesValidJSONWithFingerprint(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "codex", "auth.json")
	now := time.Unix(1_700_000_000, 0).UTC()

	d := Decoy{Path: target, Kind: KindCodex}
	if err := Place(d, "tw-deadbeefdeadbeef", now); err != nil {
		t.Fatalf("Place: %v", err)
	}

	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("not valid json: %v", err)
	}
	if !strings.Contains(string(raw), "tw-deadbeefdeadbeef") {
		t.Fatal("fingerprint not embedded")
	}
	fi, _ := os.Stat(target)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("perm = %v, want 0600", fi.Mode().Perm())
	}
}

// A decoy carrying a long-expired token is a tell that it is bait, so every
// rendered schema must express its expiry in the future relative to `now`.
func TestPlacedTokenExpiryIsInTheFuture(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0).UTC()

	claudePath := filepath.Join(dir, "claude", "credentials.json")
	if err := Place(Decoy{Path: claudePath, Kind: KindClaude}, "tw-deadbeefdeadbeef", now); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(claudePath)
	var claudeDoc struct {
		OAuth struct {
			ExpiresAt int64 `json:"expiresAt"`
		} `json:"claudeAiOauth"`
	}
	if err := json.Unmarshal(raw, &claudeDoc); err != nil {
		t.Fatal(err)
	}
	if claudeDoc.OAuth.ExpiresAt <= now.UnixMilli() {
		t.Fatalf("claude expiresAt = %d, want > %d", claudeDoc.OAuth.ExpiresAt, now.UnixMilli())
	}

	codexPath := filepath.Join(dir, "codex", "auth.json")
	if err := Place(Decoy{Path: codexPath, Kind: KindCodex}, "tw-deadbeefdeadbeef", now); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(codexPath)
	var codexDoc struct {
		LastRefresh time.Time `json:"last_refresh"`
	}
	if err := json.Unmarshal(raw, &codexDoc); err != nil {
		t.Fatal(err)
	}
	if !codexDoc.LastRefresh.Equal(now) {
		t.Fatalf("codex last_refresh = %v, want %v", codexDoc.LastRefresh, now)
	}
}

func TestVerifyDetectsMissingAndModified(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "codex", "auth.json")
	d := Decoy{Path: target, Kind: KindCodex}
	now := time.Unix(1_700_000_000, 0).UTC()
	_ = Place(d, "tw-deadbeefdeadbeef", now)

	if err := Verify(d); err != nil {
		t.Fatalf("freshly placed decoy should verify: %v", err)
	}
	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Verify(d); err == nil {
		t.Fatal("world-readable decoy should fail verify")
	}
	_ = os.Remove(target)
	if err := Verify(d); err == nil {
		t.Fatal("missing decoy should fail verify")
	}
}
