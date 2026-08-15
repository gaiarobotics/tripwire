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

func TestKindForKnownAndInferredPaths(t *testing.T) {
	cases := map[string]Kind{
		"/etc/codex/auth.json":                    KindCodex, // known default
		"/etc/claude-code/credentials.json":       KindClaude,
		"/etc/openai/codex-auth.json":             KindCodex,
		"/srv/secrets/openai.json":                KindCodex,  // inferred by name
		"/srv/secrets/CODEX-creds.json":           KindCodex,  // case-insensitive
		"/srv/secrets/anthropic-credentials.json": KindClaude, // default schema
		"/srv/secrets/api.json":                   KindClaude,
	}
	for path, want := range cases {
		if got := KindFor(path); got != want {
			t.Errorf("KindFor(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestDecoysForPairsEveryPath(t *testing.T) {
	paths := []string{"/etc/codex/auth.json", "/srv/custom/creds.json"}
	got := DecoysFor(paths)
	if len(got) != 2 {
		t.Fatalf("DecoysFor returned %d decoys", len(got))
	}
	if got[0].Kind != KindCodex || got[1].Kind != KindClaude {
		t.Fatalf("kinds = %v, %v", got[0].Kind, got[1].Kind)
	}
	for i, d := range got {
		if d.Path != paths[i] {
			t.Fatalf("path %d = %q, want %q", i, d.Path, paths[i])
		}
	}
}

// A mistyped bait path must never cost the operator a real credential file:
// placement follows configuration, so it has to refuse anything it did not write.
func TestPlaceSafeRefusesToClobberForeignFiles(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "passwd")
	const original = "root:x:0:0:root:/root:/bin/bash\n"
	if err := os.WriteFile(real, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	err := PlaceSafe(Decoy{Path: real, Kind: KindCodex}, "tw-deadbeefdeadbeef", time.Now())
	if err == nil {
		t.Fatal("PlaceSafe must refuse to overwrite a file it did not write")
	}
	if !strings.Contains(err.Error(), "not written by Tripwire") {
		t.Fatalf("err = %v, want it to explain the refusal", err)
	}
	got, _ := os.ReadFile(real)
	if string(got) != original {
		t.Fatal("the existing file was modified despite the refusal")
	}
}

func TestPlaceSafeCreatesAndThenRefreshesItsOwnFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "nested", "auth.json")
	d := Decoy{Path: target, Kind: KindCodex}

	if err := PlaceSafe(d, "tw-deadbeefdeadbeef", time.Unix(1_700_000_000, 0).UTC()); err != nil {
		t.Fatalf("creating a new decoy must succeed: %v", err)
	}
	// A refresh rewrites the same path: it is ours, so it is allowed.
	later := time.Unix(1_800_000_000, 0).UTC()
	if err := PlaceSafe(d, "tw-deadbeefdeadbeef", later); err != nil {
		t.Fatalf("refreshing our own decoy must succeed: %v", err)
	}
	raw, _ := os.ReadFile(target)
	if !strings.Contains(string(raw), later.Format(time.RFC3339)) {
		t.Fatal("refresh did not update the timestamp")
	}
}

func TestPlaceSafeRequiresAbsolutePaths(t *testing.T) {
	if err := PlaceSafe(Decoy{Path: "relative/auth.json"}, "tw-x", time.Now()); err == nil {
		t.Fatal("a relative decoy path must be rejected")
	}
}

func TestIsOursRecognisesOurFilesOnly(t *testing.T) {
	dir := t.TempDir()

	missing := filepath.Join(dir, "absent.json")
	if ours, err := IsOurs(missing); err != nil || !ours {
		t.Fatalf("a missing path is free to create: ours=%t err=%v", ours, err)
	}

	decoy := filepath.Join(dir, "auth.json")
	if err := Place(Decoy{Path: decoy, Kind: KindCodex}, "tw-deadbeefdeadbeef", time.Now()); err != nil {
		t.Fatal(err)
	}
	if ours, err := IsOurs(decoy); err != nil || !ours {
		t.Fatalf("a placed decoy must be recognised: ours=%t err=%v", ours, err)
	}

	foreign := filepath.Join(dir, "real-creds.json")
	if err := os.WriteFile(foreign, []byte(`{"api_key":"sk-live-not-a-decoy"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if ours, err := IsOurs(foreign); err != nil || ours {
		t.Fatalf("a real credential file must not look like ours: ours=%t err=%v", ours, err)
	}

	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if ours, _ := IsOurs(empty); ours {
		t.Fatal("an empty file is not recognisably ours; refuse rather than guess")
	}
}
