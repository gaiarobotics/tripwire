// Package bait generates, places, and verifies the decoy credential files that
// Tripwire watches. The tokens are structurally valid but non-functional; each
// carries the per-install fingerprint so a leaked token names the host it came
// from.
package bait

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Kind selects which credential schema a decoy mimics.
type Kind int

const (
	KindClaude Kind = iota
	KindCodex
)

// Decoy is one planted credential file.
type Decoy struct {
	Path string
	Kind Kind
}

// DefaultPaths are the shipped decoy locations. They mimic a system-wide managed
// install and are deliberately nowhere near ~/.claude or ~/.codex.
func DefaultPaths() []string {
	decoys := DefaultDecoys()
	out := make([]string, 0, len(decoys))
	for _, d := range decoys {
		out = append(out, d.Path)
	}
	return out
}

// DefaultDecoys pairs each default path with the schema it should mimic.
func DefaultDecoys() []Decoy {
	return []Decoy{
		{"/etc/claude-code/credentials.json", KindClaude},
		{"/etc/anthropic/claude.credentials.json", KindClaude},
		{"/etc/codex/auth.json", KindCodex},
		{"/etc/openai/codex-auth.json", KindCodex},
	}
}

// Place writes a structurally-valid, non-functional credential file with the
// install fingerprint embedded and a future expiry (no stale-token tell).
// Mode is 0600 root:root (ownership applied by the caller/postinst as root).
func Place(d Decoy, fingerprint string, now time.Time) error {
	if err := os.MkdirAll(filepath.Dir(d.Path), 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	body, err := render(d.Kind, fingerprint, now)
	if err != nil {
		return err
	}
	// Write atomically: temp file + rename, so a reader never sees a partial file
	// and never triggers the wire on a half-written decoy.
	tmp := d.Path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if err := os.Rename(tmp, d.Path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

func render(kind Kind, fp string, now time.Time) ([]byte, error) {
	expiry := now.Add(365 * 24 * time.Hour)
	var doc any
	switch kind {
	case KindClaude:
		doc = map[string]any{
			"claudeAiOauth": map[string]any{
				"accessToken":  "sk-ant-oat01-" + fp + "-0000000000000000000000",
				"refreshToken": "sk-ant-ort01-" + fp + "-0000000000000000000000",
				"expiresAt":    expiry.UnixMilli(),
				"scopes":       []string{"user:inference", "user:profile"},
			},
		}
	case KindCodex:
		doc = map[string]any{
			"OPENAI_API_KEY": "sk-proj-" + fp + "-0000000000000000000000",
			"tokens": map[string]any{
				"access_token":  fp + ".0000000000000000",
				"refresh_token": fp + ".1111111111111111",
				"account_id":    fp,
			},
			"last_refresh": now.UTC().Format(time.RFC3339),
		}
	default:
		return nil, fmt.Errorf("unknown decoy kind %d", kind)
	}
	return json.MarshalIndent(doc, "", "  ")
}

// Verify confirms the decoy still exists and is a regular 0600 file. It does not
// re-check contents — the daemon re-marks on replacement via the parent-dir watch.
func Verify(d Decoy) error {
	fi, err := os.Stat(d.Path)
	if err != nil {
		return fmt.Errorf("decoy %s: %w", d.Path, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("decoy %s is not a regular file", d.Path)
	}
	if fi.Mode().Perm() != 0o600 {
		return fmt.Errorf("decoy %s perm = %v, want 0600", d.Path, fi.Mode().Perm())
	}
	return nil
}

// Refresh rewrites every decoy with a fresh expiry timestamp. The daemon calls
// this periodically so the tokens never look abandoned.
func Refresh(decoys []Decoy, fingerprint string, now time.Time) error {
	for _, d := range decoys {
		if err := Place(d, fingerprint, now); err != nil {
			return err
		}
	}
	return nil
}
