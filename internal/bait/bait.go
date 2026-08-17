// Package bait generates, places, and verifies the decoy credential files that
// Tripwire watches. The tokens are structurally valid but non-functional; each
// carries the per-install fingerprint so a leaked token names the host it came
// from.
package bait

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Kind selects which credential schema a decoy mimics.
type Kind int

const (
	KindClaude Kind = iota
	KindCodex
	// KindLLM defers the file's contents to a configured language model instead
	// of a built-in template. It is never inferred — an operator has to ask for
	// it by name — and it falls back to a template if generation fails.
	KindLLM
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

// Schema names accepted in configuration. "auto" defers to KindFor, which reads
// the filename — the default, and all most installs ever need.
const (
	KindNameAuto   = "auto"
	KindNameClaude = "claude"
	KindNameCodex  = "codex"
	KindNameLLM    = "llm"
)

// ValidKindName reports whether name is a schema selector we understand. The
// empty string means unset, which is treated as "auto".
func ValidKindName(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", KindNameAuto, KindNameClaude, KindNameCodex, KindNameLLM:
		return true
	}
	return false
}

// KindNames lists the accepted selectors, for error messages.
func KindNames() string {
	return KindNameAuto + ", " + KindNameClaude + ", " + KindNameCodex + ", " + KindNameLLM
}

// KindByName resolves a configured schema selector for a path. An unset or
// "auto" selector infers from the filename; anything else names a schema
// explicitly and overrides inference.
func KindByName(name, path string) (Kind, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", KindNameAuto:
		return KindFor(path), nil
	case KindNameClaude:
		return KindClaude, nil
	case KindNameCodex:
		return KindCodex, nil
	case KindNameLLM:
		return KindLLM, nil
	}
	return 0, fmt.Errorf("unknown decoy kind %q (valid: %s)", name, KindNames())
}

// KindFor guesses which credential schema a path should mimic. Operator-added
// paths are not in DefaultDecoys, so fall back to naming: anything mentioning
// codex or openai gets the Codex schema, everything else the Claude one.
func KindFor(path string) Kind {
	for _, d := range DefaultDecoys() {
		if d.Path == path {
			return d.Kind
		}
	}
	lower := strings.ToLower(path)
	if strings.Contains(lower, "codex") || strings.Contains(lower, "openai") {
		return KindCodex
	}
	return KindClaude
}

// DecoysFor pairs configured paths with the schema each should mimic, so the
// installer, the daemon's refresh loop, and the CLI all agree on what belongs at
// a given path.
func DecoysFor(paths []string) []Decoy {
	out := make([]Decoy, 0, len(paths))
	for _, p := range paths {
		out = append(out, Decoy{Path: p, Kind: KindFor(p)})
	}
	return out
}

// fingerprintPattern matches the per-install id embedded in every decoy token.
// It is how we recognise a file as one of ours.
var fingerprintPattern = regexp.MustCompile(`tw-[0-9a-f]{16}`)

// IsOurs reports whether the path is absent (safe to create) or holds a file
// Tripwire itself wrote. It is what stands between a mistyped bait path and
// overwriting a real credential file as root.
func IsOurs(path string) (bool, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return fingerprintPattern.Match(raw), nil
}

// PlaceSafe writes a decoy, refusing to clobber any file Tripwire did not
// create. Every path that comes from configuration goes through here; Place
// itself stays a raw write for tests and for callers that have already checked.
func PlaceSafe(d Decoy, fingerprint string, now time.Time) error {
	if !filepath.IsAbs(d.Path) {
		return fmt.Errorf("decoy path %q must be absolute", d.Path)
	}
	ours, err := IsOurs(d.Path)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", d.Path, err)
	}
	if !ours {
		return fmt.Errorf("refusing to overwrite %s: it exists and was not written by Tripwire", d.Path)
	}
	return Place(d, fingerprint, now)
}

// Place writes a structurally-valid, non-functional credential file with the
// install fingerprint embedded and a future expiry (no stale-token tell).
// Mode is 0600 root:root (ownership applied by the caller/postinst as root).
func Place(d Decoy, fingerprint string, now time.Time) error {
	body, err := render(d.Kind, fingerprint, now)
	if err != nil {
		return err
	}
	return writeDecoy(d.Path, body)
}

// writeDecoy writes decoy content atomically: temp file + rename, so a reader
// never sees a partial file and never trips the wire on a half-written decoy.
func writeDecoy(path string, body []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
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
		if err := PlaceSafe(d, fingerprint, now); err != nil {
			return err
		}
	}
	return nil
}
