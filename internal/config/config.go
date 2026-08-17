// Package config defines Tripwire's on-disk configuration and its validation.
package config

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/mbarnathan/tripwire/internal/bait"
)

// Config is the parsed /etc/tripwire/config.yaml.
type Config struct {
	Profile string `yaml:"profile"` // "workstation" | "server"

	// Actions is the ordered ladder. Valid: alert, kill, poweroff.
	// "freeze" is implicit when kill is present and is not listed here.
	Actions []string `yaml:"actions"`

	// Hold defers the fanotify response so a hostile read looks like slow I/O.
	// nil => derive from ladder (see EffectiveHold). 0 => never hold.
	Hold *time.Duration `yaml:"hold"`

	AlertTimeout time.Duration `yaml:"alert_timeout"`

	Kill     KillConfig     `yaml:"kill"`
	Poweroff PoweroffConfig `yaml:"poweroff"`

	Bait  []BaitEntry `yaml:"bait"` // the decoy files: created, watched, and removed
	Sinks SinkConfig  `yaml:"sinks"`
	Allow []AllowRule `yaml:"allow"` // policy allowlist
	State string      `yaml:"state_dir"`

	// LLM configures decoy generation for `kind: llm` entries. Absent by
	// default, and only consulted by the CLI — the daemon never calls out.
	LLM *LLMConfig `yaml:"llm"`
}

// BaitEntry is one decoy. It accepts either form in YAML:
//
//	bait:
//	  - /etc/codex/auth.json                              # kind: auto
//	  - { path: /srv/app/creds.json, kind: codex }        # explicit schema
//
// The plain string is the common case and stays the documented default; the
// mapping exists for paths whose name does not reveal which credential schema
// they should mimic.
type BaitEntry struct {
	Path string `yaml:"path"`
	Kind string `yaml:"kind"` // auto (default) | claude | codex
}

// UnmarshalYAML accepts a scalar path or a mapping, so a plain list of strings
// keeps working exactly as before.
func (b *BaitEntry) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		var path string
		if err := node.Decode(&path); err != nil {
			return err
		}
		b.Path, b.Kind = path, bait.KindNameAuto
		return nil
	}
	// A named type breaks the recursion back into this method.
	type entry BaitEntry
	var e entry
	if err := node.Decode(&e); err != nil {
		return err
	}
	*b = BaitEntry(e)
	if strings.TrimSpace(b.Kind) == "" {
		b.Kind = bait.KindNameAuto
	}
	return nil
}

// MarshalYAML writes back the short form when the kind is left to inference, so
// round-tripping a config does not turn a readable list into mappings.
func (b BaitEntry) MarshalYAML() (any, error) {
	if b.Kind == "" || strings.EqualFold(b.Kind, bait.KindNameAuto) {
		return b.Path, nil
	}
	type entry BaitEntry
	return entry(b), nil
}

type KillConfig struct {
	Scope   string `yaml:"scope"` // pid | tree | session | loginuid
	MaxKill int    `yaml:"max_kill"`
}

type PoweroffConfig struct {
	Mode string `yaml:"mode"` // graceful | hard
}

type SinkConfig struct {
	Webhook *WebhookConfig `yaml:"webhook"`
	Ntfy    *NtfyConfig    `yaml:"ntfy"`
	Email   *EmailConfig   `yaml:"email"`
	// Journal controls the desktop notification only. The journald record itself
	// is always written — it is the forensic trace that outlives a poweroff, so
	// it is not configurable. nil means "not set", which enables the desktop
	// notification on the workstation profile.
	Journal *bool `yaml:"journal"`
}

// DesktopNotify reports whether the journal sink should also raise a desktop
// notification: workstation profile, not explicitly switched off.
func (c *Config) DesktopNotify() bool {
	if c.Profile != "workstation" {
		return false
	}
	return c.Sinks.Journal == nil || *c.Sinks.Journal
}

type WebhookConfig struct {
	URL     string            `yaml:"url"`
	Headers map[string]string `yaml:"headers"`
}

type NtfyConfig struct {
	URL      string `yaml:"url"`      // e.g. https://ntfy.sh/mytopic
	Priority string `yaml:"priority"` // default "urgent"
	Tags     string `yaml:"tags"`
}

type EmailConfig struct {
	To       string `yaml:"to"`
	From     string `yaml:"from"`
	SMTPAddr string `yaml:"smtp_addr"` // empty => sendmail/local MTA
}

// AllowRule matches a benign reader. Empty fields are wildcards; all set fields
// must match (AND). Match logic lives in the policy package.
type AllowRule struct {
	Exe      string `yaml:"exe"`
	UID      *int   `yaml:"uid"`
	LoginUID *int   `yaml:"loginuid"`
	Unit     string `yaml:"unit"`     // systemd unit substring
	Ancestor string `yaml:"ancestor"` // exe of any ancestor
	// CapEff is a hex capability mask (as printed in /proc/<pid>/status). The
	// rule matches only if the reader holds every capability in the mask.
	CapEff  string `yaml:"cap_eff"`
	Comment string `yaml:"comment"`
}

// CapEffMask parses the rule's capability mask. An empty mask means "no
// capability requirement" and reports ok=false.
func (r AllowRule) CapEffMask() (mask uint64, ok bool, err error) {
	if strings.TrimSpace(r.CapEff) == "" {
		return 0, false, nil
	}
	v, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(r.CapEff), "0x"), 16, 64)
	if err != nil {
		return 0, false, fmt.Errorf("allow rule cap_eff %q is not a hex capability mask: %w", r.CapEff, err)
	}
	return v, true, nil
}

var validActions = map[string]bool{"alert": true, "kill": true, "poweroff": true}
var validScopes = map[string]bool{"pid": true, "tree": true, "session": true, "loginuid": true}

// Parse reads YAML, applies defaults, then validates.
func Parse(data []byte) (*Config, error) {
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.Profile == "" {
		c.Profile = "server"
	}
	if len(c.Actions) == 0 {
		c.Actions = []string{"alert"} // install default: alert-only, both profiles
	}
	if c.AlertTimeout == 0 {
		c.AlertTimeout = 10 * time.Second
	}
	if c.Kill.Scope == "" {
		c.Kill.Scope = "tree"
	}
	if c.Kill.MaxKill == 0 {
		c.Kill.MaxKill = 50
	}
	if c.Poweroff.Mode == "" {
		c.Poweroff.Mode = "graceful"
	}
	if c.State == "" {
		c.State = "/var/lib/tripwire"
	}
	if len(c.Bait) == 0 {
		// One place decides what "no bait configured" means, so the installer,
		// the daemon, and the CLI cannot disagree about it.
		for _, d := range bait.DefaultDecoys() {
			c.Bait = append(c.Bait, BaitEntry{Path: d.Path, Kind: bait.KindNameAuto})
		}
	}
}

// BaitPaths lists the decoy paths, for marking and watching.
func (c *Config) BaitPaths() []string {
	out := make([]string, 0, len(c.Bait))
	for _, b := range c.Bait {
		out = append(out, b.Path)
	}
	return out
}

// Decoys resolves each entry to the schema it should carry: an explicit kind
// wins, "auto" (the default) infers from the filename.
func (c *Config) Decoys() ([]bait.Decoy, error) {
	out := make([]bait.Decoy, 0, len(c.Bait))
	for _, b := range c.Bait {
		kind, err := bait.KindByName(b.Kind, b.Path)
		if err != nil {
			return nil, fmt.Errorf("bait %s: %w", b.Path, err)
		}
		out = append(out, bait.Decoy{Path: b.Path, Kind: kind})
	}
	return out, nil
}

// Validate rejects nonsensical configs.
func (c *Config) Validate() error {
	for _, a := range c.Actions {
		if !validActions[a] {
			return fmt.Errorf("unknown action %q (valid: alert, kill, poweroff)", a)
		}
	}
	if !validScopes[c.Kill.Scope] {
		return fmt.Errorf("unknown kill scope %q (valid: pid, tree, session, loginuid)", c.Kill.Scope)
	}
	if c.Poweroff.Mode != "graceful" && c.Poweroff.Mode != "hard" {
		return fmt.Errorf("unknown poweroff mode %q (valid: graceful, hard)", c.Poweroff.Mode)
	}
	if c.Kill.MaxKill < 1 {
		return fmt.Errorf("kill.max_kill must be >= 1, got %d", c.Kill.MaxKill)
	}
	if c.Profile != "workstation" && c.Profile != "server" {
		return fmt.Errorf("unknown profile %q (valid: workstation, server)", c.Profile)
	}
	for i, r := range c.Allow {
		if _, _, err := r.CapEffMask(); err != nil {
			return fmt.Errorf("allow[%d]: %w", i, err)
		}
	}
	for i, b := range c.Bait {
		if strings.TrimSpace(b.Path) == "" {
			return fmt.Errorf("bait[%d]: path is required", i)
		}
		if !filepath.IsAbs(b.Path) {
			return fmt.Errorf("bait[%d]: path %q must be absolute", i, b.Path)
		}
		if !bait.ValidKindName(b.Kind) {
			return fmt.Errorf("bait[%d] (%s): unknown kind %q (valid: %s)", i, b.Path, b.Kind, bait.KindNames())
		}
	}
	return c.validateLLM()
}

// HasDestructiveAction reports whether the ladder can kill or power off.
func (c *Config) HasDestructiveAction() bool {
	for _, a := range c.Actions {
		if a == "kill" || a == "poweroff" {
			return true
		}
	}
	return false
}

// EffectiveHold resolves the hold duration: explicit value if set, else derived
// from the ladder (15s destructive, 3s alert-only).
func (c *Config) EffectiveHold() time.Duration {
	if c.Hold != nil {
		return *c.Hold
	}
	if c.HasDestructiveAction() {
		return 15 * time.Second
	}
	return 3 * time.Second
}
