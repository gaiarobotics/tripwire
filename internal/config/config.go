// Package config defines Tripwire's on-disk configuration and its validation.
package config

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
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

	Bait  []string    `yaml:"bait"` // absolute paths of decoy files
	Sinks SinkConfig  `yaml:"sinks"`
	Allow []AllowRule `yaml:"allow"` // policy allowlist
	State string      `yaml:"state_dir"`
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
	Journal bool           `yaml:"journal"` // always effectively on; false disables notify-send only
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
	Comment  string `yaml:"comment"`
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
	return nil
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
