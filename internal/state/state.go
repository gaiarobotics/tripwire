// Package state persists the tripped flag across reboots so the daemon can boot
// alert-only after a trip and refuse to re-arm destructive actions until reset.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// DefaultDir is where the tripped record lives unless configured otherwise.
const DefaultDir = "/var/lib/tripwire"

// Trip records the event that tripped the wire.
type Trip struct {
	Bait string    `json:"bait"`
	Exe  string    `json:"exe"`
	AUID int64     `json:"auid"`
	When time.Time `json:"when"`
}

// Store reads/writes tripped state under Dir (default /var/lib/tripwire).
type Store struct{ Dir string }

func (s *Store) dir() string {
	if s.Dir == "" {
		return DefaultDir
	}
	return s.Dir
}

func (s *Store) path() string { return filepath.Join(s.dir(), "tripped.json") }

// MarkTripped writes the tripped record. It runs immediately before poweroff, so
// it writes through a temp file, fsyncs the file, renames, then fsyncs the
// directory — the record has to survive a power cut moments later.
func (s *Store) MarkTripped(t Trip) error {
	if err := os.MkdirAll(s.dir(), 0o755); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path() + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path()); err != nil {
		return err
	}
	// fsync the directory so the rename itself survives a power cut.
	if d, err := os.Open(s.dir()); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// IsTripped reports whether a tripped record exists. A record that exists but
// cannot be parsed still counts as tripped: the safe reading of a damaged record
// is "something happened here".
func (s *Store) IsTripped() bool {
	_, err := os.Stat(s.path())
	return err == nil
}

// Read returns the tripped record.
func (s *Store) Read() (Trip, error) {
	b, err := os.ReadFile(s.path())
	if err != nil {
		return Trip{}, err
	}
	var t Trip
	if err := json.Unmarshal(b, &t); err != nil {
		return Trip{}, fmt.Errorf("parse %s: %w", s.path(), err)
	}
	return t, nil
}

// Reset clears the tripped state (tripwire reset).
func (s *Store) Reset() error {
	err := os.Remove(s.path())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// TestResult records the outcome of `tripwire test`. Arming destructive actions
// requires one of these on file: nobody should point a poweroff at a host
// without first proving the alert reaches them.
type TestResult struct {
	When      time.Time         `json:"when"`
	Delivered bool              `json:"delivered"`
	Sinks     map[string]string `json:"sinks"` // sink name -> "confirmed" or the error
}

func (s *Store) armPath() string  { return filepath.Join(s.dir(), "armed") }
func (s *Store) testPath() string { return filepath.Join(s.dir(), "last-test.json") }

// Arm records the operator's deliberate decision to enable destructive actions.
// A destructive ladder in config.yaml is not enough on its own — the daemon
// stays alert-only until this marker exists.
func (s *Store) Arm(now time.Time) error {
	if err := os.MkdirAll(s.dir(), 0o755); err != nil {
		return err
	}
	return os.WriteFile(s.armPath(), []byte(now.UTC().Format(time.RFC3339)+"\n"), 0o644)
}

// Disarm removes the marker, dropping the daemon back to alert-only.
func (s *Store) Disarm() error {
	err := os.Remove(s.armPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// IsArmed reports whether destructive actions have been explicitly enabled.
func (s *Store) IsArmed() bool {
	_, err := os.Stat(s.armPath())
	return err == nil
}

// RecordTest saves the result of the most recent `tripwire test`.
func (s *Store) RecordTest(r TestResult) error {
	if err := os.MkdirAll(s.dir(), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.testPath(), b, 0o644)
}

// LastTest returns the most recent recorded test result.
func (s *Store) LastTest() (TestResult, error) {
	b, err := os.ReadFile(s.testPath())
	if err != nil {
		return TestResult{}, err
	}
	var r TestResult
	if err := json.Unmarshal(b, &r); err != nil {
		return TestResult{}, fmt.Errorf("parse %s: %w", s.testPath(), err)
	}
	return r, nil
}
