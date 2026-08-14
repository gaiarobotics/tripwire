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
