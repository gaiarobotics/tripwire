package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMarkTrippedPersistsAndReads(t *testing.T) {
	dir := t.TempDir()
	st := &Store{Dir: dir}

	if st.IsTripped() {
		t.Fatal("fresh store must not be tripped")
	}
	when := time.Unix(1_700_000_000, 0).UTC()
	if err := st.MarkTripped(Trip{Bait: "/etc/codex/auth.json", Exe: "/usr/bin/curl", When: when}); err != nil {
		t.Fatalf("MarkTripped: %v", err)
	}
	if !st.IsTripped() {
		t.Fatal("must be tripped after MarkTripped")
	}
	got, err := st.Read()
	if err != nil {
		t.Fatal(err)
	}
	if got.Bait != "/etc/codex/auth.json" || got.Exe != "/usr/bin/curl" {
		t.Fatalf("read back wrong trip: %+v", got)
	}
	if !got.When.Equal(when) {
		t.Fatalf("when = %v, want %v", got.When, when)
	}
	// The record must live at the documented path so operators can find it.
	if _, err := os.Stat(filepath.Join(dir, "tripped.json")); err != nil {
		t.Fatalf("tripped.json not at the documented path: %v", err)
	}
}

func TestResetClearsTripped(t *testing.T) {
	dir := t.TempDir()
	st := &Store{Dir: dir}
	_ = st.MarkTripped(Trip{Bait: "x"})
	if err := st.Reset(); err != nil {
		t.Fatal(err)
	}
	if st.IsTripped() {
		t.Fatal("reset must clear tripped state")
	}
}

func TestResetOnUntrippedStoreIsNotAnError(t *testing.T) {
	if err := (&Store{Dir: t.TempDir()}).Reset(); err != nil {
		t.Fatalf("resetting a clean store must be a no-op: %v", err)
	}
}

// The state dir may not exist on first trip — MarkTripped runs moments before
// poweroff and cannot afford to fail on a missing directory.
func TestMarkTrippedCreatesStateDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "tripwire")
	st := &Store{Dir: dir}
	if err := st.MarkTripped(Trip{Bait: "/etc/codex/auth.json"}); err != nil {
		t.Fatalf("MarkTripped: %v", err)
	}
	if !st.IsTripped() {
		t.Fatal("state must persist into a freshly created dir")
	}
}

// A truncated or corrupt record (power cut mid-write) must read as an error,
// never as a silent "not tripped" that would re-arm destructive actions.
func TestReadRejectsCorruptRecord(t *testing.T) {
	dir := t.TempDir()
	st := &Store{Dir: dir}
	if err := os.WriteFile(filepath.Join(dir, "tripped.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !st.IsTripped() {
		t.Fatal("a present-but-corrupt record still means tripped")
	}
	if _, err := st.Read(); err == nil {
		t.Fatal("corrupt record must surface a read error")
	}
}

func TestDefaultDirIsUsedWhenUnset(t *testing.T) {
	if got := (&Store{}).path(); got != "/var/lib/tripwire/tripped.json" {
		t.Fatalf("default path = %q", got)
	}
}
