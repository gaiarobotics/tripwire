//go:build linux

package watch

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The fallback backend still answers the only question it can: was the decoy
// opened at all.
func TestInotifyReportsOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	w, err := NewInotify()
	if err != nil {
		t.Fatalf("NewInotify: %v", err)
	}
	defer w.Close()
	if err := w.Mark(path); err != nil {
		t.Fatalf("Mark: %v", err)
	}

	go func() {
		time.Sleep(20 * time.Millisecond)
		f, err := os.Open(path)
		if err == nil {
			_ = f.Close()
		}
	}()

	select {
	case ev := <-w.Events():
		if ev.Path != path {
			t.Fatalf("event path = %q, want %q", ev.Path, path)
		}
		if ev.Perm {
			t.Fatal("inotify events are not permission events — they cannot be held")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no inotify event within 3s")
	}
}

func TestInotifyCloseStopsTheStream(t *testing.T) {
	w, err := NewInotify()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case _, open := <-w.Events():
		if open {
			t.Fatal("no events should arrive after Close")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("event channel was not closed")
	}
	// Close is idempotent: the daemon calls it from a defer and on shutdown.
	_ = w.Close()
}

// fanotify marks are per-inode, so a decoy replaced by rename must be reported
// for re-marking or the wire silently goes dead.
func TestDirWatcherReportsReplacedDecoy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	dw, err := NewDirWatcher([]string{path})
	if err != nil {
		t.Fatalf("NewDirWatcher: %v", err)
	}
	defer dw.Close()

	// Replace it the way an atomic write does: write a temp file, then rename.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-dw.Replaced():
		if got != path {
			t.Fatalf("replaced = %q, want %q", got, path)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no replacement reported within 3s")
	}
}

// Unrelated files in the same directory must not cause re-marks.
func TestDirWatcherIgnoresOtherFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	dw, err := NewDirWatcher([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	defer dw.Close()

	if err := os.WriteFile(filepath.Join(dir, "unrelated.conf"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Then touch the real decoy so we have a positive event to wait for.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-dw.Replaced():
		if got != path {
			t.Fatalf("replaced = %q, want only the decoy path", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no replacement reported within 3s")
	}
}

// A missing bait directory must fail loudly at startup rather than leaving the
// daemon half-armed.
func TestDirWatcherFailsOnMissingDirectory(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope", "auth.json")
	if _, err := NewDirWatcher([]string{missing}); err == nil {
		t.Fatal("watching a nonexistent directory must fail")
	}
}
