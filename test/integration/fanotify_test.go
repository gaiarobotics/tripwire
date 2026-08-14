//go:build integration && linux

// Package integration exercises the syscall-level pieces that unit tests cannot
// reach: fanotify permission events need CAP_SYS_ADMIN, so run this in a
// privileged container:
//
//	docker run --rm --privileged -v "$PWD":/src -w /src golang:1.25 \
//	  go test -tags integration ./test/integration/ -v
package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/mbarnathan/tripwire/internal/watch"
)

func newFanotifyOrSkip(t *testing.T) *watch.Fanotify {
	t.Helper()
	fan, err := watch.NewFanotify()
	if err != nil {
		t.Skipf("fanotify unavailable (need CAP_SYS_ADMIN): %v", err)
	}
	return fan
}

func writeDecoy(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.json")
	if err := os.WriteFile(path, []byte(`{"OPENAI_API_KEY":"sk-proj-tw-test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The basic contract: a permission event arrives, carries the reader's PID, and
// the reader stays blocked until we answer.
func TestFanotifyPermissionEventRoundTrip(t *testing.T) {
	path := writeDecoy(t)
	fan := newFanotifyOrSkip(t)
	defer fan.Close()
	if err := fan.Mark(path); err != nil {
		t.Fatalf("mark: %v", err)
	}

	readDone := make(chan error, 1)
	go func() {
		time.Sleep(50 * time.Millisecond)
		readDone <- exec.Command("cat", path).Run()
	}()

	select {
	case ev := <-fan.Events():
		if !ev.Perm {
			t.Fatal("expected a permission event")
		}
		if ev.PID <= 0 {
			t.Fatalf("expected a PID, got %d", ev.PID)
		}
		if ev.Path != path {
			t.Fatalf("event path = %q, want %q", ev.Path, path)
		}
		if err := fan.Respond(watch.Response{Token: ev.Token, Allow: true}); err != nil {
			t.Fatalf("respond: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no fanotify event within 5s")
	}

	select {
	case err := <-readDone:
		if err != nil {
			t.Fatalf("the allowed read should succeed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the reader never completed after being allowed")
	}
}

// The hold is the whole trick: deferring the response must make the reader wait,
// and it must look like slow I/O rather than a denial.
func TestDeferredResponseHoldsTheReader(t *testing.T) {
	path := writeDecoy(t)
	fan := newFanotifyOrSkip(t)
	defer fan.Close()
	if err := fan.Mark(path); err != nil {
		t.Fatal(err)
	}

	const hold = 700 * time.Millisecond
	type outcome struct {
		err     error
		elapsed time.Duration
	}
	done := make(chan outcome, 1)
	go func() {
		start := time.Now()
		err := exec.Command("cat", path).Run()
		done <- outcome{err, time.Since(start)}
	}()

	ev := <-fan.Events()
	time.Sleep(hold)
	if err := fan.Respond(watch.Response{Token: ev.Token, Allow: true}); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("a held-then-allowed read must still succeed: %v", got.err)
		}
		if got.elapsed < hold {
			t.Fatalf("read took %v; it should have been held for at least %v", got.elapsed, hold)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("reader never finished")
	}
}

// Fail-open: if the daemon dies mid-hold, the kernel releases every pending
// reader. Nothing Tripwire does may permanently wedge access to a path.
func TestClosingTheGroupReleasesHeldReaders(t *testing.T) {
	path := writeDecoy(t)
	fan := newFanotifyOrSkip(t)
	if err := fan.Mark(path); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- exec.Command("cat", path).Run() }()

	<-fan.Events() // never responded to
	if err := fan.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the abandoned read should be auto-allowed, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("closing the fanotify group did not release the held reader")
	}
}

// Marks are per-inode: a decoy replaced on disk is no longer watched, which is
// exactly why the daemon runs a parent-directory watch and re-marks.
func TestReplacedDecoyNeedsRemarking(t *testing.T) {
	path := writeDecoy(t)
	fan := newFanotifyOrSkip(t)
	defer fan.Close()
	if err := fan.Mark(path); err != nil {
		t.Fatal(err)
	}

	dw, err := watch.NewDirWatcher([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	defer dw.Close()

	// Replace the file, which drops the mark with the old inode.
	tmp := path + ".new"
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
	case <-time.After(5 * time.Second):
		t.Fatal("replacement was not reported")
	}

	if err := fan.Mark(path); err != nil {
		t.Fatalf("re-mark: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- exec.Command("cat", path).Run() }()
	select {
	case ev := <-fan.Events():
		if err := fan.Respond(watch.Response{Token: ev.Token, Allow: true}); err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("re-marked decoy did not report a read")
	}
	<-done
}

// Only marked inodes generate events; the rest of /etc must stay untouched.
func TestUnmarkedFileGeneratesNoEvents(t *testing.T) {
	dir := t.TempDir()
	marked := filepath.Join(dir, "auth.json")
	other := filepath.Join(dir, "unrelated.conf")
	for _, p := range []string{marked, other} {
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fan := newFanotifyOrSkip(t)
	defer fan.Close()
	if err := fan.Mark(marked); err != nil {
		t.Fatal(err)
	}

	if err := exec.Command("cat", other).Run(); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-fan.Events():
		t.Fatalf("unmarked file produced an event: %+v", ev)
	case <-time.After(time.Second):
	}
}

// Unmark must actually stop the events, or `tripwire` could never refresh a
// decoy without deadlocking against its own permission event.
func TestUnmarkStopsEvents(t *testing.T) {
	path := writeDecoy(t)
	fan := newFanotifyOrSkip(t)
	defer fan.Close()
	if err := fan.Mark(path); err != nil {
		t.Fatal(err)
	}
	if err := fan.Unmark(path); err != nil {
		t.Fatalf("unmark: %v", err)
	}
	if err := exec.Command("cat", path).Run(); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-fan.Events():
		t.Fatalf("unmarked decoy produced an event: %+v", ev)
	case <-time.After(time.Second):
	}
}

// A decoy that is not a regular file cannot deliver open-permission events, so
// marking it must fail loudly instead of leaving the wire silently disarmed.
func TestMarkRefusesNonRegularFiles(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "auth.json")
	if err := os.Symlink("/etc/hostname", link); err != nil {
		t.Fatal(err)
	}
	fan := newFanotifyOrSkip(t)
	defer fan.Close()
	if err := fan.Mark(link); err == nil {
		t.Fatal("marking a symlink must fail")
	}
}
