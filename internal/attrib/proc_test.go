package attrib

import (
	"os"
	"path/filepath"
	"testing"
)

// writeFakeProc builds a minimal /proc/<pid> tree under dir.
func writeFakeProc(t *testing.T, root string, pid int, fields map[string]string) {
	t.Helper()
	d := filepath.Join(root, "proc", itoa(pid))
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range fields {
		if err := os.WriteFile(filepath.Join(d, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSnapshotParsesIdentity(t *testing.T) {
	root := t.TempDir()
	// stat: pid (comm) state ppid ... field22=starttime. Keep it realistic.
	stat := "4242 (curl) R 4200 4242 4200 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 987654 0 0 ..."
	writeFakeProc(t, root, 4242, map[string]string{
		"stat":      stat,
		"status":    "Name:\tcurl\nUid:\t1000\t1000\t1000\t1000\nCapEff:\t0000000000000000\n",
		"loginuid":  "1000",
		"sessionid": "3",
		"cmdline":   "curl\x00/etc/codex/auth.json\x00",
		"cgroup":    "0::/user.slice/user-1000.slice/session-3.scope\n",
	})
	writeFakeProc(t, root, 4200, map[string]string{
		"stat":      "4200 (sshd) S 1 4200 4200 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 111 0 0 ...",
		"status":    "Name:\tsshd\nUid:\t0\t0\t0\t0\nCapEff:\t000001ffffffffff\n",
		"loginuid":  "4294967295",
		"sessionid": "3",
		"cmdline":   "sshd: user@pts/0\x00",
		"cgroup":    "0::/system.slice/sshd.service\n",
	})

	s := &Snapshotter{ProcRoot: filepath.Join(root, "proc")}
	id, err := s.Snapshot(4242)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if id.PID != 4242 || id.PPID != 4200 {
		t.Fatalf("pid/ppid = %d/%d", id.PID, id.PPID)
	}
	if id.UID != 1000 {
		t.Fatalf("uid = %d", id.UID)
	}
	if id.LoginUID != 1000 {
		t.Fatalf("loginuid = %d", id.LoginUID)
	}
	if id.SessionID != 3 {
		t.Fatalf("sessionid = %d", id.SessionID)
	}
	if id.StartTime != 987654 {
		t.Fatalf("starttime = %d", id.StartTime)
	}
	if id.Comm != "curl" {
		t.Fatalf("comm = %q", id.Comm)
	}
	if len(id.Cmdline) != 2 || id.Cmdline[1] != "/etc/codex/auth.json" {
		t.Fatalf("cmdline = %v", id.Cmdline)
	}
	if len(id.Ancestors) == 0 || id.Ancestors[0].Comm != "sshd" {
		t.Fatalf("ancestors = %v", id.Ancestors)
	}
}

// A comm containing spaces and parentheses must not shift the field offsets —
// this is the classic /proc/<pid>/stat parsing trap.
func TestSnapshotParsesCommWithParensAndSpaces(t *testing.T) {
	root := t.TempDir()
	writeFakeProc(t, root, 77, map[string]string{
		"stat":   "77 (evil ) prog) S 1 77 77 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 555 0 0 ...",
		"status": "Name:\tevil\nUid:\t0\t0\t0\t0\nCapEff:\t000001ffffffffff\n",
	})
	s := &Snapshotter{ProcRoot: filepath.Join(root, "proc")}
	id, err := s.Snapshot(77)
	if err != nil {
		t.Fatal(err)
	}
	if id.Comm != "evil ) prog" {
		t.Fatalf("comm = %q", id.Comm)
	}
	if id.PPID != 1 {
		t.Fatalf("ppid = %d, want 1", id.PPID)
	}
	if id.StartTime != 555 {
		t.Fatalf("starttime = %d, want 555", id.StartTime)
	}
}

func TestSnapshotCapEffParsed(t *testing.T) {
	root := t.TempDir()
	writeFakeProc(t, root, 9, map[string]string{
		"stat":   "9 (bash) S 1 9 9 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1 0 0 ...",
		"status": "Name:\tbash\nUid:\t1000\t1000\t1000\t1000\nCapEff:\t000001ffffffffff\n",
	})
	s := &Snapshotter{ProcRoot: filepath.Join(root, "proc")}
	id, err := s.Snapshot(9)
	if err != nil {
		t.Fatal(err)
	}
	if id.CapEff != 0x000001ffffffffff {
		t.Fatalf("capeff = %x", id.CapEff)
	}
}

func TestLoginUIDUnsetSentinel(t *testing.T) {
	root := t.TempDir()
	writeFakeProc(t, root, 5, map[string]string{
		"stat":     "5 (cron) S 1 5 5 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 42 0 0 ...",
		"status":   "Name:\tcron\nUid:\t0\t0\t0\t0\nCapEff:\t000001ffffffffff\n",
		"loginuid": "4294967295",
		"cmdline":  "cron\x00",
	})
	s := &Snapshotter{ProcRoot: filepath.Join(root, "proc")}
	id, err := s.Snapshot(5)
	if err != nil {
		t.Fatal(err)
	}
	if !id.LoginUIDUnset() {
		t.Fatal("4294967295 must count as unset")
	}
}

// A missing loginuid file (kernel built without audit support) must still read
// as unset rather than as uid 0.
func TestLoginUIDDefaultsToUnsetWhenAbsent(t *testing.T) {
	root := t.TempDir()
	writeFakeProc(t, root, 6, map[string]string{
		"stat":   "6 (sh) S 1 6 6 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 7 0 0 ...",
		"status": "Name:\tsh\nUid:\t0\t0\t0\t0\nCapEff:\t0\n",
	})
	s := &Snapshotter{ProcRoot: filepath.Join(root, "proc")}
	id, err := s.Snapshot(6)
	if err != nil {
		t.Fatal(err)
	}
	if !id.LoginUIDUnset() {
		t.Fatalf("loginuid = %d, want unset sentinel", id.LoginUID)
	}
}

// The ancestor walk must terminate even if the fake tree contains a cycle.
func TestSnapshotAncestorWalkTerminatesOnCycle(t *testing.T) {
	root := t.TempDir()
	writeFakeProc(t, root, 20, map[string]string{
		"stat":   "20 (a) S 21 20 20 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1 0 0 ...",
		"status": "Name:\ta\nUid:\t0\t0\t0\t0\nCapEff:\t0\n",
	})
	writeFakeProc(t, root, 21, map[string]string{
		"stat":   "21 (b) S 20 21 21 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 2 0 0 ...",
		"status": "Name:\tb\nUid:\t0\t0\t0\t0\nCapEff:\t0\n",
	})
	s := &Snapshotter{ProcRoot: filepath.Join(root, "proc")}
	id, err := s.Snapshot(20)
	if err != nil {
		t.Fatal(err)
	}
	if len(id.Ancestors) != 1 || id.Ancestors[0].Comm != "b" {
		t.Fatalf("ancestors = %v, want just [b]", id.Ancestors)
	}
}

func TestSnapshotMissingPIDIsAnError(t *testing.T) {
	s := &Snapshotter{ProcRoot: filepath.Join(t.TempDir(), "proc")}
	if _, err := s.Snapshot(1234); err == nil {
		t.Fatal("snapshot of a nonexistent pid must fail")
	}
}
