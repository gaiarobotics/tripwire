package attrib

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProcFSReadsFakeTree(t *testing.T) {
	root := t.TempDir()
	writeFakeProc(t, root, 100, map[string]string{
		"stat":      "100 (bash) S 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 500 0 0 ...",
		"status":    "Name:\tbash\nUid:\t1000\t1000\t1000\t1000\nCapEff:\t0\n",
		"loginuid":  "1000",
		"sessionid": "7",
		"cmdline":   "bash\x00-i\x00",
	})
	writeFakeProc(t, root, 101, map[string]string{
		"stat":      "101 (curl) R 100 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 501 0 0 ...",
		"status":    "Name:\tcurl\nUid:\t1000\t1000\t1000\t1000\nCapEff:\t0\n",
		"loginuid":  "1000",
		"sessionid": "7",
		"cmdline":   "curl\x00/etc/codex/auth.json\x00",
	})

	p := &ProcFS{Root: filepath.Join(root, "proc")}

	if kids := p.Children(100); len(kids) != 1 || kids[0] != 101 {
		t.Fatalf("children = %v, want [101]", kids)
	}
	if got := p.Parent(101); got != 100 {
		t.Fatalf("parent = %d, want 100", got)
	}
	if got := p.StartTime(101); got != 501 {
		t.Fatalf("starttime = %d, want 501", got)
	}
	if got := p.Session(101); got != 7 {
		t.Fatalf("session = %d, want 7", got)
	}
	if got := p.LoginUID(101); got != 1000 {
		t.Fatalf("loginuid = %d, want 1000", got)
	}
	if !p.Alive(101) || p.Alive(999) {
		t.Fatal("Alive must track /proc entry existence")
	}

	_, cmdline, uid, auid := p.Describe(101)
	if cmdline != "curl /etc/codex/auth.json" {
		t.Fatalf("cmdline = %q", cmdline)
	}
	if uid != 1000 || auid != 1000 {
		t.Fatalf("uid/auid = %d/%d", uid, auid)
	}
}

// Missing audit fields must degrade to the unset sentinel, never to root.
func TestProcFSMissingAuditFieldsAreUnset(t *testing.T) {
	root := t.TempDir()
	writeFakeProc(t, root, 5, map[string]string{
		"stat": "5 (x) S 1 5 5 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 9 0 0 ...",
	})
	p := &ProcFS{Root: filepath.Join(root, "proc")}
	if got := p.LoginUID(5); got != LoginUIDUnsetValue {
		t.Fatalf("loginuid = %d, want unset sentinel", got)
	}
	if got := p.Session(5); got != -1 {
		t.Fatalf("session = %d, want -1", got)
	}
}

// The real /proc must be readable: this is the path the daemon actually uses.
func TestProcFSAgainstRealProc(t *testing.T) {
	p := NewProcFS()
	self := os.Getpid()
	if !p.Alive(self) {
		t.Fatal("the test process must be alive in /proc")
	}
	if got := p.Parent(self); got != os.Getppid() {
		t.Fatalf("parent = %d, want %d", got, os.Getppid())
	}
	if p.StartTime(self) == 0 {
		t.Fatal("starttime must be readable for the running process")
	}
	if _, _, uid, _ := p.Describe(self); uid != os.Getuid() {
		t.Fatalf("describe uid = %d, want %d", uid, os.Getuid())
	}
}
