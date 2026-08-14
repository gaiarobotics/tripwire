package action

import (
	"sort"
	"testing"

	"github.com/mbarnathan/tripwire/internal/attrib"
)

// procTable is an in-memory process tree for testing scope resolution.
type procTable struct {
	// pid -> (ppid, sessionid, loginuid, starttime)
	procs map[int]fakeProc
}

type fakeProc struct {
	ppid, sessionid int
	loginuid        int64
	starttime       uint64
}

func (p procTable) Children(pid int) []int {
	var out []int
	for c, fp := range p.procs {
		if fp.ppid == pid {
			out = append(out, c)
		}
	}
	sort.Ints(out)
	return out
}
func (p procTable) Parent(pid int) int       { return p.procs[pid].ppid }
func (p procTable) Session(pid int) int      { return p.procs[pid].sessionid }
func (p procTable) LoginUID(pid int) int64   { return p.procs[pid].loginuid }
func (p procTable) StartTime(pid int) uint64 { return p.procs[pid].starttime }
func (p procTable) Alive(pid int) bool       { _, ok := p.procs[pid]; return ok }

func TestResolveTreeScope(t *testing.T) {
	pt := procTable{procs: map[int]fakeProc{
		10: {ppid: 1, sessionid: 3, loginuid: 1000, starttime: 100},
		11: {ppid: 10, sessionid: 3, loginuid: 1000, starttime: 101},
		12: {ppid: 11, sessionid: 3, loginuid: 1000, starttime: 102},
		99: {ppid: 1, sessionid: 9, loginuid: 0, starttime: 200},
	}}
	id := attrib.Identity{PID: 10, SessionID: 3, LoginUID: 1000, StartTime: 100}
	k := &Killer{Tree: pt}
	set, err := k.resolve("tree", id, 50)
	if err != nil {
		t.Fatal(err)
	}
	// leaf-first: 12, 11, 10
	if len(set) != 3 || set[0] != 12 || set[2] != 10 {
		t.Fatalf("tree set = %v, want [12 11 10]", set)
	}
}

func TestResolvePIDScopeIsJustTheReader(t *testing.T) {
	pt := procTable{procs: map[int]fakeProc{
		10: {ppid: 1, sessionid: 3, loginuid: 1000, starttime: 100},
		11: {ppid: 10, sessionid: 3, loginuid: 1000, starttime: 101},
	}}
	id := attrib.Identity{PID: 10, SessionID: 3, LoginUID: 1000, StartTime: 100}
	k := &Killer{Tree: pt}
	set, err := k.resolve("pid", id, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 1 || set[0] != 10 {
		t.Fatalf("pid set = %v, want [10]", set)
	}
}

func TestResolveSessionScopeCoversWholeLogin(t *testing.T) {
	pt := procTable{procs: map[int]fakeProc{
		10: {ppid: 1, sessionid: 3, loginuid: 1000, starttime: 100},  // sshd session leader
		11: {ppid: 10, sessionid: 3, loginuid: 1000, starttime: 101}, // bash
		12: {ppid: 11, sessionid: 3, loginuid: 1000, starttime: 102}, // the reader
		99: {ppid: 1, sessionid: 9, loginuid: 0, starttime: 200},     // unrelated session
	}}
	id := attrib.Identity{PID: 12, SessionID: 3, LoginUID: 1000, StartTime: 102}
	k := &Killer{Tree: pt}
	set, err := k.resolve("session", id, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 3 {
		t.Fatalf("session set = %v, want 3 pids", set)
	}
	for _, pid := range set {
		if pid == 99 {
			t.Fatalf("session set leaked another session: %v", set)
		}
	}
	// Leaf-first so a parent cannot reap-and-respawn while we work down the list.
	if set[0] != 12 || set[len(set)-1] != 10 {
		t.Fatalf("session set = %v, want deepest (12) first and leader (10) last", set)
	}
}

func TestResolveLoginUIDScopeFollowsSudoHops(t *testing.T) {
	pt := procTable{procs: map[int]fakeProc{
		10: {ppid: 1, sessionid: 3, loginuid: 1000, starttime: 100},
		11: {ppid: 10, sessionid: 3, loginuid: 1000, starttime: 101}, // after sudo: uid 0, auid still 1000
		99: {ppid: 1, sessionid: 9, loginuid: 0, starttime: 200},
	}}
	id := attrib.Identity{PID: 11, SessionID: 3, LoginUID: 1000, StartTime: 101}
	k := &Killer{Tree: pt}
	set, err := k.resolve("loginuid", id, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 2 {
		t.Fatalf("loginuid set = %v, want the two auid=1000 pids", set)
	}
}

func TestLoginUIDScopeRefusesOnUnset(t *testing.T) {
	pt := procTable{procs: map[int]fakeProc{5: {ppid: 1, loginuid: attrib.LoginUIDUnsetValue, starttime: 1}}}
	id := attrib.Identity{PID: 5, LoginUID: attrib.LoginUIDUnsetValue}
	k := &Killer{Tree: pt}
	if _, err := k.resolve("loginuid", id, 50); err == nil {
		t.Fatal("loginuid scope must refuse when auid is unset")
	}
}

func TestMaxKillCeilingRefuses(t *testing.T) {
	procs := map[int]fakeProc{10: {ppid: 1, sessionid: 3, loginuid: 1000, starttime: 100}}
	for i := 11; i < 70; i++ {
		procs[i] = fakeProc{ppid: 10, sessionid: 3, loginuid: 1000, starttime: uint64(i)}
	}
	pt := procTable{procs: procs}
	id := attrib.Identity{PID: 10, SessionID: 3, LoginUID: 1000, StartTime: 100}
	k := &Killer{Tree: pt}
	if _, err := k.resolve("tree", id, 50); err == nil {
		t.Fatal("resolve must refuse when set exceeds max_kill")
	}
}

func TestSignalSkipsOnStartTimeMismatch(t *testing.T) {
	pt := procTable{procs: map[int]fakeProc{10: {ppid: 1, sessionid: 3, loginuid: 1000, starttime: 999}}}
	var signalled []int
	k := &Killer{
		Tree:   pt,
		signal: func(pid int, sig int) error { signalled = append(signalled, pid); return nil },
	}
	// starttime recorded (100) != table (999) -> PID reuse -> skip.
	k.signalGuarded(10, 100, 9)
	if len(signalled) != 0 {
		t.Fatalf("must skip reused pid, signalled = %v", signalled)
	}
	// Matching starttime does signal.
	k.signalGuarded(10, 999, 9)
	if len(signalled) != 1 || signalled[0] != 10 {
		t.Fatalf("matching starttime must signal, got %v", signalled)
	}
}

func TestSignalSkipsDeadPID(t *testing.T) {
	pt := procTable{procs: map[int]fakeProc{}}
	var signalled []int
	k := &Killer{Tree: pt, signal: func(pid, sig int) error { signalled = append(signalled, pid); return nil }}
	if k.signalGuarded(10, 0, 9) {
		t.Fatal("a dead pid must not be signalled")
	}
	if len(signalled) != 0 {
		t.Fatalf("signalled = %v", signalled)
	}
}

// Killing PID 1 would panic the kernel; killing ourselves would abandon the
// hold. Neither may ever end up in a kill set.
func TestProtectedPIDsAreNeverInTheSet(t *testing.T) {
	self := selfPID()
	pt := procTable{procs: map[int]fakeProc{
		1:    {ppid: 0, sessionid: 3, loginuid: 1000, starttime: 1},
		self: {ppid: 1, sessionid: 3, loginuid: 1000, starttime: 2},
		10:   {ppid: 1, sessionid: 3, loginuid: 1000, starttime: 100},
	}}
	id := attrib.Identity{PID: 10, SessionID: 3, LoginUID: 1000, StartTime: 100}
	k := &Killer{Tree: pt}
	set, err := k.resolve("session", id, 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, pid := range set {
		if pid == 1 {
			t.Fatalf("PID 1 must never be killed: %v", set)
		}
		if pid == self {
			t.Fatalf("the daemon must never kill itself: %v", set)
		}
	}
	if len(set) != 1 || set[0] != 10 {
		t.Fatalf("set = %v, want just the reader", set)
	}
}

// The reader's own ancestors are excluded from session/loginuid scopes only
// when they are the daemon's ancestors — an attacker's shell is fair game.
func TestDaemonAncestorsAreProtected(t *testing.T) {
	self := selfPID()
	parent := selfPPID()
	if parent <= 1 {
		t.Skip("test process has no non-init parent to protect")
	}
	pt := procTable{procs: map[int]fakeProc{
		parent: {ppid: 1, sessionid: 3, loginuid: 1000, starttime: 3},
		self:   {ppid: parent, sessionid: 3, loginuid: 1000, starttime: 2},
		10:     {ppid: 1, sessionid: 3, loginuid: 1000, starttime: 100},
	}}
	id := attrib.Identity{PID: 10, SessionID: 3, LoginUID: 1000, StartTime: 100}
	k := &Killer{Tree: pt}
	set, err := k.resolve("session", id, 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, pid := range set {
		if pid == parent {
			t.Fatalf("a daemon ancestor must never be killed: %v", set)
		}
	}
}

func TestFreezeStopsLeafFirstThenKill(t *testing.T) {
	pt := procTable{procs: map[int]fakeProc{
		10: {ppid: 1, sessionid: 3, loginuid: 1000, starttime: 100},
		11: {ppid: 10, sessionid: 3, loginuid: 1000, starttime: 101},
	}}
	id := attrib.Identity{PID: 10, SessionID: 3, LoginUID: 1000, StartTime: 100}

	type sig struct{ pid, sig int }
	var sent []sig
	k := &Killer{Tree: pt, signal: func(pid, s int) error {
		sent = append(sent, sig{pid, s})
		return nil
	}}

	if _, err := k.Freeze("tree", id, 50); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 2 || sent[0] != (sig{11, sigSTOP}) || sent[1] != (sig{10, sigSTOP}) {
		t.Fatalf("freeze sent %v, want SIGSTOP to 11 then 10", sent)
	}

	sent = nil
	killed, err := k.Kill("tree", id, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(killed) != 2 || killed[0].PID != 11 || killed[1].PID != 10 {
		t.Fatalf("killed = %v, want pids [11 10]", killed)
	}
	if sent[0].sig != sigKILL {
		t.Fatalf("kill must send SIGKILL, sent %v", sent)
	}
}

// With no signal function wired (unit tests, or a daemon built without kill
// support) nothing may be reported as killed.
func TestKillWithoutSignalFuncReportsNothing(t *testing.T) {
	pt := procTable{procs: map[int]fakeProc{10: {ppid: 1, starttime: 100}}}
	k := &Killer{Tree: pt}
	killed, err := k.Kill("pid", attrib.Identity{PID: 10, StartTime: 100}, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(killed) != 0 {
		t.Fatalf("killed = %v, want none", killed)
	}
}

func TestResolveUnknownScopeIsAnError(t *testing.T) {
	k := &Killer{Tree: procTable{procs: map[int]fakeProc{10: {ppid: 1}}}}
	if _, err := k.resolve("galaxy", attrib.Identity{PID: 10}, 50); err == nil {
		t.Fatal("unknown scope must error")
	}
}
