package action

import (
	"fmt"
	"os"
	"sort"

	"github.com/mbarnathan/tripwire/internal/alert"
	"github.com/mbarnathan/tripwire/internal/attrib"
)

// ProcTree abstracts the live process table so kill logic is unit-testable.
type ProcTree interface {
	Children(pid int) []int
	Session(pid int) int
	LoginUID(pid int) int64
	StartTime(pid int) uint64
	Alive(pid int) bool
}

// ProcParent is an optional ProcTree extension giving a direct parent lookup.
// It is what makes leaf-first ordering and daemon-ancestor protection exact.
type ProcParent interface {
	Parent(pid int) int
}

// ProcDescriber is an optional ProcTree extension that names a process for the
// incident payload. Details are captured before the process is signalled,
// because /proc/<pid> disappears the moment it dies.
type ProcDescriber interface {
	Describe(pid int) (exe, cmdline string, uid int, auid int64)
}

// Killer freezes and kills processes according to a scope, with guards against
// PID reuse, unset auid, runaway kill sets, and self-inflicted damage.
type Killer struct {
	Tree   ProcTree
	signal func(pid int, sig int) error // injectable; defaults to unix.Kill via SetSignal
}

const (
	sigSTOP = 19
	sigKILL = 9

	// kthreaddPID is the parent of every kernel thread; kernel threads cannot be
	// killed and signalling them is meaningless.
	kthreaddPID = 2

	// maxWalkDepth bounds every parent walk against a malformed /proc.
	maxWalkDepth = 64
)

// SetSignal injects the real kernel signal function into a Killer. Kept separate
// so cmd wiring on Linux can supply unix.Kill without the action package
// importing golang.org/x/sys/unix (keeping it OS-portable for tests).
func SetSignal(k *Killer, fn func(pid, sig int) error) { k.signal = fn }

// Freeze SIGSTOPs the target set leaf-first so the tree cannot fork away or keep
// exfiltrating while we alert. Called implicitly before the ladder runs when
// kill is configured. SIGSTOP produces no EACCES tell — to the reader it still
// looks like slow I/O.
func (k *Killer) Freeze(scope string, id attrib.Identity, maxKill int) ([]int, error) {
	set, err := k.resolve(scope, id, maxKill)
	if err != nil {
		return nil, err
	}
	var stopped []int
	for _, pid := range set {
		if k.signalGuarded(pid, startTimeFor(k.Tree, pid, id), sigSTOP) {
			stopped = append(stopped, pid)
		}
	}
	return stopped, nil
}

// Kill SIGKILLs the resolved set leaf-first, capturing each victim's identity
// first so the incident payload survives the process.
func (k *Killer) Kill(scope string, id attrib.Identity, maxKill int) ([]alert.Killed, error) {
	set, err := k.resolve(scope, id, maxKill)
	if err != nil {
		return nil, err
	}
	var killed []alert.Killed
	for _, pid := range set {
		rec := k.describe(pid)
		if k.signalGuarded(pid, startTimeFor(k.Tree, pid, id), sigKILL) {
			killed = append(killed, rec)
		}
	}
	return killed, nil
}

// describe captures what we can name about a process before killing it.
func (k *Killer) describe(pid int) alert.Killed {
	rec := alert.Killed{PID: pid, AUID: attrib.LoginUIDUnsetValue}
	if d, ok := k.Tree.(ProcDescriber); ok {
		exe, cmdline, uid, auid := d.Describe(pid)
		rec.Exe, rec.Cmdline, rec.UID, rec.AUID = exe, cmdline, uid, auid
	}
	return rec
}

// startTimeFor returns the starttime we should verify against: for the reader
// itself use the recorded snapshot value; for others use the live table.
func startTimeFor(tree ProcTree, pid int, id attrib.Identity) uint64 {
	if pid == id.PID {
		return id.StartTime
	}
	return tree.StartTime(pid)
}

// resolve computes the ordered (leaf-first) pid set for a scope, enforcing the
// unset-auid refusal and the max_kill ceiling.
func (k *Killer) resolve(scope string, id attrib.Identity, maxKill int) ([]int, error) {
	var set []int
	switch scope {
	case "pid":
		set = []int{id.PID}
	case "tree":
		set = k.descendantsLeafFirst(id.PID)
	case "session":
		if id.SessionID <= 0 {
			return nil, fmt.Errorf("kill scope session refused: reader has no audit session id")
		}
		for pid := range allPIDs(k.Tree, id) {
			if k.Tree.Session(pid) == id.SessionID {
				set = append(set, pid)
			}
		}
		set = k.orderLeafFirst(set)
	case "loginuid":
		if id.LoginUIDUnset() {
			return nil, fmt.Errorf("kill scope loginuid refused: auid is unset (would match system daemons)")
		}
		for pid := range allPIDs(k.Tree, id) {
			if k.Tree.LoginUID(pid) == id.LoginUID {
				set = append(set, pid)
			}
		}
		set = k.orderLeafFirst(set)
	default:
		return nil, fmt.Errorf("unknown kill scope %q", scope)
	}

	set = k.removeProtected(set)
	if len(set) > maxKill {
		return nil, fmt.Errorf("kill set size %d exceeds max_kill %d; refusing", len(set), maxKill)
	}
	return set, nil
}

// descendantsLeafFirst returns pid and all descendants, deepest first.
func (k *Killer) descendantsLeafFirst(root int) []int {
	var order []int
	seen := map[int]bool{}
	var walk func(pid int, depth int)
	walk = func(pid int, depth int) {
		if seen[pid] || depth > maxWalkDepth {
			return
		}
		seen[pid] = true
		for _, c := range k.Tree.Children(pid) {
			walk(c, depth+1)
		}
		order = append(order, pid) // post-order => leaves first
	}
	walk(root, 0)
	return order
}

// allPIDs collects every pid reachable in the table (from pid 1 downward) plus
// the reader, for session/loginuid scans.
func allPIDs(tree ProcTree, id attrib.Identity) map[int]bool {
	seen := map[int]bool{}
	var walk func(pid, depth int)
	walk = func(pid, depth int) {
		if seen[pid] || depth > maxWalkDepth {
			return
		}
		seen[pid] = true
		for _, c := range tree.Children(pid) {
			walk(c, depth+1)
		}
	}
	walk(1, 0)
	walk(id.PID, 0)
	delete(seen, 1)
	return seen
}

// orderLeafFirst sorts pids deepest-first so a parent never outlives the moment
// we signal its children.
func (k *Killer) orderLeafFirst(pids []int) []int {
	depth := make(map[int]int, len(pids))
	for _, p := range pids {
		depth[p] = k.depthOf(p)
	}
	out := append([]int(nil), pids...)
	sort.SliceStable(out, func(i, j int) bool {
		if depth[out[i]] != depth[out[j]] {
			return depth[out[i]] > depth[out[j]]
		}
		return out[i] > out[j] // stable, and younger pids tend to be deeper
	})
	return out
}

func (k *Killer) depthOf(pid int) int {
	d, cur := 0, pid
	for cur > 1 && d < maxWalkDepth {
		parent := parentOf(k.Tree, cur)
		if parent == 0 || parent == cur {
			break
		}
		cur = parent
		d++
	}
	return d
}

// parentOf finds a pid's parent when the tree supports it; 0 means unknown.
func parentOf(tree ProcTree, pid int) int {
	if p, ok := tree.(ProcParent); ok {
		return p.Parent(pid)
	}
	return 0
}

// removeProtected drops anything Tripwire must never signal: PID 1, kernel
// threads, the daemon itself, and the daemon's own ancestors (killing those
// would abandon the hold and take the alert path down with it).
func (k *Killer) removeProtected(set []int) []int {
	protected := k.protectedPIDs()
	out := make([]int, 0, len(set))
	for _, p := range set {
		if p <= 1 || protected[p] || k.isKernelThread(p) {
			continue
		}
		out = append(out, p)
	}
	return out
}

func (k *Killer) protectedPIDs() map[int]bool {
	protected := map[int]bool{0: true, 1: true, kthreaddPID: true}
	self := selfPID()
	protected[self] = true
	cur := parentOf(k.Tree, self)
	for depth := 0; cur > 1 && depth < maxWalkDepth && !protected[cur]; depth++ {
		protected[cur] = true
		cur = parentOf(k.Tree, cur)
	}
	return protected
}

// isKernelThread reports whether pid descends from kthreadd (PID 2).
func (k *Killer) isKernelThread(pid int) bool {
	cur := pid
	for depth := 0; cur > 1 && depth < maxWalkDepth; depth++ {
		parent := parentOf(k.Tree, cur)
		if parent == kthreaddPID || cur == kthreaddPID {
			return true
		}
		if parent == 0 || parent == cur {
			return false
		}
		cur = parent
	}
	return false
}

// signalGuarded verifies the live starttime matches recordedStart before
// signalling, defeating PID reuse. Returns true if it signalled.
func (k *Killer) signalGuarded(pid int, recordedStart uint64, sig int) bool {
	if !k.Tree.Alive(pid) {
		return false
	}
	if k.Tree.StartTime(pid) != recordedStart {
		return false // PID reused since snapshot; do not signal
	}
	if k.signal == nil {
		return false
	}
	_ = k.signal(pid, sig)
	return true
}

func selfPID() int  { return os.Getpid() }
func selfPPID() int { return os.Getppid() }
