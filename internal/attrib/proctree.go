package attrib

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ProcFS implements the live process table over /proc. It satisfies the kill
// package's ProcTree, ProcParent, and ProcDescriber interfaces.
//
// Every lookup reads the smallest file that answers the question — a kill set is
// resolved while a reader is held, so this path stays cheap.
type ProcFS struct {
	Root string // default "/proc"
}

func NewProcFS() *ProcFS { return &ProcFS{} }

func (p *ProcFS) root() string {
	if p.Root == "" {
		return "/proc"
	}
	return p.Root
}

func (p *ProcFS) file(pid int, name string) string {
	return filepath.Join(p.root(), strconv.Itoa(pid), name)
}

// pids lists every process currently in the table.
func (p *ProcFS) pids() []int {
	entries, err := os.ReadDir(p.root())
	if err != nil {
		return nil
	}
	out := make([]int, 0, len(entries))
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			out = append(out, pid)
		}
	}
	return out
}

// stat reads just /proc/<pid>/stat and returns ppid and starttime.
func (p *ProcFS) stat(pid int) (ppid int, starttime uint64, ok bool) {
	raw, err := os.ReadFile(p.file(pid, "stat"))
	if err != nil {
		return 0, 0, false
	}
	var id Identity
	if err := parseStat(string(raw), &id); err != nil {
		return 0, 0, false
	}
	return id.PPID, id.StartTime, true
}

func (p *ProcFS) Children(pid int) []int {
	var out []int
	for _, candidate := range p.pids() {
		if candidate == pid {
			continue
		}
		if ppid, _, ok := p.stat(candidate); ok && ppid == pid {
			out = append(out, candidate)
		}
	}
	return out
}

func (p *ProcFS) Parent(pid int) int {
	ppid, _, ok := p.stat(pid)
	if !ok {
		return 0
	}
	return ppid
}

func (p *ProcFS) StartTime(pid int) uint64 {
	_, start, ok := p.stat(pid)
	if !ok {
		return 0
	}
	return start
}

func (p *ProcFS) Session(pid int) int {
	b, err := os.ReadFile(p.file(pid, "sessionid"))
	if err != nil {
		return -1
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return -1
	}
	return v
}

func (p *ProcFS) LoginUID(pid int) int64 {
	b, err := os.ReadFile(p.file(pid, "loginuid"))
	if err != nil {
		return LoginUIDUnsetValue
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return LoginUIDUnsetValue
	}
	return v
}

func (p *ProcFS) Alive(pid int) bool {
	_, err := os.Stat(filepath.Join(p.root(), strconv.Itoa(pid)))
	return err == nil
}

// Describe names a process for the incident payload. It is called immediately
// before the process is signalled, because /proc/<pid> vanishes with it.
func (p *ProcFS) Describe(pid int) (exe, cmdline string, uid int, auid int64) {
	auid = LoginUIDUnsetValue
	if link, err := os.Readlink(p.file(pid, "exe")); err == nil {
		exe = link
	}
	if b, err := os.ReadFile(p.file(pid, "cmdline")); err == nil {
		cmdline = strings.Join(splitNul(string(b)), " ")
	}
	if b, err := os.ReadFile(p.file(pid, "status")); err == nil {
		var id Identity
		parseStatus(string(b), &id)
		uid = id.UID
	}
	auid = p.LoginUID(pid)
	return exe, cmdline, uid, auid
}
