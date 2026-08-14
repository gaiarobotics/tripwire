// Package attrib turns a PID into the identity of the process that read a decoy,
// including the loginuid (auid) that survives su/sudo.
package attrib

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// LoginUIDUnsetValue is the kernel sentinel for "no login uid" ((uid_t)-1).
const LoginUIDUnsetValue = 4294967295

// maxAncestorDepth bounds the parent walk so a malformed or cyclic /proc can
// never spin the daemon while a reader is held.
const maxAncestorDepth = 32

// Ancestor is a thin identity for a process in the parent chain.
type Ancestor struct {
	PID  int
	Comm string
	Exe  string
}

// Identity is everything we learn about the reader at snapshot time.
type Identity struct {
	PID       int
	PPID      int
	UID       int
	LoginUID  int64 // auid; LoginUIDUnsetValue means unset
	SessionID int
	CapEff    uint64
	Comm      string
	Exe       string // resolved /proc/<pid>/exe, best effort
	Cmdline   []string
	Cgroup    string
	StartTime uint64 // /proc/<pid>/stat field 22; PID-reuse guard
	Ancestors []Ancestor
}

// LoginUIDUnset reports whether auid is the unset sentinel. loginuid-scoped
// actions must refuse when this is true.
func (id Identity) LoginUIDUnset() bool { return id.LoginUID == LoginUIDUnsetValue }

// Snapshotter reads process identity from a (possibly fake) proc root.
type Snapshotter struct {
	ProcRoot string // default "/proc"
}

func (s *Snapshotter) root() string {
	if s.ProcRoot == "" {
		return "/proc"
	}
	return s.ProcRoot
}

// Snapshot captures the identity of pid plus its ancestor chain. It must be
// called while the reader is still blocked in open(), so /proc/<pid> is
// guaranteed to exist.
func (s *Snapshotter) Snapshot(pid int) (Identity, error) {
	id, err := s.one(pid)
	if err != nil {
		return Identity{}, err
	}
	// Walk ancestors up to init, bounded to avoid loops.
	seen := map[int]bool{pid: true}
	cur := id.PPID
	for depth := 0; cur > 1 && depth < maxAncestorDepth && !seen[cur]; depth++ {
		seen[cur] = true
		anc, err := s.one(cur)
		if err != nil {
			break
		}
		id.Ancestors = append(id.Ancestors, Ancestor{PID: anc.PID, Comm: anc.Comm, Exe: anc.Exe})
		cur = anc.PPID
	}
	return id, nil
}

func (s *Snapshotter) one(pid int) (Identity, error) {
	base := filepath.Join(s.root(), itoa(pid))
	id := Identity{PID: pid, LoginUID: LoginUIDUnsetValue}

	statRaw, err := os.ReadFile(filepath.Join(base, "stat"))
	if err != nil {
		return Identity{}, fmt.Errorf("read stat: %w", err)
	}
	if err := parseStat(string(statRaw), &id); err != nil {
		return Identity{}, err
	}

	if b, err := os.ReadFile(filepath.Join(base, "status")); err == nil {
		parseStatus(string(b), &id)
	}
	if b, err := os.ReadFile(filepath.Join(base, "loginuid")); err == nil {
		if v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil {
			id.LoginUID = v
		}
	}
	if b, err := os.ReadFile(filepath.Join(base, "sessionid")); err == nil {
		id.SessionID, _ = strconv.Atoi(strings.TrimSpace(string(b)))
	}
	if b, err := os.ReadFile(filepath.Join(base, "cmdline")); err == nil {
		id.Cmdline = splitNul(string(b))
	}
	if b, err := os.ReadFile(filepath.Join(base, "cgroup")); err == nil {
		id.Cgroup = strings.TrimSpace(string(b))
	}
	if p, err := os.Readlink(filepath.Join(base, "exe")); err == nil {
		id.Exe = p
	}
	return id, nil
}

// parseStat handles the "comm" field possibly containing spaces and parens by
// splitting on the last ')'.
func parseStat(raw string, id *Identity) error {
	open := strings.IndexByte(raw, '(')
	closing := strings.LastIndexByte(raw, ')')
	if open < 0 || closing < 0 || closing < open {
		return fmt.Errorf("malformed stat")
	}
	id.Comm = raw[open+1 : closing]
	rest := strings.Fields(raw[closing+1:])
	// rest[0]=state, rest[1]=ppid, ... field22 overall = index 19 in rest.
	if len(rest) > 1 {
		id.PPID, _ = strconv.Atoi(rest[1])
	}
	if len(rest) > 19 {
		id.StartTime, _ = strconv.ParseUint(rest[19], 10, 64)
	}
	return nil
}

func parseStatus(raw string, id *Identity) {
	for _, line := range strings.Split(raw, "\n") {
		switch {
		case strings.HasPrefix(line, "Uid:"):
			f := strings.Fields(line)
			if len(f) > 1 {
				id.UID, _ = strconv.Atoi(f[1]) // real uid
			}
		case strings.HasPrefix(line, "CapEff:"):
			f := strings.Fields(line)
			if len(f) > 1 {
				id.CapEff, _ = strconv.ParseUint(f[1], 16, 64)
			}
		}
	}
}

func splitNul(s string) []string {
	parts := strings.Split(strings.TrimRight(s, "\x00"), "\x00")
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func itoa(i int) string { return strconv.Itoa(i) }
