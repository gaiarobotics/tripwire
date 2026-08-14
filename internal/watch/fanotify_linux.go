//go:build linux

package watch

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// fanotifyMetadataVersion is the ABI version this parser understands. The kernel
// stamps every event with its own version; a mismatch means the layout we are
// about to read is not the layout we compiled against, so we stop rather than
// misattribute a read.
const fanotifyMetadataVersion = 3

// Fanotify is the production Watcher. It uses FAN_OPEN_PERM permission events,
// which block the reader inside open() until we respond — that block is what
// makes the hold possible.
//
// Deadlock warning: the listener's own opens of a marked file also generate
// permission events, so the daemon must never open a decoy. Bait writes go
// through a temp file and rename (a different inode), which is why refresh is
// safe.
type Fanotify struct {
	fd     int
	events chan Event

	writeMu sync.Mutex // serialises response writes to fd
	done    chan struct{}
	closeW  int // self-pipe write end, used to wake the poll loop on Close
	closeR  int
	once    sync.Once
}

// NewFanotify initializes a fanotify group in content class with permission
// events. Requires CAP_SYS_ADMIN.
func NewFanotify() (*Fanotify, error) {
	fd, err := unix.FanotifyInit(
		unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC|unix.FAN_UNLIMITED_QUEUE,
		unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC,
	)
	if err != nil {
		return nil, fmt.Errorf("fanotify_init (need CAP_SYS_ADMIN): %w", err)
	}
	pipe := make([]int, 2)
	if err := unix.Pipe2(pipe, unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("self-pipe: %w", err)
	}
	f := &Fanotify{
		fd:     fd,
		events: make(chan Event),
		done:   make(chan struct{}),
		closeR: pipe[0],
		closeW: pipe[1],
	}
	go f.loop()
	return f, nil
}

// Mark adds a permission-open mark on a single decoy inode. Per-inode (not
// mount-wide) so the rest of /etc sees no overhead.
func (f *Fanotify) Mark(path string) error {
	// Refuse to mark anything that is not a regular file: a decoy replaced by a
	// symlink or fifo cannot deliver open-permission events and would silently
	// leave the wire disarmed.
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("refusing to mark %s: not a regular file (mode %v)", path, fi.Mode())
	}
	if err := unix.FanotifyMark(f.fd, unix.FAN_MARK_ADD|unix.FAN_MARK_DONT_FOLLOW,
		unix.FAN_OPEN_PERM, unix.AT_FDCWD, path); err != nil {
		return fmt.Errorf("fanotify_mark %s: %w", path, err)
	}
	return nil
}

// Unmark removes the mark on a decoy.
func (f *Fanotify) Unmark(path string) error {
	return unix.FanotifyMark(f.fd, unix.FAN_MARK_REMOVE|unix.FAN_MARK_DONT_FOLLOW,
		unix.FAN_OPEN_PERM, unix.AT_FDCWD, path)
}

func (f *Fanotify) Events() <-chan Event { return f.events }

// Respond answers a permission event and releases the reader. The event fd is
// closed afterwards: every unanswered event holds an open file descriptor.
func (f *Fanotify) Respond(r Response) error {
	resp := unix.FanotifyResponse{Fd: int32(r.Token), Response: unix.FAN_DENY}
	if r.Allow {
		resp.Response = unix.FAN_ALLOW
	}
	var buf [8]byte
	binary.NativeEndian.PutUint32(buf[0:4], uint32(resp.Fd))
	binary.NativeEndian.PutUint32(buf[4:8], resp.Response)

	f.writeMu.Lock()
	_, err := unix.Write(f.fd, buf[:])
	f.writeMu.Unlock()

	// The token is the event fd; close it whether or not the write succeeded.
	_ = unix.Close(int(r.Token))
	if err != nil {
		return fmt.Errorf("fanotify respond: %w", err)
	}
	return nil
}

func (f *Fanotify) loop() {
	defer close(f.events)
	// The loop owns the read end of the self-pipe: closing an fd another
	// goroutine is polling is exactly the race we are avoiding here.
	defer unix.Close(f.closeR)
	buf := make([]byte, 4096)
	for {
		fds := []unix.PollFd{
			{Fd: int32(f.fd), Events: unix.POLLIN},
			{Fd: int32(f.closeR), Events: unix.POLLIN},
		}
		if _, err := unix.Poll(fds, -1); err != nil {
			if err == unix.EINTR {
				continue
			}
			return
		}
		if fds[1].Revents != 0 {
			return // Close was called
		}
		if fds[0].Revents&unix.POLLIN == 0 {
			continue
		}
		n, err := unix.Read(f.fd, buf)
		if err != nil {
			if err == unix.EINTR || err == unix.EAGAIN {
				continue
			}
			return // fd closed
		}
		if !f.dispatch(buf[:n]) {
			return
		}
	}
}

// dispatch parses one read's worth of events and emits them. It returns false
// when the loop should stop.
func (f *Fanotify) dispatch(buf []byte) bool {
	metaSize := int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
	for off := 0; off+metaSize <= len(buf); {
		meta := (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[off]))
		if meta.Vers != fanotifyMetadataVersion {
			log.Printf("tripwired: fanotify metadata version %d, expected %d; stopping the watch rather than misreading events",
				meta.Vers, fanotifyMetadataVersion)
			return false
		}
		if meta.Event_len < uint32(metaSize) || off+int(meta.Event_len) > len(buf) {
			return true // truncated tail; the kernel will resend the rest
		}

		// FAN_NOFD shows up on queue overflow: nothing to answer, nothing to close.
		if meta.Fd >= 0 {
			ev := Event{
				PID:   int(meta.Pid),
				Token: uint64(meta.Fd), // the event fd doubles as the response token
				Perm:  meta.Mask&unix.FAN_OPEN_PERM != 0,
				Path:  resolveFdPath(int(meta.Fd)),
			}
			select {
			case f.events <- ev:
			case <-f.done:
				// Shutting down: release the reader rather than stranding it.
				_ = f.Respond(Response{Token: ev.Token, Allow: true})
				return false
			}
		} else {
			log.Printf("tripwired: fanotify event without an fd (mask %#x) — queue overflow?", meta.Mask)
		}
		off += int(meta.Event_len)
	}
	return true
}

// resolveFdPath reads /proc/self/fd/<fd> to recover the decoy path.
func resolveFdPath(fd int) string {
	p, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return ""
	}
	return p
}

// Close stops the watch. Any reader still held by an unanswered permission event
// is released by the kernel when the group's fd closes — the hold fails open.
func (f *Fanotify) Close() error {
	var err error
	f.once.Do(func() {
		close(f.done)
		_, _ = unix.Write(f.closeW, []byte{0}) // wake the poll loop
		_ = unix.Close(f.closeW)
		err = unix.Close(f.fd)
	})
	return err
}

var _ Watcher = (*Fanotify)(nil)
var _ Marker = (*Fanotify)(nil)
