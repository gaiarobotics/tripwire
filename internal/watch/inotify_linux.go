//go:build linux

package watch

import (
	"fmt"
	"path/filepath"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// inotifyFD wraps an inotify descriptor with a self-pipe so Close never races a
// blocking read.
type inotifyFD struct {
	fd     int
	closeR int
	closeW int
	done   chan struct{}
	once   sync.Once
}

func newInotifyFD() (*inotifyFD, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("inotify_init: %w", err)
	}
	pipe := make([]int, 2)
	if err := unix.Pipe2(pipe, unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("self-pipe: %w", err)
	}
	return &inotifyFD{fd: fd, closeR: pipe[0], closeW: pipe[1], done: make(chan struct{})}, nil
}

// read blocks until inotify events arrive or the watcher is closed. A nil slice
// with ok=false means "stop".
func (i *inotifyFD) read(buf []byte) (int, bool) {
	for {
		fds := []unix.PollFd{
			{Fd: int32(i.fd), Events: unix.POLLIN},
			{Fd: int32(i.closeR), Events: unix.POLLIN},
		}
		if _, err := unix.Poll(fds, -1); err != nil {
			if err == unix.EINTR {
				continue
			}
			return 0, false
		}
		if fds[1].Revents != 0 {
			return 0, false
		}
		n, err := unix.Read(i.fd, buf)
		if err != nil {
			if err == unix.EINTR || err == unix.EAGAIN {
				continue
			}
			return 0, false
		}
		return n, true
	}
}

func (i *inotifyFD) Close() error {
	var err error
	i.once.Do(func() {
		close(i.done)
		_, _ = unix.Write(i.closeW, []byte{0})
		_ = unix.Close(i.closeW)
		err = unix.Close(i.fd)
	})
	return err
}

// eachEvent walks the inotify records in buf.
func eachEvent(buf []byte, fn func(wd int, mask uint32, name string)) {
	for off := 0; off+unix.SizeofInotifyEvent <= len(buf); {
		raw := (*unix.InotifyEvent)(unsafe.Pointer(&buf[off]))
		nameLen := int(raw.Len)
		nameStart := off + unix.SizeofInotifyEvent
		name := ""
		if nameLen > 0 && nameStart+nameLen <= len(buf) {
			name = nulTerminated(buf[nameStart : nameStart+nameLen])
		}
		fn(int(raw.Wd), raw.Mask, name)
		off = nameStart + nameLen
	}
}

func nulTerminated(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// Inotify is the degraded fallback: it reports that a decoy was accessed but
// carries NO attribution (no PID) and CANNOT hold the read. Used only when
// fanotify is unavailable (old kernels, restricted containers).
type Inotify struct {
	in     *inotifyFD
	events chan Event

	mu    sync.Mutex
	paths map[int]string // watch descriptor -> path
}

func NewInotify() (*Inotify, error) {
	in, err := newInotifyFD()
	if err != nil {
		return nil, err
	}
	i := &Inotify{in: in, events: make(chan Event), paths: map[int]string{}}
	go i.loop()
	return i, nil
}

func (i *Inotify) Mark(path string) error {
	// IN_OPEN only: adding IN_ACCESS would report the same read twice, once for
	// the open and once for the first read of its contents.
	wd, err := unix.InotifyAddWatch(i.in.fd, path, unix.IN_OPEN)
	if err != nil {
		return fmt.Errorf("inotify_add_watch %s: %w", path, err)
	}
	i.mu.Lock()
	i.paths[wd] = path
	i.mu.Unlock()
	return nil
}

func (i *Inotify) Unmark(path string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	for wd, p := range i.paths {
		if p == path {
			delete(i.paths, wd)
			if _, err := unix.InotifyRmWatch(i.in.fd, uint32(wd)); err != nil {
				return err
			}
			return nil
		}
	}
	return nil
}

func (i *Inotify) Events() <-chan Event { return i.events }

// Respond is a no-op: inotify cannot hold or deny. Present to satisfy Watcher.
func (i *Inotify) Respond(Response) error { return nil }

func (i *Inotify) loop() {
	defer close(i.events)
	defer unix.Close(i.in.closeR)
	buf := make([]byte, 4096)
	for {
		n, ok := i.in.read(buf)
		if !ok {
			return
		}
		stop := false
		eachEvent(buf[:n], func(wd int, mask uint32, _ string) {
			if stop {
				return
			}
			i.mu.Lock()
			path := i.paths[wd]
			i.mu.Unlock()
			if path == "" {
				return
			}
			select {
			case i.events <- Event{Path: path, Perm: false}: // no PID, not a perm event
			case <-i.in.done:
				stop = true
			}
		})
		if stop {
			return
		}
	}
}

func (i *Inotify) Close() error { return i.in.Close() }

var _ Watcher = (*Inotify)(nil)
var _ Marker = (*Inotify)(nil)

// DirWatcher reports when a decoy is (re)created in its parent directory.
// fanotify marks are per-inode, so a decoy that is deleted and rewritten — by an
// attacker, by config management, or by our own refresh — is no longer watched
// until it is re-marked. This is what tells the daemon to do that.
type DirWatcher struct {
	in       *inotifyFD
	replaced chan string

	mu    sync.Mutex
	dirs  map[int]string             // watch descriptor -> directory
	names map[string]map[string]bool // directory -> basenames we care about
}

// NewDirWatcher watches the parent directory of every given decoy path.
func NewDirWatcher(paths []string) (*DirWatcher, error) {
	in, err := newInotifyFD()
	if err != nil {
		return nil, err
	}
	d := &DirWatcher{
		in:       in,
		replaced: make(chan string, len(paths)),
		dirs:     map[int]string{},
		names:    map[string]map[string]bool{},
	}
	for _, p := range paths {
		dir, base := filepath.Split(p)
		dir = filepath.Clean(dir)
		if d.names[dir] == nil {
			wd, err := unix.InotifyAddWatch(in.fd, dir,
				unix.IN_CREATE|unix.IN_MOVED_TO|unix.IN_DELETE|unix.IN_MOVED_FROM)
			if err != nil {
				_ = in.Close()
				return nil, fmt.Errorf("watch dir %s: %w", dir, err)
			}
			d.dirs[wd] = dir
			d.names[dir] = map[string]bool{}
		}
		d.names[dir][base] = true
	}
	go d.loop()
	return d, nil
}

// Replaced streams the absolute paths of decoys that appeared (or reappeared)
// and therefore need re-marking.
func (d *DirWatcher) Replaced() <-chan string { return d.replaced }

func (d *DirWatcher) loop() {
	defer close(d.replaced)
	defer unix.Close(d.in.closeR)
	buf := make([]byte, 4096)
	for {
		n, ok := d.in.read(buf)
		if !ok {
			return
		}
		stop := false
		eachEvent(buf[:n], func(wd int, mask uint32, name string) {
			if stop || name == "" {
				return
			}
			if mask&(unix.IN_CREATE|unix.IN_MOVED_TO) == 0 {
				return
			}
			d.mu.Lock()
			dir := d.dirs[wd]
			watched := dir != "" && d.names[dir][name]
			d.mu.Unlock()
			if !watched {
				return
			}
			select {
			case d.replaced <- filepath.Join(dir, name):
			case <-d.in.done:
				stop = true
			}
		})
		if stop {
			return
		}
	}
}

func (d *DirWatcher) Close() error { return d.in.Close() }
