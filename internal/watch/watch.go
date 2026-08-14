// Package watch abstracts decoy-file access notification. The fanotify backend
// delivers permission events (which block the reader and carry the PID); the
// inotify backend is a degraded fallback with no attribution and no hold.
package watch

// Event is one access to a watched decoy.
type Event struct {
	PID   int
	Path  string
	Token uint64 // opaque handle to respond to a permission event
	Perm  bool   // true if this is a permission event that must be answered
}

// Response answers a permission event.
type Response struct {
	Token uint64
	Allow bool
}

// Watcher marks decoys and streams access events.
type Watcher interface {
	Events() <-chan Event
	Respond(Response) error
	Close() error
}

// Marker is implemented by watchers that can add and remove per-file marks.
// Marks are per-inode, so a decoy that is replaced must be re-marked; see
// DirWatcher, which reports replacements.
type Marker interface {
	Mark(path string) error
	Unmark(path string) error
}
