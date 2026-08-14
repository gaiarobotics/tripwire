//go:build linux

package attrib

import "golang.org/x/sys/unix"

// Signal sends sig to pid via the real kernel. It is injected into the killer so
// the action package stays free of syscall dependencies and unit-testable with a
// recorder.
func Signal(pid, sig int) error { return unix.Kill(pid, unix.Signal(sig)) }
