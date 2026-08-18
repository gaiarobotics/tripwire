package action

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// PowerOffer halts the machine. Behind an interface so tests use a recorder and
// never actually power off CI.
type PowerOffer interface {
	PowerOff(mode string) error // mode: "graceful" | "hard"
}

// SystemPowerOffer is the production implementation.
type SystemPowerOffer struct{}

func (SystemPowerOffer) PowerOff(mode string) error {
	if mode == "hard" {
		// Best-effort sync, then SysRq emergency poweroff. Fastest possible cut,
		// at the cost of unflushed writes. SysRq writes straight to the kernel
		// and never broadcasts, so there is nothing to silence here.
		_ = exec.Command("sync").Run()
		if f, err := os.OpenFile("/proc/sysrq-trigger", os.O_WRONLY, 0); err == nil {
			defer f.Close()
			if _, err := f.WriteString("o"); err == nil { // 'o' = power off
				return nil
			}
		}
		// Fall through to graceful if sysrq is unavailable or write-protected.
	}
	cmd := poweroffCmd()
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w: %s", strings.Join(cmd.Args, " "), err, out)
	}
	return nil
}

// poweroffCmd builds the graceful-shutdown command. --no-wall suppresses the
// broadcast systemd would otherwise send to every logged-in session: a hostile
// reader still holding a shell must not be told the host is going down, or they
// get the seconds before the cut to exfiltrate or cover their tracks.
func poweroffCmd() *exec.Cmd {
	return exec.Command("systemctl", "poweroff", "--no-wall")
}
