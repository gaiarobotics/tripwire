package action

import (
	"fmt"
	"os"
	"os/exec"
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
		// at the cost of unflushed writes.
		_ = exec.Command("sync").Run()
		if f, err := os.OpenFile("/proc/sysrq-trigger", os.O_WRONLY, 0); err == nil {
			defer f.Close()
			if _, err := f.WriteString("o"); err == nil { // 'o' = power off
				return nil
			}
		}
		// Fall through to graceful if sysrq is unavailable or write-protected.
	}
	if out, err := exec.Command("systemctl", "poweroff").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl poweroff: %w: %s", err, out)
	}
	return nil
}
