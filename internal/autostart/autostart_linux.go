//go:build linux

package autostart

import (
	"fmt"
	"os/exec"
	"strings"
)

const unit = "lockping-agent"

type platformManager struct{}

func (platformManager) Status() (bool, bool) {
	out, err := exec.Command("systemctl", "--user", "is-enabled", unit).Output()
	if err != nil {
		// "disabled" geeft exit 1 mét output; échte fouten (geen unit,
		// geen systemd) melden we als niet-ondersteund.
		state := strings.TrimSpace(string(out))
		return false, state == "disabled"
	}
	return strings.TrimSpace(string(out)) == "enabled", true
}

func (platformManager) Enable() error {
	if out, err := exec.Command("systemctl", "--user", "enable", unit).CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl enable: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (platformManager) Disable() error {
	if out, err := exec.Command("systemctl", "--user", "disable", unit).CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl disable: %s", strings.TrimSpace(string(out)))
	}
	return nil
}
