//go:build windows

package autostart

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows/registry"
)

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`

type platformManager struct{}

func (platformManager) Status() (bool, bool) {
	key, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false, true
	}
	defer key.Close()
	_, _, err = key.GetStringValue("LockPing")
	return err == nil, true
}

func (platformManager) Enable() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	key, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("autostart: registersleutel: %w", err)
	}
	defer key.Close()
	return key.SetStringValue("LockPing", fmt.Sprintf(`"%s" run`, exe))
}

func (platformManager) Disable() error {
	key, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("autostart: registersleutel: %w", err)
	}
	defer key.Close()
	return key.DeleteValue("LockPing")
}
