//go:build windows

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows/registry"
)

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`

// installAutostart registreert de agent in de Run-sleutel van de gebruiker
// (geen adminrechten nodig); de tray staat op Windows standaard aan.
func installAutostart() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	key, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("install: registersleutel: %w", err)
	}
	defer key.Close()
	if err := key.SetStringValue("LockPing", fmt.Sprintf(`"%s" run`, exe)); err != nil {
		return err
	}
	fmt.Println("LockPing start voortaan mee met Windows (tray-icoon bij de klok).")
	fmt.Println("Nu meteen starten: lockping-agent run")
	return nil
}

func uninstallAutostart() error {
	key, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("uninstall: registersleutel: %w", err)
	}
	defer key.Close()
	if err := key.DeleteValue("LockPing"); err != nil {
		return fmt.Errorf("uninstall: %w", err)
	}
	fmt.Println("Autostart verwijderd.")
	return nil
}
