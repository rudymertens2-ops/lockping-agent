//go:build windows

package main

import (
	"fmt"

	"github.com/rudymertens2-ops/lockping-agent/internal/autostart"
)

func installAutostart() error {
	if err := autostart.New().Enable(); err != nil {
		return err
	}
	fmt.Println("LockPing start voortaan mee met Windows (tray-icoon bij de klok).")
	fmt.Println("Nu meteen starten: lockping-agent run")
	return nil
}

func uninstallAutostart() error {
	if err := autostart.New().Disable(); err != nil {
		return err
	}
	fmt.Println("Autostart verwijderd.")
	return nil
}
