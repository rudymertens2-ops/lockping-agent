//go:build !windows

package main

import "fmt"

// Op Linux regelen de packages autostart via de systemd user unit.
func installAutostart() error {
	fmt.Println("Op Linux: systemctl --user enable --now lockping-agent")
	return nil
}

func uninstallAutostart() error {
	fmt.Println("Op Linux: systemctl --user disable --now lockping-agent")
	return nil
}
