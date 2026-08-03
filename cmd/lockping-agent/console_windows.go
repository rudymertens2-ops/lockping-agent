//go:build windows

package main

import (
	"log"
	"os"
	"syscall"
)

// De Windows-binary wordt gebouwd met -H=windowsgui, zodat autostart en de
// tray geen zwart consolevenster openen. Keerzijde: uitvoer verdwijnt dan
// ook wanneer je hem wél vanuit een terminal start. AttachConsole haalt dat
// terug: draait er een ouder-console (cmd/PowerShell), dan schrijven we
// daarnaartoe; gestart vanuit Verkenner of autostart gebeurt er niets.
func init() {
	const attachParentProcess = ^uintptr(0) // (DWORD)-1

	attach := syscall.NewLazyDLL("kernel32.dll").NewProc("AttachConsole")
	if ok, _, _ := attach.Call(attachParentProcess); ok == 0 {
		return // geen ouder-console: stil blijven
	}

	out, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0)
	if err != nil {
		return
	}
	os.Stdout = out
	os.Stderr = out
	log.SetOutput(out) // de standaardlogger hield de oude stderr vast
}
