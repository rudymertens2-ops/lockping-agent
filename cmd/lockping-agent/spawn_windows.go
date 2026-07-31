//go:build windows

package main

import "syscall"

const createNoWindow = 0x08000000

// detachAttr laat de agent zonder consolevenster draaien wanneer hij
// door `open` (of de installer) gestart wordt.
func detachAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
}
