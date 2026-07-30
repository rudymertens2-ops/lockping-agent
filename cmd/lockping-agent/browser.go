package main

import (
	"log"
	"os/exec"
	"runtime"
)

// openBrowser opent een URL in de standaardbrowser van de gebruiker.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		log.Printf("browser openen mislukt (%v) — ga zelf naar %s", err, url)
	}
}
