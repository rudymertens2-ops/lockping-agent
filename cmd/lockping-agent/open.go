package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// openCompanion opent de config-UI in de browser en start de agent eerst
// als die nog niet draait (dit is wat het startmenu-item uitvoert).
func openCompanion(port int) error {
	url := fmt.Sprintf("http://127.0.0.1:%d/", port)
	if uiAlive(port) {
		openBrowser(url)
		return nil
	}
	if err := startAgent(); err != nil {
		return fmt.Errorf("agent starten: %w", err)
	}
	for i := 0; i < 20; i++ {
		if uiAlive(port) {
			openBrowser(url)
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("agent gestart, maar de UI antwoordt niet op %s", url)
}

func uiAlive(port int) bool {
	client := http.Client{Timeout: 700 * time.Millisecond}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/api/state", port))
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// startAgent: op Linux eerst netjes via de systemd user unit; lukt dat
// niet (geen unit, geen systemd), dan als los proces.
func startAgent() error {
	if runtime.GOOS == "linux" {
		if exec.Command("systemctl", "--user", "start", "lockping-agent").Run() == nil {
			return nil
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, "run")
	cmd.SysProcAttr = detachAttr() // Windows: geen zwart consolevenster
	return cmd.Start()
}
