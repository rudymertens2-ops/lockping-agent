package main

import (
	"context"
	_ "embed"
	"fmt"
	"runtime"

	"fyne.io/systray"
)

//go:embed icon.png
var trayIconPNG []byte

//go:embed icon.ico
var trayIconICO []byte

// runWithTray draait de relay-verbinding met een tray-icoon ernaast.
// Kanttekening Linux: het icoon gebruikt het StatusNotifier-protocol
// (D-Bus); stock GNOME toont dat pas met de AppIndicator-extensie.
func runWithTray(ctx context.Context, uiPort int, connect func(context.Context) error) error {
	trayCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	result := make(chan error, 1)

	systray.Run(func() {
		systray.SetIcon(trayIcon())
		systray.SetTooltip("LockPing Agent — Check. Tap. Locked.")
		open := systray.AddMenuItem("Instellingen openen", "Opent de config-UI in je browser")
		systray.AddSeparator()
		quit := systray.AddMenuItem("Stoppen", "Stopt de agent")

		go func() {
			result <- connect(trayCtx)
			systray.Quit()
		}()
		go func() {
			for {
				select {
				case <-trayCtx.Done():
					systray.Quit()
					return
				case <-open.ClickedCh:
					openBrowser(fmt.Sprintf("http://127.0.0.1:%d/", uiPort))
				case <-quit.ClickedCh:
					cancel()
				}
			}
		}()
	}, nil)

	select {
	case err := <-result:
		return err
	default:
		return nil
	}
}

func trayIcon() []byte {
	if runtime.GOOS == "windows" {
		return trayIconICO
	}
	return trayIconPNG
}
