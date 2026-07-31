// Command lockping-agent is the on-PC agent: a local CLI around the
// session layer (status, lock, watch) plus the relay link (run).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/mdp/qrterminal/v3"

	"github.com/rudymertens2-ops/lockping-agent/internal/core"
	"github.com/rudymertens2-ops/lockping-agent/internal/gateway"
	"github.com/rudymertens2-ops/lockping-agent/internal/identity"
	"github.com/rudymertens2-ops/lockping-agent/internal/relay"
	"github.com/rudymertens2-ops/lockping-agent/internal/secure"
	"github.com/rudymertens2-ops/lockping-agent/internal/session"
	"github.com/rudymertens2-ops/lockping-agent/internal/webui"
)

// defaultRelayURL is het productie-relay; overschrijfbaar met -relay
// (bv. een lokale dev-opstelling).
const defaultRelayURL = "wss://relay.lockping.rm-worx.be/ws"

// defaultUIPort is waar de lokale config-UI luistert (alleen 127.0.0.1);
// het .desktop-bestand en de tray verwijzen hiernaar.
const defaultUIPort = 41800

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "lockping-agent:", err)
		os.Exit(1)
	}
}

func run(cmd string, args []string) error {
	switch cmd {
	case "install":
		return installAutostart()
	case "uninstall":
		return uninstallAutostart()
	}

	ctrl, err := session.New()
	if err != nil {
		return err
	}
	defer ctrl.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch cmd {
	case "status":
		locked, err := ctrl.Locked(ctx)
		if err != nil {
			return err
		}
		fmt.Println(word(locked))
		return nil
	case "lock":
		return ctrl.Lock(ctx)
	case "watch":
		err := ctrl.Watch(ctx, func(locked bool) { fmt.Println(word(locked)) })
		return ignoreCancel(err)
	case "run":
		return runRelay(ctx, ctrl, args)
	default:
		usage()
		return fmt.Errorf("unknown command %q", cmd)
	}
}

// runRelay connects the agent to the relay; the gateway enforces that only
// sealed payloads from paired devices reach the core. Daarnaast draait de
// config-UI (127.0.0.1) en optioneel een tray-icoon.
func runRelay(ctx context.Context, ctrl session.Controller, args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	relayURL := fs.String("relay", defaultRelayURL, "relay WebSocket URL")
	pair := fs.Bool("pair", false, "open a 5-minute pairing window and print the QR in the terminal")
	uiPort := fs.Int("ui-port", defaultUIPort, "poort van de lokale config-UI")
	noUI := fs.Bool("no-ui", false, "start de config-UI niet")
	tray := fs.Bool("tray", runtime.GOOS == "windows",
		"toon een tray-icoon (standaard aan op Windows; Linux/GNOME vergt de AppIndicator-extensie)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *relayURL == "" {
		return fmt.Errorf("run: -relay is required")
	}

	dir, err := configDir()
	if err != nil {
		return err
	}
	ident, err := identity.Load(dir)
	if err != nil {
		return err
	}
	devices, err := secure.LoadDevices(filepath.Join(dir, "devices.json"))
	if err != nil {
		return err
	}

	host, _ := os.Hostname()
	c := core.New(ctrl, host, runtime.GOOS, time.Now)
	gw := gateway.New(c, ident.Keys, ident.AgentID, *relayURL, devices, time.Now)

	if *pair {
		code, err := gw.OpenPairing()
		if err != nil {
			return err
		}
		fmt.Printf("Scan de QR met de LockPing-app (of plak de code), geldig %s, eenmalig:\n\n",
			secure.WindowTTL)
		qrterminal.GenerateHalfBlock(code, qrterminal.L, os.Stdout)
		fmt.Printf("\n%s\n\n", code)
	}

	if !*noUI {
		ui, err := webui.New(gw, ctrl, host)
		if err != nil {
			return err
		}
		go func() {
			if err := ui.Start(ctx, *uiPort); err != nil {
				log.Printf("webui: %v", err)
			}
		}()
	}

	log.Printf("agent %s (%s/%s, %d paired) connecting to %s",
		ident.AgentID, host, runtime.GOOS, devices.Count(), *relayURL)

	connect := func(ctx context.Context) error {
		return ignoreCancel(relay.New(*relayURL, ident.AgentID, ident.Keys, gw.Handle).Run(ctx))
	}
	if *tray {
		return runWithTray(ctx, *uiPort, connect)
	}
	return connect(ctx)
}

func configDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve config dir: %w", err)
	}
	return filepath.Join(base, "lockping"), nil
}

func ignoreCancel(err error) error {
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func word(locked bool) string {
	if locked {
		return "locked"
	}
	return "unlocked"
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: lockping-agent <command>

commands:
  status                print locked/unlocked and exit
  lock                  lock the session
  watch                 print the state now and on every change (Ctrl-C to stop)
  run [-pair] [-tray] [-ui-port N] [-relay <ws-url>]
                        connect to the relay and serve paired devices;
                        config UI on http://127.0.0.1:41800
  install | uninstall   Windows: start LockPing with your session (Run key);
                        Linux: prints the systemctl equivalent`)
}
