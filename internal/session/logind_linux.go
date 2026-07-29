//go:build linux

package session

import (
	"context"
	"fmt"
	"os"

	dbus "github.com/godbus/dbus/v5"
)

const (
	logindService = "org.freedesktop.login1"
	managerPath   = "/org/freedesktop/login1"
	managerIface  = "org.freedesktop.login1.Manager"
	sessionIface  = "org.freedesktop.login1.Session"
	propsIface    = "org.freedesktop.DBus.Properties"
)

// logind tracks one systemd-logind session over the system D-Bus.
type logind struct {
	conn *dbus.Conn
	path dbus.ObjectPath
}

// New connects to logind and binds to the current user's session.
func New() (Controller, error) {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, fmt.Errorf("session: connect system bus: %w", err)
	}
	path, err := findSessionPath(conn, uint32(os.Getuid()))
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &logind{conn: conn, path: path}, nil
}

// listedSession mirrors the (susso) tuple of Manager.ListSessions.
type listedSession struct {
	ID   string
	UID  uint32
	User string
	Seat string
	Path dbus.ObjectPath
}

func findSessionPath(conn *dbus.Conn, uid uint32) (dbus.ObjectPath, error) {
	var listed []listedSession
	obj := conn.Object(logindService, managerPath)
	if err := obj.Call(managerIface+".ListSessions", 0).Store(&listed); err != nil {
		return "", fmt.Errorf("session: list sessions: %w", err)
	}

	paths := make(map[string]dbus.ObjectPath)
	var cands []Candidate
	for _, s := range listed {
		if s.UID != uid {
			continue
		}
		paths[s.ID] = s.Path
		cands = append(cands, Candidate{
			ID:        s.ID,
			Active:    boolProp(conn, s.Path, "Active"),
			Graphical: isGraphical(stringProp(conn, s.Path, "Type")),
		})
	}

	c, ok := pickCandidate(cands)
	if !ok {
		return "", fmt.Errorf("session: no logind session for uid %d", uid)
	}
	return paths[c.ID], nil
}

// boolProp reads a session property; unreadable properties count as false,
// so a flaky session simply scores lower in the selection.
func boolProp(conn *dbus.Conn, path dbus.ObjectPath, name string) bool {
	v, err := conn.Object(logindService, path).GetProperty(sessionIface + "." + name)
	if err != nil {
		return false
	}
	b, _ := v.Value().(bool)
	return b
}

func stringProp(conn *dbus.Conn, path dbus.ObjectPath, name string) string {
	v, err := conn.Object(logindService, path).GetProperty(sessionIface + "." + name)
	if err != nil {
		return ""
	}
	s, _ := v.Value().(string)
	return s
}

func (l *logind) Locked(ctx context.Context) (bool, error) {
	v, err := l.conn.Object(logindService, l.path).GetProperty(sessionIface + ".LockedHint")
	if err != nil {
		return false, fmt.Errorf("session: read LockedHint: %w", err)
	}
	locked, ok := v.Value().(bool)
	if !ok {
		return false, fmt.Errorf("session: LockedHint has unexpected type %T", v.Value())
	}
	return locked, nil
}

func (l *logind) Lock(ctx context.Context) error {
	call := l.conn.Object(logindService, l.path).CallWithContext(ctx, sessionIface+".Lock", 0)
	if call.Err != nil {
		return fmt.Errorf("session: lock: %w", call.Err)
	}
	return nil
}

func (l *logind) Watch(ctx context.Context, onChange func(locked bool)) error {
	if err := l.conn.AddMatchSignal(
		dbus.WithMatchObjectPath(l.path),
		dbus.WithMatchInterface(propsIface),
		dbus.WithMatchMember("PropertiesChanged"),
	); err != nil {
		return fmt.Errorf("session: subscribe: %w", err)
	}

	signals := make(chan *dbus.Signal, 16)
	l.conn.Signal(signals)
	defer l.conn.RemoveSignal(signals)

	last, err := l.Locked(ctx)
	if err != nil {
		return err
	}
	onChange(last)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case sig := <-signals:
			locked, present := lockedHintFrom(sig)
			if !present || locked == last {
				continue
			}
			last = locked
			onChange(locked)
		}
	}
}

// lockedHintFrom extracts LockedHint from a PropertiesChanged signal body:
// (interface string, changed map[string]Variant, invalidated []string).
func lockedHintFrom(sig *dbus.Signal) (locked, present bool) {
	if sig == nil || len(sig.Body) < 2 {
		return false, false
	}
	iface, _ := sig.Body[0].(string)
	if iface != sessionIface {
		return false, false
	}
	changed, _ := sig.Body[1].(map[string]dbus.Variant)
	v, ok := changed["LockedHint"]
	if !ok {
		return false, false
	}
	locked, ok = v.Value().(bool)
	return locked, ok
}

func (l *logind) Close() error {
	return l.conn.Close()
}
