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

// logind tracks the current user's lockable logind session over the system
// D-Bus. The session path is resolved lazily on every operation rather than
// pinned at startup: a systemd --user service can start before the graphical
// session is registered, and re-resolving also survives fast user switching.
type logind struct {
	conn *dbus.Conn
	uid  uint32
}

// New connects to logind. It verifies that a lockable session can be found
// now, but does not pin it — each call re-resolves.
func New() (Controller, error) {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, fmt.Errorf("session: connect system bus: %w", err)
	}
	l := &logind{conn: conn, uid: uint32(os.Getuid())}
	if _, err := l.sessionPath(); err != nil {
		conn.Close()
		return nil, err
	}
	return l, nil
}

// listedSession mirrors the (susso) tuple of Manager.ListSessions.
type listedSession struct {
	ID   string
	UID  uint32
	User string
	Seat string
	Path dbus.ObjectPath
}

// sessionPath resolves the best lockable session for our uid right now.
func (l *logind) sessionPath() (dbus.ObjectPath, error) {
	var listed []listedSession
	obj := l.conn.Object(logindService, managerPath)
	if err := obj.Call(managerIface+".ListSessions", 0).Store(&listed); err != nil {
		return "", fmt.Errorf("session: list sessions: %w", err)
	}

	paths := make(map[string]dbus.ObjectPath)
	var cands []Candidate
	for _, s := range listed {
		if s.UID != l.uid {
			continue
		}
		paths[s.ID] = s.Path
		cands = append(cands, Candidate{
			ID:        s.ID,
			Class:     stringProp(l.conn, s.Path, "Class"),
			Active:    boolProp(l.conn, s.Path, "Active"),
			Graphical: isGraphical(stringProp(l.conn, s.Path, "Type")),
		})
	}

	c, ok := pickCandidate(cands)
	if !ok {
		return "", fmt.Errorf("session: no lockable logind session for uid %d", l.uid)
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
	path, err := l.sessionPath()
	if err != nil {
		return false, err
	}
	v, err := l.conn.Object(logindService, path).GetProperty(sessionIface + ".LockedHint")
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
	path, err := l.sessionPath()
	if err != nil {
		return err
	}
	call := l.conn.Object(logindService, path).CallWithContext(ctx, sessionIface+".Lock", 0)
	if call.Err != nil {
		return fmt.Errorf("session: lock: %w", call.Err)
	}
	return nil
}

// Watch reports lock/unlock changes. It listens broadly to
// PropertiesChanged on login1 sessions (the tracked session can change) and
// re-reads the current lock state on each relevant signal.
func (l *logind) Watch(ctx context.Context, onChange func(locked bool)) error {
	if err := l.conn.AddMatchSignal(
		dbus.WithMatchInterface(propsIface),
		dbus.WithMatchMember("PropertiesChanged"),
		dbus.WithMatchArg(0, sessionIface),
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
			if !mentionsLockedHint(sig) {
				continue
			}
			locked, err := l.Locked(ctx)
			if err != nil || locked == last {
				continue
			}
			last = locked
			onChange(locked)
		}
	}
}

// mentionsLockedHint reports whether a PropertiesChanged signal touches
// LockedHint, either as a changed value or an invalidated property. Body:
// (interface string, changed map[string]Variant, invalidated []string).
func mentionsLockedHint(sig *dbus.Signal) bool {
	if sig == nil || len(sig.Body) < 3 {
		return false
	}
	if iface, _ := sig.Body[0].(string); iface != sessionIface {
		return false
	}
	if changed, ok := sig.Body[1].(map[string]dbus.Variant); ok {
		if _, hit := changed["LockedHint"]; hit {
			return true
		}
	}
	if invalidated, ok := sig.Body[2].([]string); ok {
		for _, name := range invalidated {
			if name == "LockedHint" {
				return true
			}
		}
	}
	return false
}

func (l *logind) Close() error {
	return l.conn.Close()
}
