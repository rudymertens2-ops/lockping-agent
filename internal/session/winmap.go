package session

// Windows-mappings, puur gehouden (en dus ook op Linux testbaar): de
// vertaling van Win32-waarden naar lock-status. Semantiek is Windows 8+
// (Windows 7 had de beruchte omgekeerde SessionFlags-bug; buiten scope).

const (
	// WTSINFOEX.SessionFlags
	wtsSessionStateLock   = 0
	wtsSessionStateUnlock = 1

	// WM_WTSSESSION_CHANGE wParam
	wtsSessionLockEvent   = 0x7 // WTS_SESSION_LOCK
	wtsSessionUnlockEvent = 0x8 // WTS_SESSION_UNLOCK
)

// lockedFromSessionFlags interpreteert WTSINFOEX.SessionFlags.
func lockedFromSessionFlags(flags int32) (locked, known bool) {
	switch flags {
	case wtsSessionStateLock:
		return true, true
	case wtsSessionStateUnlock:
		return false, true
	}
	return false, false
}

// lockedFromSessionEvent interpreteert een WM_WTSSESSION_CHANGE-event.
func lockedFromSessionEvent(wparam uintptr) (locked, relevant bool) {
	switch wparam {
	case wtsSessionLockEvent:
		return true, true
	case wtsSessionUnlockEvent:
		return false, true
	}
	return false, false
}
