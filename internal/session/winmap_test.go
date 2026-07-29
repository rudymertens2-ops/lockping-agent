package session

import "testing"

func TestLockedFromSessionFlags(t *testing.T) {
	cases := []struct {
		flags  int32
		locked bool
		known  bool
	}{
		{0, true, true},   // WTS_SESSIONSTATE_LOCK
		{1, false, true},  // WTS_SESSIONSTATE_UNLOCK
		{-1, false, false}, // WTS_SESSIONSTATE_UNKNOWN (0xFFFFFFFF)
		{42, false, false},
	}
	for _, c := range cases {
		locked, known := lockedFromSessionFlags(c.flags)
		if locked != c.locked || known != c.known {
			t.Errorf("flags %d: got (%v,%v), want (%v,%v)", c.flags, locked, known, c.locked, c.known)
		}
	}
}

func TestLockedFromSessionEvent(t *testing.T) {
	cases := []struct {
		wparam   uintptr
		locked   bool
		relevant bool
	}{
		{0x7, true, true},  // WTS_SESSION_LOCK
		{0x8, false, true}, // WTS_SESSION_UNLOCK
		{0x1, false, false}, // WTS_CONSOLE_CONNECT e.d. negeren
		{0x0, false, false},
	}
	for _, c := range cases {
		locked, relevant := lockedFromSessionEvent(c.wparam)
		if locked != c.locked || relevant != c.relevant {
			t.Errorf("wparam %#x: got (%v,%v), want (%v,%v)", c.wparam, locked, relevant, c.locked, c.relevant)
		}
	}
}
