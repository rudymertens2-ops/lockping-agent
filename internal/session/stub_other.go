//go:build !linux && !windows

package session

// New has no implementation on this platform; Linux and Windows are the
// supported targets (macOS is deliberately out of scope).
func New() (Controller, error) {
	return nil, ErrUnsupported
}
