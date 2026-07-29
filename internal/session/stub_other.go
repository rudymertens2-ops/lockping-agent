//go:build !linux

package session

// New has no implementation on this platform yet; Windows lands next
// (WTSRegisterSessionNotification / LockWorkStation, see agent/README.md).
func New() (Controller, error) {
	return nil, ErrUnsupported
}
