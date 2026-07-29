// Package session abstracts the OS session layer: read the lock state,
// lock the session, watch for changes. Platform implementations live behind
// build tags; the rest of the agent never touches OS details.
package session

import (
	"context"
	"errors"
)

// ErrUnsupported is returned by New on platforms without an implementation.
var ErrUnsupported = errors.New("session: platform not supported yet")

// Controller is the platform-specific session layer.
type Controller interface {
	// Locked reports whether the session is currently locked.
	Locked(ctx context.Context) (bool, error)

	// Lock asks the OS to lock the session.
	Lock(ctx context.Context) error

	// Watch reports the current state immediately, then every change,
	// until ctx is cancelled.
	Watch(ctx context.Context, onChange func(locked bool)) error

	// Close releases underlying resources.
	Close() error
}
