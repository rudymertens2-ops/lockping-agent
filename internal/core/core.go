// Package core turns incoming payloads into actions on the session layer
// and reply payloads. Pure message logic: no network, injectable clock and
// session controller, so everything is unit-testable.
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/rudymertens2-ops/lockping-agent/internal/session"
	"github.com/rudymertens2-ops/lockping-agent/internal/wire"
)

// maxSkew bounds how old (or future-dated) a lock command may be.
const maxSkew = 30 * time.Second

// Core handles payloads for one machine.
type Core struct {
	sess    session.Controller
	machine string
	osName  string
	now     func() time.Time
	nonces  *nonceCache
}

// New wires a Core; now is injectable for tests (pass time.Now in prod).
func New(sess session.Controller, machine, osName string, now func() time.Time) *Core {
	return &Core{
		sess:    sess,
		machine: machine,
		osName:  osName,
		now:     now,
		nonces:  newNonceCache(2 * maxSkew),
	}
}

// Handle processes one payload; ok=false means "no reply" (unknown kind).
func (c *Core) Handle(ctx context.Context, in wire.Payload) (wire.Payload, bool) {
	switch in.Kind {
	case wire.KindStatusRequest:
		return c.status(ctx), true
	case wire.KindLock:
		return c.lock(ctx, in), true
	default:
		return wire.Payload{}, false
	}
}

// Status reports the current lock state as a status payload.
func (c *Core) Status(ctx context.Context) wire.Payload { return c.status(ctx) }

func (c *Core) status(ctx context.Context) wire.Payload {
	locked, err := c.sess.Locked(ctx)
	if err != nil {
		return wire.Payload{Kind: wire.KindStatus, Error: err.Error(), Machine: c.machine, OS: c.osName}
	}
	return wire.Payload{
		Kind: wire.KindStatus, Locked: wire.Bool(locked),
		Machine: c.machine, OS: c.osName, TS: c.now().Unix(),
	}
}

func (c *Core) lock(ctx context.Context, in wire.Payload) wire.Payload {
	if err := c.checkFreshness(in); err != nil {
		return lockResult(in.Nonce, false, err.Error())
	}
	if err := c.sess.Lock(ctx); err != nil {
		return lockResult(in.Nonce, false, err.Error())
	}
	return lockResult(in.Nonce, true, "")
}

// checkFreshness enforces the replay protection from docs/protocol.md § 3:
// a lock command needs a fresh timestamp and an unseen nonce.
func (c *Core) checkFreshness(in wire.Payload) error {
	if in.Nonce == "" {
		return fmt.Errorf("lock rejected: missing nonce")
	}
	age := c.now().Sub(time.Unix(in.TS, 0))
	if age > maxSkew || age < -maxSkew {
		return fmt.Errorf("lock rejected: stale timestamp")
	}
	if !c.nonces.add(in.Nonce, c.now()) {
		return fmt.Errorf("lock rejected: replayed nonce")
	}
	return nil
}

func lockResult(nonce string, ok bool, errMsg string) wire.Payload {
	return wire.Payload{Kind: wire.KindLockResult, Nonce: nonce, OK: wire.Bool(ok), Error: errMsg}
}
