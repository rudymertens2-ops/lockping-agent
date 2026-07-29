package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rudymertens2-ops/lockping-agent/internal/wire"
)

// fakeSession is an injectable session.Controller for tests.
type fakeSession struct {
	locked     bool
	lockErr    error
	lockCalls  int
	lockedErr  error
}

func (f *fakeSession) Locked(ctx context.Context) (bool, error) { return f.locked, f.lockedErr }
func (f *fakeSession) Lock(ctx context.Context) error {
	f.lockCalls++
	if f.lockErr == nil {
		f.locked = true
	}
	return f.lockErr
}
func (f *fakeSession) Watch(ctx context.Context, fn func(bool)) error { return nil }
func (f *fakeSession) Close() error                                  { return nil }

func newTestCore(sess *fakeSession, at time.Time) *Core {
	return New(sess, "test-pc", "linux", func() time.Time { return at })
}

func TestStatusRequest(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	c := newTestCore(&fakeSession{locked: true}, now)

	out, ok := c.Handle(context.Background(), wire.Payload{Kind: wire.KindStatusRequest})
	if !ok || out.Kind != wire.KindStatus {
		t.Fatalf("got %+v ok=%v, want status reply", out, ok)
	}
	if out.Locked == nil || !*out.Locked || out.Machine != "test-pc" || out.OS != "linux" {
		t.Errorf("unexpected status payload: %+v", out)
	}
}

func TestStatusReportsSessionError(t *testing.T) {
	c := newTestCore(&fakeSession{lockedErr: errors.New("dbus down")}, time.Unix(0, 0))
	out, _ := c.Handle(context.Background(), wire.Payload{Kind: wire.KindStatusRequest})
	if out.Error == "" || out.Locked != nil {
		t.Errorf("expected error status, got %+v", out)
	}
}

func TestLockHappyPath(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	sess := &fakeSession{}
	c := newTestCore(sess, now)

	out, ok := c.Handle(context.Background(), wire.Payload{
		Kind: wire.KindLock, Nonce: "n1", TS: now.Unix(),
	})
	if !ok || out.Kind != wire.KindLockResult || out.OK == nil || !*out.OK {
		t.Fatalf("got %+v, want ok lock_result", out)
	}
	if sess.lockCalls != 1 {
		t.Errorf("lockCalls = %d, want 1", sess.lockCalls)
	}
}

func TestLockRejectsReplayedNonce(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	sess := &fakeSession{}
	c := newTestCore(sess, now)
	msg := wire.Payload{Kind: wire.KindLock, Nonce: "dup", TS: now.Unix()}

	c.Handle(context.Background(), msg)
	out, _ := c.Handle(context.Background(), msg)
	if out.OK == nil || *out.OK {
		t.Fatalf("replay accepted: %+v", out)
	}
	if sess.lockCalls != 1 {
		t.Errorf("lockCalls = %d, want 1 (replay must not lock again)", sess.lockCalls)
	}
}

func TestLockRejectsStaleTimestamp(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	sess := &fakeSession{}
	c := newTestCore(sess, now)

	out, _ := c.Handle(context.Background(), wire.Payload{
		Kind: wire.KindLock, Nonce: "n2", TS: now.Add(-2 * time.Minute).Unix(),
	})
	if out.OK == nil || *out.OK || sess.lockCalls != 0 {
		t.Errorf("stale lock accepted: %+v calls=%d", out, sess.lockCalls)
	}
}

func TestLockRejectsMissingNonce(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	c := newTestCore(&fakeSession{}, now)
	out, _ := c.Handle(context.Background(), wire.Payload{Kind: wire.KindLock, TS: now.Unix()})
	if out.OK == nil || *out.OK {
		t.Errorf("lock without nonce accepted: %+v", out)
	}
}

func TestUnknownKindHasNoReply(t *testing.T) {
	c := newTestCore(&fakeSession{}, time.Unix(0, 0))
	if _, ok := c.Handle(context.Background(), wire.Payload{Kind: "dance"}); ok {
		t.Error("unknown kind produced a reply")
	}
}
