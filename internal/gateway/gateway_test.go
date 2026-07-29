package gateway

import (
	"context"
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"

	"github.com/rudymertens2-ops/lockping-agent/internal/core"
	"github.com/rudymertens2-ops/lockping-agent/internal/secure"
	"github.com/rudymertens2-ops/lockping-agent/internal/wire"
)

// fakeSession implements session.Controller for the core.
type fakeSession struct {
	locked    bool
	lockCalls int
}

func (f *fakeSession) Locked(ctx context.Context) (bool, error) { return f.locked, nil }
func (f *fakeSession) Lock(ctx context.Context) error           { f.lockCalls++; f.locked = true; return nil }
func (f *fakeSession) Watch(ctx context.Context, fn func(bool)) error { return nil }
func (f *fakeSession) Close() error                                   { return nil }

// testRig bundles a gateway with a fully scripted "phone" client side.
type testRig struct {
	gw         *Gateway
	sess       *fakeSession
	agentKeys  secure.Keys
	clientKeys secure.Keys
	window     *secure.Window
	secretB64  string
	now        time.Time
}

func newRig(t *testing.T, withWindow bool) *testRig {
	t.Helper()
	now := time.Unix(1_000_000, 0)
	agentKeys, _ := secure.GenerateKeys()
	clientKeys, _ := secure.GenerateKeys()
	sess := &fakeSession{}
	devices, err := secure.LoadDevices(filepath.Join(t.TempDir(), "devices.json"))
	if err != nil {
		t.Fatal(err)
	}

	var window *secure.Window
	var secretB64 string
	if withWindow {
		window, secretB64, err = secure.NewWindow(now)
		if err != nil {
			t.Fatal(err)
		}
	}

	c := core.New(sess, "test-pc", "linux", func() time.Time { return now })
	return &testRig{
		gw:         New(c, agentKeys, "agent-1", devices, window, func() time.Time { return now }),
		sess:       sess,
		agentKeys:  agentKeys,
		clientKeys: clientKeys,
		window:     window,
		secretB64:  secretB64,
		now:        now,
	}
}

// pair performs the client side of a valid pairing and returns the accept.
func (r *testRig) pair(t *testing.T, clientID string) wire.Payload {
	t.Helper()
	clientPub := secure.EncodeKey(r.clientKeys.Pub)
	req := wire.Payload{
		Kind:   wire.KindPairRequest,
		PubKey: clientPub,
		MAC:    testMAC(t, r.secretB64, clientID, clientPub),
	}
	enc, _ := wire.Encode(req)
	reply, ok := r.gw.Handle(context.Background(), clientID, enc)
	if !ok {
		t.Fatal("valid pair_request got no reply")
	}
	accept, err := wire.Decode(reply)
	if err != nil || accept.Kind != wire.KindPairAccept {
		t.Fatalf("unexpected pairing reply: %q", reply)
	}
	return accept
}

func TestPairingThenSealedStatusAndLock(t *testing.T) {
	r := newRig(t, true)
	accept := r.pair(t, "phone-1")

	agentPub, err := secure.DecodeKey(accept.PubKey)
	if err != nil {
		t.Fatal(err)
	}

	statusReq, _ := wire.Encode(wire.Payload{Kind: wire.KindStatusRequest})
	sealed, _ := secure.Seal(statusReq, agentPub, r.clientKeys)
	reply, ok := r.gw.Handle(context.Background(), "phone-1", sealed)
	if !ok {
		t.Fatal("sealed status_request from paired device ignored")
	}
	plain, ok := secure.Open(reply, agentPub, r.clientKeys)
	if !ok {
		t.Fatal("reply not decryptable by client")
	}
	status, _ := wire.Decode(plain)
	if status.Kind != wire.KindStatus || status.Locked == nil || *status.Locked {
		t.Fatalf("unexpected status: %+v", status)
	}

	lockCmd, _ := wire.Encode(wire.Payload{Kind: wire.KindLock, Nonce: "n1", TS: r.now.Unix()})
	sealedLock, _ := secure.Seal(lockCmd, agentPub, r.clientKeys)
	reply, ok = r.gw.Handle(context.Background(), "phone-1", sealedLock)
	if !ok {
		t.Fatal("sealed lock ignored")
	}
	plain, _ = secure.Open(reply, agentPub, r.clientKeys)
	result, _ := wire.Decode(plain)
	if result.OK == nil || !*result.OK || r.sess.lockCalls != 1 {
		t.Fatalf("lock did not execute: %+v calls=%d", result, r.sess.lockCalls)
	}
}

func TestPlaintextCommandsAreIgnored(t *testing.T) {
	r := newRig(t, true)
	r.pair(t, "phone-1")

	plainLock, _ := wire.Encode(wire.Payload{Kind: wire.KindLock, Nonce: "n1", TS: r.now.Unix()})
	if _, ok := r.gw.Handle(context.Background(), "phone-1", plainLock); ok {
		t.Error("plaintext lock from paired device got a reply")
	}
	if r.sess.lockCalls != 0 {
		t.Error("plaintext lock executed")
	}
}

func TestSealedFromUnpairedIsIgnored(t *testing.T) {
	r := newRig(t, false)
	statusReq, _ := wire.Encode(wire.Payload{Kind: wire.KindStatusRequest})
	sealed, _ := secure.Seal(statusReq, r.agentKeys.Pub, r.clientKeys)
	if _, ok := r.gw.Handle(context.Background(), "stranger", sealed); ok {
		t.Error("sealed payload from unpaired device got a reply")
	}
}

func TestPairRequestWithWrongMACIsRejected(t *testing.T) {
	r := newRig(t, true)
	clientPub := secure.EncodeKey(r.clientKeys.Pub)
	req := wire.Payload{
		Kind:   wire.KindPairRequest,
		PubKey: clientPub,
		MAC:    base64.StdEncoding.EncodeToString([]byte("forged-mac-32-bytes-forged-mac!!")),
	}
	enc, _ := wire.Encode(req)
	if _, ok := r.gw.Handle(context.Background(), "phone-1", enc); ok {
		t.Error("forged pair_request accepted")
	}
}

func TestPairingWindowIsSingleUse(t *testing.T) {
	r := newRig(t, true)
	r.pair(t, "phone-1")

	otherKeys, _ := secure.GenerateKeys()
	otherPub := secure.EncodeKey(otherKeys.Pub)
	req := wire.Payload{
		Kind:   wire.KindPairRequest,
		PubKey: otherPub,
		MAC:    testMAC(t, r.secretB64, "phone-2", otherPub),
	}
	enc, _ := wire.Encode(req)
	if _, ok := r.gw.Handle(context.Background(), "phone-2", enc); ok {
		t.Error("second pairing on a consumed window accepted")
	}
}

func TestPairRequestWithoutWindowIsRejected(t *testing.T) {
	r := newRig(t, false)
	clientPub := secure.EncodeKey(r.clientKeys.Pub)
	req := wire.Payload{Kind: wire.KindPairRequest, PubKey: clientPub, MAC: "AAAA"}
	enc, _ := wire.Encode(req)
	if _, ok := r.gw.Handle(context.Background(), "phone-1", enc); ok {
		t.Error("pair_request accepted while no window is open")
	}
}

// testMAC mirrors the client-side HMAC construction via the public helper.
func testMAC(t *testing.T, secretB64, clientID, clientPubB64 string) string {
	t.Helper()
	mac, err := secure.RequestMAC(secretB64, clientID, clientPubB64)
	if err != nil {
		t.Fatal(err)
	}
	return mac
}
