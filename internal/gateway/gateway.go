// Package gateway is the agent's security boundary between the relay and
// the core: only sealed payloads from paired devices reach the core, plus
// exactly one plaintext exception — a valid pair_request while a pairing
// window is open. Everything else is silently ignored.
//
// Concurrency note: relay.Client delivers messages sequentially on one
// connection, so Gateway needs no locking.
package gateway

import (
	"context"
	"log"
	"time"

	"github.com/rudymertens2-ops/lockping-agent/internal/core"
	"github.com/rudymertens2-ops/lockping-agent/internal/secure"
	"github.com/rudymertens2-ops/lockping-agent/internal/wire"
)

// Gateway guards one agent's message handling.
type Gateway struct {
	core    *core.Core
	keys    secure.Keys
	agentID string
	devices *secure.DeviceStore
	window  *secure.Window // nil = no pairing possible
	now     func() time.Time
}

// New wires a gateway; window may be nil when pairing is closed.
func New(c *core.Core, keys secure.Keys, agentID string, devices *secure.DeviceStore,
	window *secure.Window, now func() time.Time) *Gateway {
	return &Gateway{core: c, keys: keys, agentID: agentID, devices: devices, window: window, now: now}
}

// Handle implements relay.Handler.
func (g *Gateway) Handle(ctx context.Context, from, payload string) (string, bool) {
	if secure.IsSealed(payload) {
		return g.handleSealed(ctx, from, payload)
	}
	return g.handlePairRequest(from, payload)
}

func (g *Gateway) handleSealed(ctx context.Context, from, payload string) (string, bool) {
	peerPub, paired := g.devices.Get(from)
	if !paired {
		log.Printf("gateway: sealed payload from unpaired %s ignored", from)
		return "", false
	}
	plain, ok := secure.Open(payload, peerPub, g.keys)
	if !ok {
		log.Printf("gateway: undecryptable payload from %s ignored", from)
		return "", false
	}
	in, err := wire.Decode(plain)
	if err != nil {
		return "", false
	}
	out, ok := g.core.Handle(ctx, in)
	if !ok {
		return "", false
	}
	return g.sealReply(out, peerPub)
}

func (g *Gateway) handlePairRequest(from, payload string) (string, bool) {
	in, err := wire.Decode(payload)
	if err != nil || in.Kind != wire.KindPairRequest {
		return "", false
	}
	if !g.window.VerifyRequest(g.now(), from, in.PubKey, in.MAC) {
		log.Printf("gateway: pair_request from %s rejected", from)
		return "", false
	}
	if err := g.devices.Add(from, in.PubKey); err != nil {
		log.Printf("gateway: could not store paired device: %v", err)
		return "", false
	}
	g.window.Consume()
	log.Printf("gateway: paired new device %s", from)

	agentPubB64 := secure.EncodeKey(g.keys.Pub)
	accept := wire.Payload{
		Kind:   wire.KindPairAccept,
		PubKey: agentPubB64,
		MAC:    g.window.AcceptMAC(g.agentID, agentPubB64),
	}
	enc, err := wire.Encode(accept)
	if err != nil {
		return "", false
	}
	return enc, true
}

func (g *Gateway) sealReply(out wire.Payload, peerPub *[32]byte) (string, bool) {
	enc, err := wire.Encode(out)
	if err != nil {
		return "", false
	}
	sealed, err := secure.Seal(enc, peerPub, g.keys)
	if err != nil {
		return "", false
	}
	return sealed, true
}
