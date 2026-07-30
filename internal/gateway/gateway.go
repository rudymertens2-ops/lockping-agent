// Package gateway is the agent's security boundary between the relay and
// the core: only sealed payloads from paired devices reach the core, plus
// exactly one plaintext exception — a valid pair_request while a pairing
// window is open. Everything else is silently ignored.
//
// Concurrency: relay.Client delivers messages sequentially, but the config
// UI opens pairing windows and removes devices from other goroutines; the
// window is therefore mutex-guarded (the DeviceStore guards itself).
package gateway

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/rudymertens2-ops/lockping-agent/internal/core"
	"github.com/rudymertens2-ops/lockping-agent/internal/secure"
	"github.com/rudymertens2-ops/lockping-agent/internal/wire"
)

// Gateway guards one agent's message handling.
type Gateway struct {
	core     *core.Core
	keys     secure.Keys
	agentID  string
	relayURL string
	devices  *secure.DeviceStore
	now      func() time.Time

	mu      sync.Mutex
	window  *secure.Window
	code    string
	expires time.Time
}

// New wires a gateway; pairing windows worden geopend via OpenPairing.
func New(c *core.Core, keys secure.Keys, agentID, relayURL string,
	devices *secure.DeviceStore, now func() time.Time) *Gateway {
	return &Gateway{core: c, keys: keys, agentID: agentID, relayURL: relayURL,
		devices: devices, now: now}
}

// OpenPairing opent een vers (eenmalig, 5-min) pairing-window en geeft de
// code terug; een eventueel openstaand window vervalt.
func (g *Gateway) OpenPairing() (string, error) {
	window, secretB64, err := secure.NewWindow(g.now())
	if err != nil {
		return "", err
	}
	code := secure.EncodePairCode(g.relayURL, g.agentID, secretB64)
	g.mu.Lock()
	g.window = window
	g.code = code
	g.expires = g.now().Add(secure.WindowTTL)
	g.mu.Unlock()
	return code, nil
}

// Pairing geeft de actieve code en resterende geldigheid (voor de UI).
func (g *Gateway) Pairing() (code string, remaining time.Duration, active bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.window == nil {
		return "", 0, false
	}
	remaining = g.expires.Sub(g.now())
	if remaining <= 0 {
		return "", 0, false
	}
	return g.code, remaining, true
}

// Devices exposes the allowlist (voor de UI: lijst + ontkoppelen).
func (g *Gateway) Devices() *secure.DeviceStore { return g.devices }

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

	g.mu.Lock()
	window := g.window
	g.mu.Unlock()
	if !window.VerifyRequest(g.now(), from, in.PubKey, in.MAC) {
		log.Printf("gateway: pair_request from %s rejected", from)
		return "", false
	}
	if err := g.devices.Add(from, in.PubKey); err != nil {
		log.Printf("gateway: could not store paired device: %v", err)
		return "", false
	}
	window.Consume()
	log.Printf("gateway: paired new device %s", from)

	agentPubB64 := secure.EncodeKey(g.keys.Pub)
	accept := wire.Payload{
		Kind:   wire.KindPairAccept,
		PubKey: agentPubB64,
		MAC:    window.AcceptMAC(g.agentID, agentPubB64),
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
