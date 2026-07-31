// Package relay maintains the agent's outbound WebSocket to the relay:
// hello-handshake, envelope receive/reply, reconnect with backoff.
package relay

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/rudymertens2-ops/lockping-agent/internal/secure"
)

// Handler turns an incoming envelope payload into an optional reply.
type Handler func(ctx context.Context, from, payload string) (reply string, ok bool)

// Client is one agent's connection to the relay.
type Client struct {
	url     string
	id      string
	keys    secure.Keys
	handle  Handler
	backoff backoff
	onState func(connected bool)
}

// OnState registreert een callback voor verbindingsstatus (voor de UI);
// aanroepen vóór Run.
func (c *Client) OnState(fn func(connected bool)) *Client {
	c.onState = fn
	return c
}

func (c *Client) setState(connected bool) {
	if c.onState != nil {
		c.onState(connected)
	}
}

// message covers every frame we exchange with the relay.
type message struct {
	Type     string `json:"type"`
	ID       string `json:"id,omitempty"`
	Role     string `json:"role,omitempty"`
	Pub      string `json:"pub,omitempty"`
	To       string `json:"to,omitempty"`
	From     string `json:"from,omitempty"`
	Payload  string `json:"payload,omitempty"`
	Code     string `json:"code,omitempty"`
	Nonce    string `json:"nonce,omitempty"`
	RelayPub string `json:"relay_pub,omitempty"`
	MAC      string `json:"mac,omitempty"`
}

// New builds a client for the given relay URL and agent identity; the keys
// answer the relay's possession challenge (docs/protocol.md § 1).
func New(url, id string, keys secure.Keys, handle Handler) *Client {
	return &Client{url: url, id: id, keys: keys, handle: handle, backoff: newBackoff()}
}

// Run keeps the connection alive until ctx is cancelled, reconnecting with
// exponential backoff (relay restarts and Cloud Run's 60-min cap are normal).
func (c *Client) Run(ctx context.Context) error {
	for {
		err := c.session(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		wait := c.backoff.next()
		log.Printf("relay: connection lost (%v), retrying in %s", err, wait)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

func (c *Client) session(ctx context.Context) error {
	conn, _, err := websocket.Dial(ctx, c.url, nil)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "bye")

	if err := c.handshake(ctx, conn); err != nil {
		return err
	}
	c.backoff.reset()
	c.setState(true)
	defer c.setState(false)
	log.Printf("relay: connected as %s", c.id)
	return c.serve(ctx, conn)
}

func (c *Client) handshake(ctx context.Context, conn *websocket.Conn) error {
	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	hello := message{Type: "hello", ID: c.id, Role: "agent", Pub: secure.EncodeKey(c.keys.Pub)}
	if err := wsjson.Write(hctx, conn, hello); err != nil {
		return fmt.Errorf("hello: %w", err)
	}
	var resp message
	if err := wsjson.Read(hctx, conn, &resp); err != nil {
		return fmt.Errorf("welcome: %w", err)
	}
	if resp.Type == "challenge" {
		if err := c.prove(hctx, conn, resp); err != nil {
			return err
		}
		if err := wsjson.Read(hctx, conn, &resp); err != nil {
			return fmt.Errorf("welcome na challenge: %w", err)
		}
	}
	if resp.Type != "welcome" {
		return fmt.Errorf("handshake refused: %s/%s", resp.Type, resp.Code)
	}
	return nil
}

// prove answers the relay's key-possession challenge.
func (c *Client) prove(ctx context.Context, conn *websocket.Conn, challenge message) error {
	mac, err := secure.ProveChallenge(challenge.Nonce, challenge.RelayPub, c.keys)
	if err != nil {
		return err
	}
	if err := wsjson.Write(ctx, conn, message{Type: "prove", MAC: mac}); err != nil {
		return fmt.Errorf("prove: %w", err)
	}
	return nil
}

func (c *Client) serve(ctx context.Context, conn *websocket.Conn) error {
	for {
		var in message
		if err := wsjson.Read(ctx, conn, &in); err != nil {
			return err
		}
		if in.Type != "envelope" {
			continue
		}
		reply, ok := c.handle(ctx, in.From, in.Payload)
		if !ok {
			continue
		}
		out := message{Type: "envelope", To: in.From, Payload: reply}
		if err := wsjson.Write(ctx, conn, out); err != nil {
			return err
		}
	}
}

// backoff is a minimal exponential backoff: 1s doubling to 30s max.
type backoff struct{ cur time.Duration }

func newBackoff() backoff { return backoff{cur: 0} }

func (b *backoff) next() time.Duration {
	if b.cur == 0 {
		b.cur = time.Second
	} else if b.cur < 30*time.Second {
		b.cur *= 2
		if b.cur > 30*time.Second {
			b.cur = 30 * time.Second
		}
	}
	return b.cur
}

func (b *backoff) reset() { b.cur = 0 }
