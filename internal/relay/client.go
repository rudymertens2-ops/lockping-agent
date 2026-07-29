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
)

// Handler turns an incoming envelope payload into an optional reply.
type Handler func(ctx context.Context, from, payload string) (reply string, ok bool)

// Client is one agent's connection to the relay.
type Client struct {
	url     string
	id      string
	handle  Handler
	backoff backoff
}

// message covers every frame we exchange with the relay.
type message struct {
	Type    string `json:"type"`
	ID      string `json:"id,omitempty"`
	Role    string `json:"role,omitempty"`
	To      string `json:"to,omitempty"`
	From    string `json:"from,omitempty"`
	Payload string `json:"payload,omitempty"`
	Code    string `json:"code,omitempty"`
}

// New builds a client for the given relay URL and agent ID.
func New(url, id string, handle Handler) *Client {
	return &Client{url: url, id: id, handle: handle, backoff: newBackoff()}
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
	log.Printf("relay: connected as %s", c.id)
	return c.serve(ctx, conn)
}

func (c *Client) handshake(ctx context.Context, conn *websocket.Conn) error {
	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := wsjson.Write(hctx, conn, message{Type: "hello", ID: c.id, Role: "agent"}); err != nil {
		return fmt.Errorf("hello: %w", err)
	}
	var resp message
	if err := wsjson.Read(hctx, conn, &resp); err != nil {
		return fmt.Errorf("welcome: %w", err)
	}
	if resp.Type != "welcome" {
		return fmt.Errorf("handshake refused: %s/%s", resp.Type, resp.Code)
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
