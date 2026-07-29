package secure

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Window is one open pairing opportunity: a one-time secret with a TTL.
// The secret travels out-of-band (QR/terminal); over the wire both sides
// only prove possession via HMAC (docs/protocol.md § 2).
type Window struct {
	secret  []byte
	expires time.Time
	used    bool
}

// WindowTTL is how long a pairing code stays valid.
const WindowTTL = 5 * time.Minute

// NewWindow opens a pairing window and returns it with the base64 secret.
func NewWindow(now time.Time) (*Window, string, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, "", fmt.Errorf("secure: pairing secret: %w", err)
	}
	w := &Window{secret: secret, expires: now.Add(WindowTTL)}
	return w, base64.RawURLEncoding.EncodeToString(secret), nil
}

// VerifyRequest checks a pair_request: window open, unused, MAC valid.
func (w *Window) VerifyRequest(now time.Time, clientID, clientPubB64, macB64 string) bool {
	if w == nil || w.used || now.After(w.expires) {
		return false
	}
	want := w.mac("pair_request", clientID, clientPubB64)
	got, err := base64.StdEncoding.DecodeString(macB64)
	if err != nil {
		return false
	}
	return hmac.Equal(want, got)
}

// AcceptMAC authenticates the agent's pair_accept towards the client.
func (w *Window) AcceptMAC(agentID, agentPubB64 string) string {
	return base64.StdEncoding.EncodeToString(w.mac("pair_accept", agentID, agentPubB64))
}

// Consume marks the one-time window as used.
func (w *Window) Consume() { w.used = true }

func (w *Window) mac(parts ...string) []byte {
	h := hmac.New(sha256.New, w.secret)
	h.Write([]byte(strings.Join(parts, "\n")))
	return h.Sum(nil)
}

// RequestMAC computes the client-side proof for a pair_request. Lives here
// so every client implementation (tests, smoke scripts, app) agrees on the
// exact construction.
func RequestMAC(secretB64, clientID, clientPubB64 string) (string, error) {
	w, err := windowFromSecret(secretB64)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(w.mac("pair_request", clientID, clientPubB64)), nil
}

// VerifyAcceptMAC lets the client authenticate the agent's pair_accept.
func VerifyAcceptMAC(secretB64, agentID, agentPubB64, macB64 string) bool {
	w, err := windowFromSecret(secretB64)
	if err != nil {
		return false
	}
	got, err := base64.StdEncoding.DecodeString(macB64)
	if err != nil {
		return false
	}
	return hmac.Equal(w.mac("pair_accept", agentID, agentPubB64), got)
}

func windowFromSecret(secretB64 string) (*Window, error) {
	secret, err := base64.RawURLEncoding.DecodeString(secretB64)
	if err != nil {
		return nil, fmt.Errorf("secure: bad pairing secret encoding")
	}
	return &Window{secret: secret}, nil
}

// pairCode is what the QR/terminal code carries.
type pairCode struct {
	V      int    `json:"v"`
	Relay  string `json:"relay"`
	Agent  string `json:"agent"`
	Secret string `json:"secret"`
}

// EncodePairCode builds the out-of-band pairing code string.
func EncodePairCode(relayURL, agentID, secretB64 string) string {
	data, _ := json.Marshal(pairCode{V: 1, Relay: relayURL, Agent: agentID, Secret: secretB64})
	return "lockping:" + base64.RawURLEncoding.EncodeToString(data)
}
