// Package wire defines the JSON payloads that travel inside relay
// envelopes. Dev-status: payloads are plaintext JSON until the pairing
// increment wraps them in E2E encryption (docs/protocol.md § 2-3).
package wire

import "encoding/json"

// Kinds of payloads, per docs/protocol.md § 2-3.
const (
	KindStatusRequest = "status_request"
	KindStatus        = "status"
	KindLock          = "lock"
	KindLockResult    = "lock_result"
	KindPairRequest   = "pair_request"
	KindPairAccept    = "pair_accept"
)

// Payload is the single message shape; unused fields stay empty per kind.
type Payload struct {
	Kind    string `json:"kind"`
	Nonce   string `json:"nonce,omitempty"`
	TS      int64  `json:"ts,omitempty"`
	Locked  *bool  `json:"locked,omitempty"`
	Machine string `json:"machine,omitempty"`
	OS      string `json:"os,omitempty"`
	OK      *bool  `json:"ok,omitempty"`
	Error   string `json:"error,omitempty"`
	PubKey  string `json:"pub_key,omitempty"`
	MAC     string `json:"mac,omitempty"`
}

// Decode parses a payload string from an envelope.
func Decode(s string) (Payload, error) {
	var p Payload
	err := json.Unmarshal([]byte(s), &p)
	return p, err
}

// Encode serializes a payload for an envelope.
func Encode(p Payload) (string, error) {
	b, err := json.Marshal(p)
	return string(b), err
}

// Bool is a convenience for the *bool fields.
func Bool(v bool) *bool { return &v }
