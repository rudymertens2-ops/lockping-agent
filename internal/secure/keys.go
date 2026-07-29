// Package secure holds the agent's crypto: X25519 keys, NaCl-box payload
// encryption, the paired-devices store and the pairing window.
package secure

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/nacl/box"
)

// Keys is an X25519 key pair for NaCl box.
type Keys struct {
	Pub  *[32]byte
	Priv *[32]byte
}

// GenerateKeys creates a fresh key pair.
func GenerateKeys() (Keys, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return Keys{}, fmt.Errorf("secure: generate keys: %w", err)
	}
	return Keys{Pub: pub, Priv: priv}, nil
}

// EncodeKey renders a key for storage/transport.
func EncodeKey(k *[32]byte) string {
	return base64.StdEncoding.EncodeToString(k[:])
}

// DecodeKey parses a base64 key and rejects wrong sizes.
func DecodeKey(s string) (*[32]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("secure: invalid key encoding")
	}
	var k [32]byte
	copy(k[:], raw)
	return &k, nil
}
