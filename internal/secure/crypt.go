package secure

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/nacl/box"
)

// sealedPrefix versions the on-the-wire format: "e1:" + base64(nonce‖box).
const sealedPrefix = "e1:"

const nonceSize = 24

// IsSealed reports whether an envelope payload is E2E ciphertext.
func IsSealed(payload string) bool {
	return strings.HasPrefix(payload, sealedPrefix)
}

// Seal encrypts-and-authenticates plain for peerPub.
func Seal(plain string, peerPub *[32]byte, keys Keys) (string, error) {
	var nonce [nonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("secure: nonce: %w", err)
	}
	out := box.Seal(nonce[:], []byte(plain), &nonce, peerPub, keys.Priv)
	return sealedPrefix + base64.StdEncoding.EncodeToString(out), nil
}

// Open decrypts a sealed payload from peerPub; ok=false on any mismatch
// (wrong sender, tampering, truncation) without distinguishing why.
func Open(sealed string, peerPub *[32]byte, keys Keys) (string, bool) {
	if !IsSealed(sealed) {
		return "", false
	}
	raw, err := base64.StdEncoding.DecodeString(sealed[len(sealedPrefix):])
	if err != nil || len(raw) < nonceSize {
		return "", false
	}
	var nonce [nonceSize]byte
	copy(nonce[:], raw[:nonceSize])
	plain, ok := box.Open(nil, raw[nonceSize:], &nonce, peerPub, keys.Priv)
	if !ok {
		return "", false
	}
	return string(plain), true
}
