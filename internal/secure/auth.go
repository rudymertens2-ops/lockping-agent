package secure

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// authContext bindt de challenge-HMAC aan dit protocol (docs/protocol.md § 1).
const authContext = "lockping-relay-auth"

// ProveChallenge beantwoordt de sleutel-challenge van het relay:
// HMAC-SHA256(SHA256(context ‖ X25519(priv, relay_pub)), nonce).
func ProveChallenge(nonceB64, relayPubB64 string, keys Keys) (string, error) {
	relayPub, err := DecodeKey(relayPubB64)
	if err != nil {
		return "", fmt.Errorf("secure: relay-sleutel: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return "", fmt.Errorf("secure: challenge-nonce: %w", err)
	}
	shared, err := curve25519.X25519(keys.Priv[:], relayPub[:])
	if err != nil {
		return "", fmt.Errorf("secure: ECDH: %w", err)
	}
	key := sha256.Sum256(append([]byte(authContext), shared...))
	mac := hmac.New(sha256.New, key[:])
	mac.Write(nonce)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}
