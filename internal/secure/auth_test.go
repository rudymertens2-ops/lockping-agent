package secure

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestProveChallengeMatchesSpec(t *testing.T) {
	agent, _ := GenerateKeys()
	relay, _ := GenerateKeys()
	nonce := base64.StdEncoding.EncodeToString(make([]byte, 32))

	got, err := ProveChallenge(nonce, EncodeKey(relay.Pub), agent)
	if err != nil {
		t.Fatal(err)
	}

	// Onafhankelijke berekening vanuit relay-perspectief: ECDH is
	// symmetrisch, dus relay-priv × agent-pub moet hetzelfde bewijs geven.
	shared, err := curve25519.X25519(relay.Priv[:], agent.Pub[:])
	if err != nil {
		t.Fatal(err)
	}
	key := sha256.Sum256(append([]byte("lockping-relay-auth"), shared...))
	mac := hmac.New(sha256.New, key[:])
	rawNonce, _ := base64.StdEncoding.DecodeString(nonce)
	mac.Write(rawNonce)
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	if got != want {
		t.Errorf("bewijs komt niet overeen met relay-berekening")
	}
}

func TestProveChallengeRejectsBadInput(t *testing.T) {
	agent, _ := GenerateKeys()
	relay, _ := GenerateKeys()
	if _, err := ProveChallenge("geen-b64!", EncodeKey(relay.Pub), agent); err == nil {
		t.Error("kapotte nonce geaccepteerd")
	}
	if _, err := ProveChallenge("AAAA", "kapot", agent); err == nil {
		t.Error("kapotte relay-sleutel geaccepteerd")
	}
}
