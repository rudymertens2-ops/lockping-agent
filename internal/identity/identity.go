// Package identity persists the agent's stable ID and X25519 key pair in
// agent.json (0600 — the private key never leaves this file).
package identity

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rudymertens2-ops/lockping-agent/internal/secure"
)

// Identity is the agent's stable self.
type Identity struct {
	AgentID string
	Keys    secure.Keys
}

type identityFile struct {
	AgentID string `json:"agent_id"`
	BoxPub  string `json:"box_pub,omitempty"`
	BoxPriv string `json:"box_priv,omitempty"`
}

// Load reads dir/agent.json, creating it on first run. A pre-key file
// (older increments) gets its key pair added while keeping the ID.
func Load(dir string) (Identity, error) {
	path := filepath.Join(dir, "agent.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return create(dir, path, "")
	}
	if err != nil {
		return Identity{}, fmt.Errorf("identity: read %s: %w", path, err)
	}

	var f identityFile
	if err := json.Unmarshal(data, &f); err != nil || f.AgentID == "" {
		return Identity{}, fmt.Errorf("identity: %s is corrupt, refusing to overwrite", path)
	}
	if f.BoxPub == "" || f.BoxPriv == "" {
		return create(dir, path, f.AgentID)
	}
	return decode(f)
}

func decode(f identityFile) (Identity, error) {
	pub, err := secure.DecodeKey(f.BoxPub)
	if err != nil {
		return Identity{}, fmt.Errorf("identity: corrupt public key")
	}
	priv, err := secure.DecodeKey(f.BoxPriv)
	if err != nil {
		return Identity{}, fmt.Errorf("identity: corrupt private key")
	}
	return Identity{AgentID: f.AgentID, Keys: secure.Keys{Pub: pub, Priv: priv}}, nil
}

// create writes a fresh identity; keepID preserves an existing agent ID.
func create(dir, path, keepID string) (Identity, error) {
	id := keepID
	if id == "" {
		var err error
		if id, err = newUUID(); err != nil {
			return Identity{}, err
		}
	}
	keys, err := secure.GenerateKeys()
	if err != nil {
		return Identity{}, err
	}
	f := identityFile{
		AgentID: id,
		BoxPub:  secure.EncodeKey(keys.Pub),
		BoxPriv: secure.EncodeKey(keys.Priv),
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return Identity{}, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Identity{}, fmt.Errorf("identity: create config dir: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return Identity{}, fmt.Errorf("identity: write %s: %w", path, err)
	}
	return Identity{AgentID: id, Keys: keys}, nil
}

// newUUID generates a random v4 UUID without external dependencies.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("identity: entropy: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
