package secure

import (
	"encoding/json"
	"fmt"
	"os"
)

// DeviceStore is the agent's allowlist: paired client IDs and their public
// keys, persisted as JSON. Only paired devices can talk to the agent.
type DeviceStore struct {
	path    string
	devices map[string]string // client id → base64 public key
}

// LoadDevices reads the store; a missing file is an empty store.
func LoadDevices(path string) (*DeviceStore, error) {
	s := &DeviceStore{path: path, devices: map[string]string{}}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("secure: read devices: %w", err)
	}
	if err := json.Unmarshal(data, &s.devices); err != nil {
		return nil, fmt.Errorf("secure: devices file %s is corrupt", path)
	}
	return s, nil
}

// Add registers a paired device and persists the store.
func (s *DeviceStore) Add(clientID, pubB64 string) error {
	if _, err := DecodeKey(pubB64); err != nil {
		return err
	}
	s.devices[clientID] = pubB64
	data, err := json.MarshalIndent(s.devices, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(s.path, data, 0o600); err != nil {
		return fmt.Errorf("secure: write devices: %w", err)
	}
	return nil
}

// Get returns the public key of a paired device.
func (s *DeviceStore) Get(clientID string) (*[32]byte, bool) {
	pubB64, ok := s.devices[clientID]
	if !ok {
		return nil, false
	}
	k, err := DecodeKey(pubB64)
	if err != nil {
		return nil, false
	}
	return k, true
}

// Count reports how many devices are paired (for logging/UI).
func (s *DeviceStore) Count() int { return len(s.devices) }
