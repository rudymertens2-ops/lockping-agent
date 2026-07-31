package secure

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"
)

// DeviceStore is de allowlist van de agent: gepairde client-ids met hun
// publieke sleutel. Thread-safe: de relay-lus en de config-UI gebruiken
// hem tegelijk.
type DeviceStore struct {
	mu      sync.Mutex
	path    string
	devices map[string]DeviceInfo
}

// DeviceInfo is wat we per gepaird device bewaren (en in de UI tonen).
type DeviceInfo struct {
	ID       string    `json:"-"`
	Pub      string    `json:"pub"`
	Name     string    `json:"name,omitempty"`
	PairedAt time.Time `json:"paired_at"`
}

// LoadDevices leest de store; een ontbrekend bestand is een lege store.
// Het oude formaat (plat id→pubkey) wordt stil gemigreerd.
func LoadDevices(path string) (*DeviceStore, error) {
	s := &DeviceStore{path: path, devices: map[string]DeviceInfo{}}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("secure: read devices: %w", err)
	}
	if err := json.Unmarshal(data, &s.devices); err == nil {
		return s, nil
	}
	var legacy map[string]string
	if err := json.Unmarshal(data, &legacy); err != nil {
		return nil, fmt.Errorf("secure: devices file %s is corrupt", path)
	}
	for id, pub := range legacy {
		s.devices[id] = DeviceInfo{Pub: pub}
	}
	return s, nil
}

// Add registreert een gepaird device en persisteert de store.
func (s *DeviceStore) Add(clientID, pubB64, name string) error {
	if _, err := DecodeKey(pubB64); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices[clientID] = DeviceInfo{Pub: pubB64, Name: name, PairedAt: time.Now()}
	return s.persistLocked()
}

// Remove ontkoppelt een device.
func (s *DeviceStore) Remove(clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.devices[clientID]; !ok {
		return fmt.Errorf("secure: onbekend device %q", clientID)
	}
	delete(s.devices, clientID)
	return s.persistLocked()
}

// Get geeft de publieke sleutel van een gepaird device.
func (s *DeviceStore) Get(clientID string) (*[32]byte, bool) {
	s.mu.Lock()
	info, ok := s.devices[clientID]
	s.mu.Unlock()
	if !ok {
		return nil, false
	}
	k, err := DecodeKey(info.Pub)
	if err != nil {
		return nil, false
	}
	return k, true
}

// List geeft alle devices, oudste eerst (voor de UI).
func (s *DeviceStore) List() []DeviceInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]DeviceInfo, 0, len(s.devices))
	for id, info := range s.devices {
		info.ID = id
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PairedAt.Before(out[j].PairedAt) })
	return out
}

// Count telt de gepairde devices.
func (s *DeviceStore) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.devices)
}

func (s *DeviceStore) persistLocked() error {
	data, err := json.MarshalIndent(s.devices, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(s.path, data, 0o600); err != nil {
		return fmt.Errorf("secure: write devices: %w", err)
	}
	return nil
}
