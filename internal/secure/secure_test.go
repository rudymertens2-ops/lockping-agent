package secure

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSealOpenRoundtrip(t *testing.T) {
	agent, _ := GenerateKeys()
	client, _ := GenerateKeys()

	sealed, err := Seal(`{"kind":"status_request"}`, client.Pub, agent)
	if err != nil {
		t.Fatal(err)
	}
	if !IsSealed(sealed) {
		t.Fatalf("sealed payload not recognized: %q", sealed[:8])
	}
	plain, ok := Open(sealed, agent.Pub, client)
	if !ok || plain != `{"kind":"status_request"}` {
		t.Fatalf("roundtrip failed: %q ok=%v", plain, ok)
	}
}

func TestOpenRejectsTamperingAndWrongPeer(t *testing.T) {
	agent, _ := GenerateKeys()
	client, _ := GenerateKeys()
	stranger, _ := GenerateKeys()

	sealed, _ := Seal("secret message", client.Pub, agent)

	if _, ok := Open(sealed, stranger.Pub, client); ok {
		t.Error("payload opened with wrong sender key")
	}
	if _, ok := Open(sealed, agent.Pub, stranger); ok {
		t.Error("stranger decrypted payload not meant for them")
	}
	tampered := sealed[:len(sealed)-4] + "AAAA"
	if _, ok := Open(tampered, agent.Pub, client); ok {
		t.Error("tampered payload accepted")
	}
	if _, ok := Open("e1:%%%", agent.Pub, client); ok {
		t.Error("garbage accepted")
	}
}

func TestKeyEncodingRejectsWrongSize(t *testing.T) {
	if _, err := DecodeKey(base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Error("short key accepted")
	}
	if _, err := DecodeKey("not base64!!"); err == nil {
		t.Error("invalid base64 accepted")
	}
}

func TestDeviceStoreRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	s, err := LoadDevices(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Count() != 0 {
		t.Fatalf("fresh store not empty")
	}

	keys, _ := GenerateKeys()
	if err := s.Add("phone-1", EncodeKey(keys.Pub)); err != nil {
		t.Fatal(err)
	}

	reloaded, err := LoadDevices(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reloaded.Get("phone-1")
	if !ok || *got != *keys.Pub {
		t.Error("device lost or key corrupted after reload")
	}
	if _, ok := reloaded.Get("stranger"); ok {
		t.Error("unknown device reported as paired")
	}
}

func TestDeviceStoreRejectsBadKey(t *testing.T) {
	s, _ := LoadDevices(filepath.Join(t.TempDir(), "d.json"))
	if err := s.Add("x", "bogus"); err == nil {
		t.Error("bogus key accepted into allowlist")
	}
}

func TestDeviceStoreRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	s, _ := LoadDevices(path)
	keys, _ := GenerateKeys()
	if err := s.Add("phone-1", EncodeKey(keys.Pub)); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove("phone-1"); err != nil {
		t.Fatal(err)
	}
	if s.Count() != 0 {
		t.Error("device niet verwijderd")
	}
	reloaded, _ := LoadDevices(path)
	if reloaded.Count() != 0 {
		t.Error("verwijdering niet gepersisteerd")
	}
	if err := s.Remove("ghost"); err == nil {
		t.Error("verwijderen van onbekend device gaf geen fout")
	}
}

func TestDeviceStoreMigratesLegacyFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	keys, _ := GenerateKeys()
	legacy := `{"phone-1": "` + EncodeKey(keys.Pub) + `"}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := LoadDevices(path)
	if err != nil {
		t.Fatalf("legacy formaat niet gemigreerd: %v", err)
	}
	got, ok := s.Get("phone-1")
	if !ok || *got != *keys.Pub {
		t.Error("gemigreerd device verloren of sleutel corrupt")
	}
}

func TestPairingWindowFlow(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	w, secretB64, err := NewWindow(now)
	if err != nil {
		t.Fatal(err)
	}
	if secretB64 == "" {
		t.Fatal("empty secret")
	}

	clientPub := "Y2xpZW50LXB1YmxpYy1rZXktMzItYnl0ZXMhISEhISE=" // any b64; MAC is over the string
	mac := clientMAC(t, secretB64, "pair_request", "phone-1", clientPub)

	if !w.VerifyRequest(now, "phone-1", clientPub, mac) {
		t.Fatal("valid pair_request rejected")
	}
	if w.VerifyRequest(now, "phone-2", clientPub, mac) {
		t.Error("MAC accepted for different client id")
	}
	if w.VerifyRequest(now.Add(WindowTTL+time.Second), "phone-1", clientPub, mac) {
		t.Error("expired window accepted")
	}
	w.Consume()
	if w.VerifyRequest(now, "phone-1", clientPub, mac) {
		t.Error("consumed window accepted a second pairing")
	}
}

func TestEncodePairCodeShape(t *testing.T) {
	code := EncodePairCode("ws://x/ws", "agent-1", "sec")
	if !strings.HasPrefix(code, "lockping:") {
		t.Errorf("unexpected prefix: %q", code)
	}
}

// clientMAC reimplements the client side of the HMAC so the test proves
// both directions agree on the format.
func clientMAC(t *testing.T, secretB64 string, parts ...string) string {
	t.Helper()
	secret, err := base64.RawURLEncoding.DecodeString(secretB64)
	if err != nil {
		t.Fatal(err)
	}
	w := &Window{secret: secret}
	return base64.StdEncoding.EncodeToString(w.mac(parts...))
}
