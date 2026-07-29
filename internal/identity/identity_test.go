package identity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestLoadCreatesAndReturnsStableIdentity(t *testing.T) {
	dir := t.TempDir()

	first, err := Load(dir)
	if err != nil {
		t.Fatalf("first Load: %v", err)
	}
	if !uuidRe.MatchString(first.AgentID) {
		t.Fatalf("not a v4 UUID: %q", first.AgentID)
	}
	if first.Keys.Pub == nil || first.Keys.Priv == nil {
		t.Fatal("no key pair generated")
	}

	second, err := Load(dir)
	if err != nil {
		t.Fatalf("second Load: %v", err)
	}
	if second.AgentID != first.AgentID {
		t.Errorf("ID changed between loads")
	}
	if *second.Keys.Pub != *first.Keys.Pub {
		t.Errorf("key pair changed between loads")
	}
}

func TestLoadUpgradesKeylessFileKeepingID(t *testing.T) {
	dir := t.TempDir()
	old, _ := json.Marshal(map[string]string{"agent_id": "11111111-2222-4333-8444-555555555555"})
	if err := os.WriteFile(filepath.Join(dir, "agent.json"), old, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := Load(dir)
	if err != nil {
		t.Fatalf("Load on keyless file: %v", err)
	}
	if got.AgentID != "11111111-2222-4333-8444-555555555555" {
		t.Errorf("agent ID not preserved on upgrade: %q", got.AgentID)
	}
	if got.Keys.Pub == nil {
		t.Error("no keys added on upgrade")
	}
}

func TestLoadRefusesCorruptFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "agent.json"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Error("corrupt identity file was silently accepted")
	}
}

func TestIdentityFileIsPrivate(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("agent.json mode = %o, want 600 (contains private key)", perm)
	}
}
