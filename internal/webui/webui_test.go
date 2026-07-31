package webui

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rudymertens2-ops/lockping-agent/internal/core"
	"github.com/rudymertens2-ops/lockping-agent/internal/gateway"
	"github.com/rudymertens2-ops/lockping-agent/internal/secure"
)

type fakeSession struct{ locked bool }

func (f *fakeSession) Locked(ctx context.Context) (bool, error)       { return f.locked, nil }
func (f *fakeSession) Lock(ctx context.Context) error                 { f.locked = true; return nil }
func (f *fakeSession) Watch(ctx context.Context, fn func(bool)) error { return nil }
func (f *fakeSession) Close() error                                   { return nil }

func newServer(t *testing.T) (*Server, *gateway.Gateway) {
	t.Helper()
	keys, _ := secure.GenerateKeys()
	devices, err := secure.LoadDevices(filepath.Join(t.TempDir(), "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	sess := &fakeSession{locked: true}
	c := core.New(sess, "test-pc", "linux", time.Now)
	gw := gateway.New(c, keys, "agent-1", "wss://test/ws", devices, time.Now)
	s, err := New(gw, sess, Options{Machine: "test-pc"})
	if err != nil {
		t.Fatal(err)
	}
	return s, gw
}

func doJSON(t *testing.T, handler http.Handler, method, path, token string, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Host = "127.0.0.1:41800"
	if token != "" {
		req.Header.Set("X-LockPing-Token", token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestStateAndPairFlow(t *testing.T) {
	s, gw := newServer(t)
	h := s.Handler()

	rec := doJSON(t, h, "GET", "/api/state", "", "")
	if rec.Code != 200 {
		t.Fatalf("state: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"machine":"test-pc"`) {
		t.Errorf("state mist machine: %s", rec.Body.String())
	}

	rec = doJSON(t, h, "POST", "/api/pair", s.csrfToken, "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "lockping:") {
		t.Fatalf("pair: %d %s", rec.Code, rec.Body.String())
	}
	if _, _, active := gw.Pairing(); !active {
		t.Error("pairing-window niet actief na POST /api/pair")
	}

	rec = doJSON(t, h, "GET", "/qr.png", "", "")
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "image/png" {
		t.Errorf("qr: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
}

func TestQRWithoutPairingIs404(t *testing.T) {
	s, _ := newServer(t)
	rec := doJSON(t, s.Handler(), "GET", "/qr.png", "", "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("qr zonder window: %d, verwacht 404", rec.Code)
	}
}

func TestMutationsRequireToken(t *testing.T) {
	s, _ := newServer(t)
	h := s.Handler()
	if rec := doJSON(t, h, "POST", "/api/pair", "", ""); rec.Code != http.StatusForbidden {
		t.Errorf("pair zonder token: %d, verwacht 403", rec.Code)
	}
	if rec := doJSON(t, h, "POST", "/api/unpair", "fout-token", `{"id":"x"}`); rec.Code != http.StatusForbidden {
		t.Errorf("unpair met fout token: %d, verwacht 403", rec.Code)
	}
}

func TestForeignHostIsRejected(t *testing.T) {
	s, _ := newServer(t)
	req := httptest.NewRequest("GET", "/api/state", nil)
	req.Host = "evil.example.com"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("vreemde Host: %d, verwacht 403 (DNS-rebinding)", rec.Code)
	}
}

func TestUnpairRemovesDevice(t *testing.T) {
	s, gw := newServer(t)
	keys, _ := secure.GenerateKeys()
	if err := gw.Devices().Add("phone-1", secure.EncodeKey(keys.Pub), ""); err != nil {
		t.Fatal(err)
	}

	rec := doJSON(t, s.Handler(), "POST", "/api/unpair", s.csrfToken, `{"id":"phone-1"}`)
	if rec.Code != 200 {
		t.Fatalf("unpair: %d %s", rec.Code, rec.Body.String())
	}
	if gw.Devices().Count() != 0 {
		t.Error("device niet verwijderd")
	}

	rec = doJSON(t, s.Handler(), "POST", "/api/unpair", s.csrfToken, `{"id":"phone-1"}`)
	if rec.Code != http.StatusNotFound {
		t.Errorf("unpair van onbekend device: %d, verwacht 404", rec.Code)
	}
}

type fakeAutostart struct {
	enabled   bool
	supported bool
}

func (f *fakeAutostart) Status() (bool, bool) { return f.enabled, f.supported }
func (f *fakeAutostart) Enable() error        { f.enabled = true; return nil }
func (f *fakeAutostart) Disable() error       { f.enabled = false; return nil }

func TestAutostartToggleAndStop(t *testing.T) {
	keys, _ := secure.GenerateKeys()
	devices, _ := secure.LoadDevices(filepath.Join(t.TempDir(), "devices.json"))
	sess := &fakeSession{}
	gw := gateway.New(core.New(sess, "pc", "linux", time.Now), keys, "a", "wss://x/ws", devices, time.Now)
	auto := &fakeAutostart{supported: true}
	stopped := false
	s, err := New(gw, sess, Options{
		Machine:   "pc",
		Version:   "9.9.9",
		Connected: func() bool { return true },
		Autostart: auto,
		Stop:      func() { stopped = true },
	})
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()

	rec := doJSON(t, h, "GET", "/api/state", "", "")
	body := rec.Body.String()
	for _, want := range []string{`"version":"9.9.9"`, `"relay_connected":true`, `"autostart":{"enabled":false}`} {
		if !strings.Contains(body, want) {
			t.Errorf("state mist %s: %s", want, body)
		}
	}

	if rec := doJSON(t, h, "POST", "/api/autostart", s.csrfToken, `{"enable":true}`); rec.Code != 200 {
		t.Fatalf("autostart aan: %d", rec.Code)
	}
	if !auto.enabled {
		t.Error("autostart niet ingeschakeld")
	}

	if rec := doJSON(t, h, "POST", "/api/stop", s.csrfToken, ""); rec.Code != 200 {
		t.Fatalf("stop: %d", rec.Code)
	}
	for i := 0; i < 100 && !stopped; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if !stopped {
		t.Error("stopfunctie niet aangeroepen")
	}

	if rec := doJSON(t, h, "POST", "/api/stop", "", ""); rec.Code != 403 {
		t.Errorf("stop zonder token: %d, verwacht 403", rec.Code)
	}
}

func TestPageEmbedsToken(t *testing.T) {
	s, _ := newServer(t)
	rec := doJSON(t, s.Handler(), "GET", "/", "", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), s.csrfToken) {
		t.Error("pagina bevat het CSRF-token niet")
	}
	var v map[string]any
	if json.Unmarshal(rec.Body.Bytes(), &v) == nil {
		t.Error("pagina lijkt JSON in plaats van HTML")
	}
}
