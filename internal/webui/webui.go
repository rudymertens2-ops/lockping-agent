// Package webui is de mini-config-UI van de agent: een webpagina op
// uitsluitend 127.0.0.1 met status, QR-pairing en devicebeheer. Draait in
// hetzelfde proces als de relay-verbinding, dus pairing-windows openen
// altijd in de agent die écht verbonden is.
package webui

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/rudymertens2-ops/lockping-agent/internal/gateway"
	"github.com/rudymertens2-ops/lockping-agent/internal/session"
)

//go:embed page.html
var pageHTML []byte

//go:embed logo.png
var logoPNG []byte

// Server serveert de config-UI.
type Server struct {
	gw      *gateway.Gateway
	sess    session.Controller
	machine string
	// csrfToken bindt muterende verzoeken aan een pagina die wij zelf
	// geserveerd hebben (verdediging tegen cross-site POSTs naar localhost).
	csrfToken string
}

// New bouwt de server; het token is per proces-start vers.
func New(gw *gateway.Gateway, sess session.Controller, machine string) (*Server, error) {
	tok := make([]byte, 16)
	if _, err := rand.Read(tok); err != nil {
		return nil, fmt.Errorf("webui: token: %w", err)
	}
	return &Server{gw: gw, sess: sess, machine: machine, csrfToken: hex.EncodeToString(tok)}, nil
}

// Start luistert op 127.0.0.1:port tot ctx eindigt.
func (s *Server) Start(ctx context.Context, port int) error {
	srv := &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", port),
		Handler: s.Handler(),
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	log.Printf("webui: instellingen op http://%s/", srv.Addr)
	err := srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// Handler is apart zodat tests hem via httptest kunnen aanspreken.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.page)
	mux.HandleFunc("GET /logo.png", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(logoPNG)
	})
	mux.HandleFunc("GET /api/state", s.state)
	mux.HandleFunc("GET /qr.png", s.qr)
	mux.HandleFunc("POST /api/pair", s.guarded(s.pair))
	mux.HandleFunc("POST /api/unpair", s.guarded(s.unpair))
	return s.localOnly(mux)
}

/* ---- beveiliging ---- */

// localOnly weert alles wat niet als 127.0.0.1/localhost binnenkomt
// (o.a. DNS-rebinding: dan klopt de Host-header niet).
func (s *Server) localOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(r.Host); err == nil {
			host = h
		}
		if host != "127.0.0.1" && host != "localhost" {
			http.Error(w, "alleen lokaal", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// guarded eist het CSRF-token dat alleen onze eigen pagina kent.
func (s *Server) guarded(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-LockPing-Token") != s.csrfToken {
			http.Error(w, "token ontbreekt of klopt niet", http.StatusForbidden)
			return
		}
		fn(w, r)
	}
}

/* ---- endpoints ---- */

func (s *Server) page(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body := strings.Replace(string(pageHTML), "__TOKEN__", s.csrfToken, 1)
	_, _ = w.Write([]byte(body))
}

type stateResponse struct {
	Machine string       `json:"machine"`
	Locked  *bool        `json:"locked"`
	Devices []deviceJSON `json:"devices"`
	Pairing *pairingJSON `json:"pairing"`
}

type deviceJSON struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	PairedAt string `json:"paired_at"`
}

type pairingJSON struct {
	Code      string `json:"code"`
	ExpiresIn int    `json:"expires_in"`
}

func (s *Server) state(w http.ResponseWriter, r *http.Request) {
	resp := stateResponse{Machine: s.machine, Devices: []deviceJSON{}}
	if locked, err := s.sess.Locked(r.Context()); err == nil {
		resp.Locked = &locked
	}
	for _, d := range s.gw.Devices().List() {
		when := ""
		if !d.PairedAt.IsZero() {
			when = d.PairedAt.Format("2006-01-02 15:04")
		}
		resp.Devices = append(resp.Devices, deviceJSON{ID: d.ID, Name: d.Name, PairedAt: when})
	}
	if code, remaining, active := s.gw.Pairing(); active {
		resp.Pairing = &pairingJSON{Code: code, ExpiresIn: int(remaining.Seconds())}
	}
	writeJSON(w, resp)
}

func (s *Server) pair(w http.ResponseWriter, _ *http.Request) {
	code, err := s.gw.OpenPairing()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"code": code})
}

func (s *Server) unpair(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" {
		http.Error(w, "id ontbreekt", http.StatusBadRequest)
		return
	}
	if err := s.gw.Devices().Remove(body.ID); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// qr rendert uitsluitend de ACTIEVE pairing-code (geen vrije invoer).
func (s *Server) qr(w http.ResponseWriter, _ *http.Request) {
	code, _, active := s.gw.Pairing()
	if !active {
		http.Error(w, "geen actieve pairing", http.StatusNotFound)
		return
	}
	png, err := qrcode.Encode(code, qrcode.Medium, 260)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
