// Package server is the auditor's online half: it serves the published tree
// byte-for-byte, re-signs the status list on schedule with the delegated
// status key, and runs the two write operations that arrive from outside —
// accept-order and the subject's right of reply. It never holds the
// auditor's own key, so it can refresh freshness but cannot mint, alter,
// or revoke an attestation.
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"crypto/ed25519"

	"onym-audit/audit"
	"onym-audit/canon"
	"onym-audit/sig"
	"onym-audit/site"
)

// Bounds on inbound documents and on the order inbox.
const (
	MaxOrderBytes    = 64 << 10
	MaxResponseBytes = 16 << 10
	MaxInbox         = 1000
	MaxScopeText     = 8 << 10
)

// Server holds the online state.
type Server struct {
	Root      string
	Inbox     string
	Config    *site.Config
	StatusKey ed25519.PrivateKey
	Now       func() time.Time
	Hub       http.Handler // hosted auditors and the studio API, when enabled
	HubResign func()       // refreshes every hosted auditor's status list

	mu      sync.Mutex // serializes tree writes and re-signing
	limiter *limiter
}

// New validates the tree once and returns a ready server.
func New(root, inbox string, c *site.Config, statusKey ed25519.PrivateKey) (*Server, error) {
	s := &Server{Root: root, Inbox: inbox, Config: c, StatusKey: statusKey, Now: time.Now, limiter: newLimiter(1, 20)}
	if err := s.Resign(); err != nil {
		return nil, err
	}
	return s, nil
}

// Resign rebuilds and re-signs status.json.
func (s *Server) Resign() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return site.ResignStatus(s.Root, s.Config, s.StatusKey, s.Now())
}

// Loop re-signs every interval until stop closes. Failures are logged
// without request data (there is none) and retried at the next tick.
func (s *Server) Loop(interval time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if err := s.Resign(); err != nil {
				log.Printf("status re-sign failed: %v", err)
			}
			if s.HubResign != nil {
				s.HubResign()
			}
		}
	}
}

// Handler routes requests. Paths are relative to the site root (a reverse
// proxy strips any public prefix).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /orders", s.postOrder)
	mux.HandleFunc("POST /responses", s.postResponse)
	mux.HandleFunc("GET /", s.static)
	if s.Hub != nil {
		// Method-qualified, so they are more specific than "GET /".
		for _, p := range []string{"GET /hub/api/", "POST /hub/api/", "GET /a/", "POST /a/"} {
			mux.Handle(p, s.Hub)
		}
	}
	return mux
}

func jsonReply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	b, _ := json.Marshal(v)
	w.Write(append(b, '\n'))
}

func fail(w http.ResponseWriter, code int, errCode string, err error) {
	jsonReply(w, code, map[string]string{"error": errCode, "detail": err.Error()})
}

// static serves files exactly as stored: no directory listings, no
// re-serialization, no cookies.
func (s *Server) static(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(filepath.Clean("/"+r.URL.Path), "/")
	if p == "" || p == "." {
		p = "index.html"
	}
	if strings.HasPrefix(filepath.Base(p), ".") {
		http.NotFound(w, r)
		return
	}
	full := filepath.Join(s.Root, filepath.FromSlash(p))
	fi, err := os.Stat(full)
	if err == nil && fi.IsDir() {
		// A language directory serves its index page, as nginx does.
		if !strings.HasSuffix(r.URL.Path, "/") {
			http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
			return
		}
		full = filepath.Join(full, "index.html")
		fi, err = os.Stat(full)
	}
	if err != nil || fi.IsDir() {
		http.NotFound(w, r)
		return
	}
	switch filepath.Ext(p) {
	case ".json":
		w.Header().Set("Content-Type", "application/json")
	case ".sig", ".md":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	if p == site.StatusPath {
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeFile(w, r, full)
}

func (s *Server) readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	if !s.limiter.allow() {
		fail(w, http.StatusTooManyRequests, "rate_limited", errors.New("try again later"))
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil || int64(len(body)) > limit {
		fail(w, http.StatusRequestEntityTooLarge, "oversize", fmt.Errorf("at most %d bytes", limit))
		return nil, false
	}
	return body, true
}

// postOrder is accept-order's intake (Audit.md §6): a well-formed order
// signed by its subject and sponsor is queued for the auditor's review.
// Queuing is not acceptance; the auditor countersigns offline.
//
// The body is either the bare signed order, or an envelope
// {"order": …, "scopeText": …, "contact": …} for a subject that cannot host
// its own scope document: the order then pins scopes/order-<orderId>.md on
// this auditor's base URI, and scopeText must hash to that pin. The contact
// is kept with the queued order and never published.
func (s *Server) postOrder(w http.ResponseWriter, r *http.Request) {
	body, ok := s.readBody(w, r, MaxOrderBytes)
	if !ok {
		return
	}
	orderBytes, scopeText, contact, err := unwrapOrder(body)
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, "order_invalid", err)
		return
	}
	o, err := audit.ParseOrderRequest(orderBytes, s.Config.ComponentID)
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, "order_invalid", err)
		return
	}
	if scopeText != "" {
		want := s.Config.BaseURI + "scopes/order-" + o.OrderID + ".md"
		if o.Scope.URI != want {
			fail(w, http.StatusUnprocessableEntity, "order_invalid", fmt.Errorf("an order carrying its scope text pins %s", want))
			return
		}
		if sig.Digest([]byte(scopeText)) != o.Scope.Digest {
			fail(w, http.StatusUnprocessableEntity, "order_invalid", errors.New("scopeText does not hash to the order's scope digest"))
			return
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if n, _ := os.ReadDir(s.Inbox); len(n) >= MaxInbox {
		fail(w, http.StatusServiceUnavailable, "inbox_full", errors.New("order inbox is full; use the manifest contact"))
		return
	}
	dir := filepath.Join(s.Inbox, o.OrderID)
	if prev, err := os.ReadFile(filepath.Join(dir, "order.json")); err == nil {
		if string(prev) != string(orderBytes) {
			fail(w, http.StatusConflict, "order_conflict", errors.New("a different order with this id is already queued"))
			return
		}
	} else {
		meta, _ := json.Marshal(map[string]string{"contact": contact, "receivedAt": sig.FormatTime(s.Now())})
		for name, b := range map[string][]byte{"order.json": orderBytes, "scope.md": []byte(scopeText), "meta.json": meta} {
			if name == "scope.md" && scopeText == "" {
				continue
			}
			if err := site.WriteAtomic(filepath.Join(dir, name), b); err != nil {
				fail(w, http.StatusInternalServerError, "internal", errors.New("could not queue order"))
				return
			}
		}
	}
	jsonReply(w, http.StatusAccepted, map[string]string{"orderId": o.OrderID, "state": "queued-for-review", "digest": sig.Digest(orderBytes)})
}

var contactRE = regexp.MustCompile(`^mailto:[^\s@<>()",;:]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$`)

// unwrapOrder returns the canonical order bytes and, for an envelope, the
// scope text and contact.
func unwrapOrder(body []byte) ([]byte, string, string, error) {
	obj, err := canon.Parse(body)
	if err != nil {
		return nil, "", "", err
	}
	inner, isEnvelope := obj["order"].(canon.Object)
	if !isEnvelope {
		b, err := canon.Encode(obj)
		return b, "", "", err
	}
	for k := range obj {
		if k != "order" && k != "scopeText" && k != "contact" {
			return nil, "", "", fmt.Errorf("unknown envelope field %q", k)
		}
	}
	scope, _ := obj["scopeText"].(string)
	contact, _ := obj["contact"].(string)
	if strings.TrimSpace(scope) == "" || len(scope) > MaxScopeText {
		return nil, "", "", fmt.Errorf("scopeText must be 1–%d bytes", MaxScopeText)
	}
	if !contactRE.MatchString(contact) {
		return nil, "", "", errors.New("contact must be a mailto: address")
	}
	b, err := canon.Encode(inner)
	return b, scope, contact, err
}

// postResponse accepts the subject's signed reply to an attestation (Audit.md
// §5.7.5), publishes it immutably, and re-signs the status list so relying
// clients see it beside the attestation.
func (s *Server) postResponse(w http.ResponseWriter, r *http.Request) {
	body, ok := s.readBody(w, r, MaxResponseBytes)
	if !ok {
		return
	}
	var head struct {
		AttestationID string `json:"attestationId"`
		ResponseID    string `json:"responseId"`
	}
	if json.Unmarshal(body, &head) != nil || !safeID(head.AttestationID) || !safeID(head.ResponseID) {
		fail(w, http.StatusUnprocessableEntity, audit.ErrResponseInvalid.Error(), errors.New("malformed response"))
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	attRaw, err := os.ReadFile(filepath.Join(s.Root, "attestations", head.AttestationID+".json"))
	if err != nil {
		fail(w, http.StatusNotFound, "attestation_unknown", errors.New("no such attestation"))
		return
	}
	att, err := audit.ParseAttestation(attRaw)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", errors.New("published attestation does not verify"))
		return
	}
	if _, err := audit.ParseResponse(body, att, sig.Digest(attRaw)); err != nil {
		fail(w, http.StatusUnprocessableEntity, audit.ErrResponseInvalid.Error(), err)
		return
	}
	path := filepath.Join(s.Root, "responses", head.AttestationID, head.ResponseID+".json")
	if prev, err := os.ReadFile(path); err == nil {
		if string(prev) != string(body) {
			fail(w, http.StatusConflict, "response_conflict", errors.New("responses are immutable; publish a new responseId"))
			return
		}
	} else if err := site.WriteAtomic(path, body); err != nil {
		fail(w, http.StatusInternalServerError, "internal", errors.New("could not store response"))
		return
	}
	if err := site.ResignStatus(s.Root, s.Config, s.StatusKey, s.Now()); err != nil {
		log.Printf("status re-sign after response failed: %v", err)
	}
	jsonReply(w, http.StatusCreated, map[string]string{"uri": s.Config.BaseURI + "responses/" + head.AttestationID + "/" + head.ResponseID + ".json", "digest": sig.Digest(body)})
}

func safeID(id string) bool {
	if len(id) < 16 || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if !(c == '-' || c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

// limiter is a small global token bucket for the write endpoints.
type limiter struct {
	mu     sync.Mutex
	tokens float64
	rate   float64
	burst  float64
	last   time.Time
}

func newLimiter(rate, burst float64) *limiter {
	return &limiter{tokens: burst, rate: rate, burst: burst, last: time.Now()}
}

func (l *limiter) allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.tokens += now.Sub(l.last).Seconds() * l.rate
	if l.tokens > l.burst {
		l.tokens = l.burst
	}
	l.last = now
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}
