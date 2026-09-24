package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"onym-audit/audit"
	"onym-audit/sig"
	"onym-audit/site"
)

func key(label string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte(label))
	return ed25519.NewKeyFromSeed(s[:])
}

const base = "https://audit.example.org/"

func order(t *testing.T, id, scopeText string, signers ...ed25519.PrivateKey) []byte {
	t.Helper()
	sponsor := key("sponsor")
	o := audit.AuditOrder{
		OrderVersion: 1, OrderID: id, Auditor: "onym:component:test-auditor", Subject: "onym:component:test-subject",
		Sponsor:        site.KeyOf(sponsor),
		Artifact:       audit.Artifact{Kind: audit.KindSource, Source: "https://github.com/example/repo", Revision: strings.Repeat("c", 40)},
		MethodologyCls: audit.SecurityReview,
		Scope:          audit.DocRef{URI: base + "scopes/order-" + id + ".md", Digest: sig.Digest([]byte(scopeText))},
		Cooperation:    "public repository only",
		Disclosure:     audit.Disclosure{FindingsToSubjectFirst: true, EmbargoDays: 90, AttestationPublication: "public-on-issuance", FailPublication: "public-after-embargo"},
		Timeline:       map[string]string{"start": "2026-09-24", "reportDue": "2026-10-01"},
		Fee:            audit.Fee{Model: "pro-bono", OfferID: "security-review-llm-source"},
		Signatures:     []audit.OrderSignature{},
	}
	raw, err := audit.CanonicalOf(o)
	if err != nil {
		t.Fatal(err)
	}
	if signers == nil {
		signers = []ed25519.PrivateKey{sponsor}
	}
	for _, role := range []string{"subject", "sponsor"} {
		if raw, err = audit.SignOrder(raw, role, signers[0]); err != nil {
			t.Fatal(err)
		}
	}
	return raw
}

func envelope(orderRaw []byte, scope, contact string) []byte {
	var o any
	json.Unmarshal(orderRaw, &o)
	b, _ := json.Marshal(map[string]any{"order": o, "scopeText": scope, "contact": contact})
	return b
}

func testServer(t *testing.T) (*Server, http.Handler) {
	s := &Server{
		Root: t.TempDir(), Inbox: t.TempDir(),
		Config:  &site.Config{BaseURI: base, ComponentID: "onym:component:test-auditor"},
		Now:     func() time.Time { return time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC) },
		limiter: newLimiter(1000, 1000),
	}
	return s, s.Handler()
}

func post(h http.Handler, path string, body []byte) (int, string) {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", path, bytes.NewReader(body)))
	return rec.Code, rec.Body.String()
}

func TestOrderIntake(t *testing.T) {
	s, h := testServer(t)
	scope := "Examine src/ for signature verification defects."

	// Envelope: queued with its scope text and private contact.
	code, body := post(h, "/orders", envelope(order(t, "order-envelope-0001", scope), scope, "mailto:owner@example.org"))
	if code != http.StatusAccepted {
		t.Fatalf("envelope: %d %s", code, body)
	}
	for _, f := range []string{"order.json", "scope.md", "meta.json"} {
		if _, err := os.Stat(filepath.Join(s.Inbox, "order-envelope-0001", f)); err != nil {
			t.Errorf("missing %s", f)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(s.Inbox, "order-envelope-0001", "scope.md")); string(b) != scope {
		t.Error("scope text not stored verbatim")
	}
	// The same order again is idempotent.
	if code, _ := post(h, "/orders", envelope(order(t, "order-envelope-0001", scope), scope, "mailto:owner@example.org")); code != http.StatusAccepted {
		t.Errorf("resubmission: %d", code)
	}
	// A bare signed order (scope hosted elsewhere) is also accepted.
	if code, body := post(h, "/orders", order(t, "order-bare-00000001", "x")); code != http.StatusAccepted {
		t.Errorf("bare: %d %s", code, body)
	}

	for name, c := range map[string]struct {
		body []byte
		want int
	}{
		"scope text swapped":      {envelope(order(t, "order-swapped-00001", scope), "something else entirely", "mailto:a@example.org"), 422},
		"contact with a newline":  {envelope(order(t, "order-contact-00001", scope), scope, "a\nb"), 422},
		"extra envelope field":    {[]byte(strings.Replace(string(envelope(order(t, "order-extra-000001", scope), scope, "mailto:a@example.org")), `"contact"`, `"x":1,"contact"`, 1)), 422},
		"signed by subject only":  {mustDropSponsor(t, order(t, "order-onesig-000001", scope)), 422},
		"different order same id": {envelope(order(t, "order-envelope-0001", scope+" more"), scope+" more", "mailto:a@example.org"), 409},
		"not an order":            {[]byte(`{"hello":"world"}`), 422},
	} {
		if code, body := post(h, "/orders", c.body); code != c.want {
			t.Errorf("%s: %d %s, want %d", name, code, body, c.want)
		}
	}
}

func mustDropSponsor(t *testing.T, raw []byte) []byte {
	var o map[string]any
	json.Unmarshal(raw, &o)
	sigs := o["signatures"].([]any)
	o["signatures"] = sigs[:1]
	b, _ := json.Marshal(o)
	return b
}

func TestStaticServesLanguageDirectories(t *testing.T) {
	s, h := testServer(t)
	os.MkdirAll(filepath.Join(s.Root, "ru"), 0o755)
	os.WriteFile(filepath.Join(s.Root, "ru", "index.html"), []byte("ru page"), 0o644)
	os.WriteFile(filepath.Join(s.Root, ".secret"), []byte("x"), 0o644)
	for path, want := range map[string]int{"/ru/": 200, "/ru": 301, "/.secret": 404, "/missing.json": 404} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != want {
			t.Errorf("%s: %d, want %d", path, rec.Code, want)
		}
	}
}

// The hub mounts beside the static handler without a pattern conflict (a
// conflict panics when the handler is built), and each side gets its paths.
func TestHubMount(t *testing.T) {
	s := &Server{
		Root: t.TempDir(), Inbox: t.TempDir(),
		Config:  &site.Config{BaseURI: base, ComponentID: "onym:component:test-auditor"},
		limiter: newLimiter(1000, 1000),
		Hub: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(299)
		}),
	}
	h := s.Handler()
	os.WriteFile(filepath.Join(s.Root, "index.html"), []byte("home"), 0o644)
	for _, c := range []struct {
		method, path string
		want         int
	}{
		{"GET", "/", 200},
		{"GET", "/hub/api/auditors", 299},
		{"POST", "/hub/api/claim", 299},
		{"GET", "/a/someone/manifest.json", 299},
		{"POST", "/a/someone/responses", 299},
		{"GET", "/hub/studio.js", 404},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, nil))
		if rec.Code != c.want {
			t.Errorf("%s %s: %d, want %d", c.method, c.path, rec.Code, c.want)
		}
	}
}

// The orderer's contact is optional free text.
func TestOrderContactIsOptional(t *testing.T) {
	_, h := testServer(t)
	scope := "Examine src/ for signature verification defects."
	if code, body := post(h, "/orders", envelope(order(t, "order-nocontact-001", scope), scope, "")); code != http.StatusAccepted {
		t.Errorf("empty contact: %d %s", code, body)
	}
	var env map[string]any
	json.Unmarshal(envelope(order(t, "order-nocontact-002", scope), scope, ""), &env)
	delete(env, "contact")
	b, _ := json.Marshal(env)
	if code, body := post(h, "/orders", b); code != http.StatusAccepted {
		t.Errorf("no contact field: %d %s", code, body)
	}
	if code, body := post(h, "/orders", envelope(order(t, "order-nocontact-003", scope), scope, "t.me/someone")); code != http.StatusAccepted {
		t.Errorf("free-text contact: %d %s", code, body)
	}
}
