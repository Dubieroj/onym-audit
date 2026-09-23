package hub

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
)

const pubBase = "https://audit.example.org/"

func key(label string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte("hub test " + label))
	return ed25519.NewKeyFromSeed(s[:])
}

func testHub(t *testing.T) (*Hub, http.Handler) {
	pub := t.TempDir()
	for p, b := range map[string]string{"profile.json": `{"p":1}`, "severity-v1.json": `{"s":1}`, "methodology/security-review-manual.md": "manual", "hub/auditor.html": "<html>auditor page</html>"} {
		os.MkdirAll(filepath.Dir(filepath.Join(pub, p)), 0o755)
		os.WriteFile(filepath.Join(pub, p), []byte(b), 0o644)
	}
	h, err := New(t.TempDir(), pub, pubBase)
	if err != nil {
		t.Fatal(err)
	}
	h.Now = func() time.Time { return time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC) }
	h.limiter.burst = 1e6
	return h, h.Handler()
}

func call(h http.Handler, method, path string, body any) (int, map[string]any) {
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, &buf))
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func shared(p, content string) audit.DocRef {
	return audit.DocRef{URI: pubBase + p, Digest: sig.Digest([]byte(content))}
}

func own(slug, p, content string) audit.DocRef {
	return audit.DocRef{URI: pubBase + "a/" + slug + "/" + p, Digest: sig.Digest([]byte(content))}
}

// manifest builds what the studio builds: shared profile, scale and
// methodology; the auditor's own policies.
func manifest(t *testing.T, slug string, statusKey string, k ed25519.PrivateKey, offers ...string) (json.RawMessage, map[string]string) {
	docs := map[string]string{"policies/independence.md": "independent", "policies/unsolicited.md": "notice first", "policies/liability.md": "opinion only", "policies/privacy.md": "no logs"}
	m := audit.AuditorManifest{
		Version: 1, ComponentID: "onym:component:" + slug, Seat: "audit", Operator: sig.KeyOf(k.Public().(ed25519.PublicKey)),
		DisplayName: "Alice", Contact: "mailto:alice@example.org", AuditProfileID: audit.ProfileID, AuditProfile: shared("profile.json", `{"p":1}`),
		Methodologies:      []audit.Methodology{{Class: audit.SecurityReview, Specification: shared("methodology/security-review-manual.md", "manual"), ScopesOffered: []string{"source"}}},
		IndependencePolicy: own(slug, "policies/independence.md", docs["policies/independence.md"]), UnsolicitedPolicy: own(slug, "policies/unsolicited.md", docs["policies/unsolicited.md"]),
		Liability: own(slug, "policies/liability.md", docs["policies/liability.md"]), SeverityScale: shared("severity-v1.json", `{"s":1}`), PrivacyProfile: own(slug, "policies/privacy.md", docs["policies/privacy.md"]),
		StatusEndpoint: pubBase + "a/" + slug + "/status.json", StatusKey: sig.Key(statusKey), Offers: append([]string{}, offers...), ValidUntil: "2027-09-24T00:00:00Z",
	}
	raw, err := audit.SignDoc(m, k)
	if err != nil {
		t.Fatal(err)
	}
	return raw, docs
}

func attestation(t *testing.T, slug, id string, k ed25519.PrivateKey) (json.RawMessage, map[string]string) {
	scope := "src/ at the commit\n"
	floor := "low"
	exp := "2027-03-24T00:00:00Z"
	sev := shared("severity-v1.json", `{"s":1}`)
	a := audit.Attestation{
		AttestationVersion: 1, AttestationID: id, Auditor: "onym:component:" + slug, AuditorKey: sig.KeyOf(k.Public().(ed25519.PublicKey)),
		Subject: "onym:component:example", SubjectOperator: sig.KeyOf(key("subject").Public().(ed25519.PublicKey)),
		Artifact:         audit.Artifact{Kind: audit.KindSource, Source: "https://github.com/example/repo", Revision: strings.Repeat("e", 40)},
		MethodologyClass: audit.SecurityReview, Methodology: shared("methodology/security-review-manual.md", "manual"),
		Scope: own(slug, "scopes/"+id+".md", scope), ScopeSummary: "src/", Exclusions: []string{"everything else"},
		Result: audit.Clear, SeverityScale: &sev, SeverityFloor: &floor, FindingsSummary: map[string]int{},
		Engagement: "unsolicited", Sponsor: sig.KeyOf(k.Public().(ed25519.PublicKey)), SponsorName: "Alice (self-funded)", Relationships: "none",
		Unsolicited: &audit.UnsolicitedDisclosure{Policy: sig.Digest([]byte("notice first")), SubjectContact: "mailto:sec@example.org", SubjectNotifiedAt: "2026-09-23T00:00:00Z"},
		IssuedAt:    "2026-09-24T10:00:00Z", ExpiresAt: &exp, Status: pubBase + "a/" + slug + "/status.json",
	}
	raw, err := audit.SignDoc(a, k)
	if err != nil {
		t.Fatal(err)
	}
	return raw, map[string]string{"scopes/" + id + ".md": scope}
}

func TestAuditorLifecycle(t *testing.T) {
	h, srv := testHub(t)
	alice := key("alice")

	code, c := call(srv, "POST", "/hub/api/claim", map[string]string{"slug": "alice"})
	if code != 200 {
		t.Fatalf("claim %d %v", code, c)
	}
	statusKey := c["statusKey"].(string)
	for _, bad := range []string{"hub", "Al", "1abc", "a/b"} {
		if code, _ := call(srv, "POST", "/hub/api/claim", map[string]string{"slug": bad}); code != 422 {
			t.Errorf("claimed %q: %d", bad, code)
		}
	}

	m, docs := manifest(t, "alice", statusKey, alice)
	if code, out := call(srv, "POST", "/hub/api/register", map[string]any{"slug": "alice", "manifest": m, "docs": docs}); code != 201 {
		t.Fatalf("register %d %v", code, out)
	}
	// The name is pinned to Alice's key.
	mallory := key("mallory")
	m2, docs2 := manifest(t, "alice", statusKey, mallory)
	if code, _ := call(srv, "POST", "/hub/api/register", map[string]any{"slug": "alice", "manifest": m2, "docs": docs2}); code != 403 {
		t.Errorf("another key took the name: %d", code)
	}
	if code, _ := call(srv, "POST", "/hub/api/claim", map[string]string{"slug": "alice"}); code != 409 {
		t.Errorf("claimed a registered name: %d", code)
	}
	// Documents stay inside the tree.
	if code, _ := call(srv, "POST", "/hub/api/register", map[string]any{"slug": "alice", "manifest": m, "docs": map[string]string{"../../etc/x.md": "x"}}); code != 422 {
		t.Errorf("path traversal accepted: %d", code)
	}

	// Publishing.
	a, adocs := attestation(t, "alice", "alice-att-0000000001", alice)
	if code, out := call(srv, "POST", "/hub/api/a/alice/publish", map[string]any{"attestation": a, "docs": adocs}); code != 201 {
		t.Fatalf("publish %d %v", code, out)
	}
	if code, _ := call(srv, "POST", "/hub/api/a/alice/publish", map[string]any{"attestation": a, "docs": adocs}); code != 409 {
		t.Errorf("republished an immutable attestation: %d", code)
	}
	forged, fdocs := attestation(t, "alice", "alice-att-0000000002", mallory)
	if code, _ := call(srv, "POST", "/hub/api/a/alice/publish", map[string]any{"attestation": forged, "docs": fdocs}); code != 422 {
		t.Errorf("published under Alice's name with another key: %d", code)
	}
	// A document pinned outside the hub is refused.
	var ext map[string]any
	json.Unmarshal(a, &ext)
	ext["attestationId"] = "alice-att-0000000003"
	ext["scope"] = map[string]any{"uri": "https://elsewhere.example/scope.md", "digest": sig.Digest([]byte("x"))}
	delete(ext, "signature")
	extRaw, _ := audit.SignDoc(ext, alice)
	if code, _ := call(srv, "POST", "/hub/api/a/alice/publish", map[string]any{"attestation": json.RawMessage(extRaw), "docs": map[string]string{}}); code != 422 {
		t.Errorf("external document accepted: %d", code)
	}

	// The status list covers the attestation and verifies under the hub's key.
	raw, _ := os.ReadFile(filepath.Join(h.tenantDir("alice"), "manifest.json"))
	mm, err := audit.ParseManifest(raw, h.Now())
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.ReadFile(filepath.Join(h.tenantDir("alice"), "status.json"))
	l, err := audit.ParseStatus(st, mm, nil, h.Now())
	if err != nil || l.Entry("alice-att-0000000001") == nil {
		t.Fatalf("status %v", err)
	}

	// Revocation, signed by Alice only.
	rv := audit.Revocation{RevocationVersion: 1, AttestationID: "alice-att-0000000001", Auditor: "onym:component:alice", AuditorKey: sig.KeyOf(alice.Public().(ed25519.PublicKey)), IssuedAt: "2026-09-24T11:00:00Z", StatusEpoch: h.Now().Unix(), EffectiveFrom: "2026-09-24T11:00:00Z", Reason: "withdrawal"}
	rvBad, _ := audit.SignDoc(rv, mallory)
	if code, _ := call(srv, "POST", "/hub/api/a/alice/revoke", map[string]any{"revocation": json.RawMessage(rvBad)}); code != 422 {
		t.Errorf("revocation by another key: %d", code)
	}
	rvRaw, _ := audit.SignDoc(rv, alice)
	if code, out := call(srv, "POST", "/hub/api/a/alice/revoke", map[string]any{"revocation": json.RawMessage(rvRaw)}); code != 201 {
		t.Fatalf("revoke %d %v", code, out)
	}
	st, _ = os.ReadFile(filepath.Join(h.tenantDir("alice"), "status.json"))
	l, _ = audit.ParseStatus(st, mm, nil, h.Now())
	if e := l.Entry("alice-att-0000000001"); e == nil || e.State != audit.Revoked {
		t.Errorf("not revoked in the status list: %+v", e)
	}

	// Static tree, the shared page, listing, export.
	// A traversal is cleaned by the mux into a redirect to a path that serves nothing.
	for _, p := range []string{"/a/alice/../../keys/alice.key", "/a/alice/%2e%2e/%2e%2e/keys/alice.key"} {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
		if rec.Code == 200 {
			t.Errorf("GET %s served: %s", p, rec.Body.String())
		}
		if loc := rec.Header().Get("Location"); loc != "" {
			rec2 := httptest.NewRecorder()
			srv.ServeHTTP(rec2, httptest.NewRequest("GET", loc, nil))
			if rec2.Code == 200 {
				t.Errorf("redirect target %s served", loc)
			}
		}
	}
	for path, want := range map[string]int{"/a/alice/": 200, "/a/alice": 301, "/a/alice/manifest.json": 200, "/a/alice/attestations/alice-att-0000000001.json": 200, "/a/alice/.disabled": 404, "/a/nobody/manifest.json": 404, "/a/nobody/": 404} {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != want {
			t.Errorf("GET %s: %d, want %d", path, rec.Code, want)
		}
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/hub/api/auditors", nil))
	if !strings.Contains(rec.Body.String(), `"slug":"alice"`) {
		t.Errorf("listing: %s", rec.Body.String())
	}

	// The operator can take an auditor off the hub.
	if err := h.Disable("alice", "terms of use"); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/a/alice/manifest.json", nil))
	if rec.Code != 404 {
		t.Errorf("disabled auditor still served: %d", rec.Code)
	}
}

func TestFetchRefusesInside(t *testing.T) {
	_, srv := testHub(t)
	for _, u := range []string{"https://localhost/x", "https://127.0.0.1/x", "http://example.org/x", "https://example.org:8443/x"} {
		if code, out := call(srv, "POST", "/hub/api/fetch", map[string]string{"url": u}); code == 200 {
			t.Errorf("%s fetched: %v", u, out)
		}
	}
}

func TestRateLimit(t *testing.T) {
	_, srv := testHub(t)
	h, _ := testHub(t)
	h.limiter = newLimiter()
	srv = h.Handler()
	limited := false
	for i := 0; i < 20; i++ {
		if code, _ := call(srv, "POST", "/hub/api/claim", map[string]string{"slug": "someone"}); code == 429 {
			limited = true
			break
		}
	}
	if !limited {
		t.Error("twenty claims in a burst were not limited")
	}
}
