package hub

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"onym-audit/audit"
	"onym-audit/sig"
)

func offerAt(t *testing.T, k ed25519.PrivateKey, until string, days int) string {
	of := audit.Offer{
		OfferVersion: 1, OfferID: "manual-review", Auditor: "onym:component:alice", AuditorKey: pub(k),
		MethodologyClass: audit.SecurityReview, Scope: shared("methodology/security-review-manual.md", "manual"),
		Fee: audit.OfferFee{Model: "pro-bono"}, TimelineDays: days, Disclosure: disc, ValidUntil: until,
	}
	raw, err := audit.SignDoc(of, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// Offers are public and listed by id only: an older signed version, or an
// expired one, must not replace the published offer.
func TestOfferCannotBeRolledBack(t *testing.T) {
	h, srv, alice := orderingHub(t)
	m, _ := os.ReadFile(filepath.Join(h.tenantDir("alice"), "manifest.json"))
	path := filepath.Join(h.tenantDir("alice"), "offers", "manual-review.json")
	v1, _ := os.ReadFile(path)
	v2 := offerAt(t, alice, "2027-12-24T00:00:00Z", 7)
	if code, out := call(srv, "POST", "/hub/api/register", map[string]any{"slug": "alice", "manifest": json.RawMessage(m), "docs": map[string]string{"offers/manual-review.json": v2}}); code != 201 {
		t.Fatalf("newer offer %d %v", code, out)
	}
	for name, old := range map[string]string{"the previous version": string(v1), "an expired version": offerAt(t, alice, "2026-01-01T00:00:00Z", 30)} {
		if code, _ := call(srv, "POST", "/hub/api/register", map[string]any{"slug": "alice", "manifest": json.RawMessage(m), "docs": map[string]string{"offers/manual-review.json": old}}); code != 422 {
			t.Errorf("%s replayed over the published offer: %d", name, code)
		}
	}
	if now, _ := os.ReadFile(path); string(now) != v2 {
		t.Error("the published offer was rolled back")
	}
}

// A held fail carries only what its attestation references and its order,
// and its bytes count against the quota when it is held.
func TestHeldPublishCarriesOnlyItsDocuments(t *testing.T) {
	h, srv, alice := orderingHub(t)
	scope := "src/\n"
	id := "ord-0000000000000077"
	o := order(t, id, scope, nil)
	if code, out := call(srv, "POST", "/a/alice/orders", map[string]any{"order": o, "scopeText": scope, "contact": "mailto:bob@example.org"}); code != 202 {
		t.Fatalf("order %d %v", code, out)
	}
	att, docs := commissioned(t, alice, "alice-att-0000000077", o, scope, audit.Fail)
	withJunk := map[string]string{"notes/junk.md": "arbitrary bytes"}
	for k, v := range docs {
		withJunk[k] = v
	}
	if code, _ := call(srv, "POST", "/hub/api/a/alice/publish", map[string]any{"attestation": att, "docs": withJunk}); code != 422 {
		t.Errorf("a held publish carried an unreferenced document: %d", code)
	}
	os.WriteFile(filepath.Join(h.tenantDir("alice"), "filler.bin"), make([]byte, MaxTenantBytes), 0o644)
	if code, _ := call(srv, "POST", "/hub/api/a/alice/publish", map[string]any{"attestation": att, "docs": docs}); code != 507 {
		t.Errorf("held bytes past a full quota: %d", code)
	}
	os.Remove(filepath.Join(h.tenantDir("alice"), "filler.bin"))
	if code, out := call(srv, "POST", "/hub/api/a/alice/publish", map[string]any{"attestation": att, "docs": docs}); code != 202 {
		t.Fatalf("held publish %d %v", code, out)
	}
}

// A subject's replies are capped per attestation, and a full tree never
// stops the auditor from revoking.
func TestRepliesCappedAndRevocationAlwaysFits(t *testing.T) {
	h, srv := testHub(t)
	alice := key("alice")
	_, c := call(srv, "POST", "/hub/api/claim", map[string]string{"slug": "alice"})
	m, docs := manifest(t, "alice", c["statusKey"].(string), alice)
	if code, out := call(srv, "POST", "/hub/api/register", map[string]any{"slug": "alice", "manifest": m, "docs": docs}); code != 201 {
		t.Fatalf("register %d %v", code, out)
	}
	att, adocs := attestation(t, "alice", "alice-att-0000000001", alice)
	if code, out := call(srv, "POST", "/hub/api/a/alice/publish", map[string]any{"attestation": att, "docs": adocs}); code != 201 {
		t.Fatalf("publish %d %v", code, out)
	}
	stored, _ := os.ReadFile(filepath.Join(h.tenantDir("alice"), "attestations", "alice-att-0000000001.json"))
	subject := key("subject")
	reply := func(i int) int {
		r := audit.SubjectResponse{ResponseVersion: 1, ResponseID: fmt.Sprintf("reply-%016d", i), AttestationID: "alice-att-0000000001", Attestation: sig.Digest(stored),
			Subject: "onym:component:example", Respondent: pub(subject), IssuedAt: "2026-09-24T11:00:00Z", Text: "we disagree"}
		raw, err := audit.SignDoc(r, subject)
		if err != nil {
			t.Fatal(err)
		}
		code, _ := call(srv, "POST", "/a/alice/responses", json.RawMessage(raw))
		return code
	}
	for i := 0; i < MaxResponses; i++ {
		if code := reply(i); code != 201 {
			t.Fatalf("reply %d: %d", i, code)
		}
	}
	if code := reply(MaxResponses); code != 409 {
		t.Errorf("reply past the cap: %d", code)
	}
	os.WriteFile(filepath.Join(h.tenantDir("alice"), "filler.bin"), make([]byte, MaxTenantBytes), 0o644)
	rv := audit.Revocation{RevocationVersion: 1, AttestationID: "alice-att-0000000001", Auditor: "onym:component:alice", AuditorKey: pub(alice), IssuedAt: "2026-09-24T11:00:00Z", StatusEpoch: h.Now().Unix(), EffectiveFrom: "2026-09-24T11:00:00Z", Reason: "withdrawal"}
	rvRaw, _ := audit.SignDoc(rv, alice)
	if code, out := call(srv, "POST", "/hub/api/a/alice/revoke", map[string]any{"revocation": json.RawMessage(rvRaw)}); code != 201 {
		t.Errorf("revocation refused in a full tree: %d %v", code, out)
	}
}
