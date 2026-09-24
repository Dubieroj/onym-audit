package hub

import (
	"crypto/ed25519"
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

var disc = audit.Disclosure{FindingsToSubjectFirst: true, EmbargoDays: 90, AttestationPublication: "public-on-issuance", FailPublication: "public-after-embargo"}

func pub(k ed25519.PrivateKey) sig.Key { return sig.KeyOf(k.Public().(ed25519.PublicKey)) }

func offerDoc(t *testing.T, slug string, k ed25519.PrivateKey) string {
	of := audit.Offer{
		OfferVersion: 1, OfferID: "manual-review", Auditor: "onym:component:" + slug, AuditorKey: pub(k),
		MethodologyClass: audit.SecurityReview, Scope: shared("methodology/security-review-manual.md", "manual"),
		Fee: audit.OfferFee{Model: "pro-bono"}, TimelineDays: 14, Disclosure: disc, ValidUntil: "2027-09-24T00:00:00Z",
	}
	raw, err := audit.SignDoc(of, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// orderingHub registers Alice with one pro-bono offer.
func orderingHub(t *testing.T) (*Hub, http.Handler, ed25519.PrivateKey) {
	h, srv := testHub(t)
	alice := key("alice")
	_, c := call(srv, "POST", "/hub/api/claim", map[string]string{"slug": "alice"})
	statusKey := c["statusKey"].(string)
	m, docs := manifest(t, "alice", statusKey, alice, "manual-review")
	// The listed offer must be there, and be Alice's.
	if code, _ := call(srv, "POST", "/hub/api/register", map[string]any{"slug": "alice", "manifest": m, "docs": docs}); code != 422 {
		t.Errorf("registered with a missing offer: %d", code)
	}
	docs["offers/manual-review.json"] = offerDoc(t, "alice", key("mallory"))
	if code, _ := call(srv, "POST", "/hub/api/register", map[string]any{"slug": "alice", "manifest": m, "docs": docs}); code != 422 {
		t.Errorf("registered with another key's offer: %d", code)
	}
	docs["offers/manual-review.json"] = offerDoc(t, "alice", alice)
	if code, out := call(srv, "POST", "/hub/api/register", map[string]any{"slug": "alice", "manifest": m, "docs": docs}); code != 201 {
		t.Fatalf("register %d %v", code, out)
	}
	return h, srv, alice
}

// order builds what the order page builds: signed by the subject and the
// sponsor (one key), addressed to Alice under her offer.
func order(t *testing.T, id, scope string, mut func(o *audit.AuditOrder)) json.RawMessage {
	return orderBy(t, key("bob"), id, scope, mut)
}

// orderBy is an order signed as subject and sponsor by k.
func orderBy(t *testing.T, bob ed25519.PrivateKey, id, scope string, mut func(o *audit.AuditOrder)) json.RawMessage {
	o := audit.AuditOrder{
		OrderVersion: 1, OrderID: id, Auditor: "onym:component:alice", Subject: "onym:component:example", Sponsor: pub(bob),
		Artifact:       audit.Artifact{Kind: audit.KindSource, Source: "https://github.com/example/repo", Revision: strings.Repeat("e", 40)},
		MethodologyCls: audit.SecurityReview, Scope: own("alice", "scopes/order-"+id+".md", scope),
		Cooperation: "public repository", Disclosure: disc, Timeline: map[string]string{"start": "2026-09-24", "reportDue": "2026-10-08"},
		Fee: audit.Fee{Model: "pro-bono", OfferID: "manual-review"}, Signatures: []audit.OrderSignature{},
	}
	if mut != nil {
		mut(&o)
	}
	raw, err := audit.CanonicalOf(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"subject", "sponsor"} {
		if raw, err = audit.SignOrder(raw, role, bob); err != nil {
			t.Fatal(err)
		}
	}
	return raw
}

func inboxReq(t *testing.T, k ed25519.PrivateKey, action string, orderID *string, at time.Time) map[string]any {
	req := struct {
		Action   string  `json:"action"`
		Auditor  string  `json:"auditor"`
		OrderID  *string `json:"orderId"`
		IssuedAt string  `json:"issuedAt"`
	}{action, "onym:component:alice", orderID, sig.FormatTime(at)}
	raw, err := audit.SignDoc(req, k)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"request": json.RawMessage(raw)}
}

func TestOrdersFromAnyone(t *testing.T) {
	h, srv, alice := orderingHub(t)
	scope := "Signature verification in src/verify.rs.\n"
	id := "ord-0000000000000001"
	env := func(o json.RawMessage, scopeText, contact string) map[string]any {
		return map[string]any{"order": o, "scopeText": scopeText, "contact": contact}
	}

	// Intake refuses anything the offer does not cover.
	for name, c := range map[string]map[string]any{
		"scope text differs":  env(order(t, id, scope, nil), "other\n", "mailto:bob@example.org"),
		"control characters":  env(order(t, id, scope, nil), scope, "bob\r\nBcc: x"),
		"unknown offer":       env(order(t, id, scope, func(o *audit.AuditOrder) { o.Fee.OfferID = "other" }), scope, "mailto:bob@example.org"),
		"weaker disclosure":   env(order(t, id, scope, func(o *audit.AuditOrder) { o.Disclosure.EmbargoDays = 0 }), scope, "mailto:bob@example.org"),
		"other auditor":       env(order(t, id, scope, func(o *audit.AuditOrder) { o.Auditor = "onym:component:carol" }), scope, "mailto:bob@example.org"),
		"scope outside inbox": env(order(t, id, scope, func(o *audit.AuditOrder) { o.Scope = own("alice", "scopes/x.md", scope) }), scope, "mailto:bob@example.org"),
	} {
		if code, _ := call(srv, "POST", "/a/alice/orders", c); code != 422 {
			t.Errorf("%s: accepted (%d)", name, code)
		}
	}
	good := order(t, id, scope, nil)
	if code, out := call(srv, "POST", "/a/alice/orders", env(good, scope, "mailto:bob@example.org")); code != 202 {
		t.Fatalf("order %d %v", code, out)
	}
	// The inbox is private: nothing under the public tree, and only Alice's
	// fresh signature opens it.
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/a/alice/inbox/"+id+"/meta.json", nil))
	if rec.Code == 200 {
		t.Error("inbox served publicly")
	}
	if code, _ := call(srv, "POST", "/hub/api/a/alice/inbox", inboxReq(t, key("mallory"), "list", nil, h.Now())); code != 403 {
		t.Errorf("inbox opened by another key: %d", code)
	}
	if code, _ := call(srv, "POST", "/hub/api/a/alice/inbox", inboxReq(t, alice, "list", nil, h.Now().Add(-time.Hour))); code != 403 {
		t.Errorf("stale inbox request accepted: %d", code)
	}
	code, out := call(srv, "POST", "/hub/api/a/alice/inbox", inboxReq(t, alice, "list", nil, h.Now()))
	orders, _ := out["orders"].([]any)
	if code != 200 || len(orders) != 1 || orders[0].(map[string]any)["contact"] != "mailto:bob@example.org" || orders[0].(map[string]any)["scopeText"] != scope {
		t.Fatalf("inbox %d %v", code, out)
	}

	// Alice countersigns and publishes the commissioned attestation.
	att, docs := commissioned(t, alice, "alice-att-0000000010", good, scope, audit.Clear)
	bad := map[string]string{}
	for k, v := range docs {
		if !strings.HasPrefix(k, "orders/") {
			bad[k] = v
		}
	}
	if code, _ := call(srv, "POST", "/hub/api/a/alice/publish", map[string]any{"attestation": att, "docs": bad}); code != 422 {
		t.Errorf("commissioned attestation without its order: %d", code)
	}
	// It must bind exactly what the order binds, for whom the order names.
	other := "sha256:" + strings.Repeat("0", 64)
	for name, mut := range map[string]func(a *audit.Attestation){
		"other sponsor":     func(a *audit.Attestation) { a.Sponsor = pub(key("carol")) },
		"other subject key": func(a *audit.Attestation) { a.SubjectOperator = pub(key("carol")) },
		"other subject":     func(a *audit.Attestation) { a.Subject = "onym:component:other" },
		"other commit":      func(a *audit.Attestation) { a.Artifact.Revision = strings.Repeat("f", 40) },
		"other methodology": func(a *audit.Attestation) { a.MethodologyClass = audit.ConformanceRun },
		"other scope":       func(a *audit.Attestation) { a.Scope = own("alice", "scopes/other.md", scope) },
		"other orderRef":    func(a *audit.Attestation) { a.OrderRef = &other },
	} {
		ma, mdocs := commissioned(t, alice, "alice-att-0000000019", good, scope, audit.Clear, mut)
		mdocs["scopes/other.md"] = scope
		if code, _ := call(srv, "POST", "/hub/api/a/alice/publish", map[string]any{"attestation": ma, "docs": mdocs}); code != 422 {
			t.Errorf("%s: published (%d)", name, code)
		}
	}
	// An order only travels with the attestation it commissions.
	ua, udocs := attestation(t, "alice", "alice-att-0000000018", alice)
	for k, v := range docs {
		if strings.HasPrefix(k, "orders/") {
			udocs[k] = v
		}
	}
	if code, _ := call(srv, "POST", "/hub/api/a/alice/publish", map[string]any{"attestation": ua, "docs": udocs}); code != 422 {
		t.Errorf("order published with an unsolicited attestation: %d", code)
	}
	if code, out := call(srv, "POST", "/hub/api/a/alice/publish", map[string]any{"attestation": att, "docs": docs}); code != 201 {
		t.Fatalf("publish commissioned %d %v", code, out)
	}
	_, out = call(srv, "POST", "/hub/api/a/alice/inbox", inboxReq(t, alice, "list", nil, h.Now()))
	if orders, _ := out["orders"].([]any); len(orders) != 0 {
		t.Errorf("fulfilled order still queued: %v", out)
	}
	if code, _ := call(srv, "POST", "/a/alice/orders", env(good, scope, "mailto:bob@example.org")); code != 409 {
		t.Errorf("fulfilled order queued again: %d", code)
	}
	full, err := os.ReadFile(filepath.Join(h.tenantDir("alice"), "orders", id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.ParseOrder(full); err != nil {
		t.Errorf("published order: %v", err)
	}

	// A failing result under the order's embargo is held, then released.
	id2 := "ord-0000000000000002"
	o2 := order(t, id2, scope, nil)
	call(srv, "POST", "/a/alice/orders", env(o2, scope, "mailto:bob@example.org"))
	att2, docs2 := commissioned(t, alice, "alice-att-0000000011", o2, scope, audit.Fail)
	code, out = call(srv, "POST", "/hub/api/a/alice/publish", map[string]any{"attestation": att2, "docs": docs2})
	if code != 202 || out["held"] != true {
		t.Fatalf("fail under embargo: %d %v", code, out)
	}
	served := func(p string) bool {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest("GET", "/a/alice/"+p, nil))
		return rec.Code == 200
	}
	// Nothing of a held fail is served: an order without its attestation
	// would tell everyone the result was a fail.
	if served("attestations/alice-att-0000000011.json") || served("orders/"+id2+".json") || served("scopes/order-"+id2+".md") {
		t.Error("a held fail, its order or its scope is served before release")
	}
	_, out = call(srv, "POST", "/hub/api/a/alice/inbox", inboxReq(t, alice, "list", nil, h.Now()))
	if held, _ := out["held"].([]any); len(held) != 1 {
		t.Errorf("held list: %v", out)
	}
	h.ResignAll()
	if served("attestations/alice-att-0000000011.json") {
		t.Error("released before the embargo ended")
	}
	// A full tree does not keep the fail hidden past its embargo.
	os.MkdirAll(filepath.Join(h.tenantDir("alice"), "notes"), 0o755)
	os.WriteFile(filepath.Join(h.tenantDir("alice"), "notes", "filler.md"), make([]byte, MaxTenantBytes), 0o644)
	h.Now = func() time.Time { return time.Date(2026, 12, 24, 12, 0, 0, 0, time.UTC) }
	h.ResignAll()
	if !served("attestations/alice-att-0000000011.json") || !served("orders/"+id2+".json") {
		t.Fatal("attestation or order not released after the embargo")
	}
	raw, _ := os.ReadFile(filepath.Join(h.tenantDir("alice"), "manifest.json"))
	mm, _ := audit.ParseManifest(raw, h.Now())
	st, _ := os.ReadFile(filepath.Join(h.tenantDir("alice"), "status.json"))
	if l, err := audit.ParseStatus(st, mm, nil, h.Now()); err != nil || l.Entry("alice-att-0000000011") == nil {
		t.Errorf("released attestation not in the status list: %v", err)
	}

	// Declining removes an order.
	id3 := "ord-0000000000000003"
	call(srv, "POST", "/a/alice/orders", env(order(t, id3, scope, nil), scope, "mailto:bob@example.org"))
	if code, _ := call(srv, "POST", "/hub/api/a/alice/inbox", inboxReq(t, alice, "decline", &id3, h.Now())); code != 200 {
		t.Errorf("decline: %d", code)
	}
	if _, err := os.Stat(filepath.Join(h.inboxDir("alice"), id3)); err == nil {
		t.Error("declined order kept")
	}
}

// commissioned is what the studio does when an auditor takes an order.
func commissioned(t *testing.T, alice ed25519.PrivateKey, attID string, orderRaw json.RawMessage, scope string, result string, muts ...func(a *audit.Attestation)) (json.RawMessage, map[string]string) {
	full, err := audit.SignOrder(orderRaw, "auditor", alice)
	if err != nil {
		t.Fatal(err)
	}
	o, err := audit.ParseOrder(full)
	if err != nil {
		t.Fatal(err)
	}
	ref := sig.Digest(full)
	floor := "low"
	exp := "2027-06-24T00:00:00Z"
	sev := shared("severity-v1.json", `{"s":1}`)
	a := audit.Attestation{
		AttestationVersion: 1, AttestationID: attID, Auditor: "onym:component:alice", AuditorKey: pub(alice),
		Subject: o.Subject, SubjectOperator: pub(key("bob")), Artifact: o.Artifact,
		MethodologyClass: o.MethodologyCls, Methodology: shared("methodology/security-review-manual.md", "manual"),
		Scope: o.Scope, ScopeSummary: "ordered review", Exclusions: []string{"everything else"},
		Result: result, SeverityScale: &sev, SeverityFloor: &floor, FindingsSummary: map[string]int{},
		Engagement: "commissioned", Sponsor: o.Sponsor, SponsorName: "the sponsor of order " + o.OrderID, Relationships: "none", OrderRef: &ref,
		IssuedAt: "2026-09-24T10:00:00Z", ExpiresAt: &exp, Status: pubBase + "a/alice/status.json",
	}
	if result == audit.Fail {
		a.FindingsSummary = map[string]int{"critical": 1}
	}
	for _, m := range muts {
		m(&a)
	}
	raw, err := audit.SignDoc(a, alice)
	if err != nil {
		t.Fatal(err)
	}
	return raw, map[string]string{"orders/" + o.OrderID + ".json": string(full), "scopes/order-" + o.OrderID + ".md": scope}
}

func TestLibraryAndOrderStats(t *testing.T) {
	h, srv, alice := orderingHub(t)
	scope := "src/\n"
	o := order(t, "ord-0000000000000009", scope, nil)
	call(srv, "POST", "/a/alice/orders", map[string]any{"order": o, "scopeText": scope, "contact": "mailto:bob@example.org"})
	// An unsolicited, then revoked attestation stays in the library as revoked.
	a, adocs := attestation(t, "alice", "alice-att-0000000021", alice)
	if code, out := call(srv, "POST", "/hub/api/a/alice/publish", map[string]any{"attestation": a, "docs": adocs}); code != 201 {
		t.Fatalf("publish %d %v", code, out)
	}
	c2, d2 := commissioned(t, alice, "alice-att-0000000022", o, scope, audit.Clear)
	if code, out := call(srv, "POST", "/hub/api/a/alice/publish", map[string]any{"attestation": c2, "docs": d2}); code != 201 {
		t.Fatalf("publish commissioned %d %v", code, out)
	}
	rv := audit.Revocation{RevocationVersion: 1, AttestationID: "alice-att-0000000021", Auditor: "onym:component:alice", AuditorKey: pub(alice), IssuedAt: "2026-09-24T11:00:00Z", StatusEpoch: h.Now().Unix(), EffectiveFrom: "2026-09-24T11:00:00Z", Reason: "withdrawal"}
	rvRaw, _ := audit.SignDoc(rv, alice)
	call(srv, "POST", "/hub/api/a/alice/revoke", map[string]any{"revocation": json.RawMessage(rvRaw)})

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/hub/api/library", nil))
	var lib []libraryEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &lib); err != nil {
		t.Fatal(err)
	}
	states := map[string]string{}
	for _, e := range lib {
		states[e.AttestationID] = e.State
	}
	if states["alice-att-0000000021"] != audit.Revoked || states["alice-att-0000000022"] != "active" {
		t.Errorf("library states %v", states)
	}

	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/hub/api/auditors", nil))
	var auds []map[string]any
	json.Unmarshal(rec.Body.Bytes(), &auds)
	if len(auds) != 1 || auds[0]["completedOrders"] != float64(1) || auds[0]["customers"] != float64(1) || auds[0]["operator"] != string(pub(alice)) {
		t.Errorf("auditors %v", auds)
	}
}

func TestOrderStatusOnlyForTheOrderer(t *testing.T) {
	h, srv, _ := orderingHub(t)
	scope := "src/\n"
	id := "ord-0000000000000031"
	call(srv, "POST", "/a/alice/orders", map[string]any{"order": order(t, id, scope, nil), "scopeText": scope, "contact": "mailto:bob@example.org"})
	req := func(k ed25519.PrivateKey, sponsor sig.Key) map[string]any {
		q := struct {
			Action   string  `json:"action"`
			OrderID  string  `json:"orderId"`
			Sponsor  sig.Key `json:"sponsor"`
			IssuedAt string  `json:"issuedAt"`
		}{"order-status", id, sponsor, sig.FormatTime(h.Now())}
		raw, _ := audit.SignDoc(q, k)
		return map[string]any{"request": json.RawMessage(raw)}
	}
	bob := key("bob")
	if code, out := call(srv, "POST", "/hub/api/a/alice/order-status", req(bob, pub(bob))); code != 200 || out["queued"] != true {
		t.Errorf("orderer: %d %v", code, out)
	}
	mallory := key("mallory")
	if code, _ := call(srv, "POST", "/hub/api/a/alice/order-status", req(mallory, pub(bob))); code != 403 {
		t.Errorf("forged sponsor accepted: %d", code)
	}
	if _, out := call(srv, "POST", "/hub/api/a/alice/order-status", req(mallory, pub(mallory))); out["queued"] != false {
		t.Errorf("another key learned the order is queued: %v", out)
	}
}

// The orderer's contact is optional: an order without one is queued, and the
// auditor sees it with an empty contact.
func TestOrderContactIsOptional(t *testing.T) {
	h, srv, alice := orderingHub(t)
	scope := "Signature verification in src/verify.rs.\n"
	for _, c := range []struct{ id, contact string }{{"ord-0000000000000077", ""}, {"ord-0000000000000078", "@bob in Telegram"}} {
		if code, out := call(srv, "POST", "/a/alice/orders", map[string]any{"order": order(t, c.id, scope, nil), "scopeText": scope, "contact": c.contact}); code != 202 {
			t.Fatalf("contact %q: %d %v", c.contact, code, out)
		}
	}
	_, out := call(srv, "POST", "/hub/api/a/alice/inbox", inboxReq(t, alice, "list", nil, h.Now()))
	got := map[string]bool{}
	for _, o := range out["orders"].([]any) {
		got[o.(map[string]any)["contact"].(string)] = true
	}
	if !got[""] || !got["@bob in Telegram"] {
		t.Errorf("inbox contacts %v", got)
	}
}
