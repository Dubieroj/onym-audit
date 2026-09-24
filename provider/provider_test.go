package provider

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"onym-audit/audit"
	"onym-audit/conformance/discovery"
	"onym-audit/sig"
	"onym-audit/site"
)

const host = "https://audit.example.org/"

func key(label string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte("provider test " + label))
	return ed25519.NewKeyFromSeed(s[:])
}

// auditor writes a signed audit manifest under dir, named under base.
func auditor(t *testing.T, dir, base, id string, k ed25519.PrivateKey) {
	ref := func(p, content string) audit.DocRef {
		os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755)
		os.WriteFile(filepath.Join(dir, p), []byte(content), 0o644)
		return audit.DocRef{URI: base + p, Digest: sig.Digest([]byte(content))}
	}
	m := audit.AuditorManifest{
		Version: 1, ComponentID: id, Seat: "audit", Operator: site.KeyOf(k), DisplayName: id, Contact: "mailto:a@example.org",
		AuditProfileID: audit.ProfileID, AuditProfile: ref("profile.json", `{"p":1}`),
		Methodologies:      []audit.Methodology{{Class: audit.SecurityReview, Specification: ref("m.md", "m"), ScopesOffered: []string{"source"}}},
		IndependencePolicy: ref("i.md", "i"), UnsolicitedPolicy: ref("u.md", "u"), Liability: ref("l.md", "l"), SeverityScale: ref("s.json", `{"s":1}`), PrivacyProfile: ref("p.md", "p"),
		StatusEndpoint: base + "status.json", StatusKey: site.KeyOf(key("status " + id)), Offers: []string{}, ValidUntil: "2027-09-24T00:00:00Z",
	}
	raw, err := audit.SignDoc(m, k)
	if err != nil {
		t.Fatal(err)
	}
	if err := site.WriteSigned(filepath.Join(dir, "manifest.json"), raw); err != nil {
		t.Fatal(err)
	}
}

// files serves URIs from directories, like the static host.
type files map[string]string // base URI → directory

func (f files) Get(ctx context.Context, uri string) (*discovery.Response, error) {
	best := ""
	for b := range f {
		if strings.HasPrefix(uri, b) && len(b) > len(best) {
			best = b
		}
	}
	r := &discovery.Response{URI: uri, Status: 404, Header: http.Header{}}
	if best == "" {
		return r, nil
	}
	b, err := os.ReadFile(filepath.Join(f[best], filepath.FromSlash(strings.TrimPrefix(uri, best))))
	if err != nil {
		return r, nil
	}
	ct := "text/plain; charset=utf-8"
	if strings.HasSuffix(uri, ".json") {
		ct = "application/json"
	}
	r.Status, r.Body = 200, b
	r.Header.Set("Content-Type", ct)
	if limit := discovery.LimitFrom(ctx); int64(len(b)) > limit {
		r.Body, r.Truncated = b[:limit+1], true
	}
	return r, nil
}

func clean(t *testing.T, rep *discovery.Report) {
	t.Helper()
	for _, c := range rep.Checks {
		if c.Outcome == discovery.Fail || c.Outcome == discovery.Inconclusive {
			t.Errorf("%s %s: %s", c.Outcome, c.ID, c.Detail)
		}
	}
}

func TestCatalogPassesTheSuite(t *testing.T) {
	root, prov, alice := t.TempDir(), t.TempDir(), t.TempDir()
	c := Config{Base: host + "discovery/", ProviderID: "onym:component:test-discovery", CatalogID: "onym-auditors", Window: 30 * 24 * time.Hour, Renew: 7 * 24 * time.Hour}
	pk := key("provider")
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	auditor(t, root, host, "onym:component:operator-seat", key("operator"))
	auditor(t, alice, host+"a/alice/", "onym:component:alice", key("alice"))
	if err := PublishStatic(prov, c, pk, now.AddDate(1, 0, 0)); err != nil {
		t.Fatal(err)
	}
	srcs := []Source{{Base: host, Dir: root, CommonOwner: true}, {Base: host + "a/alice/", Dir: alice}}
	if ok, err := Refresh(prov, c, pk, srcs, now); err != nil || !ok {
		t.Fatalf("first snapshot: %v %v", ok, err)
	}
	fetch := files{host: root, host + "a/alice/": alice, c.Base: prov}
	rep := discovery.Run(context.Background(), fetch, c.Base+"manifest.json", now.Add(time.Minute))
	clean(t, rep)
	if rep.Result != discovery.ResultClear {
		t.Errorf("result %s", rep.Result)
	}

	// Nothing changed: no new snapshot. A new auditor: sequence 2, chained.
	if ok, _ := Refresh(prov, c, pk, srcs, now.Add(time.Hour)); ok {
		t.Error("a snapshot without a change")
	}
	bob := t.TempDir()
	auditor(t, bob, host+"a/bob/", "onym:component:bob", key("bob"))
	fetch[host+"a/bob/"] = bob
	srcs = append(srcs, Source{Base: host + "a/bob/", Dir: bob})
	if ok, err := Refresh(prov, c, pk, srcs, now.Add(2*time.Hour)); err != nil || !ok {
		t.Fatalf("second snapshot: %v %v", ok, err)
	}
	rep = discovery.Run(context.Background(), fetch, c.Base+"manifest.json", now.Add(3*time.Hour))
	clean(t, rep)
	if rep.Result != discovery.ResultClear {
		t.Errorf("result after a second snapshot %s", rep.Result)
	}
	// Renewal before expiry.
	if ok, _ := Refresh(prov, c, pk, srcs, now.Add(24*24*time.Hour)); !ok {
		t.Error("no renewal inside the margin")
	}
	// Retained snapshots that have expired are pruned; the chain still passes.
	later := now.Add(50 * 24 * time.Hour)
	if ok, _ := Refresh(prov, c, pk, srcs, later); !ok {
		t.Fatal("no renewal")
	}
	for _, k := range []int{1, 2} {
		if _, err := os.Stat(filepath.Join(prov, "catalogs", fmt.Sprintf("onym-auditors-%d.json", k))); err == nil {
			t.Errorf("expired snapshot %d kept", k)
		}
	}
	rep = discovery.Run(context.Background(), fetch, c.Base+"manifest.json", later.Add(time.Minute))
	clean(t, rep)
}

// signed writes a document signed with k at dir/p.
func signed(t *testing.T, dir, p string, doc map[string]any, k ed25519.PrivateKey) []byte {
	t.Helper()
	raw, err := audit.SignDoc(doc, k)
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755)
	if err := os.WriteFile(filepath.Join(dir, p), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestServicesCatalogShowsAttestationsAsStatus(t *testing.T) {
	const dirBase, relayBase = "https://dir.example.org/", "https://relay.example.org/"
	root, prov, dirDir, relayDir := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	dk, rk, pk := key("onym directory"), key("relay"), key("provider")
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	c := Config{Base: host + "discovery/", ProviderID: "onym:component:test-discovery", CatalogID: "onym-auditors", Window: 30 * 24 * time.Hour, Renew: 7 * 24 * time.Hour,
		ServicesCatalogID: "onym-audited-services", Directory: dirBase + "manifest.json", DirectoryKey: site.KeyOf(dk)}

	// Onym's directory lists a notary and a courier; only the notary is attested.
	relay := signed(t, relayDir, "manifest.json", map[string]any{"version": 1, "componentId": "onym:component:relay", "seat": "notary", "operator": string(site.KeyOf(rk)),
		"implementationProfiles": []string{"onym:notary-implementation:test"}, "validUntil": "2027-09-24T00:00:00Z"}, rk)
	signed(t, dirDir, "manifest.json", map[string]any{"catalogs": []map[string]any{{"snapshot": dirBase + "catalogs/svc.json"}}}, dk)
	signed(t, dirDir, "catalogs/svc.json", map[string]any{"entries": []map[string]any{
		{"componentId": "onym:component:relay", "seatType": "notary", "operator": string(site.KeyOf(rk)), "manifest": map[string]any{"uri": relayBase + "manifest.json", "digest": sig.Digest(relay)}, "profiles": []string{"onym:notary-implementation:test"}},
		{"componentId": "onym:component:courier", "seatType": "transport.message", "operator": string(site.KeyOf(rk)), "manifest": map[string]any{"uri": relayBase + "courier.json", "digest": sig.Digest(relay)}},
	}}, dk)

	auditor(t, root, host, "onym:component:operator-seat", key("operator"))
	if err := PublishStatic(prov, c, pk, now.AddDate(1, 0, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := Refresh(prov, c, pk, []Source{{Base: host, Dir: root, CommonOwner: true}}, now); err != nil {
		t.Fatal(err)
	}
	fetch := files{host: root, c.Base: prov, dirBase: dirDir, relayBase: relayDir}
	atts := []Attestation{{ID: "att-review-0000000001", Slug: "alice", Auditor: "Alice <b>", Subject: "onym:component:relay", Result: "findings-noted", Scope: "LLM review", IssuedAt: "2026-09-24T10:00:00Z"}}
	if ok, err := RefreshServices(context.Background(), prov, c, pk, atts, fetch, now); err != nil || !ok {
		t.Fatalf("services snapshot: %v %v", ok, err)
	}
	var snap snapshot
	raw, _ := os.ReadFile(filepath.Join(prov, "catalogs", "onym-audited-services.json"))
	if err := json.Unmarshal(raw, &snap); err != nil || len(snap.Entries) != 1 {
		t.Fatalf("entries: %v %s", err, raw)
	}
	e := snap.Entries[0]
	if e.ComponentID != "onym:component:relay" || e.Status == nil || e.Status.State != "review" || e.Status.URI != c.Base+"status/relay/" || e.Manifest.Digest != sig.Digest(relay) {
		t.Errorf("entry %+v status %+v", e, e.Status)
	}
	page, _ := os.ReadFile(filepath.Join(prov, "status", "relay", "index.html"))
	if !strings.Contains(string(page), "verdict/?a=alice&amp;id=att-review-0000000001") || strings.Contains(string(page), "Alice <b>") {
		t.Errorf("status page:\n%s", page)
	}

	// Both catalogs pass the provider suite, destinations included.
	rep := discovery.Run(context.Background(), fetch, c.Base+"manifest.json", now.Add(time.Minute))
	clean(t, rep)
	if rep.Result != discovery.ResultClear {
		t.Errorf("result %s", rep.Result)
	}

	// A fail warns; a revoked-away attestation drops the entry and its page.
	atts[0].Result = "fail"
	if ok, _ := RefreshServices(context.Background(), prov, c, pk, atts, fetch, now.Add(time.Hour)); !ok {
		t.Fatal("no snapshot after the result changed")
	}
	raw, _ = os.ReadFile(filepath.Join(prov, "catalogs", "onym-audited-services.json"))
	json.Unmarshal(raw, &snap)
	if snap.Entries[0].Status.State != "warning" || snap.Sequence != 2 {
		t.Errorf("after a fail: %+v seq %d", snap.Entries[0].Status, snap.Sequence)
	}
	if ok, _ := RefreshServices(context.Background(), prov, c, pk, nil, fetch, now.Add(2*time.Hour)); !ok {
		t.Fatal("no snapshot after the attestation went away")
	}
	if _, err := os.Stat(filepath.Join(prov, "status", "relay")); err == nil {
		t.Error("stale status page kept")
	}

	// A directory not signed by the pinned key is refused, and nothing is written.
	signed(t, dirDir, "manifest.json", map[string]any{"catalogs": []any{}}, key("impostor"))
	if _, err := RefreshServices(context.Background(), prov, c, pk, atts, fetch, now.Add(3*time.Hour)); err == nil {
		t.Error("an unsigned directory was accepted")
	}
}

// The published seat's own attestation is read back from the repository's
// tree: active, verified against the status list, attributed to the seat.
func TestCreditedAttestationsReadsTheSeat(t *testing.T) {
	raw, err := os.ReadFile("../public/status.json")
	if err != nil {
		t.Skip("no published seat")
	}
	var st struct {
		IssuedAt string `json:"issuedAt"`
	}
	json.Unmarshal(raw, &st)
	now, _ := sig.ParseTime(st.IssuedAt)
	atts := CreditedAttestations([]Source{{Base: "https://foldy.io/audit/", Dir: "../public", CommonOwner: true}}, Default, now.Add(time.Minute))
	found := false
	for _, a := range atts {
		if a.ID == "onym-discovery-2026-09-24" {
			found = a.Slug == "" && a.Subject == "onym:component:onym-discovery" && a.Result == "fail"
		}
	}
	if !found {
		t.Errorf("attestations %+v", atts)
	}
	// Credited by name and key: the same name under another key is not.
	c := Default
	c.Credited = map[string]sig.Key{"onym:component:onym-audit": site.KeyOf(key("impostor"))}
	if len(CreditedAttestations([]Source{{Base: "https://foldy.io/audit/", Dir: "../public", CommonOwner: true}}, c, now.Add(time.Minute))) != 0 {
		t.Error("an auditor was credited under another key")
	}
	c.Credited = nil
	if len(CreditedAttestations([]Source{{Base: "https://foldy.io/audit/", Dir: "../public", CommonOwner: true}}, c, now.Add(time.Minute))) != 0 {
		t.Error("an uncredited auditor's attestations were read")
	}
}

// Past 512 entries a client rejects the whole snapshot: the catalog keeps
// this site's own seat and the longest-listed auditors.
func TestAuditorsCatalogStaysWithinTheBound(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	auditor(t, root, host, "onym:component:zz-operator-seat", key("operator"))
	srcs := []Source{{Base: host, Dir: root, CommonOwner: true}}
	listed := map[string]string{}
	for i := 0; i < MaxEntries+5; i++ {
		d := t.TempDir()
		id := fmt.Sprintf("onym:component:a%04d", i)
		auditor(t, d, fmt.Sprintf("%sa/a%04d/", host, i), id, key(id))
		srcs = append(srcs, Source{Base: fmt.Sprintf("%sa/a%04d/", host, i), Dir: d})
		listed[id] = sig.FormatTime(now.Add(time.Duration(i) * time.Minute))
	}
	es := entries(srcs, now, listed)
	if len(es) != MaxEntries {
		t.Fatalf("%d entries", len(es))
	}
	seat, newest := false, false
	for _, e := range es {
		seat = seat || e.ComponentID == "onym:component:zz-operator-seat"
		newest = newest || e.ComponentID == fmt.Sprintf("onym:component:a%04d", MaxEntries+4)
	}
	if !seat || newest {
		t.Errorf("own seat kept %v, newest auditor kept %v", seat, newest)
	}
}
