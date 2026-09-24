package provider

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
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
}
