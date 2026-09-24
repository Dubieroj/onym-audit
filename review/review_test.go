package review

import (
	"crypto/ed25519"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"onym-audit/agent"
	"onym-audit/audit"
	"onym-audit/sig"
	"onym-audit/site"
)

func key(label string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte("review test " + label))
	return ed25519.NewKeyFromSeed(s[:])
}

const repoURL = "https://github.com/example/repo"

var commit = strings.Repeat("d", 40)

// publicTree builds a minimal published tree with a signed manifest.
func publicTree(t *testing.T) (string, *site.Config) {
	root := t.TempDir()
	for p, body := range map[string]string{
		site.ProfileSpecPath: "profile", site.IndependencePath: "i", site.UnsolicitedPath: "u", site.LiabilityPath: "l",
		site.SeverityPath: "{}", site.PrivacyPath: "p",
		"methodology/security-review-manual.md": "manual", "methodology/security-review-llm.md": "llm",
	} {
		os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755)
		os.WriteFile(filepath.Join(root, p), []byte(body), 0o644)
	}
	c := &site.Config{BaseURI: "https://audit.example.org/", ComponentID: "onym:component:test-auditor", DisplayName: "Tester", Contact: "mailto:t@example.org", ValidUntil: "2030-01-01T00:00:00Z", Offers: []string{}}
	c.Methodologies = append(c.Methodologies, struct {
		Class         string   `json:"class"`
		Specification string   `json:"specification"`
		ScopesOffered []string `json:"scopesOffered"`
	}{"security-review", "methodology/security-review-manual.md", []string{"source"}})
	prof, err := site.BuildProfile(root, c, key("auditor"))
	if err != nil {
		t.Fatal(err)
	}
	site.WriteSigned(filepath.Join(root, site.ProfilePath), prof)
	man, err := site.BuildManifest(root, c, key("auditor"), site.KeyOf(key("status")))
	if err != nil {
		t.Fatal(err)
	}
	site.WriteSigned(filepath.Join(root, site.ManifestPath), man)
	return root, c
}

// newReview makes a review over a local workspace, skipping the network checkout.
func newReview(t *testing.T, kind string) *Review {
	reviews := t.TempDir()
	r := &Review{ID: "rv-20260924-0000abcd", Kind: kind, Repo: repoURL, Commit: commit, Scope: "src/\n", CreatedAt: "2026-09-24T10:00:00Z",
		Findings: []Finding{}, Rejected: []agent.Finding{}, Coverage: agent.Coverage{Examined: []string{}, NotExamined: []string{}}}
	r.dir = filepath.Join(reviews, r.ID)
	r.mu = &sync.Mutex{}
	os.MkdirAll(filepath.Join(r.Workspace(), "src"), 0o755)
	os.WriteFile(filepath.Join(r.Workspace(), "src", "a.go"), []byte("package a\n\nfunc Verify(sig []byte) bool {\n\treturn true // signature ignored\n}\n"), 0o644)
	if err := r.save(); err != nil {
		t.Fatal(err)
	}
	return r
}

func manualFinding(sev string) agent.Finding {
	return agent.Finding{Severity: sev, Confidence: "high", Title: "Verify accepts everything", Path: "src/a.go", LineStart: 3, LineEnd: 4, Quote: "return true // signature ignored", Description: "Verify returns true for any input.", Recommendation: "Check the signature."}
}

func TestManualReviewUnsolicited(t *testing.T) {
	root, c := publicTree(t)
	r := newReview(t, KindManual)
	bad := manualFinding("high")
	bad.Quote = "return verify(sig)"
	if err := r.AddManual(bad); err == nil || !strings.Contains(err.Error(), "evidence rejected") {
		t.Fatalf("fabricated quote accepted: %v", err)
	}
	if err := r.AddManual(manualFinding("high")); err != nil {
		t.Fatal(err)
	}
	if b := r.Blockers(); len(b) != 1 || !strings.Contains(b[0], "coverage") {
		t.Fatalf("blockers %v", b)
	}
	if err := r.SetCoverage(agent.Coverage{Summary: "Read src/.", Examined: []string{"src/a.go"}, Complete: true}); err != nil {
		t.Fatal(err)
	}
	opts := SignOptions{PublicRoot: root, Config: c, AuditorKey: key("auditor"), StatusKey: key("status"), AttestationID: "att-manual-0000000001",
		Relationships: "none", Subject: "onym:component:example", SubjectOperator: site.KeyOf(key("subject")),
		Now: time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)}
	if _, err := r.Sign(opts); err == nil {
		t.Fatal("signed without a documented notice")
	}
	opts.Contact, opts.NotifiedAt = "mailto:sec@example.org", "2026-09-24T00:00:00Z"
	s, err := r.Sign(opts)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "attestations", "att-manual-0000000001.json"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := audit.ParseAttestation(raw)
	if err != nil {
		t.Fatal(err)
	}
	if a.Result != audit.FindingsNoted || a.FindingsSummary["high"] != 1 || a.MethodologyClass != audit.SecurityReview || a.Engagement != "unsolicited" || !strings.HasPrefix(a.ScopeSummary, "Manual security review") {
		t.Errorf("attestation %+v", a)
	}
	if s.Result != audit.FindingsNoted || s.Held != nil {
		t.Errorf("signed %+v", s)
	}
	for _, p := range []string{a.FindingsReport.URI, a.Scope.URI} {
		if _, err := os.Stat(filepath.Join(root, strings.TrimPrefix(p, c.BaseURI))); err != nil {
			t.Errorf("not published: %s", p)
		}
	}
	// The status list now covers it, and the review is frozen.
	st, _ := os.ReadFile(filepath.Join(root, site.StatusPath))
	if !strings.Contains(string(st), "att-manual-0000000001") {
		t.Error("status list does not cover the attestation")
	}
	if err := r.AddManual(manualFinding("low")); err == nil {
		t.Error("a signed review accepted a new finding")
	}
}

func TestEngineFindingsNeedDecisions(t *testing.T) {
	r := newReview(t, KindLLM)
	if err := r.AddManual(manualFinding("low")); err == nil {
		t.Fatal("hand-written finding accepted in an LLM review")
	}
	// Simulate a finished engine run.
	r.Update(func(x *Review) error {
		x.Agent = &AgentRun{State: "done", StopReason: "end_turn", TranscriptDigest: sig.Digest([]byte("[]"))}
		x.Coverage = agent.Coverage{Declared: true, Complete: true, Examined: []string{}, NotExamined: []string{}}
		f := manualFinding("critical")
		f.Verified = true
		x.Findings = []Finding{{Finding: f, Source: "engine", Status: Pending}}
		renumber(x.Findings)
		return nil
	})
	if b := r.Blockers(); len(b) != 1 || !strings.Contains(b[0], "decide") {
		t.Fatalf("blockers %v", b)
	}
	if err := r.Decide("F1", "drop", ""); err == nil {
		t.Error("drop without a reason accepted")
	}
	if err := r.Decide("F1", "delete", ""); err == nil {
		t.Error("engine finding deleted")
	}
	if err := r.Decide("F1", "drop", "not reachable from untrusted input"); err != nil {
		t.Fatal(err)
	}
	if r.ResultClass() != audit.Clear || len(r.Blockers()) != 0 {
		t.Errorf("class %s blockers %v", r.ResultClass(), r.Blockers())
	}
}

func TestCommissionedFailIsHeldUntilEmbargoEnds(t *testing.T) {
	root, c := publicTree(t)
	r := newReview(t, KindManual)
	r.AddManual(manualFinding("critical"))
	r.SetCoverage(agent.Coverage{Summary: "Read src/.", Complete: true})

	// A queued order from the subject.
	subject := key("subject")
	scope := []byte("src/ signature checks\n")
	o := audit.AuditOrder{OrderVersion: 1, OrderID: "ord-commissioned-0001", Auditor: c.ComponentID, Subject: "onym:component:example", Sponsor: site.KeyOf(subject),
		Artifact: audit.Artifact{Kind: audit.KindSource, Source: repoURL, Revision: commit}, MethodologyCls: audit.SecurityReview,
		Scope:       audit.DocRef{URI: c.BaseURI + "scopes/order-ord-commissioned-0001.md", Digest: sig.Digest(scope)},
		Cooperation: "public", Disclosure: audit.Disclosure{FindingsToSubjectFirst: true, EmbargoDays: 90, AttestationPublication: "public-on-issuance", FailPublication: "public-after-embargo"},
		Timeline: map[string]string{"start": "2026-09-24", "reportDue": "2026-10-01"}, Fee: audit.Fee{Model: "pro-bono", OfferID: "x"}, Signatures: []audit.OrderSignature{}}
	ob, _ := audit.CanonicalOf(o)
	ob, _ = audit.SignOrder(ob, "subject", subject)
	ob, _ = audit.SignOrder(ob, "sponsor", subject)
	odir := filepath.Join(t.TempDir(), o.OrderID)
	os.MkdirAll(odir, 0o755)
	os.WriteFile(filepath.Join(odir, "order.json"), ob, 0o644)
	os.WriteFile(filepath.Join(odir, "scope.md"), scope, 0o644)

	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	opts := SignOptions{PublicRoot: root, Config: c, AuditorKey: key("auditor"), StatusKey: key("status"), AttestationID: "att-commissioned-001", Relationships: "none", OrderDir: odir, Now: now}
	if _, err := r.Sign(opts); err == nil || !strings.Contains(err.Error(), "findings to reach the subject first") {
		t.Fatalf("signed before the findings reached the subject: %v", err)
	}
	opts.FindingsSentAt = "2026-09-24T11:00:00Z"
	s, err := r.Sign(opts)
	if err != nil {
		t.Fatal(err)
	}
	if s.Result != audit.Fail || s.HeldUntil == "" || s.Held["attestations/att-commissioned-001.json"] == "" {
		t.Fatalf("fail not held: %+v", s)
	}
	if _, err := os.Stat(filepath.Join(root, "attestations", "att-commissioned-001.json")); err == nil {
		t.Fatal("a fail was published inside the order's embargo")
	}
	// The countersigned order and its scope wait with the attestation: an
	// order published alone would say the result was a fail.
	if _, err := os.Stat(filepath.Join(root, "orders", o.OrderID+".json")); err == nil {
		t.Fatal("the order of a held fail was published")
	}
	if _, err := os.Stat(filepath.Join(root, "scopes", "order-"+o.OrderID+".md")); err == nil {
		t.Fatal("the scope of a held fail was published")
	}
	full := []byte(s.Held["orders/"+o.OrderID+".json"])
	if full, err = os.ReadFile(string(full)); err != nil {
		t.Fatal(err)
	}
	if _, err := audit.ParseOrder(full); err != nil {
		t.Fatalf("held order: %v", err)
	}
	if err := r.Release(root, c, key("status"), now.Add(24*time.Hour)); err == nil {
		t.Error("released inside the embargo")
	}
	if err := r.Release(root, c, key("status"), now.Add(91*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "attestations", "att-commissioned-001.json"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := audit.ParseAttestation(raw)
	if err != nil {
		t.Fatal(err)
	}
	if a.Engagement != "commissioned" || a.OrderRef == nil || *a.OrderRef != sig.Digest(full) || a.SubjectOperator != site.KeyOf(subject) {
		t.Errorf("commissioned attestation %+v", a)
	}
}

// A planted order cannot choose where signing writes: the scope's path is
// the one its order id names.
func TestOrderScopePathIsPinned(t *testing.T) {
	root, c := publicTree(t)
	r := newReview(t, KindManual)
	r.AddManual(manualFinding("low"))
	r.SetCoverage(agent.Coverage{Summary: "Read src/.", Complete: true})
	subject := key("subject")
	scope := []byte("console.log('planted')\n")
	o := audit.AuditOrder{OrderVersion: 1, OrderID: "ord-planted-00000001", Auditor: c.ComponentID, Subject: "onym:component:example", Sponsor: site.KeyOf(subject),
		Artifact: audit.Artifact{Kind: audit.KindSource, Source: repoURL, Revision: commit}, MethodologyCls: audit.SecurityReview,
		Scope:       audit.DocRef{URI: c.BaseURI + "../tools/verify-js-test.mjs", Digest: sig.Digest(scope)},
		Cooperation: "public", Disclosure: audit.Disclosure{FindingsToSubjectFirst: true, EmbargoDays: 0, AttestationPublication: "public-on-issuance", FailPublication: "public-on-issuance"},
		Timeline: map[string]string{"start": "2026-09-24", "reportDue": "2026-10-01"}, Fee: audit.Fee{Model: "pro-bono", OfferID: "x"}, Signatures: []audit.OrderSignature{}}
	ob, _ := audit.CanonicalOf(o)
	ob, _ = audit.SignOrder(ob, "subject", subject)
	ob, _ = audit.SignOrder(ob, "sponsor", subject)
	odir := filepath.Join(t.TempDir(), o.OrderID)
	os.MkdirAll(odir, 0o755)
	os.WriteFile(filepath.Join(odir, "order.json"), ob, 0o644)
	os.WriteFile(filepath.Join(odir, "scope.md"), scope, 0o644)
	opts := SignOptions{PublicRoot: root, Config: c, AuditorKey: key("auditor"), StatusKey: key("status"), AttestationID: "att-planted-000001", Relationships: "none",
		OrderDir: odir, FindingsSentAt: "2026-09-24T11:00:00Z", Now: time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)}
	if _, err := r.Sign(opts); err == nil || !strings.Contains(err.Error(), "scope must be") {
		t.Fatalf("signed an order whose scope names another path: %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(root), "tools", "verify-js-test.mjs")); err == nil {
		t.Fatal("a file was written outside the public tree")
	}
}
