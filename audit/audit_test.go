package audit

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"onym-audit/canon"
	"onym-audit/sig"
)

// Fixtures (profile §10 / Audit.md §14) are generated deterministically from
// seeded keys and a fixed clock, byte-pinned under testdata/fixtures, and
// re-derived on every run: `go test ./audit -update` rewrites them.
var update = flag.Bool("update", false, "rewrite byte-pinned fixtures")

var t0 = time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)

func seeded(label string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte("onym-audit fixture key: " + label))
	return ed25519.NewKeyFromSeed(s[:])
}

func keyOf(p ed25519.PrivateKey) sig.Key { return sig.KeyOf(p.Public().(ed25519.PublicKey)) }

func ptr[T any](v T) *T { return &v }

func ref(path, content string) DocRef {
	return DocRef{URI: "https://audit.example.org/" + path, Digest: sig.Digest([]byte(content))}
}

type world struct {
	auditor, status, subject, other ed25519.PrivateKey
	manifest                        []byte
	m                               *AuditorManifest
	subjectManifestURI              string
	subjectManifest                 []byte
	files                           map[string][]byte
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{
		auditor: seeded("auditor"), status: seeded("status"),
		subject: seeded("subject"), other: seeded("other-auditor"),
		subjectManifestURI: "https://discovery.example.net/manifest.json",
		subjectManifest:    []byte(`{"seat":"discovery","example":true}`),
		files:              map[string][]byte{},
	}
	man := AuditorManifest{
		Version: 1, ComponentID: "onym:component:example-auditor", Seat: "audit",
		Operator: keyOf(w.auditor), DisplayName: "Example Auditor", Contact: "mailto:audit@example.org",
		AuditProfileID: ProfileID, AuditProfile: ref("profile.json", "profile"),
		Methodologies:      []Methodology{{Class: ConformanceRun, Specification: ref("methodology/conformance-run.md", "m"), ScopesOffered: []string{"discovery"}}},
		IndependencePolicy: ref("policies/independence.md", "i"), UnsolicitedPolicy: ref("policies/unsolicited.md", "u"),
		Liability: ref("policies/liability.md", "l"), SeverityScale: ref("severity-v1.json", "s"), PrivacyProfile: ref("privacy.md", "p"),
		StatusEndpoint: "https://audit.example.org/status.json", StatusKey: keyOf(w.status),
		Offers: []string{"conformance-run-discovery"}, ValidUntil: "2027-09-24T00:00:00Z",
	}
	raw, err := SignDoc(man, w.auditor)
	if err != nil {
		t.Fatal(err)
	}
	w.manifest = raw
	if w.m, err = ParseManifest(raw, t0); err != nil {
		t.Fatal(err)
	}
	w.files["auditor-manifest.json"] = raw
	return w
}

func (w *world) attestation(id string, mut func(*Attestation)) Attestation {
	a := Attestation{
		AttestationVersion: 1, AttestationID: id,
		Auditor: w.m.ComponentID, AuditorKey: w.m.Operator,
		Subject: "onym:component:example-discovery", SubjectOperator: keyOf(w.subject),
		Artifact:         Artifact{Kind: KindDeployment, Source: w.subjectManifestURI, Revision: sig.Digest(w.subjectManifest)},
		MethodologyClass: ConformanceRun, Methodology: ref("methodology/conformance-run.md", "m"),
		Scope: ref("scopes/discovery-provider.md", "scope"), ScopeSummary: "Discovery provider publisher obligations",
		Exclusions: []string{"client behaviour", "host security"},
		Result:     Clear, SeverityScale: ptr(ref("severity-v1.json", "s")), SeverityFloor: ptr("low"),
		FindingsSummary: map[string]int{}, Engagement: "unsolicited",
		Sponsor: w.m.Operator, SponsorName: "Example Auditor (self-funded)", Relationships: "none",
		Unsolicited: &UnsolicitedDisclosure{Policy: ref("policies/unsolicited.md", "u").Digest, SubjectContact: "mailto:security@example.net", SubjectNotifiedAt: "2026-09-24T09:00:00Z"},
		IssuedAt:    "2026-09-24T10:00:00Z", ExpiresAt: ptr("2027-03-24T10:00:00Z"),
		Status: w.m.StatusEndpoint,
	}
	if mut != nil {
		mut(&a)
	}
	return a
}

func (w *world) sign(t *testing.T, name string, v any, k ed25519.PrivateKey) []byte {
	t.Helper()
	raw, err := SignDoc(v, k)
	if err != nil {
		t.Fatal(err)
	}
	w.files[name] = raw
	return raw
}

func (w *world) statusFor(t *testing.T, name string, now time.Time, pubs ...Published) []byte {
	t.Helper()
	raw, err := BuildStatus(w.m, pubs, now, 0, w.status)
	if err != nil {
		t.Fatal(err)
	}
	w.files[name] = raw
	return raw
}

func pub(t *testing.T, raw []byte, name string) Published {
	t.Helper()
	a, err := ParseAttestation(raw)
	if err != nil {
		t.Fatal(err)
	}
	return Published{Attestation: a, Ref: DocRef{URI: "https://audit.example.org/attestations/" + name, Digest: sig.Digest(raw)}}
}

func (w *world) input(att, status []byte) Input {
	return Input{
		Attestation: att, Manifest: w.manifest, Status: status,
		Target: DeploymentTarget(w.subjectManifestURI, w.subjectManifest, nil),
		Trust:  Trust{Credited: map[sig.Key]bool{w.m.Operator: true}},
		State:  &StatusState{}, Now: t0,
	}
}

func expect(t *testing.T, name string, d Decision, display, errCode string) {
	t.Helper()
	if d.Display != display || d.Error != errCode {
		t.Errorf("%s: got display=%q error=%q notes=%v, want display=%q error=%q", name, d.Display, d.Error, d.Notes, display, errCode)
	}
}

func TestLifecycleAndDisplayDecisions(t *testing.T) {
	w := newWorld(t)
	a1 := w.sign(t, "att-active.json", w.attestation("att-active-000000001", nil), w.auditor)
	fail := w.sign(t, "att-fail.json", w.attestation("att-fail-0000000001", func(a *Attestation) {
		a.Result, a.FindingsSummary = Fail, map[string]int{"high": 1}
		a.Artifact.Revision = sig.Digest([]byte("other manifest"))
	}), w.auditor)
	status := w.statusFor(t, "status-fresh.json", t0, pub(t, a1, "att-active.json"))

	d := Verify(w.input(a1, status))
	expect(t, "active, fresh, credited", d, ShowAttested, "")
	if !d.HighStakesOK || d.Render.Sponsor == "" || d.Render.Relationships != "none" || len(d.Render.Exclusions) != 2 {
		t.Errorf("render incomplete: %+v", d.Render)
	}

	// §7.3 near miss: same source, other manifest bytes → no attestation.
	in := w.input(fail, status)
	expect(t, "hash mismatch", Verify(in), ShowNone, ErrArtifactMismatch.Error())

	// §7.4/§7.5 absence vs fail: a matched fail renders as a result, absence as nothing.
	in = w.input(fail, w.statusFor(t, "status-fail.json", t0, pub(t, fail, "att-fail.json")))
	in.Target.Revision = sig.Digest([]byte("other manifest"))
	d = Verify(in)
	expect(t, "adverse result shown", d, ShowAttested, "")
	if d.Render.Result != Fail {
		t.Errorf("fail not rendered: %+v", d.Render)
	}
	if Absent().Display != ShowNone || Absent().Error != "" {
		t.Error("absence must render as absence, not failure")
	}

	// Supersession and revocation (§5.5).
	a2 := w.sign(t, "att-successor.json", w.attestation("att-successor-00000001", func(a *Attestation) { a.Supersedes = ptr("att-active-000000001") }), w.auditor)
	st := w.statusFor(t, "status-superseded.json", t0, pub(t, a1, "att-active.json"), pub(t, a2, "att-successor.json"))
	d = Verify(w.input(a1, st))
	expect(t, "superseded", d, ShowSuperseded, ErrSuperseded.Error())

	rev := w.sign(t, "revocation.json", Revocation{RevocationVersion: 1, AttestationID: "att-active-000000001", Auditor: w.m.ComponentID, AuditorKey: w.m.Operator, IssuedAt: "2026-09-24T11:00:00Z", StatusEpoch: t0.Unix(), EffectiveFrom: "2026-09-24T11:00:00Z", Reason: "new-information"}, w.auditor)
	p := pub(t, a1, "att-active.json")
	p.Revocation, p.RevokedFrom = &DocRef{URI: "https://audit.example.org/revocations/att-active.json", Digest: sig.Digest(rev)}, t0.Add(-time.Hour)
	st = w.statusFor(t, "status-revoked.json", t0, p)
	in = w.input(a1, st)
	in.Revocation = rev
	d = Verify(in)
	expect(t, "revoked", d, ShowRevoked, ErrRevoked.Error())
	if d.Render.RevokedReason != "new-information" {
		t.Errorf("reason class not shown: %+v", d.Render)
	}

	// Expiry, local and in the list.
	short := w.sign(t, "att-short.json", w.attestation("att-short-000000001", func(a *Attestation) { a.ExpiresAt = ptr("2026-09-24T11:00:00Z") }), w.auditor)
	d = Verify(w.input(short, w.statusFor(t, "status-expired.json", t0, pub(t, short, "att-short.json"))))
	expect(t, "expired", d, ShowExpired, ErrExpired.Error())
}

func TestStatusFreshnessAndRollback(t *testing.T) {
	w := newWorld(t)
	a := w.sign(t, "att.json", w.attestation("att-status-000000001", nil), w.auditor)
	newer := w.statusFor(t, "status-newer.json", t0, pub(t, a, "att.json"))
	older := w.statusFor(t, "status-older.json", t0.Add(-time.Hour), pub(t, a, "att.json"))

	in := w.input(a, newer)
	expect(t, "newer", Verify(in), ShowAttested, "")
	in.Status = older // same retained state: a lower epoch is a rollback
	d := Verify(in)
	expect(t, "rollback", d, ShowStatusUnknown, ErrStatusRollback.Error())
	if d.HighStakesOK {
		t.Error("rollback must not allow high-stakes reliance")
	}

	stale := w.statusFor(t, "status-stale.json", t0.Add(-72*time.Hour), pub(t, a, "att.json"))
	d = Verify(w.input(a, stale))
	expect(t, "stale", d, ShowStatusUnknown, ErrStatusUnavailable.Error())

	d = Verify(w.input(a, nil))
	expect(t, "no status", d, ShowStatusUnknown, ErrStatusUnavailable.Error())

	// A list signed by the operator key instead of the delegated statusKey.
	forged, _ := BuildStatus(&AuditorManifest{ComponentID: w.m.ComponentID, Operator: w.m.Operator, StatusKey: keyOf(w.auditor)}, []Published{pub(t, a, "att.json")}, t0, 0, w.auditor)
	d = Verify(w.input(a, forged))
	expect(t, "wrong status key", d, ShowStatusUnknown, ErrStatusInvalid.Error())
}

func TestIssuerTrustFiltering(t *testing.T) {
	w := newWorld(t)
	a := w.sign(t, "att.json", w.attestation("att-trust-0000000001", nil), w.auditor)
	st := w.statusFor(t, "status.json", t0, pub(t, a, "att.json"))
	in := w.input(a, st)
	in.Trust = Trust{}
	d := Verify(in)
	expect(t, "uncredited shown", d, ShowUncredited, ErrIssuerUntrusted.Error())
	if d.HighStakesOK || !strings.Contains(d.Summary(t0), "uncredited issuer") {
		t.Errorf("uncredited must be labelled: %s", d.Summary(t0))
	}
	in.Trust.OmitUncredited = true
	expect(t, "uncredited omitted", Verify(in), ShowNone, ErrIssuerUntrusted.Error())

	// An attestation signed by a key other than the manifest operator's.
	foreign := w.attestation("att-foreign-00000001", nil)
	foreign.AuditorKey = keyOf(w.other)
	fr := w.sign(t, "att-foreign.json", foreign, w.other)
	expect(t, "foreign signer", Verify(w.input(fr, st)), ShowNone, ErrAttestationInvalid.Error())
}

func TestNearMissVectors(t *testing.T) {
	w := newWorld(t)
	commit := strings.Repeat("a", 40)
	build := sig.Digest([]byte("app build 1"))
	a := w.sign(t, "att-build.json", w.attestation("att-build-000000001", func(a *Attestation) {
		a.Artifact = Artifact{Kind: KindBuild, Source: "https://github.com/example/app", Revision: commit, ArtifactHash: &build}
		a.MethodologyClass, a.ExpiresAt = BuildProvenance, nil
	}), w.auditor)
	st := w.statusFor(t, "status.json", t0, pub(t, a, "att-build.json"))
	for name, tgt := range map[string]Target{
		"exact":                    {Kind: KindBuild, Source: "https://github.com/example/app", Revision: commit, ArtifactHash: &build},
		"right repo, wrong rev":    {Kind: KindBuild, Source: "https://github.com/example/app", Revision: strings.Repeat("b", 40), ArtifactHash: &build},
		"right rev, wrong build":   {Kind: KindBuild, Source: "https://github.com/example/app", Revision: commit, ArtifactHash: ptr(sig.Digest([]byte("app build 2")))},
		"fork, same rev and build": {Kind: KindBuild, Source: "https://github.com/fork/app", Revision: commit, ArtifactHash: &build},
		"source kind, same commit": {Kind: KindSource, Source: "https://github.com/example/app", Revision: commit},
	} {
		in := w.input(a, st)
		in.Target = tgt
		d := Verify(in)
		if name == "exact" {
			expect(t, name, d, ShowAttested, "")
		} else {
			expect(t, name, d, ShowNone, ErrArtifactMismatch.Error())
		}
	}
}

func TestUnsolicitedAndSubjectResponse(t *testing.T) {
	w := newWorld(t)
	for name, mut := range map[string]func(*Attestation){
		"notified after publication": func(a *Attestation) { a.Unsolicited.SubjectNotifiedAt = "2026-09-24T11:00:00Z" },
		"no disclosure block":        func(a *Attestation) { a.Unsolicited = nil },
		"with an orderRef":           func(a *Attestation) { a.OrderRef = ptr(sig.Digest([]byte("order"))) },
		"clear without scale":        func(a *Attestation) { a.SeverityScale = nil },
		"judgment without expiry":    func(a *Attestation) { a.ExpiresAt = nil },
		"no relationships stated":    func(a *Attestation) { a.Relationships = "" },
		"bucket off the scale":       func(a *Attestation) { a.FindingsSummary = map[string]int{"severe": 1} },
	} {
		raw := w.sign(t, "invalid.json", w.attestation("att-invalid-00000001", mut), w.auditor)
		if _, err := ParseAttestation(raw); !errors.Is(err, ErrAttestationInvalid) {
			t.Errorf("%s: accepted", name)
		}
	}
	delete(w.files, "invalid.json")

	a := w.sign(t, "att-unsolicited.json", w.attestation("att-unsolicited-0001", nil), w.auditor)
	parsed, _ := ParseAttestation(a)
	resp := SubjectResponse{ResponseVersion: 1, ResponseID: "resp-00000000000001", AttestationID: parsed.AttestationID, Attestation: sig.Digest(a), Subject: parsed.Subject, Respondent: keyOf(w.subject), IssuedAt: "2026-09-24T11:30:00Z", Text: "Snapshot republished on 2026-09-24; see sequence 5."}
	good := w.sign(t, "response.json", resp, w.subject)
	forgedResp := resp
	forgedResp.Respondent = keyOf(w.other)
	forged := w.sign(t, "response-forged.json", forgedResp, w.other)
	if _, err := ParseResponse(forged, parsed, sig.Digest(a)); !errors.Is(err, ErrResponseInvalid) {
		t.Error("a reply not signed by the subject's operator key was accepted")
	}
	p := pub(t, a, "att-unsolicited.json")
	p.Responses = []DocRef{{URI: "https://audit.example.org/responses/resp.json", Digest: sig.Digest(good)}}
	in := w.input(a, w.statusFor(t, "status-response.json", t0, p))
	in.Responses = map[string][]byte{sig.Digest(good): good}
	d := Verify(in)
	expect(t, "response displayed", d, ShowAttested, "")
	if len(d.Render.Responses) != 1 || !strings.Contains(d.Summary(t0), "Subject replied") {
		t.Errorf("subject response not rendered: %s", d.Summary(t0))
	}
}

func TestEmbargoedReport(t *testing.T) {
	w := newWorld(t)
	a := w.sign(t, "att-embargo.json", w.attestation("att-embargo-00000001", func(a *Attestation) {
		a.Result, a.FindingsReport = FindingsNoted, nil
		a.FindingsSummary = map[string]int{"high": 1, "resolved": 0}
		a.Unsolicited.EmbargoUntil = ptr("2026-12-23T10:00:00Z")
	}), w.auditor)
	d := Verify(w.input(a, w.statusFor(t, "status.json", t0, pub(t, a, "att-embargo.json"))))
	expect(t, "embargoed", d, ShowAttested, "")
	if d.Render.FindingsReport != "" || d.Render.FindingsSummary["high"] != 1 {
		t.Errorf("embargo must show counts and no report: %+v", d.Render)
	}
}

func TestOrders(t *testing.T) {
	w := newWorld(t)
	sponsor := seeded("sponsor")
	o := AuditOrder{
		OrderVersion: 1, OrderID: "order-000000000001", Auditor: w.m.ComponentID, Subject: "onym:component:example-discovery",
		Sponsor: keyOf(sponsor), Artifact: Artifact{Kind: KindDeployment, Source: w.subjectManifestURI, Revision: sig.Digest(w.subjectManifest)},
		MethodologyCls: ConformanceRun, Scope: ref("scopes/discovery-provider.md", "scope"), Cooperation: "read access to the public deployment",
		Disclosure: Disclosure{FindingsToSubjectFirst: true, EmbargoDays: 90, AttestationPublication: "public-on-issuance", FailPublication: "public-after-embargo"},
		Timeline:   map[string]string{"start": "2026-09-24", "reportDue": "2026-09-25"},
		Fee:        Fee{Model: "pro-bono", OfferID: "conformance-run-discovery"}, Signatures: []OrderSignature{},
	}
	raw, err := CanonicalOf(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []struct {
		role string
		k    ed25519.PrivateKey
	}{{"auditor", w.auditor}, {"subject", w.subject}, {"sponsor", sponsor}} {
		if raw, err = SignOrder(raw, s.role, s.k); err != nil {
			t.Fatal(err)
		}
	}
	w.files["order.json"] = raw
	if _, err := ParseOrder(raw); err != nil {
		t.Fatal(err)
	}
	// Acceptance criterion 7: a verdict-contingent fee is expressible nowhere.
	obj, _ := canon.Parse(raw)
	obj["fee"].(canon.Object)["model"] = "bonus-on-clear"
	bad, _ := canon.Encode(obj)
	if _, err := ParseOrder(bad); err == nil {
		t.Error("contingent fee model accepted")
	}
	obj["fee"].(canon.Object)["model"] = "pro-bono"
	obj["fee"].(canon.Object)["bonusOnClear"] = canon.Number("100")
	bad, _ = canon.Encode(obj)
	if _, err := ParseOrder(bad); err == nil {
		t.Error("extra fee field accepted")
	}
}

// Strictness: unknown or case-variant keys are rejected, never matched.
func TestStrictKeys(t *testing.T) {
	w := newWorld(t)
	a := w.sign(t, "att.json", w.attestation("att-strict-00000001", nil), w.auditor)
	obj, _ := canon.Parse(a)
	obj["Result"] = "fail"
	bad, _ := sig.Sign(obj, "signature", w.auditor)
	if _, err := ParseAttestation(bad); !errors.Is(err, ErrAttestationInvalid) {
		t.Error("case-variant key accepted")
	}
}

// The published fixture set (Audit.md §14) is byte-pinned: every case must
// produce its expected decision, and regeneration must reproduce the
// committed bytes exactly. `go test ./audit -update` rewrites them.
func TestFixturesPinned(t *testing.T) {
	files, cases, invalid, err := GenerateFixtures()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		d, err := RunFixtureCase(files, c)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		if d.Display != c.ExpectDisplay || d.Error != c.ExpectError || d.HighStakesOK != c.ExpectHighOK {
			t.Errorf("%s: got %s/%s/%v want %s/%s/%v %v", c.Name, d.Display, d.Error, d.HighStakesOK, c.ExpectDisplay, c.ExpectError, c.ExpectHighOK, d.Notes)
		}
	}
	for _, c := range invalid {
		if err := RunFixtureInvalid(files, c); (err == nil) != c.ExpectOK {
			t.Errorf("%s: parse error %v, expectOK %v", c.Name, err, c.ExpectOK)
		}
	}
	casesJSON, _ := json.MarshalIndent(map[string]any{
		"profile": ProfileID, "keySeeds": FixtureKeySeed, "clock": sig.FormatTime(FixtureClock),
		"cases": cases, "invalid": invalid,
	}, "", "  ")
	files["cases.json"] = append(casesJSON, '\n')
	dir := filepath.Join("..", "fixtures")
	if *update {
		os.RemoveAll(dir)
		os.MkdirAll(dir, 0o755)
		for k, v := range files {
			if err := os.WriteFile(filepath.Join(dir, k), v, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != len(files) {
		t.Errorf("fixtures dir has %d files, generator %d (run go test ./audit -update)", len(entries), len(files))
	}
	for k, v := range files {
		got, err := os.ReadFile(filepath.Join(dir, k))
		if err != nil {
			t.Fatalf("%s: %v (run go test ./audit -update)", k, err)
		}
		if string(got) != string(v) {
			t.Errorf("%s drifted from its pinned bytes", k)
		}
	}
}
