package audit

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"onym-audit/canon"
	"onym-audit/sig"
)

// FixtureCase is one cross-platform verification vector (Audit.md §14,
// profile §10): named input files, the component the client is about to
// use, the relying party's policy, the clock, and the expected decision.
// Another implementation passes by reproducing every Expect from the same
// bytes alone.
type FixtureCase struct {
	Name          string   `json:"name"`
	Covers        string   `json:"covers"`
	Attestation   string   `json:"attestation"`
	Manifest      string   `json:"manifest"`
	Status        []string `json:"status,omitempty"` // applied in order to one retained state; the last decides
	Revocation    string   `json:"revocation,omitempty"`
	Responses     []string `json:"responses,omitempty"`
	Target        Target   `json:"target"`
	CreditAuditor bool     `json:"creditAuditor"`
	OmitUncredit  bool     `json:"omitUncredited,omitempty"`
	Now           string   `json:"now"`
	ExpectDisplay string   `json:"expectDisplay"`
	ExpectError   string   `json:"expectError"`
	ExpectHighOK  bool     `json:"expectHighStakesOK"`
}

// FixtureInvalid is a document that must be rejected at parse time.
type FixtureInvalid struct {
	Name     string `json:"name"`
	Covers   string `json:"covers"`
	Kind     string `json:"kind"` // attestation | order | response
	File     string `json:"file"`
	Context  string `json:"context,omitempty"` // for responses: the attestation file answered
	ExpectOK bool   `json:"expectOK"`
}

// FixtureKeySeed derives the deterministic fixture keys.
const FixtureKeySeed = `sha256("onym-audit fixture key: " + label)`

func fixtureKey(label string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte("onym-audit fixture key: " + label))
	return ed25519.NewKeyFromSeed(s[:])
}

// FixtureClock is the fixed verification time of every case.
var FixtureClock = time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)

type fixtureGen struct {
	files                            map[string][]byte
	auditor, statusK, subject, other ed25519.PrivateKey
	sponsor                          ed25519.PrivateKey
	m                                *AuditorManifest
	subjectURI                       string
	subjectBytes                     []byte
	err                              error
}

func (g *fixtureGen) key(p ed25519.PrivateKey) sig.Key {
	return sig.KeyOf(p.Public().(ed25519.PublicKey))
}

func fref(path, content string) DocRef {
	return DocRef{URI: "https://audit.example.org/" + path, Digest: sig.Digest([]byte(content))}
}

func sp[T any](v T) *T { return &v }

func (g *fixtureGen) put(name string, v any, k ed25519.PrivateKey) []byte {
	if g.err != nil {
		return nil
	}
	raw, err := SignDoc(v, k)
	if err != nil {
		g.err = fmt.Errorf("%s: %w", name, err)
		return nil
	}
	g.files[name] = raw
	return raw
}

func (g *fixtureGen) attestation(id string, mut func(*Attestation)) Attestation {
	a := Attestation{
		AttestationVersion: 1, AttestationID: id,
		Auditor: g.m.ComponentID, AuditorKey: g.m.Operator,
		Subject: "onym:component:example-discovery", SubjectOperator: g.key(g.subject),
		Artifact:         Artifact{Kind: KindDeployment, Source: g.subjectURI, Revision: sig.Digest(g.subjectBytes)},
		MethodologyClass: ConformanceRun, Methodology: fref("methodology/conformance-run.md", "m"),
		Scope: fref("scopes/discovery-provider.md", "scope"), ScopeSummary: "Discovery provider publisher obligations",
		Exclusions: []string{"client behaviour", "host security"},
		Result:     Clear, SeverityScale: sp(fref("severity-v1.json", "s")), SeverityFloor: sp("low"),
		FindingsSummary: map[string]int{}, Engagement: "unsolicited",
		Sponsor: g.m.Operator, SponsorName: "Example Auditor (self-funded)", Relationships: "none",
		Unsolicited: &UnsolicitedDisclosure{Policy: fref("policies/unsolicited.md", "u").Digest, SubjectContact: "mailto:security@example.net", SubjectNotifiedAt: "2026-09-24T09:00:00Z"},
		IssuedAt:    "2026-09-24T10:00:00Z", ExpiresAt: sp("2027-03-24T10:00:00Z"),
		Status: g.m.StatusEndpoint,
	}
	if mut != nil {
		mut(&a)
	}
	return a
}

func (g *fixtureGen) published(name string) Published {
	raw := g.files[name]
	a, err := ParseAttestation(raw)
	if err != nil && g.err == nil {
		g.err = fmt.Errorf("%s: %w", name, err)
	}
	return Published{Attestation: a, Ref: DocRef{URI: "https://audit.example.org/attestations/" + name, Digest: sig.Digest(raw)}}
}

func (g *fixtureGen) status(name string, at time.Time, pubs ...Published) {
	if g.err != nil {
		return
	}
	raw, err := BuildStatus(g.m, pubs, at, 0, g.statusK)
	if err != nil {
		g.err = err
		return
	}
	g.files[name] = raw
}

// GenerateFixtures derives the complete, deterministic fixture set.
func GenerateFixtures() (map[string][]byte, []FixtureCase, []FixtureInvalid, error) {
	g := &fixtureGen{
		files:   map[string][]byte{},
		auditor: fixtureKey("auditor"), statusK: fixtureKey("status"), subject: fixtureKey("subject"),
		other: fixtureKey("other-auditor"), sponsor: fixtureKey("sponsor"),
		subjectURI:   "https://discovery.example.net/manifest.json",
		subjectBytes: []byte(`{"seat":"discovery","example":true}`),
	}
	g.files["subject-manifest.json"] = g.subjectBytes
	man := AuditorManifest{
		Version: 1, ComponentID: "onym:component:example-auditor", Seat: "audit",
		Operator: g.key(g.auditor), DisplayName: "Example Auditor", Contact: "mailto:audit@example.org",
		AuditProfileID: ProfileID, AuditProfile: fref("profile.json", "profile"),
		Methodologies:      []Methodology{{Class: ConformanceRun, Specification: fref("methodology/conformance-run.md", "m"), ScopesOffered: []string{"discovery"}}},
		IndependencePolicy: fref("policies/independence.md", "i"), UnsolicitedPolicy: fref("policies/unsolicited.md", "u"),
		Liability: fref("policies/liability.md", "l"), SeverityScale: fref("severity-v1.json", "s"), PrivacyProfile: fref("privacy.md", "p"),
		StatusEndpoint: "https://audit.example.org/status.json", StatusKey: g.key(g.statusK),
		Offers: []string{"conformance-run-discovery"}, ValidUntil: "2027-09-24T00:00:00Z",
	}
	raw := g.put("auditor-manifest.json", man, g.auditor)
	if g.err != nil {
		return nil, nil, nil, g.err
	}
	var err error
	if g.m, err = ParseManifest(raw, FixtureClock); err != nil {
		return nil, nil, nil, err
	}
	t0 := FixtureClock
	commit := strings.Repeat("a", 40)
	build := sig.Digest([]byte("app build 1"))

	g.put("att-active.json", g.attestation("att-active-000000001", nil), g.auditor)
	g.put("att-fail.json", g.attestation("att-fail-0000000001", func(a *Attestation) {
		a.Result, a.FindingsSummary = Fail, map[string]int{"high": 1}
	}), g.auditor)
	g.put("att-successor.json", g.attestation("att-successor-00000001", func(a *Attestation) { a.Supersedes = sp("att-active-000000001") }), g.auditor)
	g.put("att-short.json", g.attestation("att-short-000000001", func(a *Attestation) { a.ExpiresAt = sp("2026-09-24T11:00:00Z") }), g.auditor)
	g.put("att-embargo.json", g.attestation("att-embargo-00000001", func(a *Attestation) {
		a.Result, a.FindingsReport = FindingsNoted, nil
		a.FindingsSummary = map[string]int{"high": 1, "resolved": 0}
		a.Unsolicited.EmbargoUntil = sp("2026-12-23T10:00:00Z")
	}), g.auditor)
	g.put("att-build.json", g.attestation("att-build-000000001", func(a *Attestation) {
		a.Artifact = Artifact{Kind: KindBuild, Source: "https://github.com/example/app", Revision: commit, ArtifactHash: &build}
		a.MethodologyClass, a.ExpiresAt = BuildProvenance, nil
	}), g.auditor)
	foreign := g.attestation("att-foreign-00000001", nil)
	foreign.AuditorKey = g.key(g.other)
	g.put("att-foreign.json", foreign, g.other)

	g.put("revocation.json", Revocation{RevocationVersion: 1, AttestationID: "att-active-000000001", Auditor: g.m.ComponentID, AuditorKey: g.m.Operator, IssuedAt: "2026-09-24T11:00:00Z", StatusEpoch: t0.Unix() - 3600, EffectiveFrom: "2026-09-24T11:00:00Z", Reason: "new-information"}, g.auditor)
	attDigest := sig.Digest(g.files["att-active.json"])
	resp := SubjectResponse{ResponseVersion: 1, ResponseID: "resp-00000000000001", AttestationID: "att-active-000000001", Attestation: attDigest, Subject: "onym:component:example-discovery", Respondent: g.key(g.subject), IssuedAt: "2026-09-24T11:30:00Z", Text: "Snapshot republished on 2026-09-24; see sequence 5."}
	g.put("response.json", resp, g.subject)
	forged := resp
	forged.Respondent = g.key(g.other)
	g.put("response-forged.json", forged, g.other)

	active := g.published("att-active.json")
	g.status("status-fresh.json", t0, active, g.published("att-fail.json"), g.published("att-embargo.json"), g.published("att-build.json"))
	g.status("status-older.json", t0.Add(-time.Hour), active)
	g.status("status-stale.json", t0.Add(-72*time.Hour), active)
	g.status("status-superseded.json", t0, active, g.published("att-successor.json"))
	rv := active
	rv.Revocation, rv.RevokedFrom = &DocRef{URI: "https://audit.example.org/revocations/att-active.json", Digest: sig.Digest(g.files["revocation.json"])}, t0.Add(-time.Hour)
	g.status("status-revoked.json", t0, rv)
	g.status("status-expired.json", t0, g.published("att-short.json"))
	withResp := active
	withResp.Responses = []DocRef{{URI: "https://audit.example.org/responses/response.json", Digest: sig.Digest(g.files["response.json"])}}
	g.status("status-response.json", t0, withResp)
	// A list signed by the operator key rather than the delegated status key.
	if g.err == nil {
		wrong := *g.m
		wrong.StatusKey = g.key(g.auditor)
		b, err := BuildStatus(&wrong, []Published{active}, t0, 0, g.auditor)
		if err != nil {
			return nil, nil, nil, err
		}
		g.files["status-wrong-key.json"] = b
	}

	// Invalid documents.
	for name, mut := range map[string]func(*Attestation){
		"invalid-notified-after-publication.json":     func(a *Attestation) { a.Unsolicited.SubjectNotifiedAt = "2026-09-24T11:00:00Z" },
		"invalid-unsolicited-without-disclosure.json": func(a *Attestation) { a.Unsolicited = nil },
		"invalid-unsolicited-with-order.json":         func(a *Attestation) { a.OrderRef = sp(sig.Digest([]byte("order"))) },
		"invalid-clear-without-scale.json":            func(a *Attestation) { a.SeverityScale = nil },
		"invalid-judgment-without-expiry.json":        func(a *Attestation) { a.ExpiresAt = nil },
		"invalid-no-relationships.json":               func(a *Attestation) { a.Relationships = "" },
		"invalid-bucket-off-scale.json":               func(a *Attestation) { a.FindingsSummary = map[string]int{"severe": 1} },
	} {
		g.put(name, g.attestation("att-invalid-00000001", mut), g.auditor)
	}
	if g.err != nil {
		return nil, nil, nil, g.err
	}
	// A case-variant key smuggled in and re-signed: strict decoding rejects it.
	if obj, err := canon.Parse(g.files["att-active.json"]); err == nil {
		obj["Result"] = Fail
		b, _ := sig.Sign(obj, "signature", g.auditor)
		g.files["invalid-case-variant-key.json"] = b
	}

	order := AuditOrder{
		OrderVersion: 1, OrderID: "order-000000000001", Auditor: g.m.ComponentID, Subject: "onym:component:example-discovery",
		Sponsor: g.key(g.sponsor), Artifact: Artifact{Kind: KindDeployment, Source: g.subjectURI, Revision: sig.Digest(g.subjectBytes)},
		MethodologyCls: ConformanceRun, Scope: fref("scopes/discovery-provider.md", "scope"), Cooperation: "read access to the public deployment",
		Disclosure: Disclosure{FindingsToSubjectFirst: true, EmbargoDays: 90, AttestationPublication: "public-on-issuance", FailPublication: "public-after-embargo"},
		Timeline:   map[string]string{"start": "2026-09-24", "reportDue": "2026-09-25"},
		Fee:        Fee{Model: "pro-bono", OfferID: "conformance-run-discovery"}, Signatures: []OrderSignature{},
	}
	ob, err := CanonicalOf(order)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, s := range []struct {
		role string
		k    ed25519.PrivateKey
	}{{"auditor", g.auditor}, {"subject", g.subject}, {"sponsor", g.sponsor}} {
		if ob, err = SignOrder(ob, s.role, s.k); err != nil {
			return nil, nil, nil, err
		}
	}
	g.files["order.json"] = ob
	if obj, err := canon.Parse(ob); err == nil {
		obj["fee"].(canon.Object)["model"] = "bonus-on-clear"
		b, _ := canon.Encode(obj)
		g.files["invalid-order-contingent-fee.json"] = b
	}

	deploy := DeploymentTarget(g.subjectURI, g.subjectBytes)
	buildT := Target{Kind: KindBuild, Source: "https://github.com/example/app", Revision: commit, ArtifactHash: &build}
	now := sig.FormatTime(t0)
	cases := []FixtureCase{
		{Name: "active-fresh-credited", Covers: "§6 verify, §7.1–7.2", Attestation: "att-active.json", Status: []string{"status-fresh.json"}, Target: deploy, CreditAuditor: true, ExpectDisplay: ShowAttested, ExpectHighOK: true},
		{Name: "deployment-manifest-drift", Covers: "§7.3 hash mismatch → no attestation", Attestation: "att-active.json", Status: []string{"status-fresh.json"}, Target: Target{Kind: KindDeployment, Source: g.subjectURI, Revision: sig.Digest([]byte("other manifest"))}, CreditAuditor: true, ExpectDisplay: ShowNone, ExpectError: "artifact_mismatch"},
		{Name: "adverse-result-rendered", Covers: "§7.5 fail rendered like favorable results", Attestation: "att-fail.json", Status: []string{"status-fresh.json"}, Target: deploy, CreditAuditor: true, ExpectDisplay: ShowAttested, ExpectHighOK: true},
		{Name: "embargoed-report", Covers: "§5.6 counts without report under embargo", Attestation: "att-embargo.json", Status: []string{"status-fresh.json"}, Target: deploy, CreditAuditor: true, ExpectDisplay: ShowAttested, ExpectHighOK: true},
		{Name: "superseded", Covers: "§5.5 supersession display", Attestation: "att-active.json", Status: []string{"status-superseded.json"}, Target: deploy, CreditAuditor: true, ExpectDisplay: ShowSuperseded, ExpectError: "attestation_superseded"},
		{Name: "revoked", Covers: "§5.5 revocation, reason class", Attestation: "att-active.json", Status: []string{"status-revoked.json"}, Revocation: "revocation.json", Target: deploy, CreditAuditor: true, ExpectDisplay: ShowRevoked, ExpectError: "attestation_revoked"},
		{Name: "expired", Covers: "§5.4.5 expiry", Attestation: "att-short.json", Status: []string{"status-expired.json"}, Target: deploy, CreditAuditor: true, ExpectDisplay: ShowExpired, ExpectError: "attestation_expired"},
		{Name: "status-rollback", Covers: "§5.5 epoch monotonicity, rollback rejected", Attestation: "att-active.json", Status: []string{"status-fresh.json", "status-older.json"}, Target: deploy, CreditAuditor: true, ExpectDisplay: ShowStatusUnknown, ExpectError: "status_rollback"},
		{Name: "status-stale", Covers: "§5.5 stale list is never active", Attestation: "att-active.json", Status: []string{"status-stale.json"}, Target: deploy, CreditAuditor: true, ExpectDisplay: ShowStatusUnknown, ExpectError: "status_unavailable"},
		{Name: "status-absent", Covers: "§12 status_unavailable degrades honestly", Attestation: "att-active.json", Target: deploy, CreditAuditor: true, ExpectDisplay: ShowStatusUnknown, ExpectError: "status_unavailable"},
		{Name: "status-wrong-key", Covers: "profile §5 delegated status key", Attestation: "att-active.json", Status: []string{"status-wrong-key.json"}, Target: deploy, CreditAuditor: true, ExpectDisplay: ShowStatusUnknown, ExpectError: "status_list_invalid"},
		{Name: "subject-response-shown", Covers: "§5.7.5 reply served and displayed beside", Attestation: "att-active.json", Status: []string{"status-response.json"}, Responses: []string{"response.json"}, Target: deploy, CreditAuditor: true, ExpectDisplay: ShowAttested, ExpectHighOK: true},
		{Name: "uncredited-issuer-shown", Covers: "§7.7 issuer-trust filtering", Attestation: "att-active.json", Status: []string{"status-fresh.json"}, Target: deploy, ExpectDisplay: ShowUncredited, ExpectError: "issuer_untrusted"},
		{Name: "uncredited-issuer-omitted", Covers: "§7.7 issuer-trust filtering", Attestation: "att-active.json", Status: []string{"status-fresh.json"}, Target: deploy, OmitUncredit: true, ExpectDisplay: ShowNone, ExpectError: "issuer_untrusted"},
		{Name: "foreign-signer", Covers: "§6 signature by the manifest operator", Attestation: "att-foreign.json", Status: []string{"status-fresh.json"}, Target: deploy, CreditAuditor: true, ExpectDisplay: ShowNone, ExpectError: "attestation_invalid"},
		{Name: "build-exact", Covers: "§14 near-miss vectors", Attestation: "att-build.json", Status: []string{"status-fresh.json"}, Target: buildT, CreditAuditor: true, ExpectDisplay: ShowAttested, ExpectHighOK: true},
		{Name: "build-right-repo-wrong-revision", Covers: "§14 near-miss vectors", Attestation: "att-build.json", Status: []string{"status-fresh.json"}, Target: Target{Kind: KindBuild, Source: buildT.Source, Revision: strings.Repeat("b", 40), ArtifactHash: &build}, CreditAuditor: true, ExpectDisplay: ShowNone, ExpectError: "artifact_mismatch"},
		{Name: "build-right-revision-wrong-build", Covers: "§14 near-miss vectors", Attestation: "att-build.json", Status: []string{"status-fresh.json"}, Target: Target{Kind: KindBuild, Source: buildT.Source, Revision: commit, ArtifactHash: sp(sig.Digest([]byte("app build 2")))}, CreditAuditor: true, ExpectDisplay: ShowNone, ExpectError: "artifact_mismatch"},
		{Name: "build-fork-same-bytes", Covers: "§13.1 bytes, not brands", Attestation: "att-build.json", Status: []string{"status-fresh.json"}, Target: Target{Kind: KindBuild, Source: "https://github.com/fork/app", Revision: commit, ArtifactHash: &build}, CreditAuditor: true, ExpectDisplay: ShowNone, ExpectError: "artifact_mismatch"},
	}
	for i := range cases {
		cases[i].Manifest, cases[i].Now = "auditor-manifest.json", now
	}
	invalid := []FixtureInvalid{
		{Name: "notified-after-publication", Covers: "§5.7.3", Kind: "attestation", File: "invalid-notified-after-publication.json"},
		{Name: "unsolicited-without-disclosure", Covers: "§5.7.3", Kind: "attestation", File: "invalid-unsolicited-without-disclosure.json"},
		{Name: "unsolicited-with-order", Covers: "§5.7.1", Kind: "attestation", File: "invalid-unsolicited-with-order.json"},
		{Name: "clear-without-scale", Covers: "§5.4.3", Kind: "attestation", File: "invalid-clear-without-scale.json"},
		{Name: "judgment-without-expiry", Covers: "§5.4.5", Kind: "attestation", File: "invalid-judgment-without-expiry.json"},
		{Name: "no-relationships", Covers: "§5.4.4", Kind: "attestation", File: "invalid-no-relationships.json"},
		{Name: "bucket-off-scale", Covers: "§5.4.3", Kind: "attestation", File: "invalid-bucket-off-scale.json"},
		{Name: "case-variant-key", Covers: "profile §4 strict keys", Kind: "attestation", File: "invalid-case-variant-key.json"},
		{Name: "order-all-signatures", Covers: "§5.3", Kind: "order", File: "order.json", ExpectOK: true},
		{Name: "order-contingent-fee", Covers: "§5.3.1, acceptance 7", Kind: "order", File: "invalid-order-contingent-fee.json"},
		{Name: "response-by-subject", Covers: "§5.7.5", Kind: "response", File: "response.json", Context: "att-active.json", ExpectOK: true},
		{Name: "response-forged", Covers: "§5.7.5", Kind: "response", File: "response-forged.json", Context: "att-active.json"},
	}
	return g.files, cases, invalid, nil
}

// RunFixtureCase evaluates one case against files.
func RunFixtureCase(files map[string][]byte, c FixtureCase) (Decision, error) {
	now, err := sig.ParseTime(c.Now)
	if err != nil {
		return Decision{}, err
	}
	man, err := ParseManifest(files[c.Manifest], now)
	if err != nil {
		return Decision{}, err
	}
	trust := Trust{Credited: map[sig.Key]bool{}, OmitUncredited: c.OmitUncredit}
	if c.CreditAuditor {
		trust.Credited[man.Operator] = true
	}
	in := Input{Attestation: files[c.Attestation], Manifest: files[c.Manifest], Target: c.Target, Trust: trust, State: &StatusState{}, Now: now, Responses: map[string][]byte{}}
	if c.Revocation != "" {
		in.Revocation = files[c.Revocation]
	}
	for _, r := range c.Responses {
		in.Responses[sig.Digest(files[r])] = files[r]
	}
	// Earlier lists only advance the retained epoch; the last one decides.
	for i, s := range c.Status {
		if i < len(c.Status)-1 {
			ParseStatus(files[s], man, in.State, now)
			continue
		}
		in.Status = files[s]
	}
	return Verify(in), nil
}

// RunFixtureInvalid reports whether the document parsed.
func RunFixtureInvalid(files map[string][]byte, c FixtureInvalid) error {
	switch c.Kind {
	case "attestation":
		_, err := ParseAttestation(files[c.File])
		return err
	case "order":
		_, err := ParseOrder(files[c.File])
		return err
	case "response":
		att, err := ParseAttestation(files[c.Context])
		if err != nil {
			return err
		}
		_, err = ParseResponse(files[c.File], att, sig.Digest(files[c.Context]))
		return err
	}
	return fmt.Errorf("unknown kind %q", c.Kind)
}
