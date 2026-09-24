package audit

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"onym-audit/sig"
)

// Target is the exact component a relying client is about to use.
type Target struct {
	Kind         string  `json:"kind"`
	Source       string  `json:"source"`
	Revision     string  `json:"revision"`
	ArtifactHash *string `json:"artifactHash"`
}

// DeploymentTarget binds a deployed component by its signed manifest's URI
// and exact bytes, plus the exact bytes of the one further served document
// the attestation pins, if any (profile §4.4).
func DeploymentTarget(manifestURI string, manifestBytes, pinned []byte) Target {
	t := Target{Kind: KindDeployment, Source: manifestURI, Revision: sig.Digest(manifestBytes)}
	if pinned != nil {
		d := sig.Digest(pinned)
		t.ArtifactHash = &d
	}
	return t
}

// Trust is the relying party's issuer policy (Audit.md §7.7): which auditor
// keys it credits, and whether uncredited issuers are omitted or shown as
// uncredited. There is no mandatory issuer.
type Trust struct {
	Credited       map[sig.Key]bool
	OmitUncredited bool
}

// Display decisions (profile §6).
const (
	ShowAttested      = "attested"       // render per §7.2, whatever the result class
	ShowUncredited    = "uncredited"     // render, labelled as from an uncredited issuer
	ShowNone          = "no-attestation" // absence: never rendered as failure
	ShowRevoked       = "revoked"        // stop displaying; show the reason class only
	ShowSuperseded    = "superseded"     // re-resolve and display the successor
	ShowExpired       = "expired"        // render as expired
	ShowStatusUnknown = "status-unknown" // render with status unverified; not for high-stakes reliance
)

// Input is everything the local `verify` operation (Audit.md §6) needs.
// Only Attestation, Manifest, Target, and Now are mandatory.
type Input struct {
	Attestation []byte
	Manifest    []byte
	Status      []byte            // stapled or fetched signed status list
	Revocation  []byte            // the revocation named by the status entry, if fetched
	Responses   map[string][]byte // subject responses by exact-bytes digest
	Target      Target
	Trust       Trust
	State       *StatusState
	Now         time.Time
}

// Render is what a conforming client shows: who attested what, how, paid by
// whom, and when (Audit.md §7.2). Every string here is untrusted input and
// must be shown as text, never interpreted.
type Render struct {
	Issuer           string         `json:"issuer"`
	IssuerKey        sig.Key        `json:"issuerKey"`
	IssuerPrint      string         `json:"issuerFingerprint"`
	Credited         bool           `json:"credited"`
	Subject          string         `json:"subject"`
	MethodologyClass string         `json:"methodologyClass"`
	Scope            string         `json:"scope"`
	Exclusions       []string       `json:"exclusions"`
	Result           string         `json:"result"`
	SeverityFloor    string         `json:"severityFloor,omitempty"`
	FindingsSummary  map[string]int `json:"findingsSummary"`
	FindingsReport   string         `json:"findingsReport,omitempty"`
	Engagement       string         `json:"engagement"`
	Sponsor          string         `json:"sponsor"`
	Relationships    string         `json:"relationships"`
	IssuedAt         string         `json:"issuedAt"`
	AgeDays          int            `json:"ageDays"`
	ExpiresAt        string         `json:"expiresAt,omitempty"`
	Responses        []string       `json:"subjectResponses"`
	RevokedReason    string         `json:"revokedReason,omitempty"`
	SupersededBy     string         `json:"supersededBy,omitempty"`
}

// Decision is the verify outcome.
type Decision struct {
	Display string   `json:"display"`
	Error   string   `json:"error,omitempty"`
	Notes   []string `json:"notes,omitempty"`
	// HighStakesOK is true only when a fresh, verified status list confirms
	// the attestation active (Audit.md §7.6).
	HighStakesOK bool    `json:"highStakesOK"`
	Render       *Render `json:"render,omitempty"`
}

func code(err error) string {
	for _, e := range []error{ErrUnsupportedProfile, ErrArtifactMismatch, ErrExpired, ErrRevoked, ErrSuperseded, ErrStatusUnavailable, ErrIssuerUntrusted, ErrAttestationInvalid, ErrManifestInvalid, ErrStatusInvalid, ErrStatusRollback, ErrResponseInvalid} {
		if errors.Is(err, e) {
			return e.Error()
		}
	}
	return ErrAttestationInvalid.Error()
}

// Absent is the decision for a component with no attestation at all:
// absence is absence, never failure (Audit.md §7.4).
func Absent() Decision { return Decision{Display: ShowNone} }

// Verify runs the relying-client procedure of profile §6.
func Verify(in Input) Decision {
	m, err := ParseManifest(in.Manifest, in.Now)
	if err != nil {
		return Decision{Display: ShowNone, Error: code(err), Notes: []string{err.Error()}}
	}
	a, err := ParseAttestation(in.Attestation)
	if err != nil {
		return Decision{Display: ShowNone, Error: code(err), Notes: []string{err.Error()}}
	}
	if a.AuditorKey != m.Operator || a.Auditor != m.ComponentID {
		return Decision{Display: ShowNone, Error: ErrAttestationInvalid.Error(), Notes: []string{"attestation is not signed by this auditor manifest's operator"}}
	}
	// §6: exact equality on the bytes the client is about to use, or nothing.
	if !matches(a.Artifact, in.Target) {
		d := Decision{Display: ShowNone, Error: ErrArtifactMismatch.Error()}
		if a.Artifact.Source == in.Target.Source {
			d.Notes = append(d.Notes, "another revision of this component was attested")
		}
		return d
	}
	r := render(a, m)
	d := Decision{Display: ShowAttested, Render: r}

	// A revocation signed by the auditor's operator key is final, whatever
	// status list is presented: a list stapled from before the revocation
	// must not bring the attestation back (profile §4.2).
	if in.Revocation != nil {
		if rv, err := ParseRevocation(in.Revocation); err == nil && rv.AttestationID == a.AttestationID && rv.AuditorKey == m.Operator {
			return Decision{Display: ShowRevoked, Error: ErrRevoked.Error(), Render: &Render{Issuer: r.Issuer, IssuerKey: r.IssuerKey, IssuerPrint: r.IssuerPrint, RevokedReason: rv.Reason}}
		}
	}

	fresh := false
	if in.Status == nil {
		d.Error = ErrStatusUnavailable.Error()
		d.Notes = append(d.Notes, "no status list: status unverified")
	} else if l, err := ParseStatus(in.Status, m, in.State, in.Now); l == nil {
		d.Error = code(err)
		d.Notes = append(d.Notes, err.Error())
	} else {
		fresh = err == nil
		if !fresh {
			d.Error = code(err)
			d.Notes = append(d.Notes, err.Error())
		}
		e := l.Entry(a.AttestationID)
		switch {
		case e == nil:
			d.Notes = append(d.Notes, "status list does not cover this attestation")
			fresh = false
		// The list's state for this attestation id stands whatever bytes are
		// presented: re-serializing a revoked attestation (whitespace,
		// escapes) changes its digest, and must not hide the revocation.
		case e.State == Revoked:
			return Decision{Display: ShowRevoked, Error: ErrRevoked.Error(), Render: &Render{Issuer: r.Issuer, IssuerKey: r.IssuerKey, IssuerPrint: r.IssuerPrint, RevokedReason: "revoked"}}
		case e.State == Superseded:
			r.SupersededBy = *e.SupersededBy
			return Decision{Display: ShowSuperseded, Error: ErrSuperseded.Error(), Render: r, Notes: []string{"re-resolve and display the successor " + *e.SupersededBy}}
		case e.State == Expired:
			return Decision{Display: ShowExpired, Error: ErrExpired.Error(), Render: r}
		case e.Attestation.Digest != sig.Digest(in.Attestation):
			d.Error = ErrStatusInvalid.Error()
			d.Notes = append(d.Notes, "status entry pins different attestation bytes")
			fresh = false
		default:
			for _, ref := range e.Responses {
				raw, ok := in.Responses[ref.Digest]
				if !ok || sig.Digest(raw) != ref.Digest {
					d.Notes = append(d.Notes, "subject response not fetched: "+ref.URI)
					continue
				}
				resp, err := ParseResponse(raw, a, sig.Digest(in.Attestation))
				if err != nil {
					d.Notes = append(d.Notes, "subject response invalid: "+err.Error())
					continue
				}
				r.Responses = append(r.Responses, resp.Text)
			}
		}
	}
	// Expiry is evaluated locally too: a stale list cannot keep an opinion alive.
	if a.ExpiresAt != nil {
		if exp, _ := sig.ParseTime(*a.ExpiresAt); in.Now.After(exp.Add(Skew)) {
			return Decision{Display: ShowExpired, Error: ErrExpired.Error(), Render: r}
		}
	}
	if !fresh {
		d.Display = ShowStatusUnknown
	}
	if !in.Trust.Credited[m.Operator] {
		r.Credited = false
		if in.Trust.OmitUncredited {
			return Decision{Display: ShowNone, Error: ErrIssuerUntrusted.Error(), Notes: []string{"omitted by the user's issuer policy"}}
		}
		if d.Display == ShowAttested {
			d.Display = ShowUncredited
		}
		if d.Error == "" {
			d.Error = ErrIssuerUntrusted.Error()
		}
	} else {
		r.Credited = true
	}
	d.HighStakesOK = fresh && r.Credited
	return d
}

func matches(a Artifact, t Target) bool {
	if a.Kind != t.Kind || a.Source != t.Source || a.Revision != t.Revision {
		return false
	}
	// Strict for every kind: a deployment attestation that pinned the
	// served document it examined (e.g. a catalog snapshot) applies only
	// while that exact document is served — opinions must not follow
	// bytes silently (Audit.md §3.4, §13.7).
	if (a.ArtifactHash == nil) != (t.ArtifactHash == nil) {
		return false
	}
	return a.ArtifactHash == nil || *a.ArtifactHash == *t.ArtifactHash
}

func render(a *Attestation, m *AuditorManifest) *Render {
	r := &Render{
		Issuer:           m.DisplayName,
		IssuerKey:        m.Operator,
		IssuerPrint:      m.Operator.Fingerprint(),
		Subject:          a.Subject,
		MethodologyClass: a.MethodologyClass,
		Scope:            a.ScopeSummary,
		Exclusions:       a.Exclusions,
		Result:           a.Result,
		FindingsSummary:  a.FindingsSummary,
		Engagement:       a.Engagement,
		Sponsor:          fmt.Sprintf("%s (%s)", a.SponsorName, a.Sponsor.Fingerprint()),
		Relationships:    a.Relationships,
		IssuedAt:         a.IssuedAt,
		Responses:        []string{},
	}
	if a.SeverityFloor != nil {
		r.SeverityFloor = *a.SeverityFloor
	}
	if a.FindingsReport != nil {
		r.FindingsReport = a.FindingsReport.URI
	}
	if a.ExpiresAt != nil {
		r.ExpiresAt = *a.ExpiresAt
	}
	return r
}

// Summary renders d as the one-paragraph text a client shows (§7.2):
// "who attested what, how, paid by whom" — never a bare checkmark.
func (d Decision) Summary(now time.Time) string {
	r := d.Render
	switch d.Display {
	case ShowNone:
		if d.Error == ErrArtifactMismatch.Error() {
			return "No attestation for this exact component." + noteSuffix(d.Notes)
		}
		return "No attestation."
	case ShowRevoked:
		return fmt.Sprintf("An attestation by %s was revoked (%s); it no longer applies.", r.Issuer, r.RevokedReason)
	}
	issued, _ := sig.ParseTime(r.IssuedAt)
	age := int(math.Floor(now.Sub(issued).Hours() / 24))
	var b strings.Builder
	fmt.Fprintf(&b, "%s [%s]%s attested %s (%s): result %s", r.Issuer, r.IssuerPrint, map[bool]string{true: "", false: " (uncredited issuer)"}[r.Credited], r.Subject, r.MethodologyClass, strings.ToUpper(r.Result))
	if r.SeverityFloor != "" {
		fmt.Fprintf(&b, " at or above %s", r.SeverityFloor)
	}
	fmt.Fprintf(&b, ". Scope: %s. Not examined: %s. Paid by %s; relationships: %s. Issued %d day(s) ago", r.Scope, strings.Join(r.Exclusions, "; "), r.Sponsor, r.Relationships, age)
	if r.ExpiresAt != "" {
		fmt.Fprintf(&b, ", expires %s", r.ExpiresAt)
	}
	b.WriteString(".")
	switch d.Display {
	case ShowExpired:
		b.WriteString(" EXPIRED.")
	case ShowSuperseded:
		b.WriteString(" SUPERSEDED by " + r.SupersededBy + ".")
	case ShowStatusUnknown:
		b.WriteString(" Status unverified.")
	}
	for _, t := range r.Responses {
		b.WriteString(" Subject replied: " + t)
	}
	return b.String()
}

func noteSuffix(notes []string) string {
	if len(notes) == 0 {
		return ""
	}
	return " (" + strings.Join(notes, "; ") + ")"
}
