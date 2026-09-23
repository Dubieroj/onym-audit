package audit

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"onym-audit/canon"
	"onym-audit/sig"
	"onym-audit/urirule"
)

// Skew is the clock-skew allowance on every time comparison (the same
// 10 minutes Discovery-Static-Ed25519 §4.2 pins).
const Skew = 10 * time.Minute

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// Error codes: Audit.md §12 plus this profile's schema/signature failures
// (profile §9, errorSchema onym-audit-errors-v1).
var (
	ErrUnsupportedProfile = errors.New("unsupported_profile")
	ErrArtifactMismatch   = errors.New("artifact_mismatch")
	ErrExpired            = errors.New("attestation_expired")
	ErrRevoked            = errors.New("attestation_revoked")
	ErrSuperseded         = errors.New("attestation_superseded")
	ErrStatusUnavailable  = errors.New("status_unavailable")
	ErrIssuerUntrusted    = errors.New("issuer_untrusted")
	ErrAttestationInvalid = errors.New("attestation_invalid")
	ErrManifestInvalid    = errors.New("auditor_manifest_invalid")
	ErrStatusInvalid      = errors.New("status_list_invalid")
	ErrStatusRollback     = errors.New("status_rollback")
	ErrResponseInvalid    = errors.New("subject_response_invalid")
)

// Severity levels of the profile's severity scale, highest first
// (profile §4.6, severity-v1).
var SeverityLevels = []string{"critical", "high", "medium", "low", "informational"}

// UnsolicitedDisclosure records the §5.7 duties an unsolicited attestation
// discharges: the published policy it followed and the documented attempt to
// reach the subject before publication (profile §4.5).
type UnsolicitedDisclosure struct {
	Policy            string  `json:"policy"`
	SubjectContact    string  `json:"subjectContact"`
	SubjectNotifiedAt string  `json:"subjectNotifiedAt"`
	EmbargoUntil      *string `json:"embargoUntil"`
}

// Attestation is Audit.md §5.4 with profile refinements (§4.4): artifact
// kind, the subject's operator key (so its signed reply can be verified),
// URIs beside hashes, a renderable scope summary, and inline exclusions.
type Attestation struct {
	AttestationVersion int                    `json:"attestationVersion"`
	AttestationID      string                 `json:"attestationId"`
	Auditor            string                 `json:"auditor"`
	AuditorKey         sig.Key                `json:"auditorKey"`
	Subject            string                 `json:"subject"`
	SubjectOperator    sig.Key                `json:"subjectOperator"`
	Artifact           Artifact               `json:"artifact"`
	MethodologyClass   string                 `json:"methodologyClass"`
	Methodology        DocRef                 `json:"methodology"`
	Scope              DocRef                 `json:"scope"`
	ScopeSummary       string                 `json:"scopeSummary"`
	Exclusions         []string               `json:"exclusions"`
	Result             string                 `json:"result"`
	SeverityScale      *DocRef                `json:"severityScale"`
	SeverityFloor      *string                `json:"severityFloor"`
	FindingsReport     *DocRef                `json:"findingsReport"`
	FindingsSummary    map[string]int         `json:"findingsSummary"`
	Engagement         string                 `json:"engagement"`
	Sponsor            sig.Key                `json:"sponsor"`
	SponsorName        string                 `json:"sponsorName"`
	Relationships      string                 `json:"relationships"`
	OrderRef           *string                `json:"orderRef"`
	Unsolicited        *UnsolicitedDisclosure `json:"unsolicited"`
	IssuedAt           string                 `json:"issuedAt"`
	ExpiresAt          *string                `json:"expiresAt"`
	Supersedes         *string                `json:"supersedes"`
	Status             string                 `json:"status"`
	Signature          string                 `json:"signature,omitempty"`
}

var attestationShape = &shape{
	required: []string{"attestationVersion", "attestationId", "auditor", "auditorKey", "subject", "subjectOperator", "artifact", "methodologyClass", "methodology", "scope", "scopeSummary", "exclusions", "result", "severityScale", "severityFloor", "findingsReport", "findingsSummary", "engagement", "sponsor", "sponsorName", "relationships", "orderRef", "unsolicited", "issuedAt", "expiresAt", "supersedes", "status", "signature"},
	nested: map[string]*shape{
		"artifact":       artifactShape,
		"methodology":    docRefShape,
		"scope":          docRefShape,
		"severityScale":  docRefShape,
		"findingsReport": docRefShape,
		"unsolicited":    {required: []string{"policy", "subjectContact", "subjectNotifiedAt", "embargoUntil"}},
	},
}

// ParseAttestation checks schema, the normative constraints of Audit.md
// §5.4 and §5.7, and the signature by the attestation's auditorKey. It does
// not decide whether that key is a credited issuer — that is Verify's job.
func ParseAttestation(raw []byte) (*Attestation, error) {
	var a Attestation
	if err := decodeStrict(raw, attestationShape, &a); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAttestationInvalid, err)
	}
	if err := a.validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAttestationInvalid, err)
	}
	if err := sig.Verify(raw, "signature", a.AuditorKey); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAttestationInvalid, err)
	}
	return &a, nil
}

func (a *Attestation) validate() error {
	if a.AttestationVersion != 1 || !idRE.MatchString(a.AttestationID) {
		return fmt.Errorf("attestationVersion/attestationId")
	}
	if !componentRE.MatchString(a.Auditor) || !componentRE.MatchString(a.Subject) {
		return fmt.Errorf("auditor/subject component ids")
	}
	for _, k := range []sig.Key{a.AuditorKey, a.SubjectOperator, a.Sponsor} {
		if _, err := k.Public(); err != nil {
			return err
		}
	}
	if err := a.Artifact.validate(); err != nil {
		return err
	}
	if !oneOf(a.MethodologyClass, MethodologyClasses...) {
		return fmt.Errorf("methodologyClass %q", a.MethodologyClass)
	}
	if err := a.Methodology.validate("methodology"); err != nil {
		return err
	}
	if err := a.Scope.validate("scope"); err != nil {
		return err
	}
	if a.ScopeSummary == "" || a.Exclusions == nil {
		return fmt.Errorf("scopeSummary and exclusions are required (§5.4.2: scope and exclusions are the whole claim)")
	}
	if !oneOf(a.Result, ResultClasses...) {
		return fmt.Errorf("result %q", a.Result)
	}
	// §5.4.3: clear and findings-noted need both the scale and the floor.
	if a.Result == Clear || a.Result == FindingsNoted {
		if a.SeverityScale == nil || a.SeverityFloor == nil {
			return fmt.Errorf("result %s requires severityScale and severityFloor (§5.4.3)", a.Result)
		}
	}
	if a.SeverityScale != nil {
		if err := a.SeverityScale.validate("severityScale"); err != nil {
			return err
		}
	}
	if a.SeverityFloor != nil && !oneOf(*a.SeverityFloor, SeverityLevels...) {
		return fmt.Errorf("severityFloor %q is not on the severity scale", *a.SeverityFloor)
	}
	for k, v := range a.FindingsSummary {
		if (!oneOf(k, SeverityLevels...) && k != "resolved") || v < 0 {
			return fmt.Errorf("findingsSummary bucket %q", k)
		}
	}
	if a.FindingsReport != nil {
		if err := a.FindingsReport.validate("findingsReport"); err != nil {
			return err
		}
	}
	if a.SponsorName == "" || a.Relationships == "" {
		return fmt.Errorf("sponsorName and relationships must be stated (\"none\" when none) (§5.4.4)")
	}
	issued, err := sig.ParseTime(a.IssuedAt)
	if err != nil {
		return err
	}
	// §5.4.5: judgment classes expire; build-provenance may not.
	if a.ExpiresAt == nil {
		if a.MethodologyClass != BuildProvenance {
			return fmt.Errorf("expiresAt is mandatory for %s (§5.4.5)", a.MethodologyClass)
		}
	} else {
		exp, err := sig.ParseTime(*a.ExpiresAt)
		if err != nil {
			return err
		}
		if !exp.After(issued) {
			return fmt.Errorf("expiresAt must be after issuedAt")
		}
	}
	if a.Supersedes != nil && !idRE.MatchString(*a.Supersedes) {
		return fmt.Errorf("supersedes %q", *a.Supersedes)
	}
	if err := urirule.Check(a.Status); err != nil {
		return fmt.Errorf("status: %w", err)
	}
	switch a.Engagement {
	case "commissioned":
		if a.OrderRef == nil || !sig.ValidDigest(*a.OrderRef) || a.Unsolicited != nil {
			return fmt.Errorf("a commissioned attestation needs orderRef and no unsolicited block")
		}
	case "unsolicited":
		// §5.7.1–5.7.3: no order, public artifact, published policy followed,
		// documented attempt to reach the subject before publication.
		if a.OrderRef != nil {
			return fmt.Errorf("an unsolicited attestation has orderRef null (§5.7.1)")
		}
		u := a.Unsolicited
		if u == nil || !sig.ValidDigest(u.Policy) || u.SubjectContact == "" {
			return fmt.Errorf("an unsolicited attestation records its policy and the subject contact (§5.7.3)")
		}
		notified, err := sig.ParseTime(u.SubjectNotifiedAt)
		if err != nil {
			return err
		}
		if notified.After(issued) {
			return fmt.Errorf("the subject must be notified before publication (§5.7.3)")
		}
		if u.EmbargoUntil != nil {
			if _, err := sig.ParseTime(*u.EmbargoUntil); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("engagement %q", a.Engagement)
	}
	return nil
}

// Revocation is Audit.md §5.5.
type Revocation struct {
	RevocationVersion int     `json:"revocationVersion"`
	AttestationID     string  `json:"attestationId"`
	Auditor           string  `json:"auditor"`
	AuditorKey        sig.Key `json:"auditorKey"`
	IssuedAt          string  `json:"issuedAt"`
	StatusEpoch       int64   `json:"statusEpoch"`
	EffectiveFrom     string  `json:"effectiveFrom"`
	Reason            string  `json:"reason"`
	Detail            *DocRef `json:"detail"`
	Signature         string  `json:"signature,omitempty"`
}

var RevocationReasons = []string{"methodology-error", "new-information", "compromise-of-auditor-key", "withdrawal"}

var revocationShape = &shape{
	required: []string{"revocationVersion", "attestationId", "auditor", "auditorKey", "issuedAt", "statusEpoch", "effectiveFrom", "reason", "detail", "signature"},
	nested:   map[string]*shape{"detail": docRefShape},
}

// ParseRevocation checks a revocation's schema and signature.
func ParseRevocation(raw []byte) (*Revocation, error) {
	var r Revocation
	if err := decodeStrict(raw, revocationShape, &r); err != nil {
		return nil, err
	}
	if r.RevocationVersion != 1 || !idRE.MatchString(r.AttestationID) || !componentRE.MatchString(r.Auditor) || !oneOf(r.Reason, RevocationReasons...) {
		return nil, fmt.Errorf("%w: revocation fields", canon.ErrMalformed)
	}
	if _, err := sig.ParseTime(r.IssuedAt); err != nil {
		return nil, err
	}
	if _, err := sig.ParseTime(r.EffectiveFrom); err != nil {
		return nil, err
	}
	if err := sig.Verify(raw, "signature", r.AuditorKey); err != nil {
		return nil, err
	}
	return &r, nil
}

// SubjectResponse is the subject's signed right of reply (Audit.md
// §5.7.5), signed by the subject operator key the attestation names.
type SubjectResponse struct {
	ResponseVersion int     `json:"responseVersion"`
	ResponseID      string  `json:"responseId"`
	AttestationID   string  `json:"attestationId"`
	Attestation     string  `json:"attestation"` // digest of the attestation's exact bytes
	Subject         string  `json:"subject"`
	Respondent      sig.Key `json:"respondent"`
	IssuedAt        string  `json:"issuedAt"`
	Text            string  `json:"text"`
	Signature       string  `json:"signature,omitempty"`
}

var responseShape = &shape{
	required: []string{"responseVersion", "responseId", "attestationId", "attestation", "subject", "respondent", "issuedAt", "text", "signature"},
}

// MaxResponseText bounds the reply the auditor must serve.
const MaxResponseText = 8000

// ParseResponse checks a subject response against the attestation it answers.
func ParseResponse(raw []byte, att *Attestation, attDigest string) (*SubjectResponse, error) {
	var r SubjectResponse
	if err := decodeStrict(raw, responseShape, &r); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrResponseInvalid, err)
	}
	if r.ResponseVersion != 1 || !idRE.MatchString(r.ResponseID) || len(r.Text) == 0 || len(r.Text) > MaxResponseText {
		return nil, fmt.Errorf("%w: fields", ErrResponseInvalid)
	}
	if r.AttestationID != att.AttestationID || r.Attestation != attDigest || r.Subject != att.Subject {
		return nil, fmt.Errorf("%w: answers a different attestation or subject", ErrResponseInvalid)
	}
	if r.Respondent != att.SubjectOperator {
		return nil, fmt.Errorf("%w: respondent is not the attested subject's operator key", ErrResponseInvalid)
	}
	if _, err := sig.ParseTime(r.IssuedAt); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrResponseInvalid, err)
	}
	if err := sig.Verify(raw, "signature", r.Respondent); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrResponseInvalid, err)
	}
	return &r, nil
}
