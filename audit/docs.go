// Package audit implements the Onym audit seat (onym-system audit/Audit.md)
// under the static-Ed25519 implementation profile in
// profile/Audit-Static-Ed25519.md: the signed boundary objects, the signed
// status list, and the relying-client verification of §6–§7.
package audit

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"onym-audit/canon"
	"onym-audit/sig"
	"onym-audit/urirule"
)

// Profile constants (profile §1).
const (
	ProfileID         = "onym:audit-profile:static-ed25519-v1"
	Interface         = "onym-audit-v1"
	AttestationSchema = "onym-attestation-v1"
	ErrorSchema       = "onym-audit-errors-v1"
	Freshness         = "onym:audit-freshness:signed-status-list-v1"
)

// Methodology classes (Audit.md §2).
const (
	SecurityReview          = "security-review"
	ConformanceRun          = "conformance-run"
	BuildProvenance         = "build-provenance"
	PrivacyReview           = "privacy-review"
	AvailabilityMeasurement = "availability-measurement"
)

var MethodologyClasses = []string{SecurityReview, ConformanceRun, BuildProvenance, PrivacyReview, AvailabilityMeasurement}

// Result classes (Audit.md §5.4.3).
const (
	Clear         = "clear"
	FindingsNoted = "findings-noted"
	Fail          = "fail"
	Inconclusive  = "inconclusive"
)

var ResultClasses = []string{Clear, FindingsNoted, Fail, Inconclusive}

// Operations (Audit.md §6). `verify` is local and not an auditor operation.
var Operations = []string{"offer-engagement", "accept-order", "issue-attestation", "supersede-attestation", "revoke-attestation", "query-status"}

// Artifact kinds (profile §4.4): what `revision` and `artifactHash` mean.
const (
	KindSource     = "source"     // revision = git commit hex; artifactHash null
	KindBuild      = "build"      // revision = git commit hex; artifactHash = sha256 of the distributed bytes
	KindDeployment = "deployment" // source = HTTPS URI of the component's signed manifest; revision = sha256 of its exact bytes
)

func oneOf(v string, set ...string) bool {
	for _, s := range set {
		if v == s {
			return true
		}
	}
	return false
}

// DocRef pins a published document by exact-bytes digest and location.
type DocRef struct {
	URI    string `json:"uri"`
	Digest string `json:"digest"`
}

var docRefShape = &shape{required: []string{"uri", "digest"}}

func (d DocRef) validate(field string) error {
	if err := urirule.Check(d.URI); err != nil {
		return fmt.Errorf("%s.uri: %w", field, err)
	}
	if !sig.ValidDigest(d.Digest) {
		return fmt.Errorf("%s.digest: not a sha256 digest", field)
	}
	return nil
}

// ---------------------------------------------------------------- profile

// AuditProfile is Audit.md §5.1, published once by the profile publisher.
type AuditProfile struct {
	ProfileVersion     int      `json:"profileVersion"`
	ProfileID          string   `json:"profileId"`
	Interface          string   `json:"interface"`
	Operations         []string `json:"operations"`
	MethodologyClasses []string `json:"methodologyClasses"`
	AttestationSchema  string   `json:"attestationSchema"`
	ResultClasses      []string `json:"resultClasses"`
	Freshness          string   `json:"freshness"`
	ErrorSchema        string   `json:"errorSchema"`
	Specification      DocRef   `json:"specification"`
	Publisher          sig.Key  `json:"publisher"`
	Signature          string   `json:"signature,omitempty"`
}

var profileShape = &shape{
	required: []string{"profileVersion", "profileId", "interface", "operations", "methodologyClasses", "attestationSchema", "resultClasses", "freshness", "errorSchema", "specification", "publisher", "signature"},
	nested:   map[string]*shape{"specification": docRefShape},
}

// ParseProfile verifies an AuditProfile's schema and publisher signature.
func ParseProfile(raw []byte) (*AuditProfile, error) {
	var p AuditProfile
	if err := decodeStrict(raw, profileShape, &p); err != nil {
		return nil, err
	}
	if p.ProfileVersion != 1 || p.ProfileID != ProfileID || p.Interface != Interface {
		return nil, fmt.Errorf("%w: profile %q v%d", ErrUnsupportedProfile, p.ProfileID, p.ProfileVersion)
	}
	if err := p.Specification.validate("specification"); err != nil {
		return nil, err
	}
	if err := sig.Verify(raw, "signature", p.Publisher); err != nil {
		return nil, err
	}
	return &p, nil
}

// ---------------------------------------------------------------- manifest

// Methodology is one entry of AuditorManifest.methodologies.
type Methodology struct {
	Class         string   `json:"class"`
	Specification DocRef   `json:"specification"`
	ScopesOffered []string `json:"scopesOffered"`
}

// AuditorManifest is Audit.md §5.2 with the profile's refinements (§4.2):
// hash-or-url fields are pinned as DocRefs, the human name and contact are
// explicit, and status lists are signed by a delegated online key.
type AuditorManifest struct {
	Version            int           `json:"version"`
	ComponentID        string        `json:"componentId"`
	Seat               string        `json:"seat"`
	Operator           sig.Key       `json:"operator"`
	DisplayName        string        `json:"displayName"`
	Contact            string        `json:"contact"`
	AuditProfileID     string        `json:"auditProfileId"`
	AuditProfile       DocRef        `json:"auditProfile"`
	Methodologies      []Methodology `json:"methodologies"`
	IndependencePolicy DocRef        `json:"independencePolicy"`
	UnsolicitedPolicy  DocRef        `json:"unsolicitedPolicy"`
	Liability          DocRef        `json:"liability"`
	SeverityScale      DocRef        `json:"severityScale"`
	PrivacyProfile     DocRef        `json:"privacyProfile"`
	StatusEndpoint     string        `json:"statusEndpoint"`
	StatusKey          sig.Key       `json:"statusKey"`
	Offers             []string      `json:"offers"`
	ValidUntil         string        `json:"validUntil"`
	Signature          string        `json:"signature,omitempty"`
}

var manifestShape = &shape{
	required: []string{"version", "componentId", "seat", "operator", "displayName", "contact", "auditProfileId", "auditProfile", "methodologies", "independencePolicy", "unsolicitedPolicy", "liability", "severityScale", "privacyProfile", "statusEndpoint", "statusKey", "offers", "validUntil", "signature"},
	nested: map[string]*shape{
		"auditProfile":       docRefShape,
		"independencePolicy": docRefShape,
		"unsolicitedPolicy":  docRefShape,
		"liability":          docRefShape,
		"severityScale":      docRefShape,
		"privacyProfile":     docRefShape,
		"methodologies": {
			required: []string{"class", "specification", "scopesOffered"},
			nested:   map[string]*shape{"specification": docRefShape},
		},
	},
}

// ParseManifest checks an auditor manifest's schema, signature, and validity
// at now. Its operator key is the auditor identity every attestation must be
// signed by.
func ParseManifest(raw []byte, now time.Time) (*AuditorManifest, error) {
	var m AuditorManifest
	if err := decodeStrict(raw, manifestShape, &m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrManifestInvalid, err)
	}
	if m.AuditProfileID != ProfileID {
		return nil, fmt.Errorf("%w: auditProfileId %q", ErrUnsupportedProfile, m.AuditProfileID)
	}
	if err := m.validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrManifestInvalid, err)
	}
	if err := sig.Verify(raw, "signature", m.Operator); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrManifestInvalid, err)
	}
	until, _ := sig.ParseTime(m.ValidUntil)
	if now.After(until.Add(Skew)) {
		return nil, fmt.Errorf("%w: validUntil %s has passed", ErrManifestInvalid, m.ValidUntil)
	}
	return &m, nil
}

func (m *AuditorManifest) validate() error {
	if m.Version != 1 || m.Seat != "audit" {
		return fmt.Errorf("version %d seat %q", m.Version, m.Seat)
	}
	if !componentRE.MatchString(m.ComponentID) {
		return fmt.Errorf("componentId %q", m.ComponentID)
	}
	if _, err := m.Operator.Public(); err != nil {
		return err
	}
	if _, err := m.StatusKey.Public(); err != nil {
		return fmt.Errorf("statusKey: %w", err)
	}
	if m.StatusKey == m.Operator {
		return fmt.Errorf("statusKey must differ from the operator key")
	}
	if m.DisplayName == "" || m.Contact == "" {
		return fmt.Errorf("displayName and contact are required")
	}
	for name, d := range map[string]DocRef{"auditProfile": m.AuditProfile, "independencePolicy": m.IndependencePolicy, "unsolicitedPolicy": m.UnsolicitedPolicy, "liability": m.Liability, "severityScale": m.SeverityScale, "privacyProfile": m.PrivacyProfile} {
		if err := d.validate(name); err != nil {
			return err
		}
	}
	if len(m.Methodologies) == 0 {
		return fmt.Errorf("no methodologies")
	}
	for i, mt := range m.Methodologies {
		if !oneOf(mt.Class, MethodologyClasses...) {
			return fmt.Errorf("methodologies[%d].class %q", i, mt.Class)
		}
		if err := mt.Specification.validate(fmt.Sprintf("methodologies[%d].specification", i)); err != nil {
			return err
		}
	}
	if err := urirule.Check(m.StatusEndpoint); err != nil {
		return fmt.Errorf("statusEndpoint: %w", err)
	}
	for _, o := range m.Offers {
		if !offerIDRE.MatchString(o) {
			return fmt.Errorf("offer id %q", o)
		}
	}
	if _, err := sig.ParseTime(m.ValidUntil); err != nil {
		return err
	}
	return nil
}

// ---------------------------------------------------------------- order

// Artifact binds exact bytes (Audit.md §5.4.1, profile §4.4).
type Artifact struct {
	Kind         string  `json:"kind"`
	Source       string  `json:"source"`
	Revision     string  `json:"revision"`
	ArtifactHash *string `json:"artifactHash"`
}

var artifactShape = &shape{required: []string{"kind", "source", "revision", "artifactHash"}}

func (a Artifact) validate() error {
	switch a.Kind {
	case KindSource, KindBuild:
		if err := urirule.Check(a.Source); err != nil {
			return fmt.Errorf("artifact.source: %w", err)
		}
		if !commitRE.MatchString(a.Revision) {
			return fmt.Errorf("artifact.revision %q is not a full git commit id", a.Revision)
		}
		if a.Kind == KindSource && a.ArtifactHash != nil {
			return fmt.Errorf("artifact.artifactHash must be null for kind source")
		}
		if a.Kind == KindBuild && (a.ArtifactHash == nil || !sig.ValidDigest(*a.ArtifactHash)) {
			return fmt.Errorf("artifact.artifactHash must be a sha256 digest for kind build")
		}
	case KindDeployment:
		if err := urirule.Check(a.Source); err != nil {
			return fmt.Errorf("artifact.source: %w", err)
		}
		if !sig.ValidDigest(a.Revision) {
			return fmt.Errorf("artifact.revision must be the sha256 of the manifest bytes")
		}
		if a.ArtifactHash != nil && !sig.ValidDigest(*a.ArtifactHash) {
			return fmt.Errorf("artifact.artifactHash must be null or a sha256 digest")
		}
	default:
		return fmt.Errorf("artifact.kind %q", a.Kind)
	}
	return nil
}

// Disclosure is AuditOrder.disclosure (Audit.md §5.3).
type Disclosure struct {
	FindingsToSubjectFirst bool   `json:"findingsToSubjectFirst"`
	EmbargoDays            int    `json:"embargoDays"`
	AttestationPublication string `json:"attestationPublication"`
	FailPublication        string `json:"failPublication"`
}

// Fee admits only verdict-independent models (Audit.md §5.3.1, acceptance
// criterion 7): there is no field in which a contingent fee can be written.
type Fee struct {
	Model   string `json:"model"`
	OfferID string `json:"offerId"`
}

var FeeModels = []string{"fixed-verdict-independent", "pro-bono"}

// OrderSignature is one party's signature over the order (profile §4.3).
type OrderSignature struct {
	Role      string  `json:"role"`
	Key       sig.Key `json:"key"`
	Signature string  `json:"signature"`
}

// AuditOrder is Audit.md §5.3. Each party signs the canonical bytes with the
// top-level `signatures` field removed.
type AuditOrder struct {
	OrderVersion   int               `json:"orderVersion"`
	OrderID        string            `json:"orderId"`
	Auditor        string            `json:"auditor"`
	Subject        string            `json:"subject"`
	Sponsor        sig.Key           `json:"sponsor"`
	Artifact       Artifact          `json:"artifact"`
	MethodologyCls string            `json:"methodologyClass"`
	Scope          DocRef            `json:"scope"`
	Cooperation    string            `json:"cooperation"`
	Disclosure     Disclosure        `json:"disclosure"`
	Timeline       map[string]string `json:"timeline"`
	Fee            Fee               `json:"fee"`
	Signatures     []OrderSignature  `json:"signatures"`
}

var orderShape = &shape{
	required: []string{"orderVersion", "orderId", "auditor", "subject", "sponsor", "artifact", "methodologyClass", "scope", "cooperation", "disclosure", "timeline", "fee", "signatures"},
	nested: map[string]*shape{
		"artifact":   artifactShape,
		"scope":      docRefShape,
		"disclosure": {required: []string{"findingsToSubjectFirst", "embargoDays", "attestationPublication", "failPublication"}},
		"timeline":   {required: []string{"start", "reportDue"}},
		"fee":        {required: []string{"model", "offerId"}},
		"signatures": {required: []string{"role", "key", "signature"}},
	},
}

// ParseOrder verifies an order's schema and every signature on it, and
// requires the auditor, subject, and sponsor roles to have signed.
func ParseOrder(raw []byte) (*AuditOrder, error) {
	var o AuditOrder
	if err := decodeStrict(raw, orderShape, &o); err != nil {
		return nil, err
	}
	if o.OrderVersion != 1 || !idRE.MatchString(o.OrderID) {
		return nil, fmt.Errorf("%w: orderVersion/orderId", canon.ErrMalformed)
	}
	if !componentRE.MatchString(o.Auditor) || !componentRE.MatchString(o.Subject) {
		return nil, fmt.Errorf("%w: auditor/subject component ids", canon.ErrMalformed)
	}
	if err := o.Artifact.validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", canon.ErrMalformed, err)
	}
	if !oneOf(o.MethodologyCls, MethodologyClasses...) || !oneOf(o.Fee.Model, FeeModels...) {
		return nil, fmt.Errorf("%w: methodologyClass or fee model not admitted", canon.ErrMalformed)
	}
	if err := o.Scope.validate("scope"); err != nil {
		return nil, fmt.Errorf("%w: %v", canon.ErrMalformed, err)
	}
	signed := map[string]bool{}
	for _, s := range o.Signatures {
		if !oneOf(s.Role, "auditor", "subject", "sponsor") {
			return nil, fmt.Errorf("%w: signature role %q", canon.ErrMalformed, s.Role)
		}
		if err := sig.VerifyDetached(raw, s.Signature, s.Key, "signatures"); err != nil {
			return nil, fmt.Errorf("%s signature: %w", s.Role, err)
		}
		if s.Role == "sponsor" && s.Key != o.Sponsor {
			return nil, fmt.Errorf("sponsor signature key differs from sponsor")
		}
		signed[s.Role] = true
	}
	for _, r := range []string{"auditor", "subject", "sponsor"} {
		if !signed[r] {
			return nil, fmt.Errorf("%w: order lacks the %s signature", canon.ErrMalformed, r)
		}
	}
	return &o, nil
}

// SignOrder appends role's signature to an order's published bytes.
func SignOrder(raw []byte, role string, priv ed25519.PrivateKey) ([]byte, error) {
	obj, err := canon.Parse(raw)
	if err != nil {
		return nil, err
	}
	sigs, _ := obj["signatures"].([]any)
	msg, err := canon.SigningBytes(raw, "signatures")
	if err != nil {
		return nil, err
	}
	s := ed25519.Sign(priv, msg)
	sigs = append(sigs, canon.Object{
		"role":      role,
		"key":       string(sig.KeyOf(priv.Public().(ed25519.PublicKey))),
		"signature": b64(s),
	})
	obj["signatures"] = sigs
	return canon.Encode(obj)
}

// ParseOrderRequest checks an order as it arrives at accept-order: the
// subject and the sponsor have signed, the auditor has not yet. The auditor
// countersigns only after reviewing it against its independence policy
// (Audit.md §8.4).
func ParseOrderRequest(raw []byte, auditorComponent string) (*AuditOrder, error) {
	var o AuditOrder
	if err := decodeStrict(raw, orderShape, &o); err != nil {
		return nil, err
	}
	if o.Auditor != auditorComponent {
		return nil, fmt.Errorf("%w: order is addressed to %q", canon.ErrMalformed, o.Auditor)
	}
	if o.OrderVersion != 1 || !idRE.MatchString(o.OrderID) || !componentRE.MatchString(o.Subject) {
		return nil, fmt.Errorf("%w: orderVersion/orderId/subject", canon.ErrMalformed)
	}
	if err := o.Artifact.validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", canon.ErrMalformed, err)
	}
	if !oneOf(o.MethodologyCls, MethodologyClasses...) || !oneOf(o.Fee.Model, FeeModels...) {
		return nil, fmt.Errorf("%w: methodologyClass or fee model not admitted", canon.ErrMalformed)
	}
	if err := o.Scope.validate("scope"); err != nil {
		return nil, fmt.Errorf("%w: %v", canon.ErrMalformed, err)
	}
	signed := map[string]bool{}
	for _, s := range o.Signatures {
		if !oneOf(s.Role, "subject", "sponsor") {
			return nil, fmt.Errorf("%w: unexpected %q signature at intake", canon.ErrMalformed, s.Role)
		}
		if err := sig.VerifyDetached(raw, s.Signature, s.Key, "signatures"); err != nil {
			return nil, fmt.Errorf("%s signature: %w", s.Role, err)
		}
		if s.Role == "sponsor" && s.Key != o.Sponsor {
			return nil, fmt.Errorf("sponsor signature key differs from sponsor")
		}
		signed[s.Role] = true
	}
	if !signed["subject"] || !signed["sponsor"] {
		return nil, fmt.Errorf("%w: an order arrives signed by its subject and its sponsor", canon.ErrMalformed)
	}
	return &o, nil
}

// OfferFee is an offer's price. Amount is in minor units of Currency; both
// are null for pro-bono. There is no field for a result-dependent price.
type OfferFee struct {
	Model    string  `json:"model"`
	Amount   *int    `json:"amount"`
	Currency *string `json:"currency"`
}

// Offer is an engagement offer (Audit.md §11: auditors publish engagement
// offers as SeatOffers), served at offers/<offerId>.json.
type Offer struct {
	OfferVersion     int        `json:"offerVersion"`
	OfferID          string     `json:"offerId"`
	Auditor          string     `json:"auditor"`
	AuditorKey       sig.Key    `json:"auditorKey"`
	MethodologyClass string     `json:"methodologyClass"`
	Scope            DocRef     `json:"scope"`
	Fee              OfferFee   `json:"fee"`
	TimelineDays     int        `json:"timelineDays"`
	Disclosure       Disclosure `json:"disclosure"`
	ValidUntil       string     `json:"validUntil"`
	Signature        string     `json:"signature,omitempty"`
}

var offerShape = &shape{
	required: []string{"offerVersion", "offerId", "auditor", "auditorKey", "methodologyClass", "scope", "fee", "timelineDays", "disclosure", "validUntil", "signature"},
	nested: map[string]*shape{
		"scope":      docRefShape,
		"fee":        {required: []string{"model", "amount", "currency"}},
		"disclosure": {required: []string{"findingsToSubjectFirst", "embargoDays", "attestationPublication", "failPublication"}},
	},
}

// ParseOffer checks an offer's schema, fee model, and signature.
func ParseOffer(raw []byte) (*Offer, error) {
	var o Offer
	if err := decodeStrict(raw, offerShape, &o); err != nil {
		return nil, err
	}
	if o.OfferVersion != 1 || !offerIDRE.MatchString(o.OfferID) || !componentRE.MatchString(o.Auditor) || !oneOf(o.MethodologyClass, MethodologyClasses...) {
		return nil, fmt.Errorf("%w: offer fields", canon.ErrMalformed)
	}
	if err := o.Scope.validate("scope"); err != nil {
		return nil, err
	}
	switch o.Fee.Model {
	case "pro-bono":
		if o.Fee.Amount != nil || o.Fee.Currency != nil {
			return nil, fmt.Errorf("%w: pro-bono carries no amount", canon.ErrMalformed)
		}
	case "fixed-verdict-independent":
		if o.Fee.Amount == nil || *o.Fee.Amount < 0 || o.Fee.Currency == nil || len(*o.Fee.Currency) != 3 {
			return nil, fmt.Errorf("%w: a fixed fee needs amount and ISO currency", canon.ErrMalformed)
		}
	default:
		return nil, fmt.Errorf("%w: fee model %q not admitted", canon.ErrMalformed, o.Fee.Model)
	}
	if _, err := sig.ParseTime(o.ValidUntil); err != nil {
		return nil, err
	}
	if err := sig.Verify(raw, "signature", o.AuditorKey); err != nil {
		return nil, err
	}
	return &o, nil
}

// OrderMatchesOffer checks that an order takes an offer as the auditor
// published it: same auditor, methodology, fee model, and disclosure terms,
// while the offer is valid. An order cannot weaken the disclosure it was
// offered, nor pay under a model the auditor did not offer.
func OrderMatchesOffer(o *AuditOrder, of *Offer, now time.Time) error {
	until, err := sig.ParseTime(of.ValidUntil)
	if err != nil {
		return err
	}
	switch {
	case o.Fee.OfferID != of.OfferID:
		return fmt.Errorf("the order names offer %q, not %q", o.Fee.OfferID, of.OfferID)
	case o.Auditor != of.Auditor:
		return fmt.Errorf("offer %s belongs to %s", of.OfferID, of.Auditor)
	case !now.Before(until):
		return fmt.Errorf("offer %s expired at %s", of.OfferID, of.ValidUntil)
	case o.MethodologyCls != of.MethodologyClass:
		return fmt.Errorf("offer %s is for %s, not %s", of.OfferID, of.MethodologyClass, o.MethodologyCls)
	case o.Fee.Model != of.Fee.Model:
		return fmt.Errorf("offer %s is %s, not %s", of.OfferID, of.Fee.Model, o.Fee.Model)
	case o.Disclosure != of.Disclosure:
		return fmt.Errorf("the order's disclosure terms differ from offer %s", of.OfferID)
	}
	return nil
}
