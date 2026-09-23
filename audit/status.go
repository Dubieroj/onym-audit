package audit

import (
	"crypto/ed25519"
	"fmt"
	"sort"
	"time"

	"onym-audit/canon"
	"onym-audit/sig"
)

// Attestation states in a status list (Audit.md §6 query-status).
const (
	Active     = "active"
	Superseded = "superseded"
	Revoked    = "revoked"
	Expired    = "expired"
)

// Freshness bounds (profile §5): the status key re-signs at least every
// ResignInterval, and a list is stale once now > nextUpdate + Skew.
const (
	ResignInterval = 6 * time.Hour
	NextUpdateIn   = 48 * time.Hour
	MaxNextUpdate  = 7 * 24 * time.Hour
)

// StatusEntry covers one attestation the auditor issued.
type StatusEntry struct {
	AttestationID string   `json:"attestationId"`
	Attestation   DocRef   `json:"attestation"`
	State         string   `json:"state"`
	SupersededBy  *string  `json:"supersededBy"`
	Revocation    *DocRef  `json:"revocation"`
	Responses     []DocRef `json:"responses"`
}

// StatusList is the signed, epoch-monotonic list covering every unexpired
// attestation (Audit.md §5.5), signed by the manifest's delegated statusKey.
type StatusList struct {
	StatusVersion int           `json:"statusVersion"`
	Auditor       string        `json:"auditor"`
	AuditorKey    sig.Key       `json:"auditorKey"`
	StatusKey     sig.Key       `json:"statusKey"`
	StatusEpoch   int64         `json:"statusEpoch"`
	IssuedAt      string        `json:"issuedAt"`
	NextUpdate    string        `json:"nextUpdate"`
	Entries       []StatusEntry `json:"entries"`
	Signature     string        `json:"signature,omitempty"`
}

var statusShape = &shape{
	required: []string{"statusVersion", "auditor", "auditorKey", "statusKey", "statusEpoch", "issuedAt", "nextUpdate", "entries", "signature"},
	nested: map[string]*shape{
		"entries": {
			required: []string{"attestationId", "attestation", "state", "supersededBy", "revocation", "responses"},
			nested: map[string]*shape{
				"attestation": docRefShape,
				"revocation":  docRefShape,
				"responses":   docRefShape,
			},
		},
	},
}

// StatusState is what a client retains per auditor to enforce §5.5
// monotonicity across refreshes.
type StatusState struct {
	LastEpoch int64
}

// ParseStatus verifies a status list against the auditor manifest: schema,
// the manifest's statusKey signature, epoch monotonicity against the
// retained state, and freshness at now. A stale list is returned together
// with ErrStatusUnavailable so the caller can degrade honestly (§12).
func ParseStatus(raw []byte, m *AuditorManifest, st *StatusState, now time.Time) (*StatusList, error) {
	var l StatusList
	if err := decodeStrict(raw, statusShape, &l); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStatusInvalid, err)
	}
	if l.StatusVersion != 1 || l.Auditor != m.ComponentID || l.AuditorKey != m.Operator || l.StatusKey != m.StatusKey {
		return nil, fmt.Errorf("%w: list does not belong to this auditor manifest", ErrStatusInvalid)
	}
	if err := sig.Verify(raw, "signature", m.StatusKey); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStatusInvalid, err)
	}
	issued, err := sig.ParseTime(l.IssuedAt)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStatusInvalid, err)
	}
	next, err := sig.ParseTime(l.NextUpdate)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStatusInvalid, err)
	}
	if !next.After(issued) || next.Sub(issued) > MaxNextUpdate {
		return nil, fmt.Errorf("%w: nextUpdate outside (issuedAt, issuedAt+7d]", ErrStatusInvalid)
	}
	if issued.After(now.Add(Skew)) {
		return nil, fmt.Errorf("%w: issuedAt is in the future", ErrStatusInvalid)
	}
	seen := map[string]bool{}
	for _, e := range l.Entries {
		if seen[e.AttestationID] {
			return nil, fmt.Errorf("%w: duplicate entry %s", ErrStatusInvalid, e.AttestationID)
		}
		seen[e.AttestationID] = true
		if !oneOf(e.State, Active, Superseded, Revoked, Expired) {
			return nil, fmt.Errorf("%w: state %q", ErrStatusInvalid, e.State)
		}
		if (e.State == Revoked) != (e.Revocation != nil) || (e.State == Superseded) != (e.SupersededBy != nil) {
			return nil, fmt.Errorf("%w: entry %s state and references disagree", ErrStatusInvalid, e.AttestationID)
		}
	}
	if st != nil {
		if l.StatusEpoch < st.LastEpoch {
			return nil, fmt.Errorf("%w: epoch %d below retained %d", ErrStatusRollback, l.StatusEpoch, st.LastEpoch)
		}
		st.LastEpoch = l.StatusEpoch
	}
	if now.After(next.Add(Skew)) {
		return &l, fmt.Errorf("%w: status list stale since %s", ErrStatusUnavailable, l.NextUpdate)
	}
	return &l, nil
}

// Entry returns the status entry for id, if the list covers it.
func (l *StatusList) Entry(id string) *StatusEntry {
	for i := range l.Entries {
		if l.Entries[i].AttestationID == id {
			return &l.Entries[i]
		}
	}
	return nil
}

// Published is one attestation as the status builder sees it on disk.
type Published struct {
	Attestation *Attestation
	Ref         DocRef
	Revocation  *DocRef
	RevokedFrom time.Time
	Responses   []DocRef
}

// BuildStatus computes every entry's state at now and signs the list with
// the status key. The epoch is the signing time in Unix seconds, which is
// monotonic across restarts without retained state; it is bumped past
// minEpoch so a revocation's declared statusEpoch is always covered.
func BuildStatus(m *AuditorManifest, pubs []Published, now time.Time, minEpoch int64, statusPriv ed25519.PrivateKey) ([]byte, error) {
	if sig.KeyOf(statusPriv.Public().(ed25519.PublicKey)) != m.StatusKey {
		return nil, fmt.Errorf("status key does not match the manifest's statusKey")
	}
	supersededBy := map[string]string{}
	for _, p := range pubs {
		if p.Attestation.Supersedes != nil {
			supersededBy[*p.Attestation.Supersedes] = p.Attestation.AttestationID
		}
	}
	entries := []StatusEntry{}
	for _, p := range pubs {
		a := p.Attestation
		e := StatusEntry{AttestationID: a.AttestationID, Attestation: p.Ref, State: Active, Responses: p.Responses}
		if e.Responses == nil {
			e.Responses = []DocRef{}
		}
		expired := false
		if a.ExpiresAt != nil {
			exp, _ := sig.ParseTime(*a.ExpiresAt)
			expired = !now.Before(exp)
		}
		switch {
		case p.Revocation != nil && !now.Before(p.RevokedFrom):
			e.State, e.Revocation = Revoked, p.Revocation
		case supersededBy[a.AttestationID] != "":
			by := supersededBy[a.AttestationID]
			e.State, e.SupersededBy = Superseded, &by
		case expired:
			e.State = Expired
		}
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].AttestationID < entries[j].AttestationID })
	epoch := now.Unix()
	if epoch <= minEpoch {
		epoch = minEpoch + 1
	}
	l := StatusList{
		StatusVersion: 1,
		Auditor:       m.ComponentID,
		AuditorKey:    m.Operator,
		StatusKey:     m.StatusKey,
		StatusEpoch:   epoch,
		IssuedAt:      sig.FormatTime(now),
		NextUpdate:    sig.FormatTime(now.Add(NextUpdateIn)),
		Entries:       entries,
	}
	obj, err := toObject(l)
	if err != nil {
		return nil, err
	}
	return sig.Sign(obj, "signature", statusPriv)
}

// SignDoc signs any profile document with its top-level `signature` field.
func SignDoc(v any, priv ed25519.PrivateKey) ([]byte, error) {
	obj, err := toObject(v)
	if err != nil {
		return nil, err
	}
	return sig.Sign(obj, "signature", priv)
}

// CanonicalOf returns v's canonical bytes (for unsigned documents).
func CanonicalOf(v any) ([]byte, error) {
	obj, err := toObject(v)
	if err != nil {
		return nil, err
	}
	return canon.Encode(obj)
}
