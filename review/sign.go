package review

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"onym-audit/agent"
	"onym-audit/audit"
	"onym-audit/canon"
	"onym-audit/sig"
	"onym-audit/site"
)

// SignOptions carries everything the auditor states at signing time.
type SignOptions struct {
	PublicRoot    string
	Config        *site.Config
	AuditorKey    ed25519.PrivateKey
	StatusKey     ed25519.PrivateKey
	AttestationID string
	Relationships string

	// Unsolicited: the subject, and the documented notice before publication.
	Subject         string
	SubjectOperator sig.Key
	Contact         string
	NotifiedAt      string

	// Commissioned: the queued order's directory (order.json, scope.md) and
	// when the findings went to the subject, as the order requires.
	OrderDir       string
	FindingsSentAt string

	// HoldReportUntil keeps the findings report (and transcript) unpublished
	// until then: the attestation circulates with counts and the report's
	// digest (Audit.md §5.6). Empty publishes the report now.
	HoldReportUntil string

	Now time.Time
}

// Sign builds the findings report and the attestation, signs it with the
// auditor key, writes what may be published into the public tree, holds the
// rest in the review, and re-signs the local status list.
func (r *Review) Sign(o SignOptions) (*Signed, error) {
	var signed *Signed
	err := r.Update(func(x *Review) error {
		if b := x.Blockers(); len(b) > 0 {
			return errors.New("not ready: " + strings.Join(b, "; "))
		}
		s, err := x.sign(o)
		if err != nil {
			return err
		}
		x.Signed, signed = s, s
		return nil
	})
	return signed, err
}

func (x *Review) sign(o SignOptions) (*Signed, error) {
	c := o.Config
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	pub := map[string][]byte{}  // published path -> bytes, written now
	held := map[string][]byte{} // published path -> bytes, held in the review

	// Engagement.
	a := audit.Attestation{AttestationVersion: 1, AttestationID: o.AttestationID, Relationships: strings.TrimSpace(o.Relationships)}
	var scopeBytes []byte
	var scopePath, orderPath string
	var failEmbargo time.Time
	if o.OrderDir != "" {
		ob, err := os.ReadFile(filepath.Join(o.OrderDir, "order.json"))
		if err != nil {
			return nil, err
		}
		ord, err := audit.ParseOrderRequest(ob, c.ComponentID)
		if err != nil {
			return nil, fmt.Errorf("queued order: %w", err)
		}
		if ord.Artifact.Source != x.Repo || ord.Artifact.Revision != x.Commit || ord.MethodologyCls != audit.SecurityReview {
			return nil, errors.New("the review does not examine what the order binds")
		}
		if ord.Disclosure.FindingsToSubjectFirst {
			t, err := sig.ParseTime(o.FindingsSentAt)
			if err != nil || t.After(o.Now) {
				return nil, errors.New("the order requires the findings to reach the subject first: record when you sent them")
			}
		}
		full, err := audit.SignOrder(ob, "auditor", o.AuditorKey)
		if err != nil {
			return nil, err
		}
		if _, err := audit.ParseOrder(full); err != nil {
			return nil, err
		}
		if err := ord.Disclosure.Check(); err != nil {
			return nil, fmt.Errorf("the order's disclosure terms: %v", err)
		}
		scopeBytes, err = os.ReadFile(filepath.Join(o.OrderDir, "scope.md"))
		if err != nil || sig.Digest(scopeBytes) != ord.Scope.Digest {
			return nil, errors.New("the order's scope text is missing or does not match its digest")
		}
		// The path comes from the order id, never from the order's own URI:
		// a planted order must not choose where signing writes.
		scopePath = "scopes/order-" + ord.OrderID + ".md"
		if ord.Scope.URI != c.BaseURI+scopePath {
			return nil, fmt.Errorf("the order's scope must be %s%s", c.BaseURI, scopePath)
		}
		var subjectKey sig.Key
		for _, s := range ord.Signatures {
			if s.Role == "subject" {
				subjectKey = s.Key
			}
		}
		orderRef := sig.Digest(full)
		a.Engagement, a.OrderRef = "commissioned", &orderRef
		a.Subject, a.SubjectOperator = ord.Subject, subjectKey
		a.Sponsor, a.SponsorName = ord.Sponsor, "the sponsor of order "+ord.OrderID
		orderPath = "orders/" + ord.OrderID + ".json"
		pub[orderPath] = full
		if ord.Disclosure.FailPublication == "public-after-embargo" {
			failEmbargo = o.Now.Add(time.Duration(ord.Disclosure.EmbargoDays) * 24 * time.Hour)
		}
	} else {
		if _, err := sig.ParseTime(o.NotifiedAt); err != nil || strings.TrimSpace(o.Contact) == "" {
			return nil, errors.New("an unsolicited attestation records the subject contact and when it was notified")
		}
		unsol, err := site.Ref(o.PublicRoot, c, site.UnsolicitedPath)
		if err != nil {
			return nil, err
		}
		a.Engagement = "unsolicited"
		a.Unsolicited = &audit.UnsolicitedDisclosure{Policy: unsol.Digest, SubjectContact: o.Contact, SubjectNotifiedAt: o.NotifiedAt}
		a.Subject, a.SubjectOperator = o.Subject, o.SubjectOperator
		a.Sponsor, a.SponsorName = site.KeyOf(o.AuditorKey), c.DisplayName+" (self-funded)"
		scopePath = "scopes/review-" + x.ID + ".md"
		scopeBytes = []byte(fmt.Sprintf("# Scope: %s at %s\n\nMethodology `%s`.\n\n%s", x.Repo, x.Commit, methodology[x.Kind], x.Scope))
	}
	pub[scopePath] = scopeBytes

	// The findings report: kept findings, the auditor's drops, the engine's
	// rejected findings, and — for an LLM review — the transcript.
	var kept []Finding
	dropped := []map[string]string{}
	summary := map[string]int{}
	for _, f := range x.Findings {
		switch f.Status {
		case Kept:
			kept = append(kept, f)
			summary[f.Severity]++
		case Dropped:
			dropped = append(dropped, map[string]string{"id": f.ID, "title": f.Title, "source": f.Source, "reason": f.DropReason})
		}
	}
	if kept == nil {
		kept = []Finding{}
	}
	report := map[string]any{
		"findingsVersion": 1, "methodology": methodology[x.Kind],
		"artifact": audit.Artifact{Kind: audit.KindSource, Source: x.Repo, Revision: x.Commit},
		"scope":    x.Scope, "coverage": x.Coverage, "findings": kept, "rejectedByEvidenceCheck": x.Rejected,
		"auditorReview": map[string]any{"reviewedBy": c.DisplayName, "dropped": dropped},
		"transcript":    nil,
	}
	reportHeld := o.HoldReportUntil != ""
	if reportHeld {
		if t, err := sig.ParseTime(o.HoldReportUntil); err != nil || !t.After(o.Now) {
			return nil, errors.New("hold the report until a future time, or not at all")
		}
	}
	dest := func(path string, b []byte, hold bool) {
		if hold {
			held[path] = b
		} else {
			pub[path] = b
		}
	}
	if x.Kind == KindLLM {
		tb, err := os.ReadFile(filepath.Join(x.dir, "transcript.json"))
		if err != nil || sig.Digest(tb) != x.Agent.TranscriptDigest {
			return nil, errors.New("the engine transcript is missing or altered")
		}
		tpath := "reports/" + strings.TrimPrefix(x.Agent.TranscriptDigest, "sha256:") + "-transcript.json"
		dest(tpath, tb, reportHeld)
		report["transcript"] = audit.DocRef{URI: c.BaseURI + tpath, Digest: x.Agent.TranscriptDigest}
		report["engine"] = map[string]any{"provider": x.Agent.Provider, "model": x.Agent.Model, "effort": x.Agent.Effort, "systemPrompt": x.Agent.PromptDigest, "iterations": x.Agent.Iterations, "stopReason": x.Agent.StopReason}
	} else {
		report["engine"] = map[string]any{"examiner": c.DisplayName, "method": "manual"}
	}
	rb, err := audit.CanonicalOf(report)
	if err != nil {
		return nil, err
	}
	if _, err := canon.Parse(rb); err != nil {
		return nil, err
	}
	rpath := "reports/" + strings.TrimPrefix(sig.Digest(rb), "sha256:") + ".json"
	dest(rpath, rb, reportHeld)

	// The attestation.
	ref := func(p string) (audit.DocRef, error) { return site.Ref(o.PublicRoot, c, p) }
	meth, err := ref(methodologyDoc[x.Kind])
	if err != nil {
		return nil, err
	}
	scale, err := ref(site.SeverityPath)
	if err != nil {
		return nil, err
	}
	floor := "low"
	excl := []string{"anything outside the stated scope", "runtime behaviour: the review reads source at one commit and executes nothing", "dependencies not vendored in the repository", "defects the examination did not find"}
	if x.Kind == KindLLM {
		excl[3] = "defects the examination did not find: an LLM-assisted review can miss issues"
	}
	a.Auditor, a.AuditorKey = c.ComponentID, site.KeyOf(o.AuditorKey)
	a.Artifact = audit.Artifact{Kind: audit.KindSource, Source: x.Repo, Revision: x.Commit}
	a.MethodologyClass, a.Methodology = audit.SecurityReview, meth
	a.Scope = audit.DocRef{URI: c.BaseURI + scopePath, Digest: sig.Digest(scopeBytes)}
	label := map[string]string{KindManual: "Manual security review", KindLLM: "LLM-assisted security review (" + modelOf(x) + ", human-reviewed)"}[x.Kind]
	a.ScopeSummary = label + ": " + firstLine(x.Scope)
	a.Exclusions = append(excl, x.Coverage.NotExamined...)
	a.Result, a.SeverityScale, a.SeverityFloor = x.ResultClass(), &scale, &floor
	a.FindingsReport = &audit.DocRef{URI: c.BaseURI + rpath, Digest: sig.Digest(rb)}
	a.FindingsSummary = summary
	a.IssuedAt = sig.FormatTime(o.Now)
	exp := sig.FormatTime(o.Now.Add(180 * 24 * time.Hour))
	a.ExpiresAt = &exp
	a.Status = c.BaseURI + site.StatusPath
	ab, err := audit.SignDoc(a, o.AuditorKey)
	if err != nil {
		return nil, err
	}
	if _, err := audit.ParseAttestation(ab); err != nil {
		return nil, err
	}
	apath := "attestations/" + o.AttestationID + ".json"
	if _, err := os.Stat(filepath.Join(o.PublicRoot, apath)); err == nil {
		return nil, fmt.Errorf("%s exists: attestations are immutable", apath)
	}
	holdAttestation := a.Result == audit.Fail && !failEmbargo.IsZero()
	s := &Signed{AttestationID: o.AttestationID, Attestation: audit.DocRef{URI: c.BaseURI + apath, Digest: sig.Digest(ab)}, Result: a.Result, Held: map[string]string{}}
	if holdAttestation {
		held[apath] = ab
		// The countersigned order and its scope wait too: published alone,
		// an order without its attestation would say the result was a fail.
		for _, p := range []string{orderPath, scopePath} {
			held[p] = pub[p]
			delete(pub, p)
		}
		s.HeldUntil = sig.FormatTime(failEmbargo)
	} else {
		pub[apath] = ab
		if reportHeld {
			s.HeldUntil = o.HoldReportUntil
		}
	}

	// Write: held files into the review, the rest into the public tree.
	for p, b := range held {
		local := filepath.Join(x.dir, "held", filepath.FromSlash(p))
		if err := site.WriteAtomic(local, b); err != nil {
			return nil, err
		}
		s.Held[p] = local
	}
	for p, b := range pub {
		full := filepath.Join(o.PublicRoot, filepath.FromSlash(p))
		if p == apath {
			if err := site.WriteSigned(full, b); err != nil {
				return nil, err
			}
			continue
		}
		if err := site.WriteAtomic(full, b); err != nil {
			return nil, err
		}
	}
	if len(s.Held) == 0 {
		s.Held = nil
	}
	if !holdAttestation {
		if err := site.ResignStatus(o.PublicRoot, c, o.StatusKey, o.Now); err != nil {
			return nil, fmt.Errorf("signed, but the local status list was not re-signed: %w", err)
		}
	}
	return s, nil
}

// Release publishes held files once their time has come.
func (r *Review) Release(publicRoot string, c *site.Config, statusKey ed25519.PrivateKey, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	x, err := Load(filepath.Dir(r.dir), r.ID)
	if err != nil {
		return err
	}
	if x.Signed == nil || len(x.Signed.Held) == 0 {
		return errors.New("nothing is held")
	}
	until, _ := sig.ParseTime(x.Signed.HeldUntil)
	if now.Before(until) {
		return fmt.Errorf("held until %s", x.Signed.HeldUntil)
	}
	for p, local := range x.Signed.Held {
		b, err := os.ReadFile(local)
		if err != nil {
			return err
		}
		full := filepath.Join(publicRoot, filepath.FromSlash(p))
		if strings.HasPrefix(p, "attestations/") {
			err = site.WriteSigned(full, b)
		} else {
			err = site.WriteAtomic(full, b)
		}
		if err != nil {
			return err
		}
	}
	x.Signed.Held, x.Signed.HeldUntil = nil, ""
	if err := x.save(); err != nil {
		return err
	}
	*r = *x
	return site.ResignStatus(publicRoot, c, statusKey, now)
}

func modelOf(x *Review) string {
	if x.Agent != nil {
		return x.Agent.Model
	}
	return agent.DefaultModel
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}
