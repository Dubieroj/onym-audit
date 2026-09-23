package discovery

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"onym-audit/canon"
	"onym-audit/sig"
	"onym-audit/urirule"
)

// Run executes the suite once against the provider manifest at manifestURI,
// evaluating every time-dependent rule at now. It never returns nil; every
// failure to reach or decode a document is itself a check outcome.
func Run(ctx context.Context, f Fetcher, manifestURI string, now time.Time) *Report {
	r := &run{
		ctx: ctx, f: f, now: now.UTC(),
		findings: map[string][]finding{},
		cache:    map[string]*fetched{},
	}
	r.providerHost = hostOf(manifestURI)
	r.execute(manifestURI)
	checks := buildChecks(r.findings, r.stopped)
	return &Report{
		Suite: SuiteID, SuiteVersion: SuiteVersion, ManifestURI: manifestURI,
		RunAt: r.now, Checks: checks, Documents: r.docs, Result: result(checks),
	}
}

type run struct {
	ctx          context.Context
	f            Fetcher
	now          time.Time
	providerHost string
	findings     map[string][]finding
	stopped      string
	cache        map[string]*fetched
	docs         []Document
	served       []*fetched // provider-served responses, for serving.no-cookies

	providerID string
	key        sig.Key
}

func (r *run) add(id string, o Outcome, format string, args ...any) {
	r.findings[id] = append(r.findings[id], finding{o, fmt.Sprintf(format, args...)})
}

// stop ends the run: every check with no finding yet becomes inconclusive
// with this reason.
func (r *run) stop(reason string) { r.stopped = reason }

// block records an inconclusive finding on each id for one subject.
func (r *run) block(ids []string, subject, reason string) {
	for _, id := range ids {
		r.add(id, Inconclusive, "%s: not evaluated (%s)", subject, reason)
	}
}

// --- fetching ---

type fetched struct {
	uri   string
	limit int64
	resp  *Response
	err   error
}

type fstate int

const (
	fsOK      fstate = iota // HTTP 200
	fsAbsent                // not published (404/410; any client error for optional documents)
	fsRefused               // definitive failure: non-200 status or a §7 redirect refusal
	fsUnknown               // network error, timeout, 429, 5xx: nothing provable
)

func (x *fetched) oversize() bool {
	return x.resp != nil && (x.resp.Truncated || int64(len(x.resp.Body)) > x.limit)
}

func (x *fetched) state(optional bool) (fstate, string) {
	if x.err != nil {
		var re *RedirectError
		switch {
		case errors.As(x.err, &re) && re.SectionSeven:
			return fsRefused, fmt.Sprintf("redirect refused under §7: %v", re)
		case errors.As(x.err, &re):
			return fsUnknown, fmt.Sprintf("redirect not followed: %v (target fails this auditor's URI policy but not the §7 redirect rule)", re)
		case errors.Is(x.err, urirule.ErrURI):
			return fsRefused, x.err.Error()
		case errors.Is(x.err, ErrIPDial):
			return fsRefused, fmt.Sprintf("the host normalizes to an IP literal, which §7 forbids: %v", x.err)
		}
		return fsUnknown, fmt.Sprintf("fetch error: %v", x.err)
	}
	s := x.resp.Status
	switch {
	case s == http.StatusOK:
		hops := ""
		if n := len(x.resp.Redirects); n > 0 {
			hops = fmt.Sprintf(" after %d redirect(s) to %s", n, x.resp.Redirects[n-1])
		}
		return fsOK, "HTTP 200" + hops
	case s == http.StatusTooManyRequests:
		return fsUnknown, fmt.Sprintf("HTTP 429 (rate_limited, Retry-After %q)", x.resp.Header.Get("Retry-After"))
	case s >= 500:
		return fsUnknown, fmt.Sprintf("HTTP %d (server error)", s)
	case s == http.StatusNotFound || s == http.StatusGone:
		return fsAbsent, fmt.Sprintf("HTTP %d", s)
	case optional && s >= 400:
		return fsAbsent, fmt.Sprintf("HTTP %d (treated as not published)", s)
	}
	return fsRefused, fmt.Sprintf("HTTP %d", s)
}

// get fetches uri once per run (cached), recording 200 bodies as documents
// and provider-served responses for the cookie check.
func (r *run) get(uri string, limit int64, role string, providerServed bool) *fetched {
	key := fmt.Sprintf("%d %s", limit, uri)
	if x, ok := r.cache[key]; ok {
		return x
	}
	x := &fetched{uri: uri, limit: limit}
	x.resp, x.err = r.f.Get(WithLimit(r.ctx, limit), uri)
	if x.err == nil && x.resp == nil {
		x.err = errors.New("fetcher returned no response")
	}
	r.cache[key] = x
	if x.resp != nil {
		if providerServed || hostOf(uri) == r.providerHost {
			r.served = append(r.served, x)
		}
		if x.resp.Status == http.StatusOK {
			d := Document{URI: uri, Digest: sig.Digest(x.resp.Body), Size: len(x.resp.Body), Role: role}
			if x.oversize() {
				d.Digest, d.Role = "", role+" (exceeds bound; truncated)"
			}
			r.docs = append(r.docs, d)
		}
	}
	return x
}

// required maps a required document's fetch to an outcome on id.
func (r *run) required(id string, x *fetched, subject string) bool {
	st, why := x.state(false)
	switch st {
	case fsOK:
		r.add(id, Pass, "%s: %s", subject, why)
		return true
	case fsUnknown:
		r.add(id, Inconclusive, "%s: %s", subject, why)
	default:
		r.add(id, Fail, "%s: %s — not served", subject, why)
	}
	return false
}

func hostOf(uri string) string {
	u, err := url.Parse(uri)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// --- the run ---

func (r *run) execute(manifestURI string) {
	if err := urirule.Check(manifestURI); err != nil {
		r.add("manifest.uri", Fail, "%v", err)
		r.stop("manifest.uri failed; a conforming client does not fetch this URL")
		return
	}
	r.add("manifest.uri", Pass, "%s", manifestURI)
	defer r.cookies()

	x := r.get(manifestURI, limitManifest, "provider-manifest", true)
	if !r.required("manifest.fetch", x, "provider manifest") {
		r.stop("provider manifest not retrieved (manifest.fetch)")
		return
	}
	raw := x.resp.Body
	if x.oversize() {
		r.add("manifest.size", Fail, "more than %d bytes served (read stopped at %d)", limitManifest, len(raw))
		r.stop("provider manifest exceeds the §7 bound (manifest.size)")
		return
	}
	r.add("manifest.size", Pass, "%d bytes", len(raw))

	m, err := canon.Parse(raw)
	if err != nil {
		r.add("manifest.schema", Fail, "does not parse under §3: %v", err)
		r.stop("provider manifest does not parse (manifest.schema)")
		return
	}
	if p := manifestSchema(m); len(p) > 0 {
		r.add("manifest.schema", Fail, "%s", strings.Join(p, "; "))
	} else {
		r.add("manifest.schema", Pass, "exactly the 12 required top-level fields, correctly typed")
	}
	if p := manifestIdentity(m); len(p) > 0 {
		r.add("manifest.identity", Fail, "%s", strings.Join(p, "; "))
	} else {
		r.add("manifest.identity", Pass, "version 1, %s, seat discovery, %s", profileID, m["providerId"])
	}

	r.detached("manifest.detached-sig", manifestURI, "provider-manifest-signature", m["signature"], "provider manifest")

	op, _ := str(m, "operator")
	r.key = sig.Key(op)
	if !validKey(op) {
		r.add("manifest.signature", Inconclusive, "no valid operator key to verify against (manifest.identity)")
		r.stop("no valid operator key (manifest.identity)")
		return
	}
	if _, ok := m["signature"].(string); !ok {
		r.add("manifest.signature", Fail, "manifest is unsigned (no string signature field)")
		r.stop("manifest not signed by its operator (manifest.signature); no content accusation is made on unsigned bytes")
		return
	}
	if err := sig.Verify(raw, "signature", r.key); err != nil {
		r.add("manifest.signature", Fail, "does not verify under %s: %v", r.key, err)
		r.stop("manifest not signed by its operator (manifest.signature); no content accusation is made on unsigned bytes")
		return
	}
	r.add("manifest.signature", Pass, "verifies under %s (fingerprint %s)", r.key, r.key.Fingerprint())
	r.providerID, _ = str(m, "providerId")

	if s, ok := str(m, "validUntil"); !ok {
		r.add("manifest.valid-until", Fail, "validUntil missing or not a string")
	} else if t, err := sig.ParseTime(s); err != nil {
		r.add("manifest.valid-until", Fail, "%v (§2)", err)
	} else if !t.After(r.now) {
		r.add("manifest.valid-until", Fail, "expired at %s (run at %s): provider_manifest_invalid", s, sig.FormatTime(r.now))
	} else {
		r.add("manifest.valid-until", Pass, "valid until %s", s)
	}

	r.privacy(m)
	public := r.descriptors(m)
	if public == nil {
		return
	}
	var verified []*catState
	for _, d := range public {
		r.policy(d)
		if cs := r.catalog(d); cs != nil {
			verified = append(verified, cs)
		}
	}
	for _, cs := range verified {
		r.destinations(cs)
	}
	r.crossCatalog(verified)
}

func (r *run) privacy(m canon.Object) {
	u, ok := str(m, "privacyProfileUri")
	if !ok {
		r.add("privacy.document", Fail, "privacyProfileUri missing or not a string (required, §4.1)")
		return
	}
	if err := urirule.Check(u); err != nil {
		r.add("uri.rules", Fail, "privacyProfileUri: %v", err)
		r.add("privacy.document", Inconclusive, "not fetched: privacyProfileUri violates §7 (uri.rules)")
		return
	}
	r.add("uri.rules", Pass, "privacyProfileUri obeys §7")
	x := r.get(u, limitDocument, "privacy-profile", true)
	r.document("privacy.document", x, "privacy profile "+u, m["privacyProfile"], "the declared privacy profile is not published")
}

func (r *run) policy(d descriptor) {
	x := r.get(d.pu, limitDocument, "policy", true)
	r.document("policy.document", x, fmt.Sprintf("catalog %s policy %s", d.catalogID, d.pu), d.policy, "policy_unavailable")
}

// document checks a pinned document: served, within 1 MiB, digest match.
func (r *run) document(id string, x *fetched, subject string, declared any, consequence string) {
	st, why := x.state(false)
	switch {
	case st == fsUnknown:
		r.add(id, Inconclusive, "%s: %s", subject, why)
		return
	case st != fsOK:
		r.add(id, Fail, "%s: %s — not served (%s)", subject, why, consequence)
		return
	case x.oversize():
		r.add(id, Fail, "%s: more than %d bytes (%s)", subject, limitDocument, consequence)
		return
	}
	want, _ := declared.(string)
	if !sig.ValidDigest(want) {
		r.add(id, Inconclusive, "%s: declared digest %s is malformed (see manifest.schema / catalog.descriptor-fields)", subject, show(declared))
		return
	}
	if got := sig.Digest(x.resp.Body); got != want {
		r.add(id, Fail, "%s: served bytes hash to %s, declared %s (%s)", subject, got, want, consequence)
		return
	}
	r.add(id, Pass, "%s: %d bytes, digest matches", subject, len(x.resp.Body))
}

// detached evaluates the optional <uri>.sig beside a signed document.
func (r *run) detached(id, docURI, role string, embedded any, subject string) {
	x := r.get(docURI+".sig", limitSig, role, true)
	st, why := x.state(true)
	switch st {
	case fsAbsent:
		r.add(id, NotApplicable, "%s: .sig not published (%s)", subject, why)
	case fsUnknown:
		r.add(id, Inconclusive, "%s: .sig %s", subject, why)
	case fsRefused:
		r.add(id, Fail, "%s: .sig %s", subject, why)
	default:
		if p := detachedProblem(x.resp.Body, x.oversize(), embedded); p != "" {
			r.add(id, Fail, "%s: %s", subject, p)
		} else {
			r.add(id, Pass, "%s: .sig agrees with the embedded signature", subject)
		}
	}
}

// catalogScoped lists checks evaluated per public catalog.
var catalogScoped = []string{
	"policy.document", "snapshot.fetch", "snapshot.size", "snapshot.schema", "snapshot.identity",
	"snapshot.signature", "snapshot.detached-sig", "snapshot.policy-digest", "snapshot.chain-fields",
	"snapshot.dates", "snapshot.window-max", "snapshot.window-short", "snapshot.fresh",
	"snapshot.entry-count", "snapshot.duplicate-component", "entry.fields", "entry.unknown-keys",
	"entry.seat-type-declared", "chain.retention", "chain.sibling-valid", "chain.links",
	"chain.latest-sibling", "dest.retrievable", "dest.digest", "dest.fields", "dest.signature",
}

// descriptors applies §4.1's descriptor rules and returns the decodable
// public descriptors (nil when catalogs cannot be read at all).
func (r *run) descriptors(m canon.Object) []descriptor {
	cats, ok := m["catalogs"].([]any)
	if !ok {
		r.block(append([]string{"catalog.descriptor-fields", "catalog.descriptor-unknown-keys", "catalog.decodable", "catalog.duplicate-id"}, catalogScoped...),
			"catalogs", "catalogs missing or not an array (manifest.schema)")
		return nil
	}
	var decoded, public []descriptor
	var skippedAudience []string
	for i, v := range cats {
		d, fieldP, unknown, uriP := decodeDescriptor(v)
		d.index = i
		subj := fmt.Sprintf("catalogs[%d]", i)
		if d.catalogID != "" {
			subj += fmt.Sprintf(" (%s)", d.catalogID)
		}
		if len(fieldP) > 0 {
			r.add("catalog.descriptor-fields", Fail, "%s: %s — descriptor skipped by conforming clients", subj, strings.Join(fieldP, "; "))
		} else {
			r.add("catalog.descriptor-fields", Pass, "%s: required fields valid", subj)
		}
		if len(unknown) > 0 {
			r.add("catalog.descriptor-unknown-keys", Fail, "%s: undefined key(s) %s — descriptor skipped by conforming v1 clients, counted as a skipped catalog", subj, quoteAll(unknown))
		} else {
			r.add("catalog.descriptor-unknown-keys", Pass, "%s: no undefined keys", subj)
		}
		for _, p := range uriP {
			r.add("uri.rules", Fail, "%s %s — descriptor skipped by conforming clients", subj, p)
		}
		if len(uriP) == 0 && len(fieldP) == 0 {
			r.add("uri.rules", Pass, "%s snapshot and policyUri obey §7", subj)
		}
		if len(fieldP)+len(unknown)+len(uriP) > 0 {
			continue
		}
		decoded = append(decoded, d)
		if d.audience == audiencePublic {
			public = append(public, d)
		} else {
			skippedAudience = append(skippedAudience, fmt.Sprintf("%s (audience %q)", d.catalogID, d.audience))
		}
	}
	if len(decoded) == 0 {
		r.add("catalog.decodable", Fail, "%d descriptor(s), none decodes: provider_manifest_invalid", len(cats))
	} else {
		note := ""
		if len(skippedAudience) > 0 {
			note = "; audience-skipped (valid, not in scope for v1): " + strings.Join(skippedAudience, ", ")
		}
		r.add("catalog.decodable", Pass, "%d of %d descriptor(s) decode, %d public%s", len(decoded), len(cats), len(public), note)
	}
	if len(decoded) > 0 {
		seen := map[string]int{}
		var dups []string
		for _, d := range decoded {
			if j, ok := seen[d.catalogID]; ok {
				dups = append(dups, fmt.Sprintf("%q at catalogs[%d] and catalogs[%d]", d.catalogID, j, d.index))
			} else {
				seen[d.catalogID] = d.index
			}
		}
		if len(dups) > 0 {
			r.add("catalog.duplicate-id", Fail, "duplicate catalogId %s: provider_manifest_invalid", strings.Join(dups, ", "))
		} else {
			r.add("catalog.duplicate-id", Pass, "%d distinct catalogId(s)", len(decoded))
		}
	}
	return public
}

// cookies records serving.no-cookies over every provider-served response.
func (r *run) cookies() {
	if len(r.served) == 0 {
		return
	}
	bad := 0
	for _, x := range r.served {
		var names []string
		for _, c := range x.resp.Header.Values("Set-Cookie") {
			name, _, _ := strings.Cut(c, "=")
			names = append(names, fmt.Sprintf("%q", strings.TrimSpace(name)))
		}
		if len(names) > 0 {
			bad++
			r.add("serving.no-cookies", Fail, "%s sets cookie(s) %s", x.uri, strings.Join(names, ", "))
		}
	}
	if bad == 0 {
		r.add("serving.no-cookies", Pass, "%d provider-served response(s), none sets a cookie", len(r.served))
	}
}
