package discovery

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"onym-audit/sig"
	"onym-audit/urirule"
)

type catState struct {
	d         descriptor
	latest    *snapDoc
	surviving []entry
	fetchDest bool
}

// afterSignature are the per-catalog checks that make claims about the
// operator's published content; they are evaluated only on bytes the
// operator signed.
var afterSignature = []string{
	"snapshot.policy-digest", "snapshot.chain-fields", "snapshot.dates", "snapshot.window-max",
	"snapshot.window-short", "snapshot.fresh", "snapshot.entry-count", "snapshot.duplicate-component",
	"entry.fields", "entry.unknown-keys", "entry.seat-type-declared", "chain.retention",
	"chain.sibling-valid", "chain.links", "chain.latest-sibling",
	"dest.retrievable", "dest.digest", "dest.fields", "dest.signature",
}

// catalog evaluates one public catalog's latest snapshot, its entries and
// its retained chain. It returns the state only when the snapshot is signed
// by the operator (so entries can be attributed to the provider).
func (r *run) catalog(d descriptor) *catState {
	subj := "catalog " + d.catalogID
	x := r.get(d.snapshot, limitSnapshot, "catalog-snapshot", true)
	if !r.required("snapshot.fetch", x, subj+" "+d.snapshot) {
		r.block(append([]string{"snapshot.size", "snapshot.schema", "snapshot.identity", "snapshot.signature", "snapshot.detached-sig"}, afterSignature...),
			subj, "latest snapshot not retrieved")
		return nil
	}
	if x.oversize() {
		r.add("snapshot.size", Fail, "%s: more than %d bytes (snapshot_invalid)", subj, limitSnapshot)
		r.block(append([]string{"snapshot.schema", "snapshot.identity", "snapshot.signature", "snapshot.detached-sig"}, afterSignature...),
			subj, "snapshot exceeds the §7 bound")
		return nil
	}
	r.add("snapshot.size", Pass, "%s: %d bytes", subj, len(x.resp.Body))

	s := decodeSnapshot(x.resp.Body, d.catalogID, r.providerID, r.key)
	if s.parseErr != nil {
		r.add("snapshot.schema", Fail, "%s: does not parse under §3: %v", subj, s.parseErr)
		r.block(append([]string{"snapshot.identity", "snapshot.signature", "snapshot.detached-sig"}, afterSignature...),
			subj, "snapshot does not parse")
		return nil
	}
	if len(s.schemaProblems) > 0 {
		r.add("snapshot.schema", Fail, "%s: %s (snapshot_invalid)", subj, strings.Join(s.schemaProblems, "; "))
	} else {
		r.add("snapshot.schema", Pass, "%s: required fields only, correctly typed", subj)
	}
	if len(s.idProblems) > 0 {
		r.add("snapshot.identity", Fail, "%s: %s", subj, strings.Join(s.idProblems, "; "))
	} else {
		r.add("snapshot.identity", Pass, "%s: version 1, v1 profile, catalogId and providerId match", subj)
	}
	r.detached("snapshot.detached-sig", d.snapshot, "catalog-snapshot-signature", s.obj["signature"], subj+" latest")
	if !s.sigOK {
		r.add("snapshot.signature", Fail, "%s: %s (snapshot_invalid)", subj, s.sigProblem)
		r.block(afterSignature, subj, "latest snapshot not signed by the operator key (snapshot.signature)")
		return nil
	}
	r.add("snapshot.signature", Pass, "%s: sequence %d signed by %s", subj, s.seq, r.key)
	cs := &catState{d: d, latest: s}

	if s.policyDigest == d.policy {
		r.add("snapshot.policy-digest", Pass, "%s: %s", subj, s.policyDigest)
	} else {
		r.add("snapshot.policy-digest", Fail, "%s: policyDigest %s ≠ manifest policy %s — snapshot_invalid for any verifier without a retained previous declaration (§4.2 one-generation grace covers only clients that retained one; re-run if a policy transition was in progress)", subj, show(s.obj["policyDigest"]), d.policy)
	}
	if len(s.chainProblems) > 0 {
		r.add("snapshot.chain-fields", Fail, "%s: %s", subj, strings.Join(s.chainProblems, "; "))
	} else {
		r.add("snapshot.chain-fields", Pass, "%s: sequence %d, previousDigest %s", subj, s.seq, map[bool]string{true: "present", false: "absent"}[s.hasPrev])
	}
	r.times(subj, s)

	if !s.haveEntries {
		r.add("snapshot.entry-count", Inconclusive, "%s: entries missing or not an array (snapshot.schema)", subj)
	} else if len(s.entries) > maxEntries {
		r.add("snapshot.entry-count", Fail, "%s: %d entries exceeds %d (snapshot_invalid)", subj, len(s.entries), maxEntries)
	} else {
		r.add("snapshot.entry-count", Pass, "%s: %d entry(ies)", subj, len(s.entries))
		cs.fetchDest = true
	}
	r.entries(cs)
	r.walk(cs)
	return cs
}

func (r *run) times(subj string, s *snapDoc) {
	if !s.timesOK {
		r.add("snapshot.dates", Fail, "%s: %s (snapshot_invalid)", subj, s.timeProblem)
		r.block([]string{"snapshot.window-max", "snapshot.window-short", "snapshot.fresh"}, subj, "timestamps unreadable (snapshot.dates)")
		return
	}
	g, e := sig.FormatTime(s.generated), sig.FormatTime(s.expires)
	var p []string
	if s.generated.After(r.now.Add(clockSkew)) {
		p = append(p, fmt.Sprintf("generatedAt %s is more than 10 minutes after run time %s (future-dated)", g, sig.FormatTime(r.now)))
	}
	if !s.expires.After(s.generated) {
		p = append(p, fmt.Sprintf("expiresAt %s is not strictly after generatedAt %s (born expired)", e, g))
	}
	if len(p) > 0 {
		r.add("snapshot.dates", Fail, "%s: %s (snapshot_invalid)", subj, strings.Join(p, "; "))
	} else {
		r.add("snapshot.dates", Pass, "%s: generated %s, expires %s", subj, g, e)
	}
	w := s.expires.Sub(s.generated)
	if w > maxWindow {
		r.add("snapshot.window-max", Fail, "%s: window %s exceeds the 90-day ceiling (snapshot_invalid)", subj, fmtDur(w))
	} else {
		r.add("snapshot.window-max", Pass, "%s: window %s", subj, fmtDur(w))
	}
	if w > shortWindow {
		r.add("snapshot.window-short", Fail, "%s: window %s exceeds six weeks; §4.2 says providers SHOULD publish \"much shorter windows (days to a few weeks)\" than the 90-day ceiling — this suite flags only windows no reading of \"a few weeks\" covers (over 42 days)", subj, fmtDur(w))
	} else {
		r.add("snapshot.window-short", Pass, "%s: window %s", subj, fmtDur(w))
	}
	if s.expires.Add(clockSkew).Before(r.now) {
		r.add("snapshot.fresh", Fail, "%s: snapshot_expired — expiresAt %s is more than 10 minutes before run time %s. The provider manifest still declares this catalog, but the latest snapshot it serves is expired, so a conforming client refreshing now must mark the catalog stale and must not treat its entries as current recommendations (§4.2, §9; Discovery.md §9, §12, invariant 9). No clause obliges a provider to republish before expiry; this check applies the suite's client-acceptance bar (see the scope document): the deployment, as served, is rejected as current by a conforming client", subj, e, sig.FormatTime(r.now))
	} else {
		r.add("snapshot.fresh", Pass, "%s: expires %s", subj, e)
	}
}

// entries applies lossy entry decoding, duplicate detection over the
// surviving entries, and the seatTypes consistency check.
func (r *run) entries(cs *catState) {
	subj := "catalog " + cs.d.catalogID
	s := cs.latest
	if !s.haveEntries {
		r.block([]string{"snapshot.duplicate-component", "entry.fields", "entry.unknown-keys", "entry.seat-type-declared"}, subj, "entries missing or not an array (snapshot.schema)")
		return
	}
	if len(s.entries) == 0 {
		r.add("snapshot.duplicate-component", Pass, "%s: no entries", subj)
		return
	}
	badFields, badKeys := 0, 0
	for i, v := range s.entries {
		e, fieldP, unknown, uriP := decodeEntry(i, v)
		es := fmt.Sprintf("%s entry[%d]", subj, i)
		if e.componentID != "" {
			es += " " + e.componentID
		}
		if len(fieldP) > 0 {
			badFields++
			r.add("entry.fields", Fail, "%s: %s — skipped by conforming clients (result_incomplete)", es, strings.Join(fieldP, "; "))
		}
		if len(unknown) > 0 {
			badKeys++
			r.add("entry.unknown-keys", Fail, "%s: undefined key(s) %s — skipped by conforming v1 clients (result_incomplete)", es, quoteAll(unknown))
		}
		for _, p := range uriP {
			r.add("uri.rules", Fail, "%s %s — entry skipped by conforming clients", es, p)
		}
		if len(fieldP)+len(unknown)+len(uriP) == 0 {
			cs.surviving = append(cs.surviving, e)
		}
	}
	n := len(s.entries)
	if badFields == 0 {
		r.add("entry.fields", Pass, "%s: all %d entries decode", subj, n)
	}
	if badKeys == 0 {
		r.add("entry.unknown-keys", Pass, "%s: no undefined keys in %d entries", subj, n)
	}
	uris := 0
	for _, e := range cs.surviving {
		if e.uri != "" {
			uris++
		}
	}
	if uris > 0 {
		r.add("uri.rules", Pass, "%s: %d surviving entry URI(s) obey §7", subj, uris)
	}

	seen := map[string]int{}
	var dups []string
	for _, e := range cs.surviving {
		if j, ok := seen[e.componentID]; ok {
			dups = append(dups, fmt.Sprintf("%s at entries[%d] and entries[%d]", e.componentID, j, e.index))
		} else {
			seen[e.componentID] = e.index
		}
	}
	if len(dups) > 0 {
		r.add("snapshot.duplicate-component", Fail, "%s: duplicate componentId %s (snapshot_invalid)", subj, strings.Join(dups, ", "))
	} else {
		r.add("snapshot.duplicate-component", Pass, "%s: %d surviving entries, componentIds distinct", subj, len(cs.surviving))
	}

	declared := map[string]bool{}
	for _, t := range cs.d.seatTypes {
		declared[t] = true
	}
	if declared["*"] {
		if len(cs.surviving) > 0 {
			r.add("entry.seat-type-declared", Pass, "%s: catalog declares \"*\"", subj)
		}
		return
	}
	bad := 0
	for _, e := range cs.surviving {
		if !declared[e.seatType] {
			bad++
			r.add("entry.seat-type-declared", Fail, "%s entry[%d] %s: seatType %q is not among the descriptor's seatTypes %v", subj, e.index, e.componentID, e.seatType, cs.d.seatTypes)
		}
	}
	if bad == 0 && len(cs.surviving) > 0 {
		r.add("entry.seat-type-declared", Pass, "%s: every surviving entry's seatType is declared", subj)
	}
}

type sibling struct {
	k      int64
	uri    string
	st     fstate
	why    string
	s      *snapDoc
	usable bool // operator-signed, of this catalog, claiming sequence k
}

// walk performs the §5/§6 retention walk over <catalogId>-<k>.json for
// k = N-1 … max(1, N-64), then checks retention, sibling validity and the
// previousDigest links, plus the latest sequence's own sibling.
func (r *run) walk(cs *catState) {
	id := cs.d.catalogID
	subj := "catalog " + id
	N := cs.latest.seq
	// §6: replace the final path segment of the snapshot URL (which
	// urirule has already confirmed starts with "https://").
	rest := strings.TrimPrefix(cs.d.snapshot, "https://")
	dir := cs.d.snapshot + "/"
	if i := strings.LastIndex(rest, "/"); i >= 0 {
		dir = "https://" + rest[:i+1]
	}
	name := func(k int64) string { return fmt.Sprintf("%s%s-%d.json", dir, id, k) }

	if !cs.latest.haveSeq {
		r.block([]string{"chain.retention", "chain.sibling-valid", "chain.links", "chain.latest-sibling"}, subj, "latest sequence unreadable (snapshot.chain-fields)")
		return
	}
	r.latestSibling(cs, name(N))
	if N <= 1 {
		for _, c := range []string{"chain.retention", "chain.sibling-valid", "chain.links"} {
			r.add(c, NotApplicable, "%s: latest is sequence %d; no superseded snapshot exists", subj, N)
		}
		return
	}
	lo := N - maxWalk
	if lo < 1 {
		lo = 1
	}
	sibs := map[int64]*sibling{}
	served := 0
	for k := N - 1; k >= lo; k-- {
		u := name(k)
		sb := &sibling{k: k, uri: u}
		sibs[k] = sb
		if err := urirule.Check(u); err != nil {
			sb.st, sb.why = fsUnknown, "derived sibling URL fails §7: "+err.Error()
			continue
		}
		x := r.get(u, limitSnapshot, "retained-snapshot", true)
		sb.st, sb.why = x.state(true)
		if sb.st == fsRefused {
			sb.st = fsAbsent // unreachable for a conforming client
		}
		if sb.st != fsOK {
			continue
		}
		served++
		ss := fmt.Sprintf("%s sibling %d", subj, k)
		if x.oversize() {
			r.add("chain.sibling-valid", Fail, "%s: more than %d bytes", ss, limitSnapshot)
			continue
		}
		sb.s = decodeSnapshot(x.resp.Body, id, r.providerID, r.key)
		var p []string
		if sb.s.parseErr != nil {
			p = append(p, "does not parse: "+sb.s.parseErr.Error())
		} else {
			p = append(p, sb.s.schemaProblems...)
			p = append(p, sb.s.idProblems...)
			p = append(p, sb.s.chainProblems...)
			if sb.s.haveSeq && sb.s.seq != k {
				p = append(p, fmt.Sprintf("carries sequence %d, not %d", sb.s.seq, k))
			}
			if !sb.s.sigOK {
				p = append(p, "signature: "+sb.s.sigProblem)
			}
			sb.usable = sb.s.sigOK && sb.s.catalogID == id && sb.s.haveSeq && sb.s.seq == k
		}
		if len(p) > 0 {
			r.add("chain.sibling-valid", Fail, "%s: %s", ss, strings.Join(p, "; "))
		} else {
			r.add("chain.sibling-valid", Pass, "%s: valid, signed by the operator", ss)
		}
		r.detached("snapshot.detached-sig", u, "retained-snapshot-signature", sb.s.obj["signature"], ss)
	}

	if served == 0 {
		r.add("chain.sibling-valid", NotApplicable, "%s: no retained sibling served in sequences %d–%d", subj, lo, N-1)
	}

	// Retention (§5): a missing sibling is a failure only when it is shown
	// to be inside the retention window — an older retained, operator-signed
	// snapshot still unexpired at run time means the later sequence k
	// "would not yet have expired" (§6). Otherwise the gap is unverifiable
	// by construction and carries no blame (§6).
	var retained, unknownGap []string
	for k := N - 1; k >= lo; k-- {
		sb := sibs[k]
		switch {
		case sb.st == fsOK && sb.usable:
			retained = append(retained, fmt.Sprint(k))
		case sb.st == fsOK:
			// Served but not the operator-signed sequence k: reported
			// under chain.sibling-valid, not double-counted here.
		case sb.st == fsUnknown:
			r.add("chain.retention", Inconclusive, "%s: sequence %d at %s: %s", subj, k, sb.uri, sb.why)
		default:
			var ev *sibling
			for j := lo; j < k; j++ {
				if o := sibs[j]; o.usable && o.s.timesOK && o.s.expires.After(r.now) {
					ev = o
					break
				}
			}
			if ev != nil {
				r.add("chain.retention", Fail, "%s: superseded sequence %d not retained at %s (%s), yet the older retained sequence %d is unexpired until %s — sequence %d, published after it, would not yet have expired (§6), so §5 requires it", subj, k, sb.uri, sb.why, ev.k, sig.FormatTime(ev.s.expires), k)
			} else {
				unknownGap = append(unknownGap, fmt.Sprint(k))
			}
		}
	}
	if len(retained) > 0 {
		r.add("chain.retention", Pass, "%s: retained sequence(s) %s", subj, strings.Join(retained, ", "))
	}
	if len(unknownGap) > 0 {
		r.add("chain.retention", NotApplicable, "%s: sequence(s) %s not served; no older unexpired snapshot shows them inside the retention window, so the gap is unverifiable by construction and carries no blame (§6)", subj, strings.Join(unknownGap, ", "))
	}
	if lo > 1 {
		r.add("chain.retention", NotApplicable, "%s: sequences 1–%d lie beyond the 64-intermediate walk bound (§7) and were not examined", subj, lo-1)
	}

	// Links (§4.2, §6): each adjacent pair of operator-signed snapshots.
	var linked []string
	pairs, notes := 0, 0
	for k := N - 1; k >= lo; k-- {
		lower := sibs[k]
		var upperPrev string
		var upperHas bool
		var upperUnknown bool
		if k+1 == N {
			upperPrev, upperHas = cs.latest.prev, cs.latest.hasPrev
		} else {
			up := sibs[k+1]
			upperUnknown = up.st == fsUnknown
			if up.usable {
				upperPrev, upperHas = up.s.prev, up.s.hasPrev
			}
		}
		if !lower.usable || !upperHas || !sig.ValidDigest(upperPrev) {
			if lower.st == fsUnknown || upperUnknown {
				notes++
				r.add("chain.links", Inconclusive, "%s: link %d→%d not checkable (sibling fetch inconclusive)", subj, k+1, k)
			}
			continue
		}
		pairs++
		if upperPrev != lower.s.digest {
			r.add("chain.links", Fail, "%s: fork — sequence %d's previousDigest %s ≠ %s, the SHA-256 of the served operator-signed sequence %d (%s): a provable chain break (equivocation, snapshot_invalid)", subj, k+1, upperPrev, lower.s.digest, k, lower.uri)
		} else {
			linked = append(linked, fmt.Sprintf("%d→%d", k+1, k))
		}
	}
	if len(linked) > 0 {
		r.add("chain.links", Pass, "%s: links %s verified", subj, strings.Join(linked, ", "))
	}
	if pairs == 0 && notes == 0 {
		r.add("chain.links", NotApplicable, "%s: no adjacent pair of served, operator-signed snapshots to compare", subj)
	}
}

func (r *run) latestSibling(cs *catState, u string) {
	subj := "catalog " + cs.d.catalogID
	x := r.get(u, limitSnapshot, "retained-snapshot", true)
	st, why := x.state(true)
	switch {
	case st == fsUnknown:
		r.add("chain.latest-sibling", Inconclusive, "%s: %s: %s", subj, u, why)
	case st != fsOK:
		r.add("chain.latest-sibling", NotApplicable, "%s: latest sequence %d is not also served as %s (%s) — informational; §5 requires only superseded snapshots", subj, cs.latest.seq, u, why)
	case bytes.Equal(x.resp.Body, cs.latest.raw):
		r.add("chain.latest-sibling", Pass, "%s: latest sequence %d also retained as %s, byte-identical", subj, cs.latest.seq, u)
	default:
		other := decodeSnapshot(x.resp.Body, cs.d.catalogID, r.providerID, r.key)
		fork := ""
		if other.sigOK && other.haveSeq && other.seq == cs.latest.seq {
			fork = " — both are operator-signed sequence " + fmt.Sprint(other.seq) + ": a fork (§6)"
		}
		r.add("chain.latest-sibling", Fail, "%s: %s serves bytes hashing to %s, but the latest sequence-%d snapshot hashes to %s; published snapshot bytes are immutable (§4.2)%s", subj, u, sig.Digest(x.resp.Body), cs.latest.seq, cs.latest.digest, fork)
	}
}

// crossCatalog applies §4.2's same-provider digest rule across catalogs.
func (r *run) crossCatalog(cats []*catState) {
	if len(cats) < 2 {
		return
	}
	type pin struct{ catalog, digest string }
	pins := map[string][]pin{}
	for _, cs := range cats {
		for _, e := range cs.surviving {
			pins[e.componentID] = append(pins[e.componentID], pin{cs.d.catalogID, e.digest})
		}
	}
	ids := make([]string, 0, len(pins))
	for id := range pins {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	bad := 0
	for _, id := range ids {
		ps := pins[id]
		for _, p := range ps[1:] {
			if p.digest != ps[0].digest {
				bad++
				r.add("provider.cross-catalog-digest", Fail, "%s: catalog %s pins %s but catalog %s pins %s (provider-level equivocation)", id, ps[0].catalog, ps[0].digest, p.catalog, p.digest)
				break
			}
		}
	}
	if bad == 0 {
		r.add("provider.cross-catalog-digest", Pass, "%d catalogs, %d componentIds, no conflicting digests", len(cats), len(ids))
	}
}
