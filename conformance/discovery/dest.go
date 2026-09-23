package discovery

import (
	"fmt"
	"strings"

	"onym-audit/canon"
	"onym-audit/sig"
)

// canonicalSeats are destination seats whose contract pins the embedded
// signature over §3-style canonical bytes (top-level "signature" removed
// structurally, keys sorted by UTF-8 byte order, compact, integers only).
// For these, a failed canonical verification is a definite
// entry_manifest_invalid; for any other seat it is inconclusive, because
// the seat may sign differently.
var canonicalSeats = map[string]string{
	"moderation":     "Discovery-Static-Ed25519 §3 (the moderation seat's canonical.rs is the precedent)",
	"notary":         "UI-Notary-BNB.md §8.1 rule 2",
	"storage.backup": "UI-Backup-Object-HTTP.md §6.3",
}

var destScoped = []string{"dest.retrievable", "dest.digest", "dest.fields", "dest.signature"}

// destinations runs §6 "before presenting" steps 1–4 for every surviving
// entry of a verified catalog. Steps 3–4 are judged only on bytes that hash
// to the pinned digest: those are the bytes the provider reviewed and
// bound, so any defect in them is the provider's inclusion decision.
func (r *run) destinations(cs *catState) {
	subj := "catalog " + cs.d.catalogID
	if !cs.fetchDest {
		reason := "entries missing or not an array (snapshot.schema)"
		if cs.latest.haveEntries {
			reason = "snapshot exceeds 512 entries (snapshot.entry-count)"
		}
		r.block(destScoped, subj, reason)
		return
	}
	for _, e := range cs.surviving {
		es := fmt.Sprintf("%s entry[%d] %s", subj, e.index, e.componentID)
		x := r.get(e.uri, limitDest, "destination-manifest", false)
		st, why := x.state(false)
		switch {
		case st == fsUnknown:
			r.add("dest.retrievable", Inconclusive, "%s: %s: %s", es, e.uri, why)
			r.block(destScoped[1:], es, "destination manifest not retrieved")
			continue
		case st != fsOK:
			r.add("dest.retrievable", Fail, "%s: %s: %s (entry_manifest_unavailable)", es, e.uri, why)
			r.block(destScoped[1:], es, "destination manifest not retrieved")
			continue
		case x.oversize():
			r.add("dest.retrievable", Fail, "%s: %s: more than %d bytes (entry_manifest_unavailable)", es, e.uri, limitDest)
			r.block(destScoped[1:], es, "destination manifest exceeds the §7 bound")
			continue
		}
		r.add("dest.retrievable", Pass, "%s: %s (%d bytes)", es, why, len(x.resp.Body))
		raw := x.resp.Body
		if got := sig.Digest(raw); got != e.digest {
			where := ""
			if hostOf(e.uri) == r.providerHost {
				where = "; this URI is on the provider's own host"
			}
			r.add("dest.digest", Fail, "%s: %s serves bytes hashing to %s, entry pins %s — entry_manifest_mismatch: conforming clients reject the entry, never refresh it (§4.2). Attribution is not provable from one run: the destination changed after review, or the pin was wrong%s", es, e.uri, got, e.digest, where)
			r.block([]string{"dest.fields", "dest.signature"}, es, "the reviewed bytes are not what is served, so the provider's review cannot be checked")
			continue
		}
		r.add("dest.digest", Pass, "%s: served bytes match %s", es, e.digest)

		m, err := canon.Parse(raw)
		if err != nil {
			reason := fmt.Sprintf("destination manifest is not parseable under §3 constraints (%v); its seat's own parsing rules are not this profile's", err)
			r.add("dest.fields", Inconclusive, "%s: %s", es, reason)
			r.add("dest.signature", Inconclusive, "%s: %s", es, reason)
			continue
		}
		r.destFields(es, e, m)
		r.destSignature(es, raw, m)
	}
}

// destFields is §6 step 3: seatType ↔ seat, operator ↔ operator, and every
// entry profile declared by the signed manifest.
func (r *run) destFields(es string, e entry, m canon.Object) {
	var conflicts, unsure []string
	switch seat, ok := m["seat"].(string); {
	case !ok:
		unsure = append(unsure, "manifest has no string \"seat\" field to compare seatType with")
	case seat != e.seatType:
		conflicts = append(conflicts, fmt.Sprintf("entry seatType %q ≠ manifest seat %q", e.seatType, seat))
	}
	switch op, ok := m["operator"].(string); {
	case !ok:
		unsure = append(unsure, "manifest has no string \"operator\" field to compare with")
	case op != e.op:
		conflicts = append(conflicts, fmt.Sprintf("entry operator %s ≠ manifest operator %s", e.op, op))
	}
	declared := declaredProfiles(m)
	for _, p := range e.profiles {
		switch {
		case declared[p]:
		case containsString(m, p):
			unsure = append(unsure, fmt.Sprintf("profile %q appears in the manifest but not in a top-level *ProfileId / *Profiles declaration", p))
		default:
			conflicts = append(conflicts, fmt.Sprintf("entry profile %q is not declared anywhere in the signed manifest", p))
		}
	}
	switch {
	case len(conflicts) > 0:
		r.add("dest.fields", Fail, "%s: %s (entry_manifest_mismatch on the reviewed bytes: the catalog advertises what the operator's signed manifest does not declare)", es, strings.Join(conflicts, "; "))
	case len(unsure) > 0:
		r.add("dest.fields", Inconclusive, "%s: %s", es, strings.Join(unsure, "; "))
	default:
		r.add("dest.fields", Pass, "%s: seat, operator and %d profile(s) agree", es, len(e.profiles))
	}
}

// declaredProfiles collects profile identifiers a seat manifest declares
// at top level: string values of "*ProfileId" keys and string members of
// "*Profiles" / "profiles" arrays (moderationProfileId, messageProfileId,
// implementationProfileId, backupProfileId, implementationProfiles, …).
func declaredProfiles(m canon.Object) map[string]bool {
	out := map[string]bool{}
	for k, v := range m {
		switch {
		case strings.HasSuffix(k, "ProfileId"):
			if s, ok := v.(string); ok {
				out[s] = true
			}
		case strings.HasSuffix(k, "Profiles") || k == "profiles":
			if a, ok := v.([]any); ok {
				for _, x := range a {
					if s, ok := x.(string); ok {
						out[s] = true
					}
				}
			}
		}
	}
	return out
}

func containsString(v any, want string) bool {
	switch t := v.(type) {
	case string:
		return t == want
	case []any:
		for _, x := range t {
			if containsString(x, want) {
				return true
			}
		}
	case canon.Object:
		for _, x := range t {
			if containsString(x, want) {
				return true
			}
		}
	}
	return false
}

// destSignature is §6 step 4 under the canonical embedded-signature
// scheme, the one every Onym seat contract that pins a scheme uses.
func (r *run) destSignature(es string, raw []byte, m canon.Object) {
	seat, _ := m["seat"].(string)
	op, _ := m["operator"].(string)
	if !validKey(op) {
		r.add("dest.signature", Inconclusive, "%s: manifest operator %s is not an onym:key; cannot verify under this profile", es, show(m["operator"]))
		return
	}
	if _, ok := m["signature"].(string); !ok {
		r.add("dest.signature", Inconclusive, "%s: no embedded signature; seat %q may sign differently (e.g. detached over served bytes), which this profile does not verify", es, seat)
		return
	}
	err := sig.Verify(raw, "signature", sig.Key(op))
	switch source, known := canonicalSeats[seat]; {
	case err == nil:
		r.add("dest.signature", Pass, "%s: embedded signature verifies under its operator %s", es, op)
	case known:
		r.add("dest.signature", Fail, "%s: embedded signature does not verify under its operator %s over canonical bytes (%v); seat %q pins that scheme (%s) — entry_manifest_invalid on the bytes the provider reviewed", es, op, err, seat, source)
	default:
		r.add("dest.signature", Inconclusive, "%s: canonical-bytes verification failed (%v), but seat %q has no contract this suite knows pinning that scheme", es, err, seat)
	}
}
