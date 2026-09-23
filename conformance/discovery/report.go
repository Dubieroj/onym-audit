// Package discovery is the conformance suite for a Discovery provider
// deployment under Discovery-Static-Ed25519 (with Discovery.md as the
// authoritative abstract contract). It exercises the provider-side
// obligations only, black-box, over HTTPS, and produces a deterministic
// report the auditor attests to under methodology class conformance-run.
package discovery

import (
	"strings"
	"time"

	"onym-audit/canon"
	"onym-audit/sig"
)

const (
	SuiteID      = "onym:conformance-suite:discovery-static-ed25519-provider"
	SuiteVersion = "1.0.0"
)

// Outcome of one check.
type Outcome string

const (
	Pass          Outcome = "pass"
	Fail          Outcome = "fail"
	NotApplicable Outcome = "not-applicable"
	Inconclusive  Outcome = "inconclusive"
)

// Levels.
const (
	MUST   = "MUST"
	SHOULD = "SHOULD"
)

// Results.
const (
	ResultClear         = "clear"
	ResultFindingsNoted = "findings-noted"
	ResultFail          = "fail"
	ResultInconclusive  = "inconclusive"
)

// Check is one normative requirement, evaluated over every subject it
// applies to (a check covering several catalogs, entries or siblings takes
// the worst subject outcome; Detail lists each subject).
type Check struct {
	ID, Clause, Level, Title string
	Outcome                  Outcome
	Detail                   string
}

// Document is one fetched HTTP 200 body, digested over its exact bytes.
type Document struct {
	URI, Digest string
	Size        int
	Role        string
}

// Report is the result of one conformance run.
type Report struct {
	Suite, SuiteVersion, ManifestURI string
	RunAt                            time.Time
	Checks                           []Check
	Documents                        []Document
	Result                           string
}

const (
	pS  = "Discovery-Static-Ed25519 "
	pA  = "Discovery.md "
	na  = "no applicable subject"
	npc = "no public catalog descriptor decoded"
)

type checkSpec struct {
	id, level, clause, title, none string
}

// checkSpecs is the suite's fixed check list, in report order.
var checkSpecs = []checkSpec{
	// Provider manifest.
	{"manifest.uri", MUST, pS + "§5, §7", "Provider manifest URL is https and obeys the §7 URI rules (raw-string port check, no IP literal, no userinfo/query/fragment)", na},
	{"manifest.fetch", MUST, pS + "§5, §6 (add step 1), §7", "Provider manifest is served: HTTP 200 within ≤ 3 HTTPS→HTTPS redirects", na},
	{"manifest.size", MUST, pS + "§7, §9 provider_manifest_invalid", "Provider manifest is at most 64 KiB", na},
	{"manifest.schema", MUST, pS + "§3, §4.1 (strictness table), §2, §9", "Provider manifest is strict §3 JSON with exactly the required top-level fields, correctly typed; unknown top-level fields rejected", na},
	{"manifest.identity", MUST, pS + "§1, §2, §6 (add step 2), §9", "version is 1, implementationProfileId is the v1 profile, seat is \"discovery\", providerId and operator have §2 syntax", na},
	{"manifest.signature", MUST, pS + "§3, §6 (add step 3); " + pA + "§14.1(1)", "Embedded signature verifies under the manifest's own operator key over §3 canonical bytes", na},
	{"manifest.detached-sig", MUST, pS + "§3, §9", "A published manifest .sig is standard padded base64 plus exactly one newline and decodes to the embedded signature's 64 bytes", "no detached .sig published (optional, §3)"},
	{"manifest.valid-until", MUST, pS + "§2, §6, §9", "validUntil is a §2 timestamp that has not passed", na},
	// Catalog descriptors.
	{"catalog.descriptor-fields", MUST, pS + "§4.1 (table, catalogId, seatTypes), §2", "Every catalogs[] descriptor carries each required field with valid type and syntax", na},
	{"catalog.descriptor-unknown-keys", SHOULD, pS + "§4.1 (table: unknown keys skip the descriptor), §1", "No catalogs[] descriptor carries keys undefined in v1 (conforming clients skip such a descriptor)", na},
	{"catalog.decodable", MUST, pS + "§4.1 (table), §9", "At least one catalogs[] descriptor decodes", na},
	{"catalog.duplicate-id", MUST, pS + "§4.1", "No catalogId repeats among decoded descriptors", na},
	// URIs in documents.
	{"uri.rules", MUST, pS + "§7, §9", "Every URI in the provider's documents (privacyProfileUri, snapshot, policyUri, entry manifest.uri, status.uri) obeys the §7 URI rules", na},
	// Policy and privacy documents.
	{"policy.document", MUST, pS + "§2, §4.1, §7, §9 policy_unavailable; " + pA + "§14.1(2)", "Each public catalog's policyUri serves (HTTP 200, ≤ 1 MiB) bytes hashing to the declared policy digest", npc},
	{"privacy.document", MUST, pS + "§2, §4.1, §7; " + pA + "§10, §14.1(8)", "privacyProfileUri serves (HTTP 200, ≤ 1 MiB) bytes hashing to the declared privacyProfile digest", na},
	// Latest catalog snapshots.
	{"snapshot.fetch", MUST, pS + "§5, §6 (refresh step 1), §7", "Each public catalog's snapshot URL serves the latest snapshot: HTTP 200 within redirect bounds", npc},
	{"snapshot.size", MUST, pS + "§7, §9", "Snapshot is at most 1 MiB", npc},
	{"snapshot.schema", MUST, pS + "§3, §4.2 (strictness table), §2, §9", "Snapshot is strict §3 JSON with exactly the required top-level fields, correctly typed; unknown top-level fields rejected", npc},
	{"snapshot.identity", MUST, pS + "§1, §6 (refresh step 3)", "Snapshot version is 1, profile is v1, catalogId matches its descriptor, providerId matches the manifest", npc},
	{"snapshot.signature", MUST, pS + "§3, §6 (refresh step 2); " + pA + "§14.1(1)", "Snapshot is signed by the provider manifest's operator key", npc},
	{"snapshot.detached-sig", MUST, pS + "§3, §9", "Every published snapshot .sig (latest and retained) is standard padded base64 plus exactly one newline and agrees with the embedded signature", "no snapshot .sig published (optional, §3)"},
	{"snapshot.policy-digest", MUST, pS + "§4.2 (chain rules), §9", "Snapshot policyDigest equals the manifest's declared policy for its catalogId", npc},
	{"snapshot.chain-fields", MUST, pS + "§4.2 (chain rules), §9", "sequence ≥ 1; previousDigest present iff sequence > 1", npc},
	{"snapshot.dates", MUST, pS + "§4.2, §9", "generatedAt is not more than 10 minutes in the future and expiresAt is strictly after generatedAt", npc},
	{"snapshot.window-max", MUST, pS + "§4.2", "expiresAt − generatedAt does not exceed 90 days", npc},
	{"snapshot.window-short", SHOULD, pS + "§4.2 (\"days to a few weeks\"); " + pA + "§13", "Expiry window is at most six weeks (flags only windows no reading of \"days to a few weeks\" covers)", npc},
	{"snapshot.fresh", MUST, "Suite bar: client acceptance — " + pS + "§4.2, §9 snapshot_expired; " + pA + "§9, §12, invariant 9", "A conforming client refreshing at run time accepts the served latest snapshot as current (not expired, 10-minute skew allowance)", npc},
	{"snapshot.entry-count", MUST, pS + "§7, §9", "At most 512 entries", npc},
	{"snapshot.duplicate-component", MUST, pS + "§4.2 (entry rules), §9", "No componentId repeats among decoded-and-surviving entries", npc},
	// Entries.
	{"entry.fields", MUST, pS + "§4.1 (table), §4.2 (entry rules), §2, §9 result_incomplete", "Every entry decodes: required fields, §2 syntax, closed relationship/placement sets, evidence absent or empty, status shape", "no entries"},
	{"entry.unknown-keys", SHOULD, pS + "§4 (lossy entry decoding), §4.1 (table), §9 result_incomplete", "No entry (or its manifest/status object) carries keys undefined in v1 (conforming clients skip such an entry)", "no entries"},
	{"entry.seat-type-declared", SHOULD, pS + "§4.1 (seatTypes); " + pA + "§5.1, §7", "Each entry's seatType is within its catalog descriptor's seatTypes (or the catalog declares \"*\")", "no surviving entries"},
	{"provider.cross-catalog-digest", MUST, pS + "§4.2 (entry rules)", "The same componentId carries the same manifest.digest across the provider's catalogs", "fewer than two verified catalogs"},
	// Retention and chain.
	{"chain.retention", MUST, pS + "§5, §6 (forward jump)", "Every superseded snapshot that has not yet expired is served as <catalogId>-<sequence>.json", npc},
	{"chain.sibling-valid", MUST, pS + "§3, §4.2, §5, §6 (intermediates: signature, chain, schema), §7", "Every retained sibling is ≤ 1 MiB, strict-schema, the named catalog's sequence, and signed by the operator key", npc},
	{"chain.links", MUST, pS + "§4.2 (chain rules), §6 (fork, provable break)", "previousDigest of sequence k+1 is the SHA-256 of the exact served bytes of sequence k", npc},
	{"chain.latest-sibling", MUST, pS + "§4.2 (published bytes immutable), §5", "If the latest sequence N is also served as <catalogId>-<N>.json, those bytes are identical to the latest snapshot", npc},
	// Destination manifests.
	{"dest.retrievable", SHOULD, pS + "§6 (before presenting, step 1), §7, §9 entry_manifest_unavailable; " + pA + "§14.1(6)", "Each surviving entry's manifest.uri serves its destination manifest (HTTP 200, ≤ 256 KiB)", "no surviving entries"},
	{"dest.digest", SHOULD, pS + "§4.2 (manifest.digest), §6 (step 2), §9 entry_manifest_mismatch; " + pA + "§14.1(4), §14.1(6)", "Served destination bytes hash to the entry's manifest.digest", "no surviving entries"},
	{"dest.fields", MUST, pS + "§6 (before presenting, step 3), §9 entry_manifest_mismatch; " + pA + "§5.3, §14.1(3)", "In the reviewed (digest-matching) bytes, seat, operator and every entry profile agree with the entry", "no surviving entries"},
	{"dest.signature", MUST, pS + "§4.3, §6 (step 4), §9 entry_manifest_invalid; " + pA + "§14.1(4)", "The reviewed destination bytes carry a valid signature by their own operator key", "no surviving entries"},
	// Serving.
	{"serving.no-cookies", MUST, pS + "§5; " + pA + "§10", "No response from the provider's documents sets a cookie", na},
}

type finding struct {
	outcome Outcome
	text    string
}

// rank orders outcomes for aggregation: the worst subject decides.
func rank(o Outcome) int {
	switch o {
	case Fail:
		return 3
	case Inconclusive:
		return 2
	case Pass:
		return 1
	}
	return 0
}

func buildChecks(findings map[string][]finding, stopped string) []Check {
	out := make([]Check, 0, len(checkSpecs))
	for _, s := range checkSpecs {
		c := Check{ID: s.id, Clause: s.clause, Level: s.level, Title: s.title}
		fs := findings[s.id]
		switch {
		case len(fs) == 0 && stopped != "":
			c.Outcome, c.Detail = Inconclusive, "not evaluated: "+stopped
		case len(fs) == 0:
			c.Outcome, c.Detail = NotApplicable, s.none
		default:
			c.Outcome = fs[0].outcome
			parts := make([]string, 0, len(fs))
			for _, f := range fs {
				if rank(f.outcome) > rank(c.Outcome) {
					c.Outcome = f.outcome
				}
				parts = append(parts, f.text)
			}
			c.Detail = strings.Join(parts, "; ")
		}
		c.Detail = strings.ToValidUTF8(c.Detail, "�")
		out = append(out, c)
	}
	return out
}

// result applies the suite's roll-up. A SHOULD-level inconclusive is a
// noted finding: the run is not clear, but nothing MUST-level is in doubt.
func result(checks []Check) string {
	var mustFail, mustInc, shouldNote bool
	for _, c := range checks {
		switch {
		case c.Level == MUST && c.Outcome == Fail:
			mustFail = true
		case c.Level == MUST && c.Outcome == Inconclusive:
			mustInc = true
		case c.Level == SHOULD && (c.Outcome == Fail || c.Outcome == Inconclusive):
			shouldNote = true
		}
	}
	switch {
	case mustFail:
		return ResultFail
	case mustInc:
		return ResultInconclusive
	case shouldNote:
		return ResultFindingsNoted
	}
	return ResultClear
}

// Canonical serializes the report deterministically with the §3 canonical
// encoder: sorted keys, compact, pinned escaping, checks in suite order and
// documents in fetch order.
func (r *Report) Canonical() ([]byte, error) {
	checks := make([]any, len(r.Checks))
	for i, c := range r.Checks {
		checks[i] = canon.Object{
			"id": c.ID, "clause": c.Clause, "level": c.Level, "title": c.Title,
			"outcome": string(c.Outcome), "detail": c.Detail,
		}
	}
	docs := make([]any, len(r.Documents))
	for i, d := range r.Documents {
		docs[i] = canon.Object{"uri": d.URI, "digest": d.Digest, "size": d.Size, "role": d.Role}
	}
	return canon.Encode(canon.Object{
		"suite":        r.Suite,
		"suiteVersion": r.SuiteVersion,
		"manifestUri":  r.ManifestURI,
		"runAt":        sig.FormatTime(r.RunAt),
		"result":       r.Result,
		"checks":       checks,
		"documents":    docs,
	})
}
