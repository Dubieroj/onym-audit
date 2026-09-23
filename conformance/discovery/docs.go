package discovery

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"onym-audit/canon"
	"onym-audit/sig"
	"onym-audit/urirule"
)

// Profile constants (Discovery-Static-Ed25519 §1, §4.2, §7).
const (
	profileID      = "onym:discovery-implementation:static-ed25519-v1"
	limitManifest  = 64 << 10
	limitSnapshot  = 1 << 20
	limitDest      = 256 << 10
	limitDocument  = 1 << 20
	limitSig       = 4 << 10
	maxEntries     = 512
	maxWalk        = 64
	clockSkew      = 10 * time.Minute
	maxWindow      = 90 * 24 * time.Hour
	shortWindow    = 42 * 24 * time.Hour
	day            = 24 * time.Hour
	stateWarning   = "warning"
	stateReview    = "review"
	audiencePublic = "public"
)

var (
	componentRE = regexp.MustCompile(`^onym:component:[a-z0-9-]{1,64}$`)
	catalogIDRE = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
	seatTypeRE  = regexp.MustCompile(`^[a-z0-9.-]{1,64}$`)
	// §3: the detached form is exactly standard padded base64 of the 64
	// signature bytes followed by one newline.
	detachedRE = regexp.MustCompile(`^[A-Za-z0-9+/]{86}==\n$`)

	relationships = map[string]bool{
		"none": true, "catalog-subscriber": true, "listing-fee": true, "sponsored-placement": true,
		"common-owner": true, "catalog-sponsor": true, "other-disclosed": true,
	}
	placements = map[string]bool{"policy-ranked": true, "sponsored": true}
)

func str(o canon.Object, k string) (string, bool) {
	s, ok := o[k].(string)
	return s, ok
}

func num(o canon.Object, k string) (int64, bool) {
	n, ok := o[k].(canon.Number)
	if !ok {
		return 0, false
	}
	return n.Int(), true
}

// fields checks o's keys against the required and optional sets, returning
// missing required keys and unknown keys (both sorted).
func fields(o canon.Object, required, optional []string) (missing, unknown []string) {
	known := map[string]bool{}
	for _, k := range required {
		known[k] = true
		if _, ok := o[k]; !ok {
			missing = append(missing, k)
		}
	}
	for _, k := range optional {
		known[k] = true
	}
	for k := range o {
		if !known[k] {
			unknown = append(unknown, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(unknown)
	return missing, unknown
}

func quoteAll(ks []string) string {
	q := make([]string, len(ks))
	for i, k := range ks {
		q[i] = fmt.Sprintf("%q", k)
	}
	return strings.Join(q, ", ")
}

type typeRule struct {
	key  string
	kind string // "string", "number", "array", "strings", "object"
}

func typeProblems(o canon.Object, rules []typeRule) []string {
	var p []string
	for _, r := range rules {
		v, ok := o[r.key]
		if !ok {
			continue
		}
		good := false
		switch r.kind {
		case "string":
			_, good = v.(string)
		case "number":
			_, good = v.(canon.Number)
		case "array":
			_, good = v.([]any)
		case "object":
			_, good = v.(canon.Object)
		case "strings":
			if a, isArr := v.([]any); isArr {
				good = true
				for _, e := range a {
					if _, s := e.(string); !s {
						good = false
					}
				}
			}
		}
		if !good {
			p = append(p, fmt.Sprintf("%q is not %s", r.key, kindName(r.kind)))
		}
	}
	return p
}

func kindName(k string) string {
	switch k {
	case "number":
		return "a non-negative integer"
	case "strings":
		return "an array of strings"
	case "object":
		return "an object"
	}
	return "a " + k
}

// --- provider manifest (§4.1) ---

var manifestRequired = []string{
	"version", "implementationProfileId", "providerId", "operator", "seat", "catalogs",
	"capabilities", "offers", "privacyProfile", "privacyProfileUri", "validUntil", "signature",
}

var manifestTypes = []typeRule{
	{"version", "number"}, {"implementationProfileId", "string"}, {"providerId", "string"},
	{"operator", "string"}, {"seat", "string"}, {"catalogs", "array"}, {"capabilities", "strings"},
	{"offers", "array"}, {"privacyProfile", "string"}, {"privacyProfileUri", "string"},
	{"validUntil", "string"}, {"signature", "string"},
}

func manifestSchema(o canon.Object) []string {
	missing, unknown := fields(o, manifestRequired, nil)
	var p []string
	if len(missing) > 0 {
		p = append(p, "missing required field(s) "+quoteAll(missing))
	}
	if len(unknown) > 0 {
		p = append(p, "unknown top-level field(s) "+quoteAll(unknown))
	}
	p = append(p, typeProblems(o, manifestTypes)...)
	if s, ok := str(o, "privacyProfile"); ok && !sig.ValidDigest(s) {
		p = append(p, fmt.Sprintf("privacyProfile %q is not sha256:<64 lowercase hex> (§2)", s))
	}
	return p
}

func manifestIdentity(o canon.Object) []string {
	var p []string
	if v, ok := o["version"].(canon.Number); !ok || v != "1" {
		p = append(p, fmt.Sprintf("version is %s, want 1 (§1)", show(o["version"])))
	}
	if s, _ := str(o, "implementationProfileId"); s != profileID {
		p = append(p, fmt.Sprintf("implementationProfileId is %s, want %q", show(o["implementationProfileId"]), profileID))
	}
	if s, _ := str(o, "seat"); s != "discovery" {
		p = append(p, fmt.Sprintf("seat is %s, want \"discovery\"", show(o["seat"])))
	}
	if s, _ := str(o, "providerId"); !componentRE.MatchString(s) {
		p = append(p, fmt.Sprintf("providerId %s does not match onym:component:[a-z0-9-]{1,64} (§2)", show(o["providerId"])))
	}
	if s, _ := str(o, "operator"); !validKey(s) {
		p = append(p, fmt.Sprintf("operator %s is not onym:key:<64 lowercase hex> (§2)", show(o["operator"])))
	}
	return p
}

func validKey(s string) bool {
	_, err := sig.Key(s).Public()
	return err == nil
}

// show renders a decoded JSON value briefly for a detail string.
func show(v any) string {
	switch t := v.(type) {
	case nil:
		return "absent or null"
	case string:
		if len(t) > 120 {
			t = t[:120] + "…"
		}
		return fmt.Sprintf("%q", t)
	case canon.Number:
		return string(t)
	case bool:
		return fmt.Sprint(t)
	case []any:
		return "an array"
	case canon.Object:
		return "an object"
	}
	return fmt.Sprintf("%T", v)
}

// --- catalog descriptors (§4.1) ---

type descriptor struct {
	index                                     int
	catalogID, snapshot, audience, policy, pu string
	seatTypes                                 []string
}

var descriptorRequired = []string{"catalogId", "snapshot", "audience", "seatTypes", "policy", "policyUri"}

// decodeDescriptor applies §4.1's descriptor rules. fieldP are violations
// of required fields and syntax, unknown lists undefined keys, uriP lists
// §7 violations; any of the three makes a conforming client skip it.
func decodeDescriptor(v any) (d descriptor, fieldP, unknown, uriP []string) {
	o, ok := v.(canon.Object)
	if !ok {
		return d, []string{"descriptor is " + show(v) + ", not an object"}, nil, nil
	}
	missing, unknown := fields(o, descriptorRequired, nil)
	if len(missing) > 0 {
		fieldP = append(fieldP, "missing required field(s) "+quoteAll(missing))
	}
	fieldP = append(fieldP, typeProblems(o, []typeRule{
		{"catalogId", "string"}, {"snapshot", "string"}, {"audience", "string"},
		{"seatTypes", "strings"}, {"policy", "string"}, {"policyUri", "string"},
	})...)
	d.catalogID, _ = str(o, "catalogId")
	d.snapshot, _ = str(o, "snapshot")
	d.audience, _ = str(o, "audience")
	d.policy, _ = str(o, "policy")
	d.pu, _ = str(o, "policyUri")
	if _, ok := o["catalogId"].(string); ok && !catalogIDRE.MatchString(d.catalogID) {
		fieldP = append(fieldP, fmt.Sprintf("catalogId %q does not match [a-z0-9-]{1,64}", d.catalogID))
	}
	if _, ok := o["policy"].(string); ok && !sig.ValidDigest(d.policy) {
		fieldP = append(fieldP, fmt.Sprintf("policy %q is not sha256:<64 lowercase hex> (§2)", d.policy))
	}
	if a, ok := o["seatTypes"].([]any); ok {
		star := false
		for _, m := range a {
			s, _ := m.(string)
			d.seatTypes = append(d.seatTypes, s)
			switch {
			case s == "*":
				star = true
			case !seatTypeRE.MatchString(s):
				fieldP = append(fieldP, fmt.Sprintf("seatTypes member %s is neither [a-z0-9.-]{1,64} nor \"*\"", show(m)))
			}
		}
		if len(a) == 0 {
			fieldP = append(fieldP, "seatTypes is empty (not a defined state)")
		}
		if star && len(a) > 1 {
			fieldP = append(fieldP, "\"*\" does not appear alone in seatTypes")
		}
	}
	for _, k := range []string{"snapshot", "policyUri"} {
		if s, ok := str(o, k); ok {
			if err := urirule.Check(s); err != nil {
				uriP = append(uriP, fmt.Sprintf("%s: %v", k, err))
			}
		}
	}
	return d, fieldP, unknown, uriP
}

// --- catalog snapshots (§4.2) ---

type snapDoc struct {
	raw                        []byte
	obj                        canon.Object
	digest                     string
	seq                        int64
	haveSeq                    bool
	prev                       string
	hasPrev                    bool
	catalogID, providerID      string
	policyDigest               string
	generated, expires         time.Time
	timesOK                    bool
	timeProblem                string
	entries                    []any
	haveEntries                bool
	sigOK                      bool
	sigProblem                 string
	schemaProblems, idProblems []string
	chainProblems              []string
	parseErr                   error
}

var snapshotRequired = []string{
	"version", "implementationProfileId", "catalogId", "providerId", "sequence",
	"policyDigest", "generatedAt", "expiresAt", "entries", "signature",
}

// decodeSnapshot parses raw and evaluates schema, identity against the
// expected catalogId/providerId, chain fields and the signature under key.
func decodeSnapshot(raw []byte, catalogID, providerID string, key sig.Key) *snapDoc {
	s := &snapDoc{raw: raw, digest: sig.Digest(raw)}
	o, err := canon.Parse(raw)
	if err != nil {
		s.parseErr = err
		return s
	}
	s.obj = o
	missing, unknown := fields(o, snapshotRequired, []string{"previousDigest"})
	if len(missing) > 0 {
		s.schemaProblems = append(s.schemaProblems, "missing required field(s) "+quoteAll(missing))
	}
	if len(unknown) > 0 {
		s.schemaProblems = append(s.schemaProblems, "unknown top-level field(s) "+quoteAll(unknown))
	}
	s.schemaProblems = append(s.schemaProblems, typeProblems(o, []typeRule{
		{"version", "number"}, {"implementationProfileId", "string"}, {"catalogId", "string"},
		{"providerId", "string"}, {"sequence", "number"}, {"policyDigest", "string"},
		{"generatedAt", "string"}, {"expiresAt", "string"}, {"entries", "array"}, {"signature", "string"},
	})...)
	s.catalogID, _ = str(o, "catalogId")
	s.providerID, _ = str(o, "providerId")
	s.policyDigest, _ = str(o, "policyDigest")
	if _, ok := o["policyDigest"].(string); ok && !sig.ValidDigest(s.policyDigest) {
		s.schemaProblems = append(s.schemaProblems, fmt.Sprintf("policyDigest %q is not sha256:<64 lowercase hex> (§2)", s.policyDigest))
	}
	s.entries, s.haveEntries = o["entries"].([]any)
	s.seq, s.haveSeq = num(o, "sequence")

	// Identity (§1, §6 refresh step 3).
	if v, ok := o["version"].(canon.Number); !ok || v != "1" {
		s.idProblems = append(s.idProblems, fmt.Sprintf("version is %s, want 1", show(o["version"])))
	}
	if p, _ := str(o, "implementationProfileId"); p != profileID {
		s.idProblems = append(s.idProblems, fmt.Sprintf("implementationProfileId is %s", show(o["implementationProfileId"])))
	}
	if s.catalogID != catalogID {
		s.idProblems = append(s.idProblems, fmt.Sprintf("catalogId is %s, descriptor declares %q", show(o["catalogId"]), catalogID))
	}
	if s.providerID != providerID {
		s.idProblems = append(s.idProblems, fmt.Sprintf("providerId is %s, manifest declares %q", show(o["providerId"]), providerID))
	}

	// Chain fields (§4.2).
	pv, hasPrev := o["previousDigest"]
	s.hasPrev = hasPrev
	s.prev, _ = pv.(string)
	switch {
	case !s.haveSeq:
		s.chainProblems = append(s.chainProblems, "sequence missing or not an integer")
	case s.seq < 1:
		s.chainProblems = append(s.chainProblems, fmt.Sprintf("sequence %d; sequences start at 1", s.seq))
	case s.seq == 1 && hasPrev:
		s.chainProblems = append(s.chainProblems, "previousDigest present at sequence 1 (forbidden)")
	case s.seq > 1 && !hasPrev:
		s.chainProblems = append(s.chainProblems, fmt.Sprintf("previousDigest missing at sequence %d (required)", s.seq))
	case s.seq > 1 && !sig.ValidDigest(s.prev):
		s.chainProblems = append(s.chainProblems, fmt.Sprintf("previousDigest %s is not sha256:<64 lowercase hex>", show(pv)))
	}

	// Timestamps (§2).
	g, gOK := str(o, "generatedAt")
	e, eOK := str(o, "expiresAt")
	if gOK && eOK {
		var gErr, eErr error
		s.generated, gErr = sig.ParseTime(g)
		s.expires, eErr = sig.ParseTime(e)
		switch {
		case gErr != nil:
			s.timeProblem = "generatedAt: " + gErr.Error()
		case eErr != nil:
			s.timeProblem = "expiresAt: " + eErr.Error()
		default:
			s.timesOK = true
		}
	} else {
		s.timeProblem = "generatedAt/expiresAt missing or not strings"
	}

	// Signature (§3) under the provider manifest's operator key.
	if _, ok := o["signature"].(string); !ok {
		s.sigProblem = "snapshot is unsigned (no string signature field)"
	} else if err := sig.Verify(raw, "signature", key); err != nil {
		s.sigProblem = fmt.Sprintf("does not verify under %s: %v", key, err)
	} else {
		s.sigOK = true
	}
	return s
}

// --- catalog entries (§4.1 table, §4.2 entry rules) ---

type entry struct {
	index                                  int
	componentID, seatType, uri, digest, op string
	profiles                               []string
}

var entryRequired = []string{"componentId", "seatType", "manifest", "operator", "listedAt", "relationship", "placement"}
var entryOptional = []string{"profiles", "evidence", "reviewedAt", "status"}

// decodeEntry applies the lossy per-entry rules: any returned problem makes
// a conforming client skip the entry.
func decodeEntry(i int, v any) (e entry, fieldP, unknown, uriP []string) {
	e.index = i
	o, ok := v.(canon.Object)
	if !ok {
		return e, []string{"entry is " + show(v) + ", not an object"}, nil, nil
	}
	missing, unk := fields(o, entryRequired, entryOptional)
	if len(missing) > 0 {
		fieldP = append(fieldP, "missing required field(s) "+quoteAll(missing))
	}
	unknown = append(unknown, unk...)
	fieldP = append(fieldP, typeProblems(o, []typeRule{
		{"componentId", "string"}, {"seatType", "string"}, {"manifest", "object"}, {"operator", "string"},
		{"listedAt", "string"}, {"relationship", "string"}, {"placement", "string"},
		{"profiles", "strings"}, {"evidence", "array"}, {"reviewedAt", "string"}, {"status", "object"},
	})...)
	e.componentID, _ = str(o, "componentId")
	e.seatType, _ = str(o, "seatType")
	e.op, _ = str(o, "operator")
	if _, ok := o["componentId"].(string); ok && !componentRE.MatchString(e.componentID) {
		fieldP = append(fieldP, fmt.Sprintf("componentId %q does not match onym:component:[a-z0-9-]{1,64} (§2)", e.componentID))
	}
	if _, ok := o["seatType"].(string); ok && e.seatType == "" {
		fieldP = append(fieldP, "seatType is empty")
	}
	if _, ok := o["operator"].(string); ok && !validKey(e.op) {
		fieldP = append(fieldP, fmt.Sprintf("operator %q is not onym:key:<64 lowercase hex> (§2)", e.op))
	}
	for _, k := range []string{"listedAt", "reviewedAt"} {
		if s, ok := str(o, k); ok {
			if _, err := sig.ParseTime(s); err != nil {
				fieldP = append(fieldP, fmt.Sprintf("%s: %v (§2)", k, err))
			}
		}
	}
	if s, ok := str(o, "relationship"); ok && !relationships[s] {
		fieldP = append(fieldP, fmt.Sprintf("relationship %q is outside the pinned v1 set (fails closed)", s))
	}
	if s, ok := str(o, "placement"); ok && !placements[s] {
		fieldP = append(fieldP, fmt.Sprintf("placement %q is outside the pinned v1 set (fails closed)", s))
	}
	if a, ok := o["evidence"].([]any); ok && len(a) > 0 {
		fieldP = append(fieldP, fmt.Sprintf("evidence has %d member(s); v1 requires it absent or empty", len(a)))
	}
	if a, ok := o["profiles"].([]any); ok {
		for _, p := range a {
			if s, ok := p.(string); ok {
				e.profiles = append(e.profiles, s)
			}
		}
	}
	if m, ok := o["manifest"].(canon.Object); ok {
		mm, mu := fields(m, []string{"uri", "digest"}, nil)
		if len(mm) > 0 {
			fieldP = append(fieldP, "manifest missing "+quoteAll(mm))
		}
		for _, k := range mu {
			unknown = append(unknown, "manifest."+k)
		}
		fieldP = append(fieldP, prefixed("manifest.", typeProblems(m, []typeRule{{"uri", "string"}, {"digest", "string"}}))...)
		e.uri, _ = str(m, "uri")
		e.digest, _ = str(m, "digest")
		if _, ok := m["digest"].(string); ok && !sig.ValidDigest(e.digest) {
			fieldP = append(fieldP, fmt.Sprintf("manifest.digest %q is not sha256:<64 lowercase hex> (§2)", e.digest))
		}
		if _, ok := m["uri"].(string); ok {
			if err := urirule.Check(e.uri); err != nil {
				uriP = append(uriP, fmt.Sprintf("manifest.uri: %v", err))
			}
		}
	}
	if st, ok := o["status"].(canon.Object); ok {
		sm, su := fields(st, []string{"state"}, []string{"uri"})
		if len(sm) > 0 {
			fieldP = append(fieldP, "status missing \"state\"")
		}
		for _, k := range su {
			unknown = append(unknown, "status."+k)
		}
		fieldP = append(fieldP, prefixed("status.", typeProblems(st, []typeRule{{"state", "string"}, {"uri", "string"}}))...)
		if s, ok := str(st, "state"); ok && s != stateWarning && s != stateReview {
			fieldP = append(fieldP, fmt.Sprintf("status.state %q is neither \"warning\" nor \"review\"", s))
		}
		if s, ok := str(st, "uri"); ok {
			if err := urirule.Check(s); err != nil {
				uriP = append(uriP, fmt.Sprintf("status.uri: %v", err))
			}
		}
	}
	sort.Strings(unknown)
	return e, fieldP, unknown, uriP
}

func prefixed(p string, ss []string) []string {
	for i, s := range ss {
		ss[i] = p + s
	}
	return ss
}

// --- detached signatures (§3) ---

// detachedProblem returns "" when body is a conforming detached form of the
// embedded signature, else the reason.
func detachedProblem(body []byte, truncated bool, embedded any) string {
	if truncated {
		return fmt.Sprintf("larger than %d bytes; not a detached signature", limitSig)
	}
	var p []string
	if !detachedRE.Match(body) {
		p = append(p, fmt.Sprintf("content %s is not exactly standard padded base64 of 64 bytes followed by one \"\\n\"", briefBytes(body)))
	}
	d, derr := sig.DecodeSignature(strings.TrimRight(string(body), "\r\n"))
	es, isStr := embedded.(string)
	var e []byte
	var eerr error = fmt.Errorf("no embedded signature string")
	if isStr {
		e, eerr = sig.DecodeSignature(es)
	}
	switch {
	case derr != nil:
		p = append(p, "detached content does not decode to 64 signature bytes")
	case eerr != nil:
		p = append(p, "embedded signature does not decode to 64 bytes, so agreement fails")
	case string(d) != string(e):
		p = append(p, "decodes to different signature bytes than the embedded signature (disagreement; fails closed)")
	}
	return strings.Join(p, "; ")
}

func briefBytes(b []byte) string {
	if len(b) > 100 {
		return fmt.Sprintf("%q… (%d bytes)", b[:100], len(b))
	}
	return fmt.Sprintf("%q", b)
}

func fmtDur(d time.Duration) string {
	if d%day == 0 {
		return fmt.Sprintf("%d days", d/day)
	}
	return fmt.Sprintf("%.2f days", d.Hours()/24)
}
