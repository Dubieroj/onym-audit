package discovery

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"onym-audit/canon"
	"onym-audit/sig"
)

// fakeFetcher serves a URI → Response map like a static host: unknown URIs
// are 404, and bodies are cut at limit+1 exactly as the real fetcher reads.
type fakeFetcher struct {
	files map[string]*Response
	errs  map[string]error
	log   []string
}

func (f *fakeFetcher) Get(ctx context.Context, uri string) (*Response, error) {
	f.log = append(f.log, uri)
	if err, ok := f.errs[uri]; ok {
		return nil, err
	}
	src, ok := f.files[uri]
	if !ok {
		return &Response{URI: uri, Status: http.StatusNotFound, Header: http.Header{}, Body: []byte("not found")}, nil
	}
	r := *src
	r.URI = uri
	if r.Header == nil {
		r.Header = http.Header{}
	}
	if limit := LimitFrom(ctx); int64(len(r.Body)) > limit {
		r.Body, r.Truncated = r.Body[:limit+1], true
	}
	return &r, nil
}

func ok200(b []byte) *Response {
	return &Response{Status: http.StatusOK, Header: http.Header{}, Body: b}
}

func seed(b byte) ed25519.PrivateKey {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = b
	}
	return ed25519.NewKeyFromSeed(s)
}

func keyOf(p ed25519.PrivateKey) string { return string(sig.KeyOf(p.Public().(ed25519.PublicKey))) }

func ts(s string) time.Time {
	t, err := sig.ParseTime(s)
	if err != nil {
		panic(err)
	}
	return t
}

const (
	host        = "https://provider.example"
	manifestURI = host + "/manifest.json"
	policyURI   = host + "/policies/main.md"
	privacyURI  = host + "/privacy.md"
	snapshotURI = host + "/catalogs/main.json"
	destAURI    = "https://relayer.example/manifest.json"
	destBURI    = host + "/manifests/courier.json"
)

func siblingURI(k int) string { return fmt.Sprintf("%s/catalogs/main-%d.json", host, k) }

// world is a fully valid provider: manifest + policy + privacy documents, a
// three-snapshot chain with every sibling retained (the latest too), and
// two destination manifests. Hooks and post-publish edits make tampers.
type world struct {
	t       *testing.T
	now     time.Time
	op      ed25519.PrivateKey
	keyA    ed25519.PrivateKey
	keyB    ed25519.PrivateKey
	window  time.Duration
	policy  []byte
	privacy []byte

	manifestHook func(canon.Object)
	snapHook     func(seq int, o canon.Object)
	snapSigner   func(seq int) ed25519.PrivateKey

	files  map[string]*Response
	bytes  map[string][]byte
	digest map[string]string
}

func newWorld(t *testing.T) *world {
	return &world{
		t:       t,
		now:     ts("2026-09-20T12:00:00Z"),
		op:      seed(0x11),
		keyA:    seed(0x22),
		keyB:    seed(0x33),
		window:  14 * day,
		policy:  []byte("# Inclusion and ranking policy\n\nEvery listed instance is reviewed.\n"),
		privacy: []byte("# Privacy profile\n\nLocal filtering; no query logs.\n"),
	}
}

var generated = map[int]string{1: "2026-09-10T00:00:00Z", 2: "2026-09-14T00:00:00Z", 3: "2026-09-18T00:00:00Z"}

func (w *world) sign(o canon.Object, k ed25519.PrivateKey) []byte {
	b, err := sig.Sign(o, "signature", k)
	if err != nil {
		w.t.Fatal(err)
	}
	return b
}

// serveSigned publishes b at uri plus its §3 detached .sig.
func (w *world) serveSigned(uri string, b []byte) {
	o, err := canon.Parse(b)
	if err != nil {
		w.t.Fatal(err)
	}
	w.files[uri] = ok200(b)
	w.files[uri+".sig"] = ok200([]byte(o["signature"].(string) + "\n"))
	w.bytes[uri] = b
	w.digest[uri] = sig.Digest(b)
}

func (w *world) destA() canon.Object {
	return canon.Object{
		"version": 1, "componentId": "onym:component:relayer", "seat": "notary", "operator": keyOf(w.keyA),
		"implementationProfiles": []any{"onym:notary-implementation:test-v1"},
		"validUntil":             "2027-01-01T00:00:00Z",
	}
}

func (w *world) destB() canon.Object {
	return canon.Object{
		"version": 1, "componentId": "onym:component:courier", "seat": "transport.message", "operator": keyOf(w.keyB),
		"messageProfileId":        "onym:message-profile:opaque-topic-inbox-v1",
		"implementationProfileId": "onym:message-implementation:nostr-courier-v1",
		"validUntil":              "2027-01-01T00:00:00Z",
	}
}

func (w *world) manifest() canon.Object {
	return canon.Object{
		"version":                 1,
		"implementationProfileId": profileID,
		"providerId":              "onym:component:test-discovery",
		"operator":                keyOf(w.op),
		"seat":                    "discovery",
		"catalogs": []any{canon.Object{
			"catalogId": "main", "snapshot": snapshotURI, "audience": "public",
			"seatTypes": []any{"notary", "transport.message"},
			"policy":    sig.Digest(w.policy), "policyUri": policyURI,
		}},
		"capabilities":      []any{"signed-snapshot-v1", "local-filtering-v1"},
		"privacyProfile":    sig.Digest(w.privacy),
		"privacyProfileUri": privacyURI,
		"offers":            []any{},
		"validUntil":        "2027-01-01T00:00:00Z",
	}
}

// snapshot builds sequence seq chained onto prev (ignored at sequence 1).
func (w *world) snapshot(seq int, prev string) canon.Object {
	g := ts(generated[seq])
	o := canon.Object{
		"version": 1, "implementationProfileId": profileID, "catalogId": "main",
		"providerId": "onym:component:test-discovery", "sequence": seq,
		"policyDigest": sig.Digest(w.policy),
		"generatedAt":  sig.FormatTime(g), "expiresAt": sig.FormatTime(g.Add(w.window)),
		"entries": []any{
			canon.Object{
				"componentId": "onym:component:relayer", "seatType": "notary",
				"manifest": canon.Object{"uri": destAURI, "digest": w.digest[destAURI]},
				"operator": keyOf(w.keyA), "profiles": []any{"onym:notary-implementation:test-v1"},
				"evidence": []any{}, "listedAt": "2026-09-01T00:00:00Z", "reviewedAt": "2026-09-09T00:00:00Z",
				"relationship": "common-owner", "placement": "policy-ranked",
			},
			canon.Object{
				"componentId": "onym:component:courier", "seatType": "transport.message",
				"manifest": canon.Object{"uri": destBURI, "digest": w.digest[destBURI]},
				"operator": keyOf(w.keyB), "profiles": []any{"onym:message-implementation:nostr-courier-v1"},
				"listedAt": "2026-09-01T00:00:00Z", "relationship": "none", "placement": "sponsored",
				"status": canon.Object{"state": "review", "uri": host + "/reviews/courier.md"},
			},
		},
	}
	if seq > 1 {
		o["previousDigest"] = prev
	}
	return o
}

func (w *world) publish() *fakeFetcher {
	w.files, w.bytes, w.digest = map[string]*Response{}, map[string][]byte{}, map[string]string{}
	w.serveSigned(destAURI, w.sign(w.destA(), w.keyA))
	w.serveSigned(destBURI, w.sign(w.destB(), w.keyB))
	w.files[policyURI], w.files[privacyURI] = ok200(w.policy), ok200(w.privacy)

	m := w.manifest()
	if w.manifestHook != nil {
		w.manifestHook(m)
	}
	w.serveSigned(manifestURI, w.sign(m, w.op))

	prev := ""
	for seq := 1; seq <= 3; seq++ {
		o := w.snapshot(seq, prev)
		if w.snapHook != nil {
			w.snapHook(seq, o)
		}
		k := w.op
		if w.snapSigner != nil {
			k = w.snapSigner(seq)
		}
		b := w.sign(o, k)
		w.serveSigned(siblingURI(seq), b)
		prev = sig.Digest(b)
		if seq == 3 {
			w.serveSigned(snapshotURI, b)
		}
	}
	return &fakeFetcher{files: w.files, errs: map[string]error{}}
}

func runWorld(t *testing.T, f Fetcher, now time.Time) *Report {
	t.Helper()
	rep := Run(context.Background(), f, manifestURI, now)
	if _, err := rep.Canonical(); err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	return rep
}

func find(t *testing.T, rep *Report, id string) Check {
	t.Helper()
	for _, c := range rep.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no check %q", id)
	return Check{}
}

func want(t *testing.T, rep *Report, id string, o Outcome) {
	t.Helper()
	if c := find(t, rep, id); c.Outcome != o {
		t.Errorf("%s: outcome %s, want %s — %s", id, c.Outcome, o, c.Detail)
	}
}

func wantResult(t *testing.T, rep *Report, result string) {
	t.Helper()
	if rep.Result != result {
		t.Errorf("result %s, want %s", rep.Result, result)
		for _, c := range rep.Checks {
			if c.Outcome == Fail || c.Outcome == Inconclusive {
				t.Logf("  %s %s %s: %s", c.Level, c.ID, c.Outcome, c.Detail)
			}
		}
	}
}

func dump(t *testing.T, rep *Report) {
	t.Helper()
	var b strings.Builder
	for _, c := range rep.Checks {
		fmt.Fprintf(&b, "%-32s %-6s %-14s %s\n", c.ID, c.Level, c.Outcome, c.Detail)
	}
	t.Log("\n" + b.String())
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
