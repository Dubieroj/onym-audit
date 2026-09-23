package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

// The onym-discovery reference fixtures (byte-pinned, Rust-signed) served
// at the URIs they declare: the signature, schema and chain layers must
// pass on them exactly as the reference verifier accepts them.
func TestReferenceFixtures(t *testing.T) {
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "discovery-reference", name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	const base = "https://discovery.onym.app"
	const snap = base + "/catalogs/public-all-seats.json"
	f := &fakeFetcher{files: map[string]*Response{
		base + "/manifest.json":     ok200(read("provider-manifest.json")),
		base + "/manifest.json.sig": ok200(read("provider-manifest.json.sig")),
		snap:                        ok200(read("snapshot-3.json")),
		base + "/catalogs/public-all-seats-2.json": ok200(read("snapshot-2.json")),
		base + "/catalogs/public-all-seats-1.json": ok200(read("snapshot-1.json")),
	}}
	// All three snapshots are generated 2026-08-13 and expire 2026-09-12;
	// the manifest is valid until 2026-12-31.
	rep := Run(t.Context(), f, base+"/manifest.json", ts("2026-08-20T00:00:00Z"))
	for _, id := range []string{
		"manifest.uri", "manifest.fetch", "manifest.size", "manifest.schema", "manifest.identity",
		"manifest.signature", "manifest.detached-sig", "manifest.valid-until",
		"catalog.descriptor-fields", "catalog.descriptor-unknown-keys", "catalog.decodable", "catalog.duplicate-id",
		"uri.rules",
		"snapshot.fetch", "snapshot.size", "snapshot.schema", "snapshot.identity", "snapshot.signature",
		"snapshot.policy-digest", "snapshot.chain-fields", "snapshot.dates", "snapshot.window-max",
		"snapshot.fresh", "snapshot.entry-count", "snapshot.duplicate-component",
		"entry.fields", "entry.unknown-keys", "entry.seat-type-declared",
		"chain.retention", "chain.sibling-valid", "chain.links",
		"serving.no-cookies",
	} {
		want(t, rep, id, Pass)
	}
	want(t, rep, "chain.latest-sibling", NotApplicable) // fixtures carry no -3 sibling
	// The fixtures pin a 30-day window: within "days to a few weeks".
	want(t, rep, "snapshot.window-short", Pass)
	if testing.Verbose() {
		dump(t, rep)
	}
}
