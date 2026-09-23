package discovery

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"onym-audit/canon"
	"onym-audit/sig"
)

func TestValidProviderIsClear(t *testing.T) {
	w := newWorld(t)
	f := w.publish()
	rep := runWorld(t, f, w.now)
	wantResult(t, rep, ResultClear)
	for _, c := range rep.Checks {
		if c.Outcome != Pass && c.Outcome != NotApplicable {
			t.Errorf("%s: %s — %s", c.ID, c.Outcome, c.Detail)
		}
	}
	// Everything the valid world publishes is actually exercised.
	for _, id := range []string{"manifest.detached-sig", "snapshot.detached-sig", "chain.retention", "chain.links", "chain.latest-sibling", "dest.fields", "dest.signature", "policy.document", "privacy.document"} {
		want(t, rep, id, Pass)
	}
	want(t, rep, "provider.cross-catalog-digest", NotApplicable) // one catalog
	if len(rep.Checks) != len(checkSpecs) {
		t.Fatalf("%d checks, want %d", len(rep.Checks), len(checkSpecs))
	}
	if testing.Verbose() {
		dump(t, rep)
	}
}

func TestCanonicalIsDeterministic(t *testing.T) {
	w := newWorld(t)
	a, err := runWorld(t, w.publish(), w.now).Canonical()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := runWorld(t, w.publish(), w.now).Canonical()
	if !bytes.Equal(a, b) {
		t.Fatal("two runs over the same bytes differ")
	}
	o, err := canon.Parse(a)
	if err != nil {
		t.Fatal(err)
	}
	if o["runAt"] != "2026-09-20T12:00:00Z" || o["suite"] != SuiteID || o["result"] != ResultClear {
		t.Fatalf("unexpected header: %v %v %v", o["runAt"], o["suite"], o["result"])
	}
	if re, _ := canon.Encode(o); !bytes.Equal(re, a) {
		t.Fatal("report bytes are not canonical")
	}
	docs := o["documents"].([]any)
	first := docs[0].(canon.Object)
	if first["uri"] != manifestURI || first["digest"] != sig.Digest(w.bytes[manifestURI]) {
		t.Fatalf("first document %v", first)
	}
}

// Each tamper must fail its specific check and roll up to the stated result.
func TestTampers(t *testing.T) {
	other := seed(0x99)
	cases := []struct {
		name   string
		setup  func(w *world, f *fakeFetcher)
		hook   func(w *world)
		now    time.Time
		check  string
		result string
	}{
		{
			name: "bad manifest signature",
			setup: func(w *world, f *fakeFetcher) {
				b := bytes.Replace(w.bytes[manifestURI], []byte(`"validUntil":"2027-01-01T00:00:00Z"`), []byte(`"validUntil":"2028-01-01T00:00:00Z"`), 1)
				f.files[manifestURI] = ok200(b)
			},
			check: "manifest.signature", result: ResultFail,
		},
		{
			name: "snapshot signed by another key",
			hook: func(w *world) {
				w.snapSigner = func(seq int) ed25519.PrivateKey {
					return map[bool]ed25519.PrivateKey{true: other, false: w.op}[seq == 3]
				}
			},
			check: "snapshot.signature", result: ResultFail,
		},
		{
			name:  "expired snapshot",
			now:   ts("2026-10-05T00:00:00Z"),
			check: "snapshot.fresh", result: ResultFail,
		},
		{
			name: "expiry window over 90 days",
			hook: func(w *world) {
				w.snapHook = func(seq int, o canon.Object) {
					if seq == 3 {
						o["expiresAt"] = sig.FormatTime(ts(generated[3]).Add(91 * day))
					}
				}
			},
			check: "snapshot.window-max", result: ResultFail,
		},
		{
			name:  "expiry window over six weeks is a SHOULD finding only",
			hook:  func(w *world) { w.window = 60 * day },
			check: "snapshot.window-short", result: ResultFindingsNoted,
		},
		{
			name: "broken previousDigest chain via siblings",
			setup: func(w *world, f *fakeFetcher) {
				o := w.snapshot(2, w.digest[siblingURI(1)])
				o["generatedAt"] = "2026-09-14T00:00:01Z" // a different, validly signed sequence 2
				w.serveSigned(siblingURI(2), w.sign(o, w.op))
			},
			check: "chain.links", result: ResultFail,
		},
		{
			name: "missing unexpired sibling",
			setup: func(w *world, f *fakeFetcher) {
				delete(f.files, siblingURI(2))
				delete(f.files, siblingURI(2)+".sig")
			},
			check: "chain.retention", result: ResultFail,
		},
		{
			name: "duplicate componentId",
			hook: func(w *world) {
				w.snapHook = func(seq int, o canon.Object) {
					if seq == 3 {
						es := o["entries"].([]any)
						o["entries"] = append(es, es[0])
					}
				}
			},
			check: "snapshot.duplicate-component", result: ResultFail,
		},
		{
			name:  "policy document digest mismatch",
			setup: func(w *world, f *fakeFetcher) { f.files[policyURI] = ok200([]byte("# A different policy\n")) },
			check: "policy.document", result: ResultFail,
		},
		{
			name: "URI with :443",
			hook: func(w *world) {
				w.manifestHook = func(m canon.Object) { m["privacyProfileUri"] = "https://provider.example:443/privacy.md" }
			},
			check: "uri.rules", result: ResultFail,
		},
		{
			name: "IP literal (integer IPv4 form) in an entry",
			hook: func(w *world) {
				w.snapHook = func(seq int, o canon.Object) {
					if seq == 3 {
						o["entries"].([]any)[1].(canon.Object)["manifest"].(canon.Object)["uri"] = "https://3232235777/courier.json"
					}
				}
			},
			check: "uri.rules", result: ResultFail,
		},
		{
			name:  "Set-Cookie on the snapshot",
			setup: func(w *world, f *fakeFetcher) { f.files[snapshotURI].Header.Set("Set-Cookie", "sid=abc123; Path=/") },
			check: "serving.no-cookies", result: ResultFail,
		},
		{
			// The drift is a SHOULD finding; the provider's MUST-level review
			// of the pinned bytes (dest.fields/dest.signature) becomes
			// unverifiable, so the run is inconclusive rather than clear.
			name: "destination digest mismatch",
			setup: func(w *world, f *fakeFetcher) {
				o := w.destA()
				o["validUntil"] = "2027-06-01T00:00:00Z"
				f.files[destAURI] = ok200(w.sign(o, w.keyA))
			},
			check: "dest.digest", result: ResultInconclusive,
		},
		{
			name:  "unknown top-level manifest field",
			hook:  func(w *world) { w.manifestHook = func(m canon.Object) { m["homepage"] = "https://provider.example" } },
			check: "manifest.schema", result: ResultFail,
		},
		{
			name: "detached .sig disagreement",
			setup: func(w *world, f *fakeFetcher) {
				f.files[manifestURI+".sig"] = ok200([]byte(b64(ed25519.Sign(other, []byte("x"))) + "\n"))
			},
			check: "manifest.detached-sig", result: ResultFail,
		},
		{
			name: "oversize manifest",
			setup: func(w *world, f *fakeFetcher) {
				f.files[manifestURI] = ok200(append(append([]byte{}, w.bytes[manifestURI]...), bytes.Repeat([]byte(" "), 64<<10)...))
			},
			check: "manifest.size", result: ResultFail,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			if tc.hook != nil {
				tc.hook(w)
			}
			f := w.publish()
			if tc.setup != nil {
				tc.setup(w, f)
			}
			now := w.now
			if !tc.now.IsZero() {
				now = tc.now
			}
			rep := runWorld(t, f, now)
			want(t, rep, tc.check, Fail)
			wantResult(t, rep, tc.result)
			if testing.Verbose() {
				t.Logf("%s: %s", tc.check, find(t, rep, tc.check).Detail)
			}
		})
	}
}

// A few further outcomes the tamper list does not name.
func TestOtherOutcomes(t *testing.T) {
	t.Run("detached .sig without trailing newline", func(t *testing.T) {
		w := newWorld(t)
		f := w.publish()
		s := f.files[manifestURI+".sig"].Body
		f.files[manifestURI+".sig"] = ok200(s[:len(s)-1])
		rep := runWorld(t, f, w.now)
		want(t, rep, "manifest.detached-sig", Fail)
	})
	t.Run("no detached .sig is not applicable", func(t *testing.T) {
		w := newWorld(t)
		f := w.publish()
		delete(f.files, manifestURI+".sig")
		rep := runWorld(t, f, w.now)
		want(t, rep, "manifest.detached-sig", NotApplicable)
		wantResult(t, rep, ResultClear)
	})
	t.Run("network error is inconclusive", func(t *testing.T) {
		w := newWorld(t)
		f := w.publish()
		f.errs[privacyURI] = errors.New("dial tcp: i/o timeout")
		rep := runWorld(t, f, w.now)
		want(t, rep, "privacy.document", Inconclusive)
		wantResult(t, rep, ResultInconclusive)
	})
	t.Run("manifest unreachable stops the run inconclusively", func(t *testing.T) {
		w := newWorld(t)
		f := w.publish()
		f.errs[manifestURI] = errors.New("no such host")
		rep := runWorld(t, f, w.now)
		want(t, rep, "manifest.fetch", Inconclusive)
		want(t, rep, "snapshot.signature", Inconclusive)
		wantResult(t, rep, ResultInconclusive)
	})
	t.Run("expired sibling may be gone", func(t *testing.T) {
		w := newWorld(t)
		w.snapHook = func(seq int, o canon.Object) {
			if seq == 1 {
				o["expiresAt"] = "2026-09-12T00:00:00Z"
			}
		}
		f := w.publish()
		delete(f.files, siblingURI(1))
		rep := runWorld(t, f, w.now)
		want(t, rep, "chain.retention", Pass)
		wantResult(t, rep, ResultClear)
	})
	t.Run("missing sibling without older evidence carries no blame", func(t *testing.T) {
		w := newWorld(t)
		f := w.publish()
		delete(f.files, siblingURI(1))
		delete(f.files, siblingURI(2))
		rep := runWorld(t, f, w.now)
		want(t, rep, "chain.retention", NotApplicable)
		want(t, rep, "chain.links", NotApplicable)
	})
	t.Run("latest sibling with different signed bytes is a fork", func(t *testing.T) {
		w := newWorld(t)
		f := w.publish()
		o := w.snapshot(3, w.digest[siblingURI(2)])
		o["generatedAt"] = "2026-09-18T00:00:01Z"
		f.files[siblingURI(3)] = ok200(w.sign(o, w.op))
		rep := runWorld(t, f, w.now)
		want(t, rep, "chain.latest-sibling", Fail)
		if d := find(t, rep, "chain.latest-sibling").Detail; !strings.Contains(d, "a fork") {
			t.Errorf("detail does not name the fork: %s", d)
		}
	})
	t.Run("reviewed destination bytes that contradict the entry", func(t *testing.T) {
		w := newWorld(t)
		w.snapHook = func(seq int, o canon.Object) {
			o["entries"].([]any)[0].(canon.Object)["profiles"] = []any{"onym:notary-implementation:other-v1"}
		}
		rep := runWorld(t, w.publish(), w.now)
		want(t, rep, "dest.fields", Fail)
		wantResult(t, rep, ResultFail)
	})
	t.Run("reviewed destination bytes with a bad signature", func(t *testing.T) {
		w := newWorld(t)
		f := w.publish()
		// Pin bytes whose notary signature is by the wrong key.
		bad := w.sign(w.destA(), seed(0x44))
		f.files[destAURI] = ok200(bad)
		w.digest[destAURI] = sig.Digest(bad)
		prev := ""
		for seq := 1; seq <= 3; seq++ {
			b := w.sign(w.snapshot(seq, prev), w.op)
			w.serveSigned(siblingURI(seq), b)
			prev = sig.Digest(b)
			if seq == 3 {
				w.serveSigned(snapshotURI, b)
			}
		}
		rep := runWorld(t, f, w.now)
		want(t, rep, "dest.signature", Fail)
	})
	t.Run("entry with non-empty evidence is skipped", func(t *testing.T) {
		w := newWorld(t)
		w.snapHook = func(seq int, o canon.Object) {
			o["entries"].([]any)[1].(canon.Object)["evidence"] = []any{canon.Object{"type": "audit-attestation"}}
		}
		rep := runWorld(t, w.publish(), w.now)
		want(t, rep, "entry.fields", Fail)
	})
	t.Run("previousDigest at sequence 1", func(t *testing.T) {
		w := newWorld(t)
		w.snapHook = func(seq int, o canon.Object) {
			if seq == 1 {
				o["previousDigest"] = sig.Digest(nil)
			}
		}
		rep := runWorld(t, w.publish(), w.now)
		want(t, rep, "chain.sibling-valid", Fail)
	})
	t.Run("snapshot citing another policy digest", func(t *testing.T) {
		w := newWorld(t)
		w.snapHook = func(seq int, o canon.Object) { o["policyDigest"] = sig.Digest([]byte("old policy")) }
		rep := runWorld(t, w.publish(), w.now)
		want(t, rep, "snapshot.policy-digest", Fail)
		wantResult(t, rep, ResultFail)
	})
	t.Run("descriptor lossiness: unknown key is a SHOULD finding, non-public audience is valid", func(t *testing.T) {
		w := newWorld(t)
		w.manifestHook = func(m canon.Object) {
			extra := func(id, audience string) canon.Object {
				return canon.Object{
					"catalogId": id, "snapshot": host + "/catalogs/" + id + ".json", "audience": audience,
					"seatTypes": []any{"*"}, "policy": sig.Digest(w.policy), "policyUri": policyURI,
				}
			}
			future := extra("future", "public")
			future["region"] = "eu"
			m["catalogs"] = append(m["catalogs"].([]any), future, extra("members", "private"))
		}
		rep := runWorld(t, w.publish(), w.now)
		want(t, rep, "catalog.descriptor-unknown-keys", Fail)
		want(t, rep, "catalog.decodable", Pass)
		wantResult(t, rep, ResultFindingsNoted)
	})
	t.Run("a sequence-1 catalog has nothing to retain", func(t *testing.T) {
		w := newWorld(t)
		f := w.publish()
		b := w.sign(w.snapshot(1, ""), w.op)
		w.serveSigned(snapshotURI, b)
		delete(f.files, siblingURI(2))
		delete(f.files, siblingURI(3))
		rep := runWorld(t, f, w.now)
		want(t, rep, "chain.retention", NotApplicable)
		want(t, rep, "chain.latest-sibling", Pass) // main-1.json is byte-identical
		wantResult(t, rep, ResultClear)
	})
	t.Run("manifest URL with an IP literal is never fetched", func(t *testing.T) {
		f := &fakeFetcher{files: map[string]*Response{}}
		rep := Run(t.Context(), f, "https://0x7f000001/manifest.json", ts("2026-09-20T12:00:00Z"))
		want(t, rep, "manifest.uri", Fail)
		wantResult(t, rep, ResultFail)
		if len(f.log) != 0 {
			t.Fatalf("fetched %v", f.log)
		}
	})
}
