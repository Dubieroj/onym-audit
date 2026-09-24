package sig

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"onym-audit/canon"
)

func read(t *testing.T, parts ...string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"..", "testdata"}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func operatorOf(t *testing.T, raw []byte) Key {
	t.Helper()
	obj, err := canon.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return Key(obj["operator"].(string))
}

// Signatures produced by the Rust reference verify here, embedded and
// detached, and fail under any other key.
func TestReferenceSignatures(t *testing.T) {
	for _, name := range []string{"provider-manifest.json", "snapshot-1.json", "snapshot-2.json", "snapshot-3.json"} {
		raw := read(t, "discovery-reference", name)
		key := operatorOf(t, read(t, "discovery-reference", "provider-manifest.json"))
		if err := Verify(raw, "signature", key); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		other := KeyOf(ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey))
		if err := Verify(raw, "signature", other); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s verified under a foreign key", name)
		}
	}
	detached := strings.TrimSuffix(string(read(t, "discovery-reference", "provider-manifest.json.sig")), "\n")
	raw := read(t, "discovery-reference", "provider-manifest.json")
	if err := VerifyDetached(raw, detached, operatorOf(t, raw), "signature"); err != nil {
		t.Fatal(err)
	}
}

// The live Onym provider manifest (fetched 2026-09-23) verifies, and its key
// fingerprint equals the one Onym publishes out of band.
func TestLiveOnymManifest(t *testing.T) {
	raw := read(t, "onym-live-manifest-2026-09-23.json")
	key := operatorOf(t, raw)
	if err := Verify(raw, "signature", key); err != nil {
		t.Fatal(err)
	}
	if got, want := key.Fingerprint(), "4d:a9:ec:c9:e8:6f:6e:97"; got != want {
		t.Fatalf("fingerprint %s, published %s", got, want)
	}
}

func TestSignRoundTripIsCanonical(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	out, err := Sign(canon.Object{"b": "x", "a": canon.Number("1")}, "signature", priv)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(out), `{"a":1,"b":"x","signature":"`) {
		t.Fatalf("not canonical: %s", out)
	}
	if err := Verify(out, "signature", KeyOf(priv.Public().(ed25519.PublicKey))); err != nil {
		t.Fatal(err)
	}
}

func TestParseTimeIsSecondPrecisionOnly(t *testing.T) {
	if _, err := ParseTime("2026-09-24T10:00:00Z"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"2026-09-24T10:00:00.123Z", "2026-09-24T10:00:00,5Z", "2026-09-24T10:00:00+00:00", "2026-09-24 10:00:00Z"} {
		if _, err := ParseTime(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
