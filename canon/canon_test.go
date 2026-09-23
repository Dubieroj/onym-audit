package canon

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func ref(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "testdata", "discovery-reference", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The Rust reference's published canonical vectors must reproduce
// byte-for-byte: scrambled order, case divergence, escaping, and the
// cross-language "foundation" vector.
func TestReferenceCanonicalVectors(t *testing.T) {
	for _, v := range []struct{ in, want string }{
		{"canonical-input.json", "canonical-bytes.bin"},
		{"canonical-case-input.json", "canonical-case-bytes.bin"},
		{"canonical-escaping-input.json", "canonical-escaping-bytes.bin"},
		{"foundation-vectors-input.json", "foundation-vectors-bytes.bin"},
	} {
		got, err := SigningBytes(ref(t, v.in), "signature")
		if err != nil {
			t.Fatalf("%s: %v", v.in, err)
		}
		if want := ref(t, v.want); !bytes.Equal(got, want) {
			t.Errorf("%s:\n got %q\nwant %q", v.in, got, want)
		}
	}
}

func TestReferenceDuplicateKeysRejected(t *testing.T) {
	if _, err := SigningBytes(ref(t, "duplicate-keys-input.json"), "signature"); !errors.Is(err, ErrMalformed) {
		t.Fatalf("duplicate keys accepted: %v", err)
	}
}

// Signature removal is structural and top-level only: a nested
// "signature" is signed content.
func TestNestedSignatureIsContent(t *testing.T) {
	got, err := SigningBytes([]byte(`{"signature":"x","b":{"signature":"y"}}`), "signature")
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"b":{"signature":"y"}}`; string(got) != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestRejections(t *testing.T) {
	for name, in := range map[string]string{
		"array top level":  `[1]`,
		"float":            `{"a":1.5}`,
		"exponent":         `{"a":1e3}`,
		"negative":         `{"a":-1}`,
		"leading zero":     `{"a":01}`,
		"too large":        `{"a":9007199254740992}`,
		"lone surrogate":   `{"a":"\ud800"}`,
		"lone trail":       `{"a":"\udc00"}`,
		"invalid utf8":     "{\"a\":\"\xff\"}",
		"raw control":      "{\"a\":\"\x01\"}",
		"trailing":         `{"a":1} x`,
		"nested duplicate": `{"a":{"k":1,"k":2}}`,
	} {
		if _, err := Parse([]byte(in)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestMaxSafeIntegerAccepted(t *testing.T) {
	got, err := SigningBytes([]byte(`{"a":9007199254740991}`))
	if err != nil || string(got) != `{"a":9007199254740991}` {
		t.Fatalf("%s %v", got, err)
	}
}

func TestSurrogatePairDecodes(t *testing.T) {
	got, err := SigningBytes([]byte(`{"a":"\ud83d\ude00"}`))
	if err != nil || string(got) != "{\"a\":\"\U0001F600\"}" {
		t.Fatalf("%q %v", got, err)
	}
}
