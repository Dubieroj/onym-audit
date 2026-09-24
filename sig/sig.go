// Package sig holds the identifier, digest, and Ed25519 signing rules this
// profile shares with Discovery-Static-Ed25519 §2–§3.
package sig

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"onym-audit/canon"
)

var (
	ErrBadKey       = errors.New("invalid onym:key identifier")
	ErrBadSignature = errors.New("signature verification failed")
)

// Key is an Ed25519 public key in the `onym:key:<64 lowercase hex>` form.
type Key string

var keyRE = regexp.MustCompile(`^onym:key:[0-9a-f]{64}$`)

// KeyOf formats a public key.
func KeyOf(pub ed25519.PublicKey) Key {
	return Key("onym:key:" + hex.EncodeToString(pub))
}

// Public parses k.
func (k Key) Public() (ed25519.PublicKey, error) {
	if !keyRE.MatchString(string(k)) {
		return nil, fmt.Errorf("%w: %q", ErrBadKey, k)
	}
	b, _ := hex.DecodeString(strings.TrimPrefix(string(k), "onym:key:"))
	return ed25519.PublicKey(b), nil
}

// Fingerprint renders the first 8 bytes as colon hex, the form the
// Discovery docs publish out of band (e.g. 4d:a9:ec:c9:e8:6f:6e:97). It is
// the SHA-256 of the raw key, not the key itself.
func (k Key) Fingerprint() string {
	pub, err := k.Public()
	if err != nil {
		return "invalid"
	}
	sum := sha256.Sum256(pub)
	parts := make([]string, 8)
	for i := range parts {
		parts[i] = hex.EncodeToString(sum[i : i+1])
	}
	return strings.Join(parts, ":")
}

// Digest is `sha256:<64 lowercase hex>` over exact bytes, never a
// canonical form.
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ValidDigest reports whether s has the digest syntax.
func ValidDigest(s string) bool { return digestRE.MatchString(s) }

// Sign sets obj[field] to the Ed25519 signature over obj's canonical bytes
// (without that field) and returns the published bytes: the canonical
// serialization including the signature, so the served file is
// byte-deterministic.
func Sign(obj canon.Object, field string, priv ed25519.PrivateKey) ([]byte, error) {
	delete(obj, field)
	msg, err := canon.Encode(obj)
	if err != nil {
		return nil, err
	}
	obj[field] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
	return canon.Encode(obj)
}

// DecodeSignature accepts padded or unpadded standard base64 (§3).
func DecodeSignature(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(s)
	}
	if err != nil || len(b) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: malformed signature encoding", ErrBadSignature)
	}
	return b, nil
}

// Verify checks raw's embedded `field` signature against key, over the
// canonical bytes with that field removed structurally at the top level.
func Verify(raw []byte, field string, key Key) error {
	obj, err := canon.Parse(raw)
	if err != nil {
		return err
	}
	s, ok := obj[field].(string)
	if !ok {
		return fmt.Errorf("%w: missing %s", ErrBadSignature, field)
	}
	return VerifyDetached(raw, s, key, field)
}

// VerifyDetached verifies a base64 signature over raw's canonical bytes
// with the omitted fields removed.
func VerifyDetached(raw []byte, signature string, key Key, omit ...string) error {
	pub, err := key.Public()
	if err != nil {
		return err
	}
	sigBytes, err := DecodeSignature(signature)
	if err != nil {
		return err
	}
	msg, err := canon.SigningBytes(raw, omit...)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, msg, sigBytes) {
		return ErrBadSignature
	}
	return nil
}

// TimeFormat is RFC 3339 UTC, second precision, `Z` suffix.
const TimeFormat = "2006-01-02T15:04:05Z"

// FormatTime renders t in the profile's timestamp form.
func FormatTime(t time.Time) string { return t.UTC().Truncate(time.Second).Format(TimeFormat) }

// ParseTime accepts only the profile's timestamp form.
func ParseTime(s string) (time.Time, error) {
	t, err := time.Parse(TimeFormat, s)
	// time.Parse accepts a fractional second the layout does not name
	// ("…:05.123Z", "…:05,5Z"); the profile's form has none.
	if err != nil || FormatTime(t) != s {
		return time.Time{}, fmt.Errorf("timestamp %q is not RFC 3339 UTC with Z and second precision", s)
	}
	return t, nil
}
