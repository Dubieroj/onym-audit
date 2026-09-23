// Package onymid derives an Onym identity's Stellar-facing Ed25519 key from
// its BIP-39 phrase exactly as the Onym apps do (onym-ios, onym-android;
// Identity-BIP39 profile §5):
//
//	seed    = BIP-39 PBKDF2-HMAC-SHA512(NFKD(phrase), "mnemonic", 2048)
//	nostr   = HKDF-SHA256(seed,  salt "app.onym.bip39", info "nostr-secp256k1-v1")
//	stellar = HKDF-SHA256(nostr, salt "app.onym.ios",   info "stellar-ed25519-v1")
//
// so the same phrase added to the Onym app shows the same Stellar account.
// The audit apps use a phrase of its own — never a holder's main identity
// (Identity-BIP39 §9–10: the phrase is the whole identity, and a public
// auditor key must not link to a person's messaging keys).
package onymid

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
)

//go:embed bip39-english.txt
var wordlist string

var (
	words = strings.Fields(wordlist)
	index = func() map[string]int {
		m := make(map[string]int, len(words))
		for i, w := range words {
			m[w] = i
		}
		return m
	}()
)

// Normalize lower-cases a phrase and joins its words with single spaces.
func Normalize(phrase string) string {
	return strings.Join(strings.Fields(strings.ToLower(phrase)), " ")
}

// Check validates a normalized phrase: known words, a BIP-39 length, and the
// checksum. Invalid phrases are refused, never corrected (profile §4.1).
func Check(phrase string) error {
	ws := strings.Fields(phrase)
	if n := len(ws); n < 12 || n > 24 || n%3 != 0 {
		return fmt.Errorf("a phrase has 12, 15, 18, 21 or 24 words, not %d", n)
	}
	bits := make([]byte, 0, len(ws)*11)
	for _, w := range ws {
		i, ok := index[w]
		if !ok {
			return fmt.Errorf("%q is not a BIP-39 word", w)
		}
		for b := 10; b >= 0; b-- {
			bits = append(bits, byte(i>>b)&1)
		}
	}
	cs := len(bits) / 33
	ent := make([]byte, (len(bits)-cs)/8)
	for i := range ent {
		for b := 0; b < 8; b++ {
			ent[i] = ent[i]<<1 | bits[i*8+b]
		}
	}
	sum := sha256.Sum256(ent)
	for b := 0; b < cs; b++ {
		if bits[len(ent)*8+b] != (sum[0]>>(7-b))&1 {
			return errors.New("the phrase's checksum does not match: a word is wrong or missing")
		}
	}
	return nil
}

// Seed is the BIP-39 seed of a checked phrase (empty passphrase). A checked
// English phrase is lower-case ASCII, which NFKD leaves unchanged.
func Seed(phrase string) []byte {
	s, err := pbkdf2.Key(sha512.New, phrase, []byte("mnemonic"), 2048, 64)
	if err != nil {
		panic(err) // fixed parameters; cannot fail
	}
	return s
}

func derive(ikm []byte, salt, info string) []byte {
	k, err := hkdf.Key(sha256.New, ikm, []byte(salt), info, 32)
	if err != nil {
		panic(err)
	}
	return k
}

// StellarKey is the identity's Ed25519 ledger-authorization key.
func StellarKey(seed []byte) ed25519.PrivateKey {
	nostr := derive(seed, "app.onym.bip39", "nostr-secp256k1-v1")
	return ed25519.NewKeyFromSeed(derive(nostr, "app.onym.ios", "stellar-ed25519-v1"))
}

// OrderKey is the per-order key an orderer signs one order with: a
// seed-scoped key in the Onym apps' pattern (HKDF over the seed with salt
// "app.onym.bip39"), so orders are unlinkable to each other and to the
// phrase's auditor key without the phrase.
func OrderKey(seed []byte, orderID string) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(derive(seed, "app.onym.bip39", "onym-audit-order-v1:"+orderID))
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

const accountVersion = 6 << 3 // StrKey version byte of an account ID ('G')

func crc16(b []byte) uint16 {
	var c uint16
	for _, x := range b {
		c ^= uint16(x) << 8
		for i := 0; i < 8; i++ {
			if c&0x8000 != 0 {
				c = c<<1 ^ 0x1021
			} else {
				c <<= 1
			}
		}
	}
	return c
}

// AccountID is the Stellar StrKey ("G…") of an Ed25519 public key.
func AccountID(pub ed25519.PublicKey) string {
	p := append([]byte{accountVersion}, pub...)
	c := crc16(p)
	return b32.EncodeToString(append(p, byte(c), byte(c>>8)))
}

// ParseAccountID decodes a "G…" account ID to its Ed25519 public key.
func ParseAccountID(id string) (ed25519.PublicKey, error) {
	b, err := b32.DecodeString(id)
	if err != nil || len(b) != 35 || b[0] != accountVersion {
		return nil, errors.New("not a Stellar account ID")
	}
	if c := crc16(b[:33]); byte(c) != b[33] || byte(c>>8) != b[34] {
		return nil, errors.New("the account ID's checksum does not match")
	}
	return ed25519.PublicKey(b[1:33]), nil
}
