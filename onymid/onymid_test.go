package onymid

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// The cross-platform fixture of the Onym apps (onym-ios
// IdentityRepositoryTests.test_derivation_matchesCrossPlatformFixture,
// onym-android CrossPlatformFixtureTest).
const (
	fixturePhrase  = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	fixtureSeed    = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
	fixturePub     = "7a33c09cdb7f51fe723a4003d2f28272cddc8fa2cf3d74a374a5f2ee6fb1fcdc"
	fixtureAccount = "GB5DHQE43N7VD7TSHJAAHUXSQJZM3XEPULHT25FDOSS7F3TPWH6NYJ7A"
)

func TestOnymFixture(t *testing.T) {
	if sum := sha256.Sum256([]byte(wordlist)); hex.EncodeToString(sum[:]) != "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda" || len(words) != 2048 {
		t.Fatal("not the canonical BIP-39 English wordlist")
	}
	if err := Check(fixturePhrase); err != nil {
		t.Fatal(err)
	}
	seed := Seed(Normalize("  Abandon abandon abandon abandon abandon abandon\nabandon abandon abandon abandon abandon ABOUT "))
	if hex.EncodeToString(seed) != fixtureSeed {
		t.Fatalf("seed %x", seed)
	}
	pub := StellarKey(seed).Public().(ed25519.PublicKey)
	if hex.EncodeToString(pub) != fixturePub {
		t.Fatalf("stellar key %x", pub)
	}
	if AccountID(pub) != fixtureAccount {
		t.Fatalf("account %s", AccountID(pub))
	}
	back, err := ParseAccountID(fixtureAccount)
	if err != nil || !back.Equal(pub) {
		t.Fatalf("parse %v", err)
	}
}

func TestCheckRefuses(t *testing.T) {
	for _, p := range []string{
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon", // checksum
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",         // 11 words
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abouts",  // unknown word
	} {
		if Check(p) == nil {
			t.Errorf("accepted %q", p)
		}
	}
	if _, err := ParseAccountID("GB5DHQE43N7VD7TSHJAAHUXSQJZM3XEPULHT25FDOSS7F3TPWH6NYJ7B"); err == nil {
		t.Error("accepted a corrupted account ID")
	}
}

func TestOrderKeysAreUnlinked(t *testing.T) {
	seed := Seed(fixturePhrase)
	a, b := OrderKey(seed, "ord-0000000000000001"), OrderKey(seed, "ord-0000000000000002")
	if a.Equal(b) || a.Equal(StellarKey(seed)) {
		t.Error("order keys repeat or equal the auditor key")
	}
	if !a.Equal(OrderKey(seed, "ord-0000000000000001")) {
		t.Error("order key not deterministic")
	}
}

// The browser implementation (public/onym-id.js) pins the same order key
// for the fixture in tools/onym-id-test.mjs.
func TestOrderKeyMatchesBrowser(t *testing.T) {
	k := OrderKey(Seed(fixturePhrase), "ord-0000000000000001").Public().(ed25519.PublicKey)
	if hex.EncodeToString(k) != "6e65953ba9a600d43d7b7bd87ec2eb26b85bd2aaae5ea516bd9d5f16291fb431" {
		t.Fatalf("order key %x", k)
	}
}
