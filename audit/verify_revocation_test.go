package audit

import (
	"bytes"
	"testing"
)

func fixtureCase(t *testing.T, name string) (map[string][]byte, FixtureCase) {
	t.Helper()
	files, cases, _, err := GenerateFixtures()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		if c.Name == name {
			return files, c
		}
	}
	t.Fatalf("no fixture case %q", name)
	return nil, FixtureCase{}
}

// A revoked or superseded attestation re-serialized (still validly signed,
// different bytes) is shown as revoked or superseded, not as an opinion with
// unknown status.
func TestReserializedAttestationKeepsItsState(t *testing.T) {
	for _, name := range []string{"revoked", "superseded"} {
		files, c := fixtureCase(t, name)
		orig := files[c.Attestation]
		for label, v := range map[string][]byte{
			"leading space":  append([]byte(" "), orig...),
			"escaped slash":  bytes.Replace(orig, []byte("https://"), []byte(`https:\/\/`), 1),
			"trailing space": append(append([]byte{}, orig...), ' '),
		} {
			if bytes.Equal(v, orig) {
				t.Fatalf("%s: variant %s is unchanged", name, label)
			}
			files[c.Attestation] = v
			d, err := RunFixtureCase(files, c)
			if err != nil {
				t.Fatal(err)
			}
			if d.Display != c.ExpectDisplay {
				t.Errorf("%s, %s: display %s, want %s", name, label, d.Display, c.ExpectDisplay)
			}
		}
	}
}

// A valid revocation signed by the auditor wins over a status list that
// still says active (one stapled from before the revocation).
func TestSignedRevocationBeatsAStaleActiveList(t *testing.T) {
	files, c := fixtureCase(t, "active-fresh-credited")
	c.Revocation = "revocation.json"
	d, err := RunFixtureCase(files, c)
	if err != nil {
		t.Fatal(err)
	}
	if d.Display != ShowRevoked || d.HighStakesOK {
		t.Errorf("display %s, high stakes %v", d.Display, d.HighStakesOK)
	}
}
