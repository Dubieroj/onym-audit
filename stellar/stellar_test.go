package stellar

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
)

// Vectors shared with public/stellar.js (tools/stellar-test.mjs): the same
// status list, transaction and signature payload in both implementations.
// The transaction encoding was accepted by the Stellar test network.
const vectorStatus = `{"statusVersion":1,"auditor":"onym:component:vector","entries":[` +
	`{"attestationId":"att-b","attestation":{"uri":"https://x/b.json","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"state":"revoked","supersededBy":null,"revocation":{"uri":"https://x/rb.json","digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"responses":[{"uri":"https://x/r.json","digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}]},` +
	`{"attestationId":"att-a","attestation":{"uri":"https://x/a.json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"state":"active","supersededBy":null,"revocation":null,"responses":[]}]}`

func TestVectors(t *testing.T) {
	d, err := Digest([]byte(vectorStatus))
	if err != nil || hex.EncodeToString(d[:]) != "a105a95b65ba805e293af07a65c65797769cb905f7530dba64596a16461a218e" {
		t.Fatalf("digest %x %v", d, err)
	}
	tx := Transaction(ed25519.PublicKey(bytes.Repeat([]byte{7}, 32)), 123456789012, 1790000000, DataName, bytes.Repeat([]byte{9}, 32))
	if hex.EncodeToString(tx) != "000000000707070707070707070707070707070707070707070707070707070707070707000000640000001cbe991a14000000010000000000000000000000006ab13b800000000000000001000000000000000a000000116f6e796d2d61756469742d7374617475730000000000000100000020090909090909090909090909090909090909090909090909090909090909090900000000" {
		t.Fatalf("tx %x", tx)
	}
	if p := SignaturePayload(tx); hex.EncodeToString(p[:]) != "56b78a34e638a3ed91950fc8080c4632ab95bb114da6d7729513ae064189b95f" {
		t.Fatalf("payload %x", p)
	}
	// Responses are not the auditor's acts; the order of entries is not either.
	noResp := strings.Replace(vectorStatus, `[{"uri":"https://x/r.json","digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}]`, `[]`, 1)
	if d2, _ := Digest([]byte(noResp)); d2 != d {
		t.Error("a subject's response changed the anchor")
	}
	revived := strings.Replace(vectorStatus, `"state":"revoked"`, `"state":"active"`, 1)
	if d3, _ := Digest([]byte(revived)); d3 == d {
		t.Error("a change of state did not change the anchor")
	}
}
