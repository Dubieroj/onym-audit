// Checks public/stellar.js against the vectors pinned in stellar/stellar_test.go
// (Go), so both anchor implementations write the same bytes:
// node tools/stellar-test.mjs
import { anchorDigest, transaction, signaturePayload, DATA_NAME } from "../public/stellar.js";

const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const status = JSON.stringify({ statusVersion: 1, auditor: "onym:component:vector", entries: [
  { attestationId: "att-b", attestation: { uri: "https://x/b.json", digest: "sha256:" + "bb".repeat(32) }, state: "revoked", supersededBy: null, revocation: { uri: "https://x/rb.json", digest: "sha256:" + "cc".repeat(32) }, responses: [{ uri: "https://x/r.json", digest: "sha256:" + "dd".repeat(32) }] },
  { attestationId: "att-a", attestation: { uri: "https://x/a.json", digest: "sha256:" + "aa".repeat(32) }, state: "active", supersededBy: null, revocation: null, responses: [] } ] });
let failed = 0;
const ok = (c, what) => { if (!c) { failed++; console.log("FAIL", what); } };
ok(hex(await anchorDigest(status)) === "a105a95b65ba805e293af07a65c65797769cb905f7530dba64596a16461a218e", "digest");
const tx = transaction(new Uint8Array(32).fill(7), 123456789012n, 1790000000, DATA_NAME, new Uint8Array(32).fill(9));
ok(hex(tx) === "000000000707070707070707070707070707070707070707070707070707070707070707000000640000001cbe991a14000000010000000000000000000000006ab13b800000000000000001000000000000000a000000116f6e796d2d61756469742d7374617475730000000000000100000020090909090909090909090909090909090909090909090909090909090909090900000000", "transaction");
ok(hex(await signaturePayload(tx)) === "56b78a34e638a3ed91950fc8080c4632ab95bb114da6d7729513ae064189b95f", "signature payload");
if (failed) process.exit(1);
console.log("stellar: all pass");
