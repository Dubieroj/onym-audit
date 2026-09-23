// Cross-checks public/verify.js against the Discovery reference vectors and
// this repository's fixture cases: node tools/verify-js-test.mjs
import { readFileSync, readdirSync } from "node:fs";
import { signingBytes, verifySig, verifyAttestation, parseStrict, plain } from "../public/verify.js";

let failed = 0;
const check = (name, ok) => { if (!ok) failed++; console.log(`${ok ? "pass" : "FAIL"}  ${name}`); };
const ref = (f) => readFileSync(new URL(`../testdata/discovery-reference/${f}`, import.meta.url));
const fx = (f) => readFileSync(new URL(`../fixtures/${f}`, import.meta.url), "utf8");

for (const [inp, out] of [["canonical-input.json", "canonical-bytes.bin"], ["canonical-case-input.json", "canonical-case-bytes.bin"], ["canonical-escaping-input.json", "canonical-escaping-bytes.bin"], ["foundation-vectors-input.json", "foundation-vectors-bytes.bin"]]) {
  check(`reference vector ${inp}`, Buffer.compare(Buffer.from(signingBytes(ref(inp).toString("utf8"))), ref(out)) === 0);
}
let dup = false; try { signingBytes(ref("duplicate-keys-input.json").toString("utf8")); } catch { dup = true; }
check("duplicate keys rejected", dup);
const pm = ref("provider-manifest.json").toString("utf8");
const op = plain(parseStrict(pm)).operator;
for (const f of ["provider-manifest.json", "snapshot-1.json", "snapshot-2.json", "snapshot-3.json"]) {
  check(`reference signature ${f}`, await verifySig(ref(f).toString("utf8"), op));
}

// Fixture cases the browser client can evaluate (single status list, no responses).
const set = JSON.parse(fx("cases.json"));
for (const c of set.cases) {
  if ((c.status ?? []).length > 1 || c.responses || c.omitUncredited) continue;
  const d = await verifyAttestation({
    manifestText: fx(c.manifest), attText: fx(c.attestation),
    statusText: c.status ? fx(c.status[0]) : null,
    target: c.target, credited: c.creditAuditor, now: Date.parse(c.now),
  });
  check(`fixture ${c.name}: ${d.display}/${d.error ?? ""}`, d.display === c.expectDisplay && (d.error ?? "") === c.expectError);
}
if (failed) { console.log(`\n${failed} failed`); process.exit(1); }
console.log("\nall pass");
