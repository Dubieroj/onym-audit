// Checks public/onym-id.js against the Onym apps' cross-platform identity
// fixture (onym-ios IdentityRepositoryTests, onym-android
// CrossPlatformFixtureTest) and against the Go implementation's rules:
// node tools/onym-id-test.mjs
import { normalize, check, generate, derive, orderKey, accountID, keyOfAccount, accountOfKey } from "../public/onym-id.js";

const PHRASE = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PUB = "7a33c09cdb7f51fe723a4003d2f28272cddc8fa2cf3d74a374a5f2ee6fb1fcdc";
const ACCOUNT = "GB5DHQE43N7VD7TSHJAAHUXSQJZM3XEPULHT25FDOSS7F3TPWH6NYJ7A";

let failed = 0;
const ok = (cond, what) => {
  if (!cond) {
    failed++;
    console.log("FAIL", what);
  }
};

const p = normalize("  Abandon abandon abandon abandon abandon abandon\nabandon abandon abandon abandon abandon ABOUT ");
ok(p === PHRASE, "normalize");
ok((await check(PHRASE)) === null, "fixture phrase checks");
const id = await derive(PHRASE);
ok(id.key === "onym:key:" + PUB, "stellar key " + id.key);
ok(id.account === ACCOUNT, "account " + id.account);
ok(keyOfAccount(ACCOUNT) === "onym:key:" + PUB, "parse account");
ok(keyOfAccount(ACCOUNT.slice(0, -1) + "B") === null, "corrupted account refused");
ok(accountOfKey("onym:key:" + PUB) === ACCOUNT, "account of key");
for (const bad of [PHRASE.replace("about", "abandon"), PHRASE.replace(" about", ""), PHRASE.replace("about", "abouts")]) {
  ok((await check(bad)) !== null, "refused " + bad.slice(-20));
}
for (let i = 0; i < 20; i++) {
  const g = await generate();
  ok(g.split(" ").length === 12 && (await check(g)) === null, "generated phrase checks: " + g);
}
const a = await orderKey(id.seedKey, "ord-0000000000000001");
const b = await orderKey(id.seedKey, "ord-0000000000000002");
const a2 = await orderKey(id.seedKey, "ord-0000000000000001");
ok(a.key !== b.key && a.key !== id.key && a.key === a2.key, "order keys");
// Pinned identically in onymid.TestOrderKeyMatchesBrowser (Go).
ok(a.key === "onym:key:6e65953ba9a600d43d7b7bd87ec2eb26b85bd2aaae5ea516bd9d5f16291fb431", "order key matches Go " + a.key);
ok(accountID(new Uint8Array(32)).length === 56, "account length");

if (failed) {
  console.log(`${failed} failed`);
  process.exit(1);
}
console.log("onym-id: all pass");
