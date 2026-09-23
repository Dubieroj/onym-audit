// Onym identity keys from a BIP-39 phrase, derived exactly as the Onym apps
// do (onym-ios, onym-android; Identity-BIP39 profile §5), with WebCrypto:
//
//   seed    = PBKDF2-HMAC-SHA512(phrase, "mnemonic", 2048)            (BIP-39)
//   nostr   = HKDF-SHA256(seed,  salt "app.onym.bip39", info "nostr-secp256k1-v1")
//   stellar = HKDF-SHA256(nostr, salt "app.onym.ios",   info "stellar-ed25519-v1")
//
// The same phrase added to the Onym app shows the same Stellar account. The
// audit apps take a phrase of its own, never a holder's main identity: that
// phrase is the whole identity (profile §9), and a public auditor key must
// not link to a person's messaging keys (§10).
import { WORDS } from "./bip39-english.js";

const enc = new TextEncoder();
const INDEX = new Map(WORDS.map((w, i) => [w, i]));
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
const PKCS8 = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);

export const normalize = (phrase) => phrase.toLowerCase().split(/\s+/).filter(Boolean).join(" ");

// check returns null for a valid phrase, or the reason it is refused.
// Invalid phrases are refused, never corrected (profile §4.1).
export async function check(phrase) {
  const ws = phrase.split(" ").filter(Boolean);
  if (ws.length < 12 || ws.length > 24 || ws.length % 3) return "length";
  const bad = ws.find((w) => !INDEX.has(w));
  if (bad) return "word:" + bad;
  const bits = ws.map((w) => INDEX.get(w).toString(2).padStart(11, "0")).join("");
  const cs = bits.length / 33;
  const ent = Uint8Array.from(bits.slice(0, bits.length - cs).match(/.{8}/g).map((b) => parseInt(b, 2)));
  const sum = new Uint8Array(await crypto.subtle.digest("SHA-256", ent));
  const want = sum[0].toString(2).padStart(8, "0").slice(0, cs);
  return bits.slice(bits.length - cs) === want ? null : "checksum";
}

// generate makes a new twelve-word phrase from the platform's CSPRNG.
export async function generate() {
  const ent = crypto.getRandomValues(new Uint8Array(16));
  const sum = new Uint8Array(await crypto.subtle.digest("SHA-256", ent));
  const bits = [...ent].map((x) => x.toString(2).padStart(8, "0")).join("") + sum[0].toString(2).padStart(8, "0").slice(0, 4);
  return bits.match(/.{11}/g).map((b) => WORDS[parseInt(b, 2)]).join(" ");
}

async function hkdf(ikm, salt, info) {
  const k = ikm instanceof CryptoKey ? ikm : await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: enc.encode(salt), info: enc.encode(info) }, k, 256));
}

// ed25519 turns a 32-byte seed into a non-extractable signing key and its
// public key.
async function ed25519(seed) {
  const pk = new Uint8Array([...PKCS8, ...seed]);
  const probe = await crypto.subtle.importKey("pkcs8", pk, { name: "Ed25519" }, true, ["sign"]);
  const jwk = await crypto.subtle.exportKey("jwk", probe);
  const pub = Uint8Array.from(atob(jwk.x.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
  const priv = await crypto.subtle.importKey("pkcs8", pk, { name: "Ed25519" }, false, ["sign"]);
  pk.fill(0);
  return { priv, pub };
}

// derive returns what the audit apps keep of a checked phrase: the
// auditor's signing key (the Onym Stellar key), its "onym:key:" and "G…"
// forms, and a non-extractable handle on the BIP-39 seed from which
// per-order keys are derived. The phrase itself is not kept.
export async function derive(phrase) {
  const pw = await crypto.subtle.importKey("raw", enc.encode(phrase.normalize("NFKD")), "PBKDF2", false, ["deriveBits"]);
  const seed = new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-512", salt: enc.encode("mnemonic"), iterations: 2048 }, pw, 512));
  const nostr = await hkdf(seed, "app.onym.bip39", "nostr-secp256k1-v1");
  const stellar = await hkdf(nostr, "app.onym.ios", "stellar-ed25519-v1");
  const { priv, pub } = await ed25519(stellar);
  const seedKey = await crypto.subtle.importKey("raw", seed, "HKDF", false, ["deriveBits"]);
  seed.fill(0);
  nostr.fill(0);
  stellar.fill(0);
  return { priv, key: "onym:key:" + hex(pub), account: accountID(pub), seedKey };
}

// orderKey is the key an orderer signs one order with: seed-scoped, in the
// Onym apps' pattern, so orders are unlinkable to each other and to the
// auditor key without the phrase.
export async function orderKey(seedKey, orderId) {
  const s = await hkdf(seedKey, "app.onym.bip39", "onym-audit-order-v1:" + orderId);
  const { priv, pub } = await ed25519(s);
  s.fill(0);
  return { priv, key: "onym:key:" + hex(pub) };
}

// ---- Stellar StrKey account IDs ("G…")

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function crc16(b) {
  let c = 0;
  for (const x of b) {
    c ^= x << 8;
    for (let i = 0; i < 8; i++) c = c & 0x8000 ? ((c << 1) ^ 0x1021) & 0xffff : (c << 1) & 0xffff;
  }
  return c;
}

export function accountID(pub) {
  const p = new Uint8Array([6 << 3, ...pub]);
  const c = crc16(p);
  const all = [...p, c & 0xff, c >> 8];
  let bits = all.map((x) => x.toString(2).padStart(8, "0")).join("");
  bits += "0".repeat((5 - (bits.length % 5)) % 5);
  return bits.match(/.{5}/g).map((b) => B32[parseInt(b, 2)]).join("");
}

// keyOfAccount turns "G…" into "onym:key:<hex>", or null if it is not a
// valid account ID.
export function keyOfAccount(id) {
  if (!/^G[A-Z2-7]{55}$/.test(id)) return null;
  const bits = [...id].map((ch) => B32.indexOf(ch).toString(2).padStart(5, "0")).join("");
  const b = Uint8Array.from(bits.slice(0, 280).match(/.{8}/g).map((x) => parseInt(x, 2)));
  const c = crc16(b.slice(0, 33));
  if (b[0] !== 6 << 3 || b[33] !== (c & 0xff) || b[34] !== c >> 8) return null;
  return "onym:key:" + hex(b.slice(1, 33));
}

export function accountOfKey(key) {
  return accountID(Uint8Array.from(key.slice(9).match(/../g).map((x) => parseInt(x, 16))));
}
