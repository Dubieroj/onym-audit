// Anchoring an auditor's register on the Stellar test network. The anchor
// is a hash of the auditor's own acts in its status list — which
// attestations it issued, their digests, which it revoked or superseded —
// written as the data entry "onym-audit-status" of the auditor's Stellar
// account, which is the auditor key itself. Re-signing for freshness does
// not change it; issuing or revoking does. The network keeps every write
// with its ledger time, so a register cannot be backdated or shown
// differently to different readers without the difference being visible.
// Only public Stellar nodes are asked; nothing here trusts the hub.
import { parseStrict, canonical, plain } from "./verify.js";

export const NETWORK = {
  name: "testnet",
  passphrase: "Test SDF Network ; September 2015",
  horizon: "https://horizon-testnet.stellar.org",
  friendbot: "https://friendbot.stellar.org",
  explorer: "https://stellar.expert/explorer/testnet/account/",
};
export const DATA_NAME = "onym-audit-status";

const enc = new TextEncoder();
const sha256 = async (b) => new Uint8Array(await crypto.subtle.digest("SHA-256", b));
const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const unhex = (h) => Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16)));
const b64 = (u) => btoa(String.fromCharCode(...u));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

// anchorDigest hashes the auditor's acts in a status list: canonical JSON of
// {anchorVersion, auditor, entries sorted by attestationId}, each entry its
// id, attestation digest, state, supersededBy and revocation digest.
// Subjects' responses are not the auditor's acts and are left out.
export async function anchorDigest(statusText) {
  const st = plain(parseStrict(statusText));
  const entries = st.entries
    .map((e) => ({ attestationId: e.attestationId, attestation: e.attestation.digest, state: e.state, supersededBy: e.supersededBy ?? null, revocation: e.revocation ? e.revocation.digest : null }))
    .sort((a, b) => (a.attestationId < b.attestationId ? -1 : 1));
  return sha256(enc.encode(canonical(parseStrict(JSON.stringify({ anchorVersion: 1, auditor: st.auditor, entries })))));
}

// ---- XDR for one ManageData transaction

class XDR {
  constructor() { this.b = []; }
  u32(n) { this.b.push((n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255); return this; }
  u64(v) { const x = BigInt.asUintN(64, BigInt(v)); for (let i = 7; i >= 0; i--) this.b.push(Number((x >> BigInt(i * 8)) & 255n)); return this; }
  fixed(bytes) { this.b.push(...bytes); return this; }
  opaque(bytes) { this.u32(bytes.length); this.b.push(...bytes); while (this.b.length % 4) this.b.push(0); return this; }
  bytes() { return new Uint8Array(this.b); }
}

// transaction: source account (an Ed25519 key), fee 100 stroops, sequence
// number, time bounds, no memo, one ManageData operation, no extension.
export function transaction(pub, seq, maxTime, name, value) {
  return new XDR()
    .u32(0).fixed(pub)            // MuxedAccount: KEY_TYPE_ED25519
    .u32(100)                     // fee
    .u64(seq)                     // seqNum
    .u32(1).u64(0).u64(maxTime)   // Preconditions: PRECOND_TIME, TimeBounds
    .u32(0)                       // Memo: MEMO_NONE
    .u32(1)                       // one operation
    .u32(0)                       // no operation source account
    .u32(10)                      // MANAGE_DATA
    .opaque(enc.encode(name))     // string64 dataName
    .u32(1).opaque(value)         // DataValue present
    .u32(0)                       // ext v0
    .bytes();
}

// signaturePayload is what a Stellar signature covers: the hash of the
// network id, the envelope type (ENVELOPE_TYPE_TX = 2) and the transaction.
export async function signaturePayload(tx, passphrase = NETWORK.passphrase) {
  return sha256(new XDR().fixed(await sha256(enc.encode(passphrase))).u32(2).fixed(tx).bytes());
}

export function envelope(tx, pub, sig) {
  return new XDR().u32(2).fixed(tx).u32(1).fixed(pub.slice(28)).opaque(sig).bytes();
}

// ---- Horizon

async function account(g) {
  const r = await fetch(`${NETWORK.horizon}/accounts/${g}`, { credentials: "omit", cache: "no-store" });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`Stellar: HTTP ${r.status}`);
  return r.json();
}

// anchor writes the digest to the auditor's account, first creating the
// account with the test network's free Friendbot funds if it has none.
// Returns the transaction hash.
export async function anchor({ priv, key, account: g }, digest) {
  let acct = await account(g);
  if (!acct) {
    await fetch(`${NETWORK.friendbot}/?addr=${g}`, { credentials: "omit" });
    acct = await account(g);
    if (!acct) throw new Error("Stellar: the test account could not be funded");
  }
  const pub = unhex(key.slice("onym:key:".length));
  const tx = transaction(pub, BigInt(acct.sequence) + 1n, Math.floor(Date.now() / 1000) + 300, DATA_NAME, digest);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, priv, await signaturePayload(tx)));
  const r = await fetch(`${NETWORK.horizon}/transactions`, {
    method: "POST", credentials: "omit", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "tx=" + encodeURIComponent(b64(envelope(tx, pub, sig))),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error("Stellar: " + (j.extras?.result_codes ? JSON.stringify(j.extras.result_codes) : j.title || "HTTP " + r.status));
  return j.hash;
}

// anchorState compares a status list with the anchor on the network:
// "match" (with the ledger time of the account's last change), "stale"
// (the register changed since it was anchored), or "none".
export async function anchorState(g, statusText) {
  const acct = await account(g);
  const v = acct?.data?.[DATA_NAME];
  if (!v) return { state: "none" };
  const want = hex(await anchorDigest(statusText));
  return { state: hex(unb64(v)) === want ? "match" : "stale", at: acct.last_modified_time, anchored: hex(unb64(v)), want };
}

// ---- Linking an auditor to an account on the public network
//
// The account's holder writes two data entries on it, in one transaction
// they sign in their own wallet: the auditor's key, and the auditor key's
// signature over linkMessage(account). Both sides consent on the network;
// the auditor needs no account or funds of its own there.

export const MAINNET = {
  passphrase: "Public Global Stellar Network ; September 2015",
  horizon: "https://horizon.stellar.org",
  explorer: "https://stellar.expert/explorer/public/account/",
};
export const LINK_KEY = "onym-audit-auditor";
export const LINK_PROOF = "onym-audit-proof";
export const linkMessage = (g) => enc.encode(`onym-audit-link-v1\n${MAINNET.passphrase}\n${g}`);

// linkTransaction: source account, fee (for the whole transaction), sequence
// number, time bounds, no memo, one ManageData operation per entry.
export function linkTransaction(pub, seq, maxTime, entries, fee = 10000) {
  const x = new XDR().u32(0).fixed(pub).u32(fee).u64(seq).u32(1).u64(0).u64(maxTime).u32(0).u32(entries.length);
  for (const [name, value] of entries) x.u32(0).u32(10).opaque(enc.encode(name)).u32(1).opaque(value);
  return x.u32(0).bytes();
}

// unsignedEnvelope is what a wallet signs: the transaction, no signatures.
export const unsignedEnvelope = (tx) => b64(new XDR().u32(2).fixed(tx).u32(0).bytes());

export async function mainnetAccount(g) {
  const r = await fetch(`${MAINNET.horizon}/accounts/${g}`, { credentials: "omit", cache: "no-store" });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`Stellar: HTTP ${r.status}`);
  return r.json();
}

// sep7 is the web+stellar link a wallet opens to sign and submit a
// transaction on the public network (SEP-7; the public network is the default).
export const sep7 = (envelopeB64) => "web+stellar:tx?xdr=" + encodeURIComponent(envelopeB64);

// linkState checks the two entries on account g against an auditor key:
// "linked", "none" (no entries), "other" (another auditor's key), "bad"
// (the proof does not verify) or "no-account".
export async function linkState(g, key) {
  const acct = await mainnetAccount(g);
  if (!acct) return { state: "no-account" };
  const k = acct.data?.[LINK_KEY], p = acct.data?.[LINK_PROOF];
  if (!k || !p) return { state: "none" };
  if (hex(unb64(k)) !== key.slice("onym:key:".length)) return { state: "other" };
  const pub = await crypto.subtle.importKey("raw", unb64(k), { name: "Ed25519" }, false, ["verify"]);
  const good = await crypto.subtle.verify({ name: "Ed25519" }, pub, unb64(p), linkMessage(g)).catch(() => false);
  return { state: good ? "linked" : "bad", at: acct.last_modified_time };
}
