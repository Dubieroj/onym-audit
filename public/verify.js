// Relying-client verification for the Onym audit static-Ed25519 profile,
// runnable in any browser with WebCrypto Ed25519 and in Node. Everything is
// checked locally: signatures, the status list, and exact-byte matching.

const enc = new TextEncoder();

// ---- canonical JSON (Discovery-Static-Ed25519 §3) --------------------------

class Malformed extends Error {}

export function parseStrict(text) {
  let i = 0;
  const s = text;
  const ws = () => { while (i < s.length && " \t\n\r".includes(s[i])) i++; };
  const fail = (m) => { throw new Malformed(`${m} at ${i}`); };
  const value = (depth) => {
    if (depth > 64) fail("nesting too deep");
    ws();
    const c = s[i];
    if (c === "{") return object(depth);
    if (c === "[") return array(depth);
    if (c === '"') return string();
    if (s.startsWith("true", i)) { i += 4; return true; }
    if (s.startsWith("false", i)) { i += 5; return false; }
    if (s.startsWith("null", i)) { i += 4; return null; }
    if (c === "-") fail("negative numbers are not permitted");
    if (c >= "0" && c <= "9") return number();
    fail("unexpected character");
  };
  const object = (depth) => {
    i++; const o = new Map(); ws();
    if (s[i] === "}") { i++; return o; }
    for (;;) {
      ws(); if (s[i] !== '"') fail("expected key");
      const k = string();
      if (o.has(k)) fail(`duplicate key ${k}`);
      ws(); if (s[i] !== ":") fail("expected ':'"); i++;
      o.set(k, value(depth + 1)); ws();
      if (s[i] === ",") { i++; continue; }
      if (s[i] === "}") { i++; return o; }
      fail("expected ',' or '}'");
    }
  };
  const array = (depth) => {
    i++; const a = []; ws();
    if (s[i] === "]") { i++; return a; }
    for (;;) {
      a.push(value(depth + 1)); ws();
      if (s[i] === ",") { i++; continue; }
      if (s[i] === "]") { i++; return a; }
      fail("expected ',' or ']'");
    }
  };
  const number = () => {
    const m = /^[0-9]+/.exec(s.slice(i));
    const d = m[0];
    i += d.length;
    if (".eE".includes(s[i] ?? " ")) fail("only integers are permitted");
    if (d.length > 1 && d[0] === "0") fail("leading zero");
    if (BigInt(d) > 9007199254740991n) fail("integer out of range");
    return { num: d };
  };
  const string = () => {
    i++; let out = "";
    for (;;) {
      if (i >= s.length) fail("unterminated string");
      const c = s[i];
      if (c === '"') { i++; return out; }
      if (c < " ") fail("raw control character");
      if (c !== "\\") { out += c; i++; continue; }
      const e = s[i + 1]; i += 2;
      const simple = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
      if (e in simple) { out += simple[e]; continue; }
      if (e !== "u") fail("invalid escape");
      const hex = (at) => { const h = s.slice(at, at + 4); if (!/^[0-9a-fA-F]{4}$/.test(h)) fail("bad \\u"); return parseInt(h, 16); };
      let cp = hex(i); i += 4;
      if (cp >= 0xdc00 && cp <= 0xdfff) fail("lone trailing surrogate");
      if (cp >= 0xd800 && cp <= 0xdbff) {
        if (s[i] !== "\\" || s[i + 1] !== "u") fail("lone leading surrogate");
        const lo = hex(i + 2);
        if (lo < 0xdc00 || lo > 0xdfff) fail("invalid surrogate pair");
        i += 6; cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
      }
      out += String.fromCodePoint(cp);
    }
  };
  const v = value(0); ws();
  if (i !== s.length) fail("trailing data");
  if (!(v instanceof Map)) throw new Malformed("top level is not an object");
  return v;
}

function byteCompare(a, b) {
  const x = enc.encode(a), y = enc.encode(b);
  for (let k = 0; k < Math.min(x.length, y.length); k++) if (x[k] !== y[k]) return x[k] - y[k];
  return x.length - y.length;
}

function encString(str) {
  let out = '"';
  for (const ch of str) {
    const c = ch.codePointAt(0);
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (c === 8) out += "\\b";
    else if (c === 12) out += "\\f";
    else if (c === 10) out += "\\n";
    else if (c === 13) out += "\\r";
    else if (c === 9) out += "\\t";
    else if (c < 0x20) out += "\\u00" + c.toString(16).padStart(2, "0");
    else out += ch;
  }
  return out + '"';
}

export function canonical(v) {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "string") return encString(v);
  if (v && v.num !== undefined) return v.num;
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  if (v instanceof Map) {
    const keys = [...v.keys()].sort(byteCompare);
    return "{" + keys.map((k) => encString(k) + ":" + canonical(v.get(k))).join(",") + "}";
  }
  throw new Malformed("unsupported value");
}

export function signingBytes(text, omit = "signature") {
  const m = parseStrict(text);
  m.delete(omit);
  return enc.encode(canonical(m));
}

// Plain JS view of a parsed document (numbers as Number).
export function plain(v) {
  if (v instanceof Map) return Object.fromEntries([...v].map(([k, x]) => [k, plain(x)]));
  if (Array.isArray(v)) return v.map(plain);
  if (v && v.num !== undefined) return Number(v.num);
  return v;
}

// ---- keys, digests, signatures ---------------------------------------------

const hexToBytes = (h) => Uint8Array.from(h.match(/../g).map((b) => parseInt(b, 16)));
const toHex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");

export async function digest(bytes) {
  return "sha256:" + toHex(await crypto.subtle.digest("SHA-256", bytes));
}

export async function fingerprint(key) {
  const d = await crypto.subtle.digest("SHA-256", hexToBytes(key.slice(9)));
  return toHex(d).slice(0, 16).match(/../g).join(":");
}

export async function verifySig(text, key, field = "signature") {
  if (!/^onym:key:[0-9a-f]{64}$/.test(key)) return false;
  const doc = parseStrict(text);
  const sigB64 = doc.get(field);
  if (typeof sigB64 !== "string") return false;
  let sig;
  try { sig = Uint8Array.from(atob(sigB64.padEnd(Math.ceil(sigB64.length / 4) * 4, "=")), (c) => c.charCodeAt(0)); } catch { return false; }
  if (sig.length !== 64) return false;
  const pub = await crypto.subtle.importKey("raw", hexToBytes(key.slice(9)), { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "Ed25519" }, pub, sig, signingBytes(text, field));
}

// ---- profile §6 --------------------------------------------------------------

const SKEW = 10 * 60 * 1000;

// verifyAttestation mirrors the Go reference's audit.Verify for the parts a
// browser can check. target: {kind, source, revision, artifactHash} or null
// when the reader has not supplied the component bytes.
export async function verifyAttestation({ manifestText, attText, statusText, target, credited, now = Date.now() }) {
  const r = { notes: [] };
  const m = plain(parseStrict(manifestText));
  if (!(await verifySig(manifestText, m.operator))) return { display: "no-attestation", error: "auditor_manifest_invalid" };
  if (Date.parse(m.validUntil) + SKEW < now) return { display: "no-attestation", error: "auditor_manifest_invalid", notes: ["manifest validUntil has passed"] };
  const a = plain(parseStrict(attText));
  r.att = a;
  if (a.auditorKey !== m.operator || a.auditor !== m.componentId || !(await verifySig(attText, a.auditorKey))) {
    return { display: "no-attestation", error: "attestation_invalid", att: a };
  }
  if (target) {
    const x = a.artifact;
    const same = x.kind === target.kind && x.source === target.source && x.revision === target.revision && (x.artifactHash ?? null) === (target.artifactHash ?? null);
    if (!same) return { display: "no-attestation", error: "artifact_mismatch", att: a, notes: x.source === target.source ? ["another revision of this component was attested"] : [] };
  } else {
    r.notes.push("component bytes not supplied: applies only to the exact bytes shown");
  }
  let fresh = false, entry = null;
  if (!statusText) {
    r.error = "status_unavailable";
  } else {
    const st = plain(parseStrict(statusText));
    if (st.statusKey !== m.statusKey || st.auditorKey !== m.operator || !(await verifySig(statusText, m.statusKey))) {
      r.error = "status_list_invalid";
    } else {
      entry = st.entries.find((e) => e.attestationId === a.attestationId);
      r.status = st;
      fresh = Date.parse(st.nextUpdate) + SKEW >= now;
      if (!fresh) r.error = "status_unavailable";
      if (!entry) { fresh = false; r.notes.push("status list does not cover this attestation"); }
      else if (entry.attestation.digest !== (await digest(enc.encode(attText)))) { fresh = false; r.error = "status_list_invalid"; }
      else if (entry.state !== "active") return { display: entry.state, error: "attestation_" + entry.state, att: a, entry };
    }
  }
  if (a.expiresAt && Date.parse(a.expiresAt) + SKEW < now) return { display: "expired", error: "attestation_expired", att: a, entry };
  r.entry = entry;
  r.display = fresh ? (credited ? "attested" : "uncredited") : "status-unknown";
  if (!credited && !r.error) r.error = "issuer_untrusted";
  r.highStakesOK = fresh && credited && !!target;
  return r;
}
