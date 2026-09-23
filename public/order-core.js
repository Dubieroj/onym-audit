// Ordering, shared by the order page and the app's customer cabinet: find
// the auditors that take orders, verify their manifests and signed offers,
// pin the exact bytes an order binds, build the AuditOrder from an offer,
// sign it as subject and sponsor, and queue it with the auditor.
import { parseStrict, canonical, plain, digest, fingerprint, verifySig } from "./verify.js";

const enc = new TextEncoder();
const b64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b)));

export const RE = {
  https: /^https:\/\/[A-Za-z0-9.-]+\.[A-Za-z]{2,}(\/[^\s?#:@]*)?$/,
  github: /^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/,
  commit: /^[0-9a-f]{40}$/,
  component: /^onym:component:[a-z0-9-]{1,64}$/,
  email: /^[^\s@<>()",;:]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$/,
};

// Signed text stays English, whatever the page's language.
const COOPERATION = {
  source: "Public repository access only; the subject answers the auditor's questions at the contact given with the order.",
  build: "Public repository and release access only; the subject answers the auditor's questions at the contact given with the order.",
  deployment: "Read access to the public deployment only; the subject answers the auditor's questions at the contact given with the order.",
};

const getText = async (url) => {
  const r = await fetch(url, { credentials: "omit", cache: "no-cache" });
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  return r.text();
};

export function hub(root) {
  const base = new URL("hub/api/", root);
  return async (path, body) => {
    const r = await fetch(new URL(path, base), body === undefined ? { credentials: "omit" } : { method: "POST", credentials: "omit", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.error || "HTTP " + r.status);
    return data;
  };
}

// auditors lists who takes orders: this site's operator (its console
// fulfils source reviews only, so only that offer is shown for it) and every
// hub auditor with published offers, each with the hub's public facts.
export async function auditors(root) {
  const api = hub(root);
  const list = [];
  const seat = await api("seat").catch(() => null);
  if (seat) list.push({ ...seat, base: new URL("./", root).href, endpoint: new URL("orders", root).href, only: ["security-review-llm-source"] });
  const hosted = await api("auditors").catch(() => []);
  for (const a of hosted) if (a.offers > 0) list.push({ ...a, base: new URL(`a/${a.slug}/`, root).href, endpoint: new URL(`a/${a.slug}/orders`, root).href, only: null });
  return list;
}

// load verifies an auditor's manifest and every offer under its key; an
// offer that does not verify, or has expired, is left out.
export async function load(a) {
  const text = await getText(new URL("manifest.json", a.base));
  const m = plain(parseStrict(text));
  if (!(await verifySig(text, m.operator).catch(() => false))) throw new Error("manifest signature");
  a.manifest = m;
  a.print = await fingerprint(m.operator);
  a.offerDocs = [];
  for (const id of m.offers) {
    if (a.only && !a.only.includes(id)) continue;
    try {
      const ot = await getText(new URL(`offers/${id}.json`, a.base));
      const o = plain(parseStrict(ot));
      if (o.offerId === id && o.auditor === m.componentId && o.auditorKey === m.operator && Date.parse(o.validUntil) > Date.now() && (await verifySig(ot, m.operator))) a.offerDocs.push(o);
    } catch { /* left out */ }
  }
  return a;
}

// kindsOf: what an offer covers — the scopes the manifest offers for its
// methodology.
export function kindsOf(manifest, offer) {
  const ks = new Set();
  for (const mt of manifest.methodologies) {
    if (mt.class !== offer.methodologyClass) continue;
    for (const s of mt.scopesOffered) ks.add(["source", "deployment", "build"].includes(s) ? s : "discovery");
  }
  return [...ks];
}

export const feeText = (o, t) => (o.fee.model === "pro-bono" ? t("fee_probono") : `${(o.fee.amount / 100).toFixed(2)} ${o.fee.currency}`);

const trimRepo = (u) => u.trim().replace(/\/+$/, "").replace(/\.git$/, "");

// pin reads the exact bytes an order binds. Running services and builds are
// read by the hub, which fetches only public addresses. Hub auditors read
// repositories in the app, which opens GitHub repositories.
export async function pin(root, kind, f, hosted, t, progress = () => {}) {
  const api = hub(root);
  if (kind === "source" || kind === "build") {
    const repo = trimRepo(f.repo), commit = f.commit.trim().toLowerCase();
    if (!RE.https.test(repo)) throw new Error(t("err_repo"));
    if (!RE.commit.test(commit)) throw new Error(t("err_commit"));
    if (kind === "source") {
      if (hosted && !RE.github.test(repo)) throw new Error(t("err_github"));
      return { artifact: { kind: "source", source: repo, revision: commit, artifactHash: null }, preface: "" };
    }
    const file = f.file.trim();
    if (!RE.https.test(file)) throw new Error(t("err_repo"));
    progress(t("hashing"));
    const d = await api("digest", { url: file }).catch((e) => { throw new Error(t("err_pin", { url: file, err: e.message })); });
    return { artifact: { kind: "build", source: repo, revision: commit, artifactHash: d.digest }, preface: `Build file: ${file}\n\n` };
  }
  const url = f.manifestUrl.trim();
  if (!RE.https.test(url)) throw new Error(t("err_url"));
  progress(t("pinning"));
  const d = await api("fetch", { url }).catch((e) => { throw new Error(t("err_pin", { url, err: e.message })); });
  if (d.status !== 200) throw new Error(t("err_pin", { url, err: "HTTP " + d.status }));
  // A service is ordered by its manifest, and the Discovery suite applies
  // to Discovery providers only: anything else would yield a verdict about
  // a document that is not the component.
  let m = null;
  try { m = plain(parseStrict(d.body)); } catch { /* not JSON */ }
  if (!m || typeof m !== "object" || typeof m.seat !== "string") throw new Error(t("err_not_manifest", { url }));
  if (kind === "discovery" && m.seat !== "discovery") throw new Error(t("err_not_discovery", { seat: m.seat }));
  return { artifact: { kind: "deployment", source: url, revision: d.digest, artifactHash: null }, preface: "" };
}

// subjectOf reads the component id a service's manifest names (a Discovery
// provider names itself providerId).
export async function subjectOf(root, url) {
  const d = await hub(root)("fetch", { url });
  const m = plain(parseStrict(d.body));
  return [m.componentId, m.providerId, m.authorityId].find((x) => typeof x === "string" && RE.component.test(x)) || null;
}

export function newOrderID() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  return "ord-" + [...crypto.getRandomValues(new Uint8Array(20))].map((x) => alphabet[x % alphabet.length]).join("");
}

const day = (d) => d.toISOString().slice(0, 10);

// sign builds the order from the offer and signs it as subject and sponsor
// with one key; every party signs the canonical bytes without `signatures`.
export async function sign({ auditor, offer, artifact, scopeText, component, orderId, key, priv }) {
  const base = auditor.manifest.statusEndpoint.replace(/status\.json$/, "");
  const now = new Date();
  const order = {
    orderVersion: 1, orderId, auditor: auditor.manifest.componentId, subject: component, sponsor: key, artifact,
    methodologyClass: offer.methodologyClass,
    scope: { uri: `${base}scopes/order-${orderId}.md`, digest: await digest(enc.encode(scopeText)) },
    cooperation: COOPERATION[artifact.kind], disclosure: offer.disclosure,
    timeline: { start: day(now), reportDue: day(new Date(now.getTime() + offer.timelineDays * 864e5)) },
    fee: { model: offer.fee.model, offerId: offer.offerId }, signatures: [],
  };
  const unsigned = parseStrict(JSON.stringify(order));
  unsigned.delete("signatures");
  const s = b64(await crypto.subtle.sign({ name: "Ed25519" }, priv, enc.encode(canonical(unsigned))));
  order.signatures = [{ role: "subject", key, signature: s }, { role: "sponsor", key, signature: s }];
  return canonical(parseStrict(JSON.stringify(order)));
}

// send queues a signed order with its scope text and the orderer's contact.
export async function send(endpoint, signed, scopeText, email) {
  const r = await fetch(endpoint, {
    method: "POST", credentials: "omit", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ order: JSON.parse(signed), scopeText, contact: "mailto:" + email }),
  });
  const reply = await r.json().catch(() => ({}));
  if (r.status !== 202) throw new Error(reply.detail || reply.error || "HTTP " + r.status);
  return reply;
}
