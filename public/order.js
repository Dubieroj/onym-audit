// Order page: order an examination from any auditor — this site's operator
// or any auditor on the hub — under one of the offers the auditor signed.
// The browser pins the exact bytes, builds the AuditOrder from the offer,
// signs it as subject and sponsor with an Ed25519 key that never leaves the
// page, and queues it with the auditor (the envelope form of profile §5.3).
import { parseStrict, canonical, plain, digest, fingerprint, verifySig } from "./verify.js";

const $ = (id) => document.getElementById(id);
const ROOT = new URL(".", import.meta.url);
const HUB = new URL("hub/api/", ROOT);
const T = JSON.parse($("strings")?.textContent || "{}");
const t = (k, v = {}) => (T[k] ?? k).replace(/\{(\w+)\}/g, (_, x) => v[x] ?? "");
const enc = new TextEncoder();
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
const unhex = (h) => Uint8Array.from(h.match(/../g).map((b) => parseInt(b, 16)));
const b64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b)));
const PKCS8_ED25519 = unhex("302e020100300506032b657004220420");

const RE = {
  https: /^https:\/\/[A-Za-z0-9.-]+\.[A-Za-z]{2,}(\/[^\s?#:@]*)?$/,
  commit: /^[0-9a-f]{40}$/,
  component: /^onym:component:[a-z0-9-]{1,64}$/,
  email: /^[^\s@<>()",;:]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$/,
  seed: /^[0-9a-f]{64}$/,
};

const el = (tag, props = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v; // untrusted strings are only ever text
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null && v !== false) n.setAttribute(k, v === true ? "" : v);
  }
  for (const c of kids.flat()) if (c != null) n.append(c.nodeType ? c : document.createTextNode(String(c)));
  return n;
};
const getText = async (url) => {
  const r = await fetch(url, { credentials: "omit", cache: "no-cache" });
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  return r.text();
};
async function hub(path, body) {
  const r = await fetch(new URL(path, HUB), { method: "POST", credentials: "omit", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || "HTTP " + r.status);
  return data;
}

let keyFileURL = null;
let auditor = null; // {base, endpoint, manifest, offers, only}
let offer = null;
let kind = null;

function fail(msg) {
  const e = $("form-error");
  e.textContent = msg;
  e.hidden = false;
  e.scrollIntoView({ block: "center", behavior: "smooth" });
}

// ---------------------------------------------------------------- auditors and offers

// The operator of this site takes orders at ROOT/orders; its console fulfils
// source reviews only, so only that offer is shown for it. Hub auditors take
// orders at ROOT/a/<name>/orders under any offer they signed.
async function listAuditors() {
  const list = [{ slug: "", base: ROOT.href, endpoint: new URL("orders", ROOT).href, only: ["security-review-llm-source"] }];
  try {
    const hosted = await fetch(new URL("auditors", HUB), { credentials: "omit" }).then((r) => r.json());
    for (const a of hosted) if (a.offers > 0) list.push({ slug: a.slug, base: new URL(`a/${a.slug}/`, ROOT).href, endpoint: new URL(`a/${a.slug}/orders`, ROOT).href, only: null });
  } catch { /* the hub is optional */ }
  const box = $("auditors");
  box.replaceChildren();
  const wanted = new URLSearchParams(location.search).get("auditor") || "";
  for (const a of list) {
    const card = el("button", { type: "button", class: "choice", role: "radio", "aria-checked": "false", onclick: () => pickAuditor(a, card) }, el("b", { text: a.slug || "…" }), el("span", { text: t("loading") }));
    box.append(card);
    loadAuditor(a).then(() => {
      card.firstChild.textContent = a.manifest.displayName;
      card.lastChild.textContent = t("auditor_line", { fp: a.print, n: a.offers.length });
      if (!a.offers.length) card.disabled = true;
      if (a.slug === wanted && a.offers.length) pickAuditor(a, card);
    }, () => {
      card.lastChild.textContent = t("err_auditor");
      card.disabled = true;
    });
  }
}

// loadAuditor verifies the manifest and every offer under the auditor's key;
// an offer that does not verify is not shown.
async function loadAuditor(a) {
  const text = await getText(new URL("manifest.json", a.base));
  const m = plain(parseStrict(text));
  if (!(await verifySig(text, m.operator).catch(() => false))) throw new Error("manifest signature");
  a.manifest = m;
  a.print = await fingerprint(m.operator);
  a.offers = [];
  for (const id of m.offers) {
    if (a.only && !a.only.includes(id)) continue;
    try {
      const ot = await getText(new URL(`offers/${id}.json`, a.base));
      const o = plain(parseStrict(ot));
      if (o.offerId === id && o.auditor === m.componentId && o.auditorKey === m.operator && Date.parse(o.validUntil) > Date.now() && (await verifySig(ot, m.operator))) a.offers.push(o);
    } catch { /* not shown */ }
  }
}

function select(box, card) {
  for (const c of box.children) {
    c.classList.toggle("on", c === card);
    c.setAttribute("aria-checked", String(c === card));
  }
}

function pickAuditor(a, card) {
  auditor = a;
  select($("auditors"), card);
  $("t-auditor").textContent = `${a.manifest.displayName} · ${a.print}`;
  const box = $("offers");
  box.replaceChildren();
  for (const o of a.offers) {
    const c = el("button", { type: "button", class: "choice", role: "radio", "aria-checked": "false", onclick: () => pickOffer(o, c) },
      el("b", { text: t("m_" + o.methodologyClass) }), el("span", { text: `${feeText(o)} · ${t("due_days", { n: o.timelineDays })}` }), el("code", { class: "small", text: o.offerId }));
    box.append(c);
  }
  if (box.firstChild) box.firstChild.click();
}

const feeText = (o) => (o.fee.model === "pro-bono" ? t("fee_probono") : t("fee_fixed", { amount: (o.fee.amount / 100).toFixed(2), currency: o.fee.currency }));

// Kinds an offer covers: the scopes the manifest offers for its methodology.
function kindsOf(o) {
  const ks = new Set();
  for (const mt of auditor.manifest.methodologies) {
    if (mt.class !== o.methodologyClass) continue;
    for (const s of mt.scopesOffered) ks.add(["source", "deployment", "build"].includes(s) ? s : "discovery");
  }
  return [...ks];
}

function pickOffer(o, card) {
  offer = o;
  select($("offers"), card);
  $("offer-code").textContent = o.offerId;
  $("t-fee").textContent = feeText(o) + " — " + t("fee_same");
  $("t-due").textContent = t("due_days", { n: o.timelineDays });
  $("t-first").textContent = o.disclosure.findingsToSubjectFirst ? t("first_yes") : t("first_no");
  $("t-embargo").textContent = o.disclosure.embargoDays > 0 ? t("embargo_days", { n: o.disclosure.embargoDays }) : t("embargo_none");
  $("t-publish").textContent = o.disclosure.failPublication === "public-after-embargo" ? t("publish_embargo") : t("publish_now");
  const m = auditor.manifest;
  const link = (href, text) => el("a", { href, text, target: "_blank", rel: "noopener" });
  $("t-links").replaceChildren(t("links"), " ", link(o.scope.uri, t("l_method")), " · ", link(m.independencePolicy.uri, t("l_indep")), " · ", link(m.liability.uri, t("l_liab")), " · ", link(m.privacyProfile.uri, t("l_priv")));
  const box = $("kinds");
  box.replaceChildren();
  const ks = kindsOf(o);
  for (const k of ks) {
    box.append(el("label", { class: "radio" }, el("input", { type: "radio", name: "kind", value: k, onchange: () => pickKind(k) }), " ", t("k_" + k)));
  }
  box.querySelector("input").checked = true;
  pickKind(ks[0]);
}

function pickKind(k) {
  kind = k;
  for (const d of document.querySelectorAll("[data-kind]")) d.hidden = !d.dataset.kind.split(" ").includes(k);
}

// ---------------------------------------------------------------- keys and signing

// A seed-based keypair: a fresh one, or the holder's existing seed.
async function keypair(mode) {
  if (!crypto.subtle || !(await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign"]).then(() => true, () => false))) {
    throw new Error(t("err_crypto"));
  }
  let seed;
  if (mode === "existing") {
    const h = $("seed").value.trim().toLowerCase();
    if (!RE.seed.test(h)) throw new Error(t("err_seed"));
    seed = unhex(h);
  } else {
    seed = crypto.getRandomValues(new Uint8Array(32));
  }
  const pkcs8 = new Uint8Array([...PKCS8_ED25519, ...seed]);
  const priv = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"]);
  const jwk = await crypto.subtle.exportKey("jwk", priv);
  const pub = Uint8Array.from(atob(jwk.x.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
  return { priv, seedHex: hex(seed), key: "onym:key:" + hex(pub) };
}

function orderID() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  const r = crypto.getRandomValues(new Uint8Array(20));
  return "ord-" + [...r].map((x) => alphabet[x % alphabet.length]).join("");
}

// Signed text stays English, whatever the page's language.
const COOPERATION = {
  source: "Public repository access only; the subject answers the auditor's questions at the contact given with the order.",
  build: "Public repository and release access only; the subject answers the auditor's questions at the contact given with the order.",
  deployment: "Read access to the public deployment only; the subject answers the auditor's questions at the contact given with the order.",
};

const day = (d) => d.toISOString().slice(0, 10);
const trimRepo = (u) => u.trim().replace(/\/+$/, "").replace(/\.git$/, "");

// pin reads the exact bytes the order will bind. Running services and
// builds are read by the hub, which fetches only public addresses.
async function pin() {
  if (kind === "source") {
    const repo = trimRepo($("repo").value), commit = $("commit").value.trim().toLowerCase();
    if (!RE.https.test(repo)) throw new Error(t("err_repo"));
    if (!RE.commit.test(commit)) throw new Error(t("err_commit"));
    // Hub auditors read repositories in the studio, which browses GitHub.
    if (!auditor.only && !/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)) throw new Error(t("err_github"));
    return { artifact: { kind: "source", source: repo, revision: commit, artifactHash: null }, preface: "" };
  }
  if (kind === "build") {
    const repo = trimRepo($("repo").value), commit = $("commit").value.trim().toLowerCase(), file = $("file").value.trim();
    if (!RE.https.test(repo) || !RE.https.test(file)) throw new Error(t("err_repo"));
    if (!RE.commit.test(commit)) throw new Error(t("err_commit"));
    $("submit").textContent = t("hashing");
    const d = await hub("digest", { url: file }).catch((e) => { throw new Error(t("err_pin", { url: file, err: e.message })); });
    return { artifact: { kind: "build", source: repo, revision: commit, artifactHash: d.digest }, preface: `Build file: ${file}\n\n` };
  }
  const url = $("manifest-url").value.trim();
  if (!RE.https.test(url)) throw new Error(t("err_url"));
  $("submit").textContent = t("pinning");
  const d = await hub("fetch", { url }).catch((e) => { throw new Error(t("err_pin", { url, err: e.message })); });
  if (d.status !== 200) throw new Error(t("err_pin", { url, err: "HTTP " + d.status }));
  return { artifact: { kind: "deployment", source: url, revision: d.digest, artifactHash: null }, preface: "" };
}

async function submit(ev) {
  ev.preventDefault();
  $("form-error").hidden = true;
  if (!auditor || !offer) return fail(t("err_offer"));
  const component = $("component").value.trim();
  const email = $("email").value.trim();
  if (!RE.component.test(component)) return fail(t("err_component"));
  if (!$("scope").value.trim()) return fail(t("err_scope"));
  if (!RE.email.test(email)) return fail(t("err_email"));
  if (!$("authority").checked || !$("terms").checked) return fail(t("err_checks"));

  const btn = $("submit");
  btn.disabled = true;
  btn.textContent = t("signing");
  try {
    const { artifact, preface } = await pin();
    const scopeText = preface + $("scope").value.trim() + "\n";
    if (enc.encode(scopeText).length > 8000) throw new Error(t("err_scope"));
    btn.textContent = t("signing");
    const base = auditor.manifest.statusEndpoint.replace(/status\.json$/, "");
    const { priv, seedHex, key } = await keypair(document.querySelector('input[name="keymode"]:checked').value);
    const id = orderID();
    const now = new Date();
    const order = {
      orderVersion: 1,
      orderId: id,
      auditor: auditor.manifest.componentId,
      subject: component,
      sponsor: key,
      artifact,
      methodologyClass: offer.methodologyClass,
      scope: { uri: `${base}scopes/order-${id}.md`, digest: await digest(enc.encode(scopeText)) },
      cooperation: COOPERATION[artifact.kind],
      disclosure: offer.disclosure,
      timeline: { start: day(now), reportDue: day(new Date(now.getTime() + offer.timelineDays * 864e5)) },
      fee: { model: offer.fee.model, offerId: offer.offerId },
      signatures: [],
    };
    // Every party signs the canonical bytes with `signatures` removed.
    const unsigned = parseStrict(JSON.stringify(order));
    unsigned.delete("signatures");
    const s = b64(await crypto.subtle.sign({ name: "Ed25519" }, priv, enc.encode(canonical(unsigned))));
    order.signatures = [
      { role: "subject", key, signature: s },
      { role: "sponsor", key, signature: s },
    ];
    const signed = canonical(parseStrict(JSON.stringify(order)));

    btn.textContent = t("sending");
    const r = await fetch(auditor.endpoint, {
      method: "POST",
      credentials: "omit",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ order: JSON.parse(signed), scopeText, contact: "mailto:" + email }),
    });
    const reply = await r.json().catch(() => ({}));
    if (r.status !== 202) throw new Error(t("err_server", { err: reply.detail || reply.error || "HTTP " + r.status }));

    keyFileURL = URL.createObjectURL(new Blob([seedHex + "\n"], { type: "text/plain" }));
    $("dl-key").href = keyFileURL;
    $("dl-key").download = `onym-subject-${id}.key`;
    $("dl-order").href = URL.createObjectURL(new Blob([signed], { type: "application/json" }));
    $("dl-order").download = `onym-order-${id}.json`;
    $("done-id").textContent = reply.orderId;
    $("done-digest").textContent = reply.digest;
    $("done-key").textContent = key;
    $("order-form").hidden = true;
    $("done").hidden = false;
    $("done").scrollIntoView({ behavior: "smooth" });
    let saved = false;
    $("dl-key").addEventListener("click", () => { saved = true; });
    window.addEventListener("beforeunload", (e) => { if (!saved) { e.preventDefault(); e.returnValue = ""; } });
  } catch (e) {
    fail(e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = t("submit");
  }
}

// Suggest a component id from the repository or the service's manifest,
// until the holder edits it.
let componentEdited = false;
$("component").addEventListener("input", () => { componentEdited = true; });
$("repo").addEventListener("input", () => {
  if (componentEdited) return;
  const m = $("repo").value.trim().match(/\/([^/]+?)(?:\.git)?\/?$/);
  if (m) $("component").value = "onym:component:" + m[1].toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 64);
});
$("manifest-url").addEventListener("change", async () => {
  const url = $("manifest-url").value.trim();
  if (componentEdited || !RE.https.test(url)) return;
  try {
    const d = await hub("fetch", { url });
    const m = plain(parseStrict(d.body));
    // Seats name themselves differently (a Discovery provider: providerId).
    const id = [m.componentId, m.providerId, m.authorityId].find((x) => typeof x === "string" && RE.component.test(x));
    if (id) $("component").value = id;
  } catch { /* the holder types it */ }
});
for (const r of document.querySelectorAll('input[name="keymode"]')) {
  r.addEventListener("change", () => { $("seed-wrap").hidden = r.value !== "existing" || !r.checked; });
}
$("order-form").addEventListener("submit", submit);
pickKind("source");
listAuditors();
