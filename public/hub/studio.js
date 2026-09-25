// Onym audit app: an auditor's cabinet and the library of every attestation
// the hub serves. The holder signs in with a phrase of its own — an Onym
// identity kept for this role, never their main one — and the auditor key
// is that identity's Stellar key, derived exactly as the Onym apps derive it
// (onym-id.js). Only non-extractable keys are kept in this browser's
// IndexedDB; the phrase is not stored and the hub never sees a key. Every
// document is built to the static-Ed25519 profile and signed here.
import { parseStrict, canonical, plain, digest, fingerprint, verifySig, verifyAttestation } from "../verify.js";
import { normalize, check, generate, derive, orderKey, accountOfKey, keyOfAccount, vaultKeys } from "../onym-id.js";
import { NETWORK, anchorDigest, anchor, anchorState, MAINNET, LINK_KEY, LINK_PROOF, linkMessage, linkTransaction, unsignedEnvelope, mainnetAccount, submitMainnet, linkState } from "../stellar.js";
import { RE as ORE, auditors as orderAuditors, load as loadAuditor, kindsOf, feeText, pin, subjectOf, newOrderID, sign as signOrder, send as sendOrder, contactOf } from "../order-core.js";

const $ = (id) => document.getElementById(id);
const ROOT = new URL("../", import.meta.url); // …/audit/
const HUB = new URL("hub/api/", ROOT);
const T = JSON.parse($("strings")?.textContent || "{}");
const t = (k, v = {}) => (T[k] ?? k).replace(/\{(\w+)\}/g, (_, x) => v[x] ?? "");
// A label for a value from a signed document: its translation, or the value itself.
const tr = (prefix, v) => T[prefix + v] ?? v;
const enc = new TextEncoder();
const b64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b)));
const nowISO = (d = new Date()) => d.toISOString().slice(0, 19) + "Z";
const addDays = (n) => nowISO(new Date(Date.now() + n * 864e5));
const rid = (p) => p + [...crypto.getRandomValues(new Uint8Array(18))].map((x) => "abcdefghijkmnpqrstuvwxyz23456789"[x % 32]).join("");

const el = (tag, props = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null && v !== false) n.setAttribute(k, v === true ? "" : v);
  }
  for (const c of kids.flat()) if (c != null) n.append(c.nodeType ? c : document.createTextNode(String(c)));
  return n;
};

let toastTimer;
function toast(msg, bad = false) {
  const x = $("toast");
  x.textContent = msg;
  x.className = "toast" + (bad ? " bad" : "");
  x.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (x.hidden = true), bad ? 10000 : 4000);
}
const guard = (fn) => async (...a) => { try { await fn(...a); } catch (e) { toast(e.message, true); } };

async function api(path, body) {
  const r = await fetch(new URL(path, HUB), body === undefined ? { credentials: "omit" } : { method: "POST", credentials: "omit", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const text = await r.text();
  let data;
  try { data = JSON.parse(text); } catch { data = {}; }
  // A proxy's error page is never shown; a busy hub is said in the reader's language.
  if (!r.ok) throw Object.assign(new Error(r.status === 429 ? t("e_rate") : data.error || "HTTP " + r.status), { status: r.status });
  return data;
}
// Documents are named by the hub's public URIs (the base the hub assigns) and
// fetched from wherever this page is served, so the studio works the same
// behind any origin.
let PUB = ROOT.href;
const setPub = (base) => (PUB = base.replace(/a\/[a-z0-9-]+\/$/, ""));
const loc = (u) => (u.startsWith(PUB) ? new URL(u.slice(PUB.length), ROOT).href : u);
const getText = async (url) => {
  const r = await fetch(loc(String(url)), { credentials: "omit", cache: "no-cache" });
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  return r.text();
};

// ---------------------------------------------------------------- keys

function idb() {
  return new Promise((res, rej) => {
    const req = indexedDB.open("onym-audit-app", 2);
    req.onupgradeneeded = () => {
      for (const s of ["identity", "orders"]) if (!req.result.objectStoreNames.contains(s)) req.result.createObjectStore(s);
    };
    req.onsuccess = () => res(req.result);
    req.onerror = () => rej(req.error);
  });
}
async function idbDo(mode, fn, store = "identity") {
  const d = await idb();
  return new Promise((res, rej) => {
    const tx = d.transaction(store, mode);
    const r = fn(tx.objectStore(store));
    tx.oncomplete = () => res(r?.result);
    tx.onerror = () => rej(tx.error);
  });
}
const loadIdentity = () => idbDo("readonly", (s) => s.get("me")).catch(() => null);
const saveIdentity = (v) => idbDo("readwrite", (s) => s.put(v, "me"));
const forgetIdentity = () => idbDo("readwrite", (s) => s.delete("me"));
// The orders and requests an identity placed. Per-order keys make them
// unlinkable, so only this list ties them together: it is kept here and,
// encrypted with a key derived from the phrase, in the identity's vault on
// the hub — so the same phrase finds them on any device.
const idOf = (r) => r.orderId || r.requestId;
const mine = () => idbDo("readonly", (s) => s.getAll(), "orders").then((all) => (all || []).filter((o) => o.account === me.account));
const myOrders = () => mine().then((all) => all.filter((o) => o.orderId));
const myRequests = () => mine().then((all) => all.filter((o) => o.requestId));
const keep = (r) => idbDo("readwrite", (s) => s.put(r, idOf(r)), "orders");
// A record is kept here first; the vault catches up now or on the next sync.
const later = (e) => toast(t("vault_unreachable", { err: e.message }), true);
const saveOrder = (o) => keep(o).then(() => syncVault().catch(later));
const saveRequest = (q) => keep(q).then(() => syncVault().catch(later));

let VAULT = null;
const vault = () => (VAULT ||= vaultKeys(me.seedKey));
const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64big = (u) => {
  let s = "";
  for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000));
  return btoa(s);
};

// syncVault merges the vault's list with this browser's, keeps the union
// here, and writes it back when this browser knew something the vault did
// not. An unreachable vault is never overwritten.
async function syncVault() {
  const v = await vault();
  const res = await ask("vault", { action: "get", key: v.key, data: null }, v.priv);
  let remote = [];
  if (res.data) {
    const raw = b64d(res.data);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: raw.slice(0, 12), additionalData: enc.encode(v.key) }, v.aes, raw.slice(12));
    remote = JSON.parse(new TextDecoder().decode(pt));
  }
  const byId = new Map(remote.map((r) => [idOf(r), r]));
  let fresh = false;
  for (const r of await mine()) {
    if (!byId.has(idOf(r))) fresh = true;
    byId.set(idOf(r), r);
  }
  for (const r of remote) await keep(r);
  if (!fresh) return;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(v.key) }, v.aes, enc.encode(JSON.stringify([...byId.values()]))));
  const blob = new Uint8Array(iv.length + ct.length);
  blob.set(iv);
  blob.set(ct, iv.length);
  await ask("vault", { action: "put", key: v.key, data: b64big(blob) }, v.priv);
}



// signDoc returns the published bytes: canonical JSON with the signature
// field in place, signed over the canonical form without it.
async function signDoc(obj, priv, field = "signature") {
  const m = parseStrict(JSON.stringify(obj));
  m.delete(field);
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, priv, enc.encode(canonical(m)));
  m.set(field, b64(sig));
  return canonical(m);
}
const canonText = (obj) => canonical(parseStrict(JSON.stringify(obj)));
const ref = async (uri, text) => ({ uri, digest: await digest(enc.encode(text)) });
async function sharedRef(path) {
  const text = await getText(new URL(path, ROOT));
  return ref(PUB + path, text);
}
const LANG_PATH = { ru: "ru/", "sr-Latn-ME": "cnr/" }[document.documentElement.lang] || "";
const verdictPage = (id, slug) => new URL(`${LANG_PATH}verdict/?${slug ? `a=${encodeURIComponent(slug)}&` : ""}id=${encodeURIComponent(id)}`, ROOT).href;

// ---------------------------------------------------------------- offers

// The disclosure terms of every hub offer: findings reach the subject first;
// a failing result is held — a conformance fail for a week, any other for 90
// days — and then published. The hub enforces the hold.
const DISCLOSURE = {
  "security-review": { findingsToSubjectFirst: true, embargoDays: 90, attestationPublication: "public-on-issuance", failPublication: "public-after-embargo" },
  "conformance-run": { findingsToSubjectFirst: true, embargoDays: 7, attestationPublication: "public-on-issuance", failPublication: "public-after-embargo" },
};
const OFFER_ID = { "security-review": "manual-review", "conformance-run": "conformance-run-discovery" };

// feeFields builds the price inputs; read() returns the fee or throws.
function feeFields(box, prefix) {
  const radio = (v, label) => el("label", { class: "radio" }, el("input", { type: "radio", name: prefix + "-fee", value: v, checked: v === "pro-bono" }), " ", label);
  const amount = el("input", { inputmode: "decimal", placeholder: "150.00", class: "mono", "aria-label": t("fee_amount") });
  const currency = el("input", { value: "EUR", maxlength: 3, class: "mono", "aria-label": t("fee_currency") });
  const days = el("input", { type: "number", min: 1, max: 365, value: 14 });
  const price = el("div", { class: "row-inline", hidden: true }, amount, currency);
  box.replaceChildren(radio("pro-bono", t("fee_probono")), radio("fixed-verdict-independent", t("fee_fixed_l")),
    price,
    el("label", {}, t("fee_days"), days),
    el("p", { class: "hint", text: t("fee_h") }));
  // The price is asked only for a fixed fee.
  box.addEventListener("change", () => (price.hidden = box.querySelector(`input[name="${prefix}-fee"]:checked`).value === "pro-bono"));
  return {
    read() {
      const model = box.querySelector(`input[name="${prefix}-fee"]:checked`).value;
      const n = Number(days.value);
      if (!Number.isInteger(n) || n < 1 || n > 365) throw new Error(t("e_days"));
      if (model === "pro-bono") return { model, amount: null, currency: null, days: n };
      const a = Math.round(Number(amount.value.replace(",", ".")) * 100);
      const c = currency.value.trim().toUpperCase();
      if (!Number.isFinite(a) || a <= 0 || !/^[A-Z]{3}$/.test(c)) throw new Error(t("e_fee"));
      return { model, amount: a, currency: c, days: n };
    },
  };
}

// buildOffers signs one offer per methodology the manifest names.
async function buildOffers(methodologies, fee, id) {
  const ids = [], docs = {};
  for (const mt of methodologies) {
    const offerId = OFFER_ID[mt.class];
    if (!offerId || ids.includes(offerId)) continue;
    const offer = {
      offerVersion: 1, offerId, auditor: id.componentId, auditorKey: id.key, methodologyClass: mt.class, scope: mt.specification,
      fee: { model: fee.model, amount: fee.amount, currency: fee.currency }, timelineDays: fee.days, disclosure: DISCLOSURE[mt.class], validUntil: addDays(365),
    };
    docs[`offers/${offerId}.json`] = await signDoc(offer, id.priv);
    ids.push(offerId);
  }
  return { ids, docs };
}

// ---------------------------------------------------------------- views

let me = null; // {priv, key, account, seedKey} and, once registered, {slug, componentId, name, base}
const views = ["login", "newphrase", "onboard", "dash", "audit", "customer", "library"];
let wantTab = "auditor";
function show(v) {
  if (["onboard", "dash", "audit", "customer"].includes(v) && !me) v = "login";
  for (const x of views) $("v-" + x).hidden = x !== v;
  // One sign-in serves both dashboards; it speaks to the one asked for.
  $("v-login").dataset.for = wantTab;
  const tab = v === "library" || v === "customer" ? v : v === "login" || v === "newphrase" ? wantTab : "auditor";
  for (const b of document.querySelectorAll("[data-tab]")) {
    b.classList.toggle("on", b.dataset.tab === tab);
    if (b.dataset.tab === tab) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current");
  }
  window.scrollTo(0, 0);
  if (v === "dash") dash();
  if (v === "audit") startAudit();
  if (v === "login") listAuditors();
  if (v === "library") library().catch((e) => $("lib-list").replaceChildren(el("p", { class: "bad", text: e.message })));
  if (v === "customer") customer();
  if (v === "onboard") {
    $("ob-account").textContent = me.account;
    requestsFor().then((rs) => {
      $("ob-invited").hidden = !rs.length;
      $("ob-invited").textContent = t("invited", { n: rs.length });
    }, () => {});
  }
  whoChip();
}
const home = () => show(!me ? "login" : wantTab === "customer" ? "customer" : me.slug ? "dash" : "onboard");
for (const b of document.querySelectorAll("[data-tab]")) b.addEventListener("click", () => {
  // The tab is kept in the address, so a link or a reload opens the same one.
  history.replaceState(null, "", "#" + b.dataset.tab);
  if (b.dataset.tab === "library") return show("library");
  wantTab = b.dataset.tab;
  home();
});
async function whoChip() {
  $("who").hidden = !me;
  if (me) $("who").textContent = (me.name ? me.name + " · " : "") + me.account.slice(0, 4) + "…" + me.account.slice(-4);
  // The chip signs out: say so to screen readers, not only in the tooltip.
  if (me) $("who").setAttribute("aria-label", `${$("who").title} — ${$("who").textContent}`);
}
document.addEventListener("click", (e) => {
  const g = e.target.closest("[data-go]");
  if (g) show(g.dataset.go);
});

async function listAuditors() {
  const list = $("auditor-list");
  try {
    const all = await api("auditors");
    list.replaceChildren(...(all.length ? all.map((a) => el("li", {}, el("a", { href: a.page, text: a.name }), el("span", {}, `${a.fingerprint} · ${t("n_atts", { n: a.attestations })}`, a.offers ? el("a", { class: "order-link", href: new URL(`${LANG_PATH}order/?auditor=${a.slug}`, ROOT).href, text: t("order_link") }) : null))) : [el("li", { class: "muted", text: t("no_auditors") })]));
  } catch { list.replaceChildren(); }
}

// ---------------------------------------------------------------- sign in

// signIn keeps what the phrase derives and finds the auditor registered
// under its key, if any.
async function signIn(id) {
  VAULT = null;
  me = { priv: id.priv, key: id.key, account: id.account, seedKey: id.seedKey };
  const mine = (await api("auditors")).find((a) => a.operator === me.key);
  if (mine) Object.assign(me, { slug: mine.slug, componentId: "onym:component:" + mine.slug, name: mine.name, base: mine.page });
  if (me.base) setPub(me.base);
  await saveIdentity(me);
  home();
}

let pending = null; // a new identity, until its holder has written the phrase down
$("login-new").addEventListener("click", guard(async () => {
  const phrase = await generate();
  pending = await derive(phrase);
  $("np-words").replaceChildren(...phrase.split(" ").map((w) => el("li", { text: w })));
  $("np-account").textContent = pending.account;
  $("np-saved").checked = false;
  $("np-continue").disabled = true;
  show("newphrase");
}));
$("np-saved").addEventListener("change", () => ($("np-continue").disabled = !$("np-saved").checked));
$("np-continue").addEventListener("click", guard(async () => {
  $("np-words").replaceChildren(); // the phrase leaves the page
  const id = pending;
  pending = null;
  await signIn(id);
}));
$("login-have").addEventListener("click", () => {
  $("login-form").hidden = false;
  $("login-phrase").focus();
});
$("login-form").addEventListener("submit", guard(async (ev) => {
  ev.preventDefault();
  const err = $("login-error");
  err.hidden = true;
  const phrase = normalize($("login-phrase").value);
  const why = await check(phrase);
  if (why) {
    err.textContent = why === "checksum" ? t("e_phrase_checksum") : why === "length" ? t("e_phrase_length") : t("e_phrase_word", { w: why.slice(5) });
    err.hidden = false;
    return;
  }
  $("login-phrase").value = "";
  $("login-go").disabled = true;
  try {
    await signIn(await derive(phrase));
  } finally {
    $("login-go").disabled = false;
  }
}));

// ---------------------------------------------------------------- onboarding

const templates = (name, slug) => ({
  independence: t("tpl_independence", { name, slug }),
  unsolicited: t("tpl_unsolicited", { name, slug }),
  liability: t("tpl_liability", { name, slug }),
  privacy: t("tpl_privacy", { name, slug }),
});

function fillTemplates(force) {
  const name = $("ob-name").value.trim() || "…", slug = $("ob-slug").value.trim() || "…";
  const tp = templates(name, slug);
  for (const k of Object.keys(tp)) {
    const ta = $("ob-p-" + k);
    if (force || !ta.dataset.edited) ta.value = tp[k];
  }
}
for (const k of ["independence", "unsolicited", "liability", "privacy"]) $("ob-p-" + k).addEventListener("input", (e) => (e.target.dataset.edited = "1"));
const obFee = feeFields($("ob-fee"), "ob");
$("ob-orders").addEventListener("change", () => ($("ob-fee").hidden = !$("ob-orders").checked));
$("ob-name").addEventListener("input", () => {
  if (!$("ob-slug").dataset.edited) $("ob-slug").value = $("ob-name").value.toLowerCase().normalize("NFKD").replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").replace(/^[^a-z]+/, "").slice(0, 32);
  $("ob-url").textContent = `foldy.io/audit/a/${$("ob-slug").value || "…"}/`;
  fillTemplates(false);
});
$("ob-slug").addEventListener("input", () => {
  $("ob-slug").dataset.edited = "1";
  $("ob-url").textContent = `foldy.io/audit/a/${$("ob-slug").value || "…"}/`;
  fillTemplates(false);
});

$("ob-form").addEventListener("submit", guard(async (ev) => {
  ev.preventDefault();
  const err = $("ob-error");
  err.hidden = true;
  const name = $("ob-name").value.trim(), slug = $("ob-slug").value.trim(), contact = $("ob-email").value.trim();
  const bad = (m) => { err.textContent = m; err.hidden = false; err.scrollIntoView({ block: "center" }); };
  if (!name) return bad(t("e_name"));
  if (!/^[a-z][a-z0-9-]{2,31}$/.test(slug)) return bad(t("e_slug"));
  if (!$("ob-m-manual").checked && !$("ob-m-conf").checked) return bad(t("e_methods"));
  if (!$("ob-terms").checked) return bad(t("e_terms"));
  let fee = null;
  try { fee = $("ob-orders").checked ? obFee.read() : null; } catch (e) { return bad(e.message); }
  if (!(await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign"]).then(() => true, () => false))) return bad(t("e_crypto"));
  const btn = $("ob-submit");
  btn.disabled = true;
  btn.textContent = t("working");
  try {
    let claim;
    try { claim = await api("claim", { slug }); } catch (e) {
      if (e.status === 409) return bad(t("e_slug_taken"));
      throw e;
    }
    const { priv, key } = me;
    const base = claim.base;
    setPub(base);
    const docs = {
      "policies/independence.md": $("ob-p-independence").value,
      "policies/unsolicited.md": $("ob-p-unsolicited").value,
      "policies/liability.md": $("ob-p-liability").value,
      "policies/privacy.md": $("ob-p-privacy").value,
    };
    const own = (p) => ref(base + p, docs[p]);
    const methodologies = [];
    if ($("ob-m-manual").checked) methodologies.push({ class: "security-review", specification: await sharedRef("hub/methodology/manual-review-v1.md"), scopesOffered: ["source", "deployment", "build"] });
    if ($("ob-m-conf").checked) methodologies.push({ class: "conformance-run", specification: await sharedRef("hub/methodology/conformance-run-v1.md"), scopesOffered: ["discovery.static-ed25519.provider"] });
    const manifest = {
      version: 1, componentId: claim.componentId, seat: "audit", operator: key, displayName: name, contact: contact ? contactOf(contact) : base,
      auditProfileId: "onym:audit-profile:static-ed25519-v1", auditProfile: await sharedRef("profile.json"), methodologies,
      independencePolicy: await own("policies/independence.md"), unsolicitedPolicy: await own("policies/unsolicited.md"),
      liability: await own("policies/liability.md"), severityScale: await sharedRef("severity-v1.json"), privacyProfile: await own("policies/privacy.md"),
      statusEndpoint: base + "status.json", statusKey: claim.statusKey, offers: [], validUntil: addDays(365),
    };
    if (fee) {
      const offers = await buildOffers(methodologies, fee, { componentId: claim.componentId, key, priv });
      manifest.offers = offers.ids;
      Object.assign(docs, offers.docs);
    }
    const signed = await signDoc(manifest, priv);
    await api("register", { slug, manifest: JSON.parse(signed), docs });
    Object.assign(me, { slug, componentId: claim.componentId, name, base });
    await saveIdentity(me);
    toast(t("registered"));
    show("dash");
  } finally {
    btn.disabled = false;
    btn.textContent = t("ob_submit");
  }
}));

// ---------------------------------------------------------------- dashboard

async function dash() {
  $("d-name").textContent = me.name;
  $("d-account").textContent = me.account;
  $("d-page").href = me.base;
  $("d-page").textContent = me.base.replace(/^https:\/\//, "");
  $("d-key").textContent = `${await fingerprint(me.key)} (${me.key})`;
  loadOrders().catch((e) => $("d-orders").replaceChildren(el("p", { class: "bad", text: e.message })));
  loadRequests().catch((e) => $("d-requests").replaceChildren(el("p", { class: "bad", text: e.message })));
  const box = $("d-atts");
  box.replaceChildren(el("p", { class: "muted", text: t("loading") }));
  try {
    const manifestText = await getText(me.base + "manifest.json");
    const statusText = await getText(me.base + "status.json");
    const st = plain(parseStrict(statusText));
    if (!(await verifySig(statusText, plain(parseStrict(manifestText)).statusKey))) throw new Error(t("e_status"));
    showAnchor(statusText);
    showMainnet();
    $("pipe-published").textContent = st.entries.filter((e) => e.state === "active").length;
    $("pipe-revoked").textContent = st.entries.filter((e) => e.state !== "active").length;
    if (!st.entries.length) return box.replaceChildren(el("p", { class: "empty", text: t("no_atts") }));
    const rows = [];
    for (const e of st.entries) {
      const a = plain(parseStrict(await getText(e.attestation.uri)));
      const row = el("article", { class: "entry" },
        el("div", { class: "entry-side" }, el("span", { class: `stamp r-${a.result}`, text: a.result.toUpperCase() }), el("span", { class: "state", text: tr("state_", e.state) })),
        el("div", {}, el("h3", {}, el("a", { href: verdictPage(a.attestationId, me.slug), text: a.subject })),
          el("p", { class: "who", text: `${tr("m_", a.methodologyClass)} · ${tr("kind_", a.artifact.kind)} · ${a.issuedAt.slice(0, 10)}` }),
          el("p", { class: "small mono", text: a.artifact.source }),
          el("p", { class: "links" }, el("a", { href: verdictPage(a.attestationId, me.slug), text: t("l_verdict") }), el("a", { href: e.attestation.uri, text: t("l_att") }), a.findingsReport ? el("a", { href: a.findingsReport.uri, text: t("l_report") }) : null)));
      if (e.state === "active") {
        const reason = el("select", {}, ["withdrawal", "new-information", "methodology-error", "compromise-of-auditor-key"].map((r) => el("option", { value: r, text: tr("rv_", r) })));
        row.lastChild.append(el("div", { class: "row-inline" }, reason, el("button", { class: "btn btn-line small-btn", text: t("revoke"), onclick: guard(() => revoke(a.attestationId, reason.value)) })));
      }
      rows.push(row);
    }
    box.replaceChildren(...rows);
  } catch (e) {
    box.replaceChildren(el("p", { class: "bad", text: e.message }));
  }
}

// inboxCall sends a request signed by the auditor's key: only it opens the
// order inbox, where the orderers' contacts wait.
async function inboxCall(action, orderId = null) {
  const req = { action, auditor: me.componentId, orderId, issuedAt: nowISO() };
  return api(`a/${me.slug}/inbox`, { request: JSON.parse(await signDoc(req, me.priv)) });
}

async function loadOrders() {
  const box = $("d-orders");
  box.replaceChildren(el("p", { class: "muted", text: t("loading") }));
  const m = plain(parseStrict(await getText(me.base + "manifest.json")));
  $("d-offers-off").hidden = !m.offers.length;
  if (!m.offers.length) {
    $("pipe-orders").textContent = $("pipe-held").textContent = "–";
    $("d-offers").open = true;
    return box.replaceChildren(el("p", { class: "empty", text: t("orders_off") }));
  }
  const res = await inboxCall("list");
  $("pipe-orders").textContent = res.orders.length;
  $("pipe-held").textContent = res.held.length;
  const rows = res.held.map((h) => el("p", { class: "note", text: t("held_row", { id: h.attestationId, date: h.releaseAt.slice(0, 10) }) }));
  for (const q of res.orders) {
    const o = q.order;
    const decline = guard(async () => {
      if (!confirm(t("confirm_decline", { id: o.orderId }))) return;
      await inboxCall("decline", o.orderId);
      toast(t("declined"));
      loadOrders();
    });
    rows.push(el("article", { class: "entry" },
      el("div", { class: "entry-side" }, el("span", { class: "stamp", text: t("order_stamp") }), el("span", { class: "state", text: t("due", { date: o.timeline.reportDue }) })),
      el("div", {}, el("h3", { text: o.subject }),
        el("p", { class: "who", text: `${t("m_" + o.methodologyClass)} · ${tr("kind_", o.artifact.kind)} · ${feeText(o, t)} · ${o.fee.offerId}` }),
        el("p", { class: "small mono", text: `${o.artifact.source} @ ${o.artifact.revision}` }),
        el("pre", { class: "quote", text: q.scopeText }),
        termsBox(o),
        el("p", { class: "small" }, q.contact ? el("a", { href: /^mailto:/.test(q.contact) ? q.contact : null, text: q.contact.replace(/^mailto:/, "") }) : t("no_contact"), ` · ${t("sponsor_fp", { fp: await fingerprint(o.sponsor) })} · ${o.orderId} · ${t("received", { date: q.receivedAt.slice(0, 10) })}`),
        el("p", { class: "row-inline" }, el("button", { class: "btn btn-ink small-btn", text: t("take"), onclick: () => takeOrder(q) }), el("button", { class: "btn btn-line small-btn", text: t("decline"), onclick: decline })))));
  }
  box.replaceChildren(...(rows.length ? rows : [el("p", { class: "empty", text: t("no_orders") })]));
}

const dFee = feeFields($("d-fee"), "d");
// setOffers re-signs the manifest with a new set of offers (none: no orders).
async function setOffers(fee) {
  const m = plain(parseStrict(await getText(me.base + "manifest.json")));
  const { ids, docs } = fee ? await buildOffers(m.methodologies, fee, me) : { ids: [], docs: {} };
  delete m.signature;
  m.offers = ids;
  await api("register", { slug: me.slug, manifest: JSON.parse(await signDoc(m, me.priv)), docs });
}
$("d-offers-save").addEventListener("click", guard(async () => {
  await setOffers(dFee.read());
  toast(t("offers_saved"));
  $("d-offers").open = false;
  loadOrders();
}));
$("d-offers-off").addEventListener("click", guard(async () => {
  if (!confirm(t("confirm_offers_off"))) return;
  await setOffers(null);
  toast(t("offers_stopped"));
  loadOrders();
}));

// ---------------------------------------------------------------- Stellar anchor

// showAnchor compares this auditor's register with its anchor on Stellar.
async function showAnchor(statusText) {
  $("d-anchor-link").href = NETWORK.explorer + me.account;
  try {
    const a = await anchorState(me.account, statusText);
    $("d-anchor").textContent = t("anchor_" + a.state, { at: (a.at || "").replace("T", " ").replace("Z", " UTC") });
    $("d-anchor").className = a.state === "match" ? "ok-line" : "muted";
  } catch (e) {
    $("d-anchor").textContent = t("anchor_fail", { err: e.message });
  }
}

// anchorNow writes the register's current digest to the auditor's Stellar
// account. Called after every issue and revocation; a failure never undoes
// the publication — the register can be anchored again at any time.
async function anchorNow() {
  $("d-anchor").textContent = t("anchor_working");
  try {
    const statusText = await getText(me.base + "status.json");
    const tx = await anchor(me, await anchorDigest(statusText));
    toast(t("anchor_done", { tx: tx.slice(0, 12) + "…" }));
    await showAnchor(statusText);
  } catch (e) {
    toast(t("anchor_fail", { err: e.message }), true);
    $("d-anchor").textContent = t("anchor_fail", { err: e.message });
  }
}
$("d-anchor-go").addEventListener("click", guard(anchorNow));

// ---- The auditor's account on the Stellar public network

// The Freighter wallet's page API, served from this site; loaded only here.
let freighterLoad;
const freighter = () => (window.freighterApi ? Promise.resolve(window.freighterApi) : (freighterLoad ??= new Promise((ok, bad) => {
  const s = document.createElement("script");
  s.src = new URL("vendor/freighter-api-6.0.1.min.js", ROOT).href;
  s.onload = () => ok(window.freighterApi);
  s.onerror = () => { freighterLoad = null; bad(new Error(t("mn_fr_load"))); };
  document.head.append(s);
})));
const shortG = (g) => g.slice(0, 4) + "…" + g.slice(-4);

// showMainnet reads the published link and checks it on the network.
async function showMainnet() {
  const line = $("d-mainnet"), view = $("d-mainnet-link");
  view.hidden = true;
  $("d-mainnet-off").hidden = true;
  let text;
  try { text = await getText(me.base + "stellar-link.json"); } catch {
    line.textContent = t("mn_unlinked");
    line.className = "muted";
    $("d-mainnet-go").textContent = t("mn_go");
    return;
  }
  const q = plain(parseStrict(text));
  view.href = MAINNET.explorer + q.account;
  view.hidden = false;
  $("d-mainnet-off").hidden = false;
  $("d-mainnet-go").textContent = t("mn_again");
  const s = await linkState(q.account, me.key).catch(() => ({ state: "unknown" }));
  line.textContent = t("mn_" + s.state, { g: shortG(q.account) });
  line.className = s.state === "linked" ? "ok-line" : "bad";
}

// linkMainnet writes the two entries on the account chosen in Freighter,
// signed there, then asks the hub to publish the link it checks.
async function linkMainnet() {
  const fr = await freighter();
  if (!(await fr.isConnected()).isConnected) throw new Error(t("mn_fr_missing"));
  const acc = await fr.requestAccess();
  if (acc.error || !acc.address) throw new Error(t("mn_fr_denied"));
  const g = acc.address;
  $("d-mainnet").textContent = t("mn_working", { g: shortG(g) });
  const acct = await mainnetAccount(g);
  if (!acct) throw new Error(t("mn_no_account", { g: shortG(g) }));
  const proof = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, me.priv, linkMessage(g)));
  const auditorKey = Uint8Array.from(me.key.slice(9).match(/../g), (x) => parseInt(x, 16));
  const pub = Uint8Array.from(keyOfAccount(g).slice(9).match(/../g), (x) => parseInt(x, 16));
  const tx = linkTransaction(pub, BigInt(acct.sequence) + 1n, Math.floor(Date.now() / 1000) + 600, [[LINK_KEY, auditorKey], [LINK_PROOF, proof]]);
  const signed = await fr.signTransaction(unsignedEnvelope(tx), { networkPassphrase: MAINNET.passphrase, address: g });
  if (signed.error || !signed.signedTxXdr) throw new Error(t("mn_fr_declined", { err: signed.error?.message || "" }));
  await submitMainnet(signed.signedTxXdr);
  await ask(`a/${me.slug}/stellar-link`, { action: "stellar-link", auditor: me.componentId, account: g }, me.priv);
  toast(t("mn_done", { g: shortG(g) }));
  await showMainnet();
}
$("d-mainnet-go").addEventListener("click", guard(async () => {
  $("d-mainnet-go").disabled = true;
  try { await linkMainnet(); } catch (e) { await showMainnet(); throw e; } finally { $("d-mainnet-go").disabled = false; }
}));
$("d-mainnet-off").addEventListener("click", guard(async () => {
  if (!confirm(t("mn_confirm_off"))) return;
  await ask(`a/${me.slug}/stellar-link`, { action: "stellar-unlink", auditor: me.componentId, account: "" }, me.priv);
  await showMainnet();
}));

async function revoke(id, reason) {
  if (!confirm(t("confirm_revoke", { id }))) return;
  const now = nowISO();
  const rv = { revocationVersion: 1, attestationId: id, auditor: me.componentId, auditorKey: me.key, issuedAt: now, statusEpoch: Math.floor(Date.now() / 1000), effectiveFrom: now, reason, detail: null };
  await api(`a/${me.slug}/revoke`, { revocation: JSON.parse(await signDoc(rv, me.priv)) });
  toast(t("revoked"));
  await anchorNow();
  dash();
}

$("d-export").addEventListener("click", guard(async () => {
  const ex = await api(`a/${me.slug}/export`);
  const files = {};
  for (const f of ex.files) files[f] = await getText(ex.base + f);
  const blob = new Blob([JSON.stringify({ onymAuditorTree: 1, base: ex.base, files }, null, 1)], { type: "application/json" });
  const a = el("a", { href: URL.createObjectURL(blob), download: `onym-auditor-${me.slug}-tree.json` });
  document.body.append(a);
  a.click();
  a.remove();
}));
const signOut = guard(async () => {
  if (!confirm(t("confirm_logout"))) return;
  // The list of this identity's orders and requests is the only thing that
  // ties its per-order keys together: it leaves this browser too, once the
  // vault has it (the next sign-in restores it from there).
  const synced = await syncVault().then(() => true, () => false);
  if (synced || confirm(t("confirm_logout_unsynced"))) {
    for (const r of await mine()) await idbDo("readwrite", (s) => s.delete(idOf(r)), "orders");
  }
  await forgetIdentity();
  me = null;
  VAULT = null;
  show("login");
});
$("d-forget").addEventListener("click", signOut);
$("who").addEventListener("click", signOut);

// ---------------------------------------------------------------- audit

let A = null;

// Everything learned from one target; cleared whenever the target changes, so
// no finding, key, or digest from one target can reach another's attestation.
function resetTarget() {
  Object.assign(A, { artifact: null, method: null, evidence: [], findings: [], report: null, subject: "", subjectKey: "", scope: "" });
  $("a-subject").value = "";
  $("a-subject-key").value = "";
  $("a-inspect").replaceChildren();
  $("a-findings").replaceChildren();
  $("a-finding-form").hidden = true;
  for (const s of ["a-step3", "a-step4"]) $(s).hidden = true;
}

function startAudit() {
  A = { kind: null, order: null };
  resetTarget();
  $("a-order-banner").hidden = true;
  $("a-unsol").hidden = false;
  $("a-comm").hidden = true;
  $("a-sent").checked = false;
  $("a-subject").readOnly = $("a-subject-key").readOnly = false;
  for (const b of document.querySelectorAll("#a-step1 .choice")) b.disabled = false;
  for (const s of ["a-step2", "a-step3", "a-step4"]) $(s).hidden = true;
  $("a-step1").hidden = false;
  $("a-done").hidden = true;
  $("a-publish").disabled = false;
  $("a-notified").value = nowISO();
  for (const id of ["a-cov-sum", "a-cov-ex", "a-cov-nx", "a-contact"]) $(id).value = "";
  $("a-cov-complete").checked = false;
  $("a-rel").value = "none";
  for (const b of document.querySelectorAll("#a-step1 .choice")) b.classList.remove("on");
}

// takeOrder starts an examination bound to a queued order: the target and
// the scope are the order's, and signing countersigns it.
// termsOf lists every term the auditor's countersignature covers, as signed.
const termsOf = (o) => [
  `cooperation: ${o.cooperation}`,
  `disclosure: findingsToSubjectFirst ${o.disclosure.findingsToSubjectFirst}; embargoDays ${o.disclosure.embargoDays}; attestation ${o.disclosure.attestationPublication}; fail ${o.disclosure.failPublication}`,
  `fee: ${o.fee.model} (${o.fee.offerId})`,
  `timeline: ${Object.entries(o.timeline).map(([k, v]) => `${k} ${v}`).join(", ")}`,
].join("\n");
const termsBox = (o) => el("details", {}, el("summary", { text: t("terms_signed") }), el("pre", { class: "quote", text: termsOf(o) }));

function takeOrder(q) {
  show("audit");
  A.order = q;
  const o = q.order;
  const kind = o.methodologyClass === "conformance-run" ? "discovery" : o.artifact.kind;
  const banner = $("a-order-banner");
  banner.replaceChildren(el("p", {}, el("b", { text: t("order_banner", { id: o.orderId }) }), " ", t("order_banner_h")),
    el("p", { class: "mono small", text: [o.artifact.source, o.artifact.revision, o.artifact.artifactHash].filter(Boolean).join(" · ") }),
    termsBox(o));
  banner.hidden = false;
  $("a-unsol").hidden = true;
  $("a-comm").hidden = false;
  if (/^mailto:/.test(q.contact)) $("a-comm-contact").href = q.contact;
  $("a-comm-contact").textContent = q.contact.replace(/^mailto:/, "");
  $("a-sent").closest("label").hidden = !o.disclosure.findingsToSubjectFirst;
  for (const b of document.querySelectorAll("#a-step1 .choice")) b.disabled = b.dataset.kind !== kind;
  document.querySelector(`#a-step1 .choice[data-kind="${kind}"]`).click();
}

for (const b of document.querySelectorAll("#a-step1 .choice")) {
  b.addEventListener("click", () => {
    for (const x of document.querySelectorAll("#a-step1 .choice")) x.classList.toggle("on", x === b);
    A.kind = b.dataset.kind;
    resetTarget();
    targetForm();
  });
}

function field(label, attrs, hint) {
  const input = el(attrs.tag || "input", { ...attrs, tag: undefined });
  return { input, node: el("label", {}, label, input, hint ? el("small", { class: "hint", text: hint }) : null) };
}

function targetForm() {
  const f = $("a-target");
  const scope = field(t("f_scope"), { tag: "textarea", rows: 3, required: true, placeholder: t("f_scope_ph") });
  const parts = { scope };
  if (A.kind === "source") {
    parts.repo = field(t("f_repo"), { placeholder: "https://github.com/org/repo", class: "mono" }, t("f_repo_h"));
    parts.commit = field(t("f_commit"), { placeholder: t("ph_commit"), class: "mono" });
    parts.owner = field(t("f_owner"), { placeholder: "https://…/manifest.json", class: "mono" }, t("f_owner_h"));
  } else if (A.kind === "deployment" || A.kind === "discovery") {
    parts.url = field(A.kind === "discovery" ? t("f_provider") : t("f_manifest"), { placeholder: "https://…/manifest.json", class: "mono" }, A.kind === "discovery" ? t("f_provider_h") : t("f_manifest_h"));
  } else {
    parts.file = field(t("f_file"), { placeholder: "https://github.com/org/repo/releases/download/v1/app.apk", class: "mono" });
    parts.repo = field(t("f_repo"), { placeholder: "https://github.com/org/repo", class: "mono" });
    parts.commit = field(t("f_commit"), { placeholder: t("ph_commit"), class: "mono" });
    parts.owner = field(t("f_owner"), { placeholder: "https://…/manifest.json", class: "mono" }, t("f_owner_h"));
  }
  if (A.order) {
    const o = A.order.order;
    const fix = (p, v) => { p.input.value = v; p.input.readOnly = true; };
    delete parts.owner;
    if (parts.repo) fix(parts.repo, o.artifact.source);
    if (parts.commit) fix(parts.commit, o.artifact.revision);
    if (parts.url) fix(parts.url, o.artifact.source);
    if (parts.file) fix(parts.file, (A.order.scopeText.match(/^Build file: (https:\/\/\S+)$/m) || [])[1] || "");
    fix(scope, A.order.scopeText.trim());
  }
  const go = el("button", { class: "btn btn-ink", type: "submit", text: t("inspect") });
  f.replaceChildren(...Object.values(parts).filter((p) => p !== scope).map((p) => p.node), scope.node, go);
  f.onsubmit = guard(async (ev) => {
    ev.preventDefault();
    go.disabled = true;
    go.textContent = t("working");
    try {
      resetTarget();
      A.scope = scope.input.value.trim();
      if (!A.scope) throw new Error(t("e_scope"));
      await inspect(parts);
      $("a-step3").hidden = false;
      $("a-step4").hidden = false;
      renderFindings();
      updateResult();
    } finally {
      go.disabled = false;
      go.textContent = t("inspect");
    }
  });
  $("a-step2").hidden = false;
  $("a-inspect").replaceChildren();
  $("a-step2").scrollIntoView({ behavior: "smooth" });
}

const httpsOK = (u) => /^https:\/\/[A-Za-z0-9.-]+\.[A-Za-z]{2,}(\/[^\s?#]*)?$/.test(u);

async function inspect(p) {
  const out = $("a-inspect");
  if (A.kind === "source") {
    const repo = p.repo.input.value.trim().replace(/\/+$/, "").replace(/\.git$/, "");
    const commit = p.commit.input.value.trim().toLowerCase();
    const m = repo.match(/^https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/);
    if (!m) throw new Error(t("e_github"));
    if (!/^[0-9a-f]{40}$/.test(commit)) throw new Error(t("e_commit"));
    const tree = await (await fetch(`https://api.github.com/repos/${m[1]}/${m[2]}/git/trees/${commit}?recursive=1`, { credentials: "omit" })).json();
    if (!tree.tree) throw new Error(t("e_tree", { err: tree.message || "?" }));
    A.artifact = { kind: "source", source: repo, revision: commit, artifactHash: null };
    A.method = "manual";
    A.raw = (path) => `https://raw.githubusercontent.com/${m[1]}/${m[2]}/${commit}/${path.split("/").map(encodeURIComponent).join("/")}`;
    A.subject = "onym:component:" + m[2].toLowerCase().replace(/[^a-z0-9-]+/g, "-").slice(0, 64);
    const files = tree.tree.filter((x) => x.type === "blob").map((x) => x.path);
    codeBrowser(out, files);
  } else if (A.kind === "deployment" || A.kind === "discovery") {
    const url = p.url.input.value.trim();
    if (!httpsOK(url)) throw new Error(t("e_https"));
    const doc = await api("fetch", { url });
    let m = null;
    try { m = plain(parseStrict(doc.body)); } catch { /* not JSON */ }
    const checks = [];
    checks.push([doc.status === 200, t("c_served", { status: doc.status })]);
    checks.push([!doc.setsCookie, t("c_cookies")]);
    if (m) {
      const opKey = m.operator;
      checks.push([true, t("c_json")]);
      if (typeof opKey === "string" && typeof m.signature === "string") {
        const ok = await verifySig(doc.body, opKey).catch(() => false);
        checks.push([ok, ok ? t("c_sig_ok", { fp: await fingerprint(opKey) }) : t("c_sig_bad")]);
        A.subjectKey = opKey;
      } else checks.push([false, t("c_unsigned")]);
      if (m.validUntil) checks.push([Date.parse(m.validUntil) > Date.now(), t("c_valid", { until: m.validUntil })]);
      A.subject = m.componentId || m.providerId || m.authorityId || "";
    } else checks.push([false, t("c_not_json")]);
    A.evidence = [{ uri: url, digest: doc.digest }];
    out.replaceChildren(el("ul", { class: "checks" }, checks.map(([ok, text]) => el("li", { class: ok ? "ok" : "bad", text: (ok ? "✓ " : "✗ ") + text }))));
    if (A.kind === "discovery") {
      if (!m || m.seat !== "discovery") throw new Error(t("err_not_discovery", { seat: m ? m.seat : "—" }));
      out.append(el("p", { class: "muted", text: t("running_suite") }));
      const rep = await api("conformance/discovery", { manifestUrl: url });
      A.method = "conformance";
      A.report = rep;
      const man = rep.documents.find((d) => d.role === "provider-manifest");
      const snaps = rep.documents.filter((d) => d.role === "catalog-snapshot");
      A.artifact = { kind: "deployment", source: url, revision: man ? man.digest : doc.digest, artifactHash: snaps.length === 1 ? snaps[0].digest : null };
      const fails = rep.checks.filter((c) => c.outcome !== "pass");
      out.lastChild.replaceWith(el("div", {},
        el("p", {}, t("suite_result"), " ", el("b", { class: `stamp r-${rep.result}`, text: rep.result.toUpperCase() }), " ", t("suite_counts", { n: rep.checks.length, pass: rep.checks.filter((c) => c.outcome === "pass").length })),
        el("ul", { class: "checks" }, fails.map((c) => el("li", { class: c.outcome === "fail" ? "bad" : "", text: `${c.outcome} · ${c.level} · ${c.id} — ${c.detail}` })))));
      A.findings = rep.checks.filter((c) => c.outcome === "fail").map((c) => ({ severity: c.level === "MUST" ? "high" : "low", title: c.title || c.id, check: c.id, clause: c.clause, description: c.detail, auto: true }));
    } else {
      A.method = "manual";
      A.artifact = { kind: "deployment", source: url, revision: doc.digest, artifactHash: null };
      const box = el("div");
      out.append(box);
      codeBrowser(box, null, { path: url.split("/").pop(), lines: (m ? JSON.stringify(m, null, 2) : doc.body).split("\n"), rawBody: doc.body });
    }
  } else {
    const file = p.file.input.value.trim(), repo = p.repo.input.value.trim().replace(/\/+$/, ""), commit = p.commit.input.value.trim().toLowerCase();
    if (!httpsOK(file) || !httpsOK(repo)) throw new Error(t("e_https"));
    if (!/^[0-9a-f]{40}$/.test(commit)) throw new Error(t("e_commit"));
    out.replaceChildren(el("p", { class: "muted", text: t("hashing") }));
    const d = await api("digest", { url: file });
    A.method = "manual";
    A.artifact = { kind: "build", source: repo, revision: commit, artifactHash: d.digest };
    A.evidence = [{ uri: file, digest: d.digest }];
    A.buildFile = file;
    out.replaceChildren(el("p", {}, t("hashed", { size: d.size >= 1048576 ? (d.size / 1048576).toFixed(1) + " MiB" : Math.max(1, Math.round(d.size / 1024)) + " KiB" }), " ", el("code", { text: d.digest })));
    manualFindingForm({ path: file.split("/").pop(), a: 1, b: 1, quote: d.digest });
  }
  // Code and builds carry no operator key; the component's signed manifest
  // names the subject and the only key that can sign a reply.
  const owner = p.owner && p.owner.input.value.trim();
  if (owner) {
    if (!httpsOK(owner)) throw new Error(t("e_https"));
    const doc = await api("fetch", { url: owner });
    const m = plain(parseStrict(doc.body));
    if (typeof m.operator !== "string" || !(await verifySig(doc.body, m.operator).catch(() => false))) throw new Error(t("c_sig_bad"));
    A.subject = m.componentId || A.subject;
    A.subjectKey = m.operator;
  }
  // Under an order, the bytes examined must be the bytes ordered, and the
  // attestation binds exactly the order's artifact, subject and key.
  if (A.order) {
    const o = A.order.order;
    const same = A.kind === "build" ? A.artifact.artifactHash === o.artifact.artifactHash : A.kind === "source" || A.artifact.revision === o.artifact.revision;
    if (!same) throw new Error(t("e_order_changed"));
    A.artifact = JSON.parse(JSON.stringify(o.artifact));
    A.subject = o.subject;
    A.subjectKey = o.signatures.find((x) => x.role === "subject").key;
  }
  $("a-subject").value = A.subject;
  $("a-subject-key").value = A.subjectKey;
  $("a-subject").readOnly = $("a-subject-key").readOnly = !!A.order;
}

// codeBrowser shows files (a GitHub tree) or one served document; clicking
// and shift-clicking lines selects the evidence for a finding.
function codeBrowser(out, files, single) {
  const view = el("div", { class: "src-view studio-src" });
  const list = files ? el("ul", { class: "tree" }) : null;
  const filter = files ? el("input", { placeholder: t("filter"), class: "filter" }) : null;
  let cur = single || null, sel = null;
  const draw = () => {
    if (!cur) return view.replaceChildren(el("p", { class: "muted pad", text: t("pick_file") }));
    view.replaceChildren(...cur.lines.map((line, i) => el("div", { class: "ln" + (sel && i + 1 >= sel[0] && i + 1 <= sel[1] ? " sel" : ""), onclick: (e) => {
      const n = i + 1;
      sel = e.shiftKey && sel ? [Math.min(sel[0], n), Math.max(sel[1], n)] : [n, n];
      draw();
      if (sel[1] - sel[0] < 60) manualFindingForm({ path: cur.path, a: sel[0], b: sel[1], quote: cur.lines.slice(sel[0] - 1, sel[1]).join("\n") });
    } }, el("span", { class: "num", text: i + 1 }), el("span", { class: "src", text: line || " " }))));
  };
  if (files) {
    const fill = () => list.replaceChildren(...files.filter((f) => f.toLowerCase().includes(filter.value.toLowerCase())).slice(0, 600).map((f) =>
      el("li", { class: cur && cur.path === f ? "on" : "", text: f, onclick: guard(async () => {
        const text = await getText(A.raw(f));
        cur = { path: f, lines: text.replace(/\r\n/g, "\n").split("\n") };
        sel = null;
        fill();
        draw();
      }) })));
    filter.addEventListener("input", fill);
    fill();
  }
  draw();
  out.replaceChildren(el("p", { class: "hint", text: t("select_hint") }), el("div", { class: files ? "studio-code" : "" }, files ? el("div", { class: "tree-col" }, filter, list) : null, view));
}

function manualFindingForm(ev) {
  const f = $("a-finding-form");
  const sev = el("select", {}, ["critical", "high", "medium", "low", "informational"].map((s) => el("option", { value: s, text: tr("sev_", s) })));
  sev.value = "medium";
  const title = el("input", { placeholder: t("ff_title") });
  const desc = el("textarea", { rows: 3, placeholder: t("ff_desc") });
  const rec = el("textarea", { rows: 2, placeholder: t("ff_rec") });
  f.replaceChildren(
    el("p", { class: "small muted", text: t("ff_at", { where: `${ev.path}:${ev.a}-${ev.b}` }) }),
    el("pre", { class: "quote", text: ev.quote }),
    el("label", {}, t("ff_sev"), sev), el("label", {}, t("ff_title_l"), title), el("label", {}, t("ff_desc_l"), desc), el("label", {}, t("ff_rec_l"), rec),
    el("button", { class: "btn btn-ink", type: "submit", text: t("ff_add") }));
  f.onsubmit = (e) => {
    e.preventDefault();
    if (!title.value.trim() || !desc.value.trim()) return toast(t("e_finding"), true);
    A.findings.push({ severity: sev.value, title: title.value.trim(), path: ev.path, lineStart: ev.a, lineEnd: ev.b, quote: ev.quote, description: desc.value.trim(), recommendation: rec.value.trim() });
    f.hidden = true;
    renderFindings();
    updateResult();
    toast(t("finding_added"));
  };
  f.hidden = false;
  if (A.kind !== "build") f.scrollIntoView({ block: "nearest", behavior: "smooth" });
}

function renderFindings() {
  const box = $("a-findings");
  if (!A.findings.length) return box.replaceChildren(el("p", { class: "empty", text: A.method === "conformance" ? t("no_fail_checks") : t("no_findings") }));
  box.replaceChildren(...A.findings.map((f, i) => el("article", { class: "entry" },
    el("div", { class: "entry-side" }, el("span", { class: `stamp sev-${f.severity}`, text: tr("sev_", f.severity).toUpperCase() })),
    el("div", {}, el("h3", { text: f.title }),
      f.quote ? el("pre", { class: "quote", text: f.quote }) : null,
      el("p", { text: f.description }),
      f.auto ? el("p", { class: "small muted", text: t("from_suite", { clause: f.clause || "" }) }) : el("button", { class: "link-btn", text: t("remove"), onclick: () => { A.findings.splice(i, 1); renderFindings(); updateResult(); } })))));
}

function resultClass() {
  const sev = (s) => A.findings.filter((f) => f.severity === s).length;
  const complete = $("a-cov-complete").checked;
  if (A.method === "conformance") {
    let r = A.report?.result || "inconclusive";
    if (r === "clear" && A.findings.some((f) => !f.auto && f.severity !== "informational")) r = "findings-noted";
    return r;
  }
  if (sev("critical")) return "fail";
  if (sev("high") + sev("medium") + sev("low")) return "findings-noted";
  return complete ? "clear" : "inconclusive";
}
function updateResult() {
  const r = resultClass();
  $("a-result").textContent = r.toUpperCase();
  $("a-result").className = "stamp r-" + r;
}
$("a-cov-complete").addEventListener("change", updateResult);

function coverageOf() {
  const lines = (id) => $(id).value.split("\n").map((s) => s.trim()).filter(Boolean);
  return { summary: $("a-cov-sum").value.trim(), examined: lines("a-cov-ex"), notExamined: lines("a-cov-nx"), complete: $("a-cov-complete").checked, declared: true };
}

// reportOf builds the findings report: what is sent to the subject first
// and published by digest.
function reportOf(coverage) {
  if (A.method === "conformance") return canonText({ findingsVersion: 1, suiteReport: A.report, observations: [] });
  return canonText({ findingsVersion: 1, methodology: "hub-manual-review-v1", examiner: me.name, artifact: A.artifact, scope: A.scope, coverage, evidence: A.evidence,
    findings: A.findings.map((f, i) => ({ id: "F" + (i + 1), severity: f.severity, title: f.title, path: f.path, lineStart: f.lineStart, lineEnd: f.lineEnd, quote: f.quote, description: f.description, recommendation: f.recommendation || "" })) });
}

$("a-report-dl").addEventListener("click", () => {
  const a = el("a", { href: URL.createObjectURL(new Blob([reportOf(coverageOf())], { type: "application/json" })), download: `findings-${A.order.order.orderId}.json` });
  document.body.append(a);
  a.click();
  a.remove();
});

$("a-publish").addEventListener("click", guard(async () => {
  const err = $("a-error");
  err.hidden = true;
  const bad = (m) => { err.textContent = m; err.hidden = false; };
  const subject = $("a-subject").value.trim(), subjectKey = $("a-subject-key").value.trim();
  const contact = $("a-contact").value.trim(), notified = $("a-notified").value.trim(), rel = $("a-rel").value.trim();
  const q = A.order;
  if (!/^onym:component:[a-z0-9-]{1,64}$/.test(subject)) return bad(t("e_subject"));
  if (!/^onym:key:[0-9a-f]{64}$/.test(subjectKey)) return bad(t("e_subject_key"));
  if (q) {
    if (q.order.disclosure.findingsToSubjectFirst && !$("a-sent").checked) return bad(t("e_sent"));
  } else {
    if (!contact) return bad(t("e_contact"));
    if (!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(notified) || Date.parse(notified) > Date.now()) return bad(t("e_notified"));
  }
  if (!rel) return bad(t("e_rel"));
  const summary = $("a-cov-sum").value.trim();
  if (!summary) return bad(t("e_coverage"));
  if (!confirm(t("confirm_publish", { result: resultClass().toUpperCase() }))) return;

  const coverage = coverageOf();
  const manifest = plain(parseStrict(await getText(me.base + "manifest.json")));
  const id = rid("att-");
  const docs = {};
  let scopeRef;
  if (q) {
    docs[q.order.scope.uri.slice(me.base.length)] = q.scopeText;
    scopeRef = q.order.scope;
  } else {
    const scopeText = `# Scope: ${A.artifact.source}\n\n${A.artifact.kind === "deployment" ? "Manifest digest" : "Revision"}: ${A.artifact.revision}\n\n${A.scope}\n`;
    docs[`scopes/${id}.md`] = scopeText;
    scopeRef = await ref(me.base + `scopes/${id}.md`, scopeText);
  }
  const reportText = reportOf(coverage);
  const reportPath = `reports/${(await digest(enc.encode(reportText))).slice(7)}.json`;
  docs[reportPath] = reportText;
  const summaryCounts = {};
  for (const f of A.findings) summaryCounts[f.severity] = (summaryCounts[f.severity] || 0) + 1;
  const isConf = A.method === "conformance";
  // Countersigning: the auditor's signature joins the subject's and the
  // sponsor's over the same bytes.
  let orderRef = null, held = false;
  if (q) {
    const full = parseStrict(canonText(q.order));
    const unsigned = parseStrict(canonText(q.order));
    unsigned.delete("signatures");
    const s = b64(await crypto.subtle.sign({ name: "Ed25519" }, me.priv, enc.encode(canonical(unsigned))));
    full.get("signatures").push(parseStrict(JSON.stringify({ role: "auditor", key: me.key, signature: s })));
    const orderText = canonical(full);
    docs[`orders/${q.order.orderId}.json`] = orderText;
    orderRef = await digest(enc.encode(orderText));
    const dsc = q.order.disclosure;
    held = resultClass() === "fail" && dsc.failPublication === "public-after-embargo" && dsc.embargoDays > 0;
  }
  const exclusions = isConf
    ? ["client behaviour", "availability, honesty, or security of the listed instances beyond their signed manifests' digests, fields, and signatures", "host security and key custody", "any state of the deployment other than the one served at run time"]
    : ["anything outside the stated scope", "runtime behaviour beyond the examined bytes", "defects the examination did not find"];
  const att = {
    attestationVersion: 1, attestationId: id, auditor: me.componentId, auditorKey: me.key,
    subject, subjectOperator: subjectKey, artifact: A.artifact,
    methodologyClass: isConf ? "conformance-run" : "security-review",
    methodology: await sharedRef(isConf ? "hub/methodology/conformance-run-v1.md" : "hub/methodology/manual-review-v1.md"),
    scope: scopeRef,
    scopeSummary: (q ? "Commissioned " : "") + (isConf ? (q ? "conformance run: " : "Discovery provider conformance run: ") : q ? "examination: " : "Manual examination: ") + A.scope.split("\n")[0].slice(0, 160).replace(/[.\s]+$/, ""),
    exclusions: [...exclusions, ...coverage.notExamined],
    result: resultClass(), severityScale: await sharedRef("severity-v1.json"), severityFloor: "low",
    findingsReport: await ref(me.base + reportPath, reportText), findingsSummary: summaryCounts,
    engagement: q ? "commissioned" : "unsolicited",
    sponsor: q ? q.order.sponsor : me.key, sponsorName: q ? `the sponsor of order ${q.order.orderId}` : me.name + " (self-funded)", relationships: rel, orderRef,
    unsolicited: q ? null : { policy: manifest.unsolicitedPolicy.digest, subjectContact: contact, subjectNotifiedAt: notified, embargoUntil: null },
    // A held attestation's validity starts counting when it is published.
    issuedAt: nowISO(), expiresAt: addDays((isConf ? 30 : 180) + (held ? q.order.disclosure.embargoDays : 0)), supersedes: null, status: manifest.statusEndpoint,
  };
  const signed = await signDoc(att, me.priv);
  $("a-publish").disabled = true;
  let res;
  try { res = await api(`a/${me.slug}/publish`, { attestation: JSON.parse(signed), docs }); } catch (e) {
    $("a-publish").disabled = false;
    throw e;
  }
  const done = $("a-done");
  done.replaceChildren(
    el("p", { class: "kicker", text: res.held ? t("held_kicker") : t("published_kicker") }),
    el("h2", { text: res.held ? t("held_h", { date: res.releaseAt.slice(0, 10) }) : t("published_h") }),
    el("p", {}, el("a", { href: res.uri, target: "_blank", rel: "noopener", text: res.uri })),
    el("p", { class: "mono small", text: res.digest }),
    el("p", { class: "cta" }, el("a", { class: "btn btn-ink", href: me.base, target: "_blank", rel: "noopener", text: t("see_page") }), el("button", { class: "btn btn-line", "data-go": "dash", text: t("to_dash") })));
  done.hidden = false;
  done.scrollIntoView({ behavior: "smooth" });
  if (!res.held) anchorNow();
}));

// ---------------------------------------------------------------- customer

let AUD = null, cAud = null, cOffer = null, cKind = null;

async function customer() {
  $("c-form").hidden = true;
  $("c-rfp").hidden = true;
  await syncVault().catch(later);
  renderRequests().catch((e) => $("c-reqs").replaceChildren(el("p", { class: "bad", text: e.message })));
  renderMine().catch((e) => $("c-mine").replaceChildren(el("p", { class: "bad", text: e.message })));
  $("c-list").replaceChildren(el("p", { class: "muted", text: t("loading") }));
  AUD = await orderAuditors(ROOT);
  renderAuditors();
}

// renderAuditors sorts by public facts only — fulfilled orders or distinct
// customers, recountable from each auditor's published orders — and says
// so: they are not a measure of quality, and keys are free.
function renderAuditors() {
  const q = $("c-q").value.trim().toLowerCase(), by = $("c-sort").value;
  const rows = AUD.filter((a) => !q || [a.name, a.slug, a.fingerprint, accountOfKey(a.operator)].some((x) => (x || "").toLowerCase().includes(q)))
    .sort((a, b) => (by === "name" ? 0 : b[by] - a[by]) || a.name.localeCompare(b.name));
  const count = by === "customers" ? "customers" : "completedOrders";
  $("c-list").replaceChildren(...(rows.length ? rows.map((a) => el("article", { class: "entry" },
    el("div", { class: "entry-side" }, el("span", { class: "stamp", text: String(a[count]) }), el("span", { class: "state", text: t(count === "customers" ? "c_customers" : "c_orders") })),
    el("div", {}, el("h3", {}, el("a", { href: a.page, target: "_blank", rel: "noopener", text: a.name })),
      el("p", { class: "small mono", text: `${accountOfKey(a.operator)} · ${a.fingerprint}` }),
      el("p", { class: "who", text: t("c_facts", { orders: a.completedOrders, customers: a.customers, atts: a.attestations }) }),
      el("p", { class: "row-inline" }, el("button", { class: "btn btn-ink small-btn", text: t("c_order"), onclick: guard(() => orderFrom(a)) })))))
    : [el("p", { class: "empty", text: t("c_none") })]));
}
$("c-q").addEventListener("input", () => AUD && renderAuditors());
$("c-sort").addEventListener("change", () => AUD && renderAuditors());

function pickOne(box, card) {
  for (const c of box.children) c.classList.toggle("on", c === card);
}

async function orderFrom(a) {
  await loadAuditor(a);
  if (!a.offerDocs.length) throw new Error(t("c_no_offers"));
  cAud = a;
  $("c-to").textContent = t("c_to", { name: a.manifest.displayName });
  const box = $("c-offers");
  box.replaceChildren(...a.offerDocs.map((o) => {
    const c = el("button", { type: "button", class: "choice", onclick: () => pickCOffer(o, c) },
      el("b", { text: t("m_" + o.methodologyClass) }), el("span", { text: `${feeText(o, t)} · ${t("due_days", { n: o.timelineDays })} · ${t("fee_same")}` }), el("code", { class: "small", text: o.offerId }));
    return c;
  }));
  box.firstChild.click();
  $("c-error").hidden = true;
  $("c-form").hidden = false;
  $("c-form").scrollIntoView({ behavior: "smooth" });
}

function pickCOffer(o, card) {
  cOffer = o;
  pickOne($("c-offers"), card);
  const ks = kindsOf(cAud.manifest, o);
  $("c-kinds").replaceChildren(...ks.map((k) => el("label", { class: "radio" }, el("input", { type: "radio", name: "c-kind", value: k, onchange: () => pickCKind(k) }), " ", t("k_" + k))));
  $("c-kinds").querySelector("input").checked = true;
  pickCKind(ks[0]);
}

function pickCKind(k) {
  cKind = k;
  for (const d of document.querySelectorAll("[data-ckind]")) d.hidden = !d.dataset.ckind.split(" ").includes(k);
}

// The order is signed with a key of its own, derived from the phrase for
// this order only: no key file to keep, and nothing links it to the
// auditor key or to the holder's other orders.
$("c-form").addEventListener("submit", guard(async (ev) => {
  ev.preventDefault();
  const err = $("c-error");
  err.hidden = true;
  const bad = (m) => { err.textContent = m; err.hidden = false; };
  const component = $("c-component").value.trim(), contact = $("c-email").value.trim();
  if (!ORE.component.test(component)) return bad(t("err_component"));
  if (!$("c-scope").value.trim()) return bad(t("err_scope"));
  if (!$("c-authority").checked || !$("c-terms").checked) return bad(t("err_checks"));
  const btn = $("c-submit");
  btn.disabled = true;
  try {
    const f = { repo: $("c-repo").value, commit: $("c-commit").value, file: $("c-file").value, manifestUrl: $("c-manifest").value };
    const { artifact, preface } = await pin(ROOT, cKind, f, !cAud.only, t, (m) => (btn.textContent = m));
    const scopeText = preface + $("c-scope").value.trim() + "\n";
    if (enc.encode(scopeText).length > 8000) return bad(t("err_scope"));
    btn.textContent = t("signing");
    const orderId = newOrderID();
    const { priv, key } = await orderKey(me.seedKey, orderId);
    const signed = await signOrder({ auditor: cAud, offer: cOffer, artifact, scopeText, component, orderId, key, priv });
    btn.textContent = t("sending");
    const reply = await sendOrder(cAud.endpoint, signed, scopeText, contact).catch((e) => { throw new Error(t("err_server", { err: e.message })); });
    await saveOrder({ orderId, account: me.account, auditor: cAud.manifest.displayName, slug: cAud.slug, base: cAud.base, subject: component, kind: artifact.kind, source: artifact.source, createdAt: nowISO(), digest: reply.digest });
    $("c-form").hidden = true;
    toast(t("c_sent", { id: orderId }));
    renderMine();
    $("c-mine").scrollIntoView({ behavior: "smooth" });
  } catch (e) {
    bad(e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = t("c_submit");
  }
}));
$("c-repo").addEventListener("input", () => {
  const m = $("c-repo").value.trim().match(/\/([^/]+?)(?:\.git)?\/?$/);
  if (m && !$("c-component").dataset.edited) $("c-component").value = "onym:component:" + m[1].toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 64);
});
$("c-component").addEventListener("input", () => ($("c-component").dataset.edited = "1"));
$("c-manifest").addEventListener("change", async () => {
  if ($("c-component").dataset.edited) return;
  const id = await subjectOf(ROOT, $("c-manifest").value.trim()).catch(() => null);
  if (id) $("c-component").value = id;
});

async function renderMine() {
  const box = $("c-mine");
  const mine = (await myOrders()).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  if (!mine.length) return box.replaceChildren(el("p", { class: "empty", text: t("c_no_mine") }));
  const lib = await api("library").catch(() => []);
  box.replaceChildren(...mine.map((o) => {
    const state = el("span", { class: "state", text: t("loading") });
    const extra = el("p", { class: "small" });
    orderState(o, lib).then((s) => {
      state.textContent = t("st_" + s.state);
      if (s.att) extra.replaceChildren(el("a", { href: verdictPage(s.att, o.slug), text: t("st_open", { id: s.att }) }));
    }, () => (state.textContent = "?"));
    return el("article", { class: "entry" },
      el("div", { class: "entry-side" }, el("span", { class: "stamp", text: t("order_stamp") }), state),
      el("div", {}, el("h3", { text: o.subject }), el("p", { class: "who", text: `${o.auditor} · ${o.kind} · ${o.createdAt.slice(0, 10)}` }),
        el("p", { class: "small mono", text: `${o.orderId} · ${o.source}` }), extra));
  }));
}

// orderState: fulfilled once the auditor published the countersigned order
// (the library then names the attestation it commissioned, unless a fail
// is held under the embargo); otherwise the hub says, to the order's own
// key only, whether it still waits in the queue.
async function orderState(o, lib) {
  const r = await fetch(new URL(`orders/${o.orderId}.json`, o.base), { credentials: "omit", cache: "no-cache" });
  if (r.ok) {
    const d = await digest(new Uint8Array(await r.arrayBuffer()));
    const e = lib.find((x) => x.orderRef === d);
    return e ? { state: "done", att: e.attestationId } : { state: "held" };
  }
  if (!o.slug) return { state: "sent" };
  const { priv, key } = await orderKey(me.seedKey, o.orderId);
  const req = { action: "order-status", orderId: o.orderId, sponsor: key, issuedAt: nowISO() };
  const res = await api(`a/${o.slug}/order-status`, { request: JSON.parse(await signDoc(req, priv)) });
  return { state: res.queued ? "queued" : "gone" };
}

// ---------------------------------------------------------------- requests for proposals

const REQ_KINDS = ["source", "deployment", "discovery", "build"];
let rKind = "source";
const requestID = () => "req-" + [...crypto.getRandomValues(new Uint8Array(20))].map((x) => "abcdefghijklmnopqrstuvwxyz0123456789"[x % 36]).join("");
const classOf = (kind) => (kind === "discovery" ? "conformance-run" : "security-review");

// A request signed by the holder's key for it, or by the auditor's key.
async function ask(path, fields, priv) {
  return api(path, { request: JSON.parse(await signDoc({ ...fields, issuedAt: nowISO() }, priv)) });
}
const requestsFor = () => ask("requests/for", { action: "requests-for", key: me.key }, me.priv);

$("c-new-rfp").addEventListener("click", () => {
  $("r-kinds").replaceChildren(...REQ_KINDS.map((k) => el("label", { class: "radio" }, el("input", { type: "radio", name: "r-kind", value: k, checked: k === rKind, onchange: () => pickRKind(k) }), " ", t("k_" + k))));
  pickRKind(rKind);
  $("r-error").hidden = true;
  $("c-rfp").hidden = false;
  $("c-rfp").scrollIntoView({ behavior: "smooth" });
});
function pickRKind(k) {
  rKind = k;
  for (const d of document.querySelectorAll("[data-rkind]")) d.hidden = !d.dataset.rkind.split(" ").includes(k);
}
$("r-manifest").addEventListener("change", async () => {
  const id = await subjectOf(ROOT, $("r-manifest").value.trim()).catch(() => null);
  if (id && !$("r-component").value) $("r-component").value = id;
});

// A request pins the exact bytes now, so every auditor answers about the
// same thing; it is signed with a key of its own, derived from the phrase.
$("c-rfp").addEventListener("submit", guard(async (ev) => {
  ev.preventDefault();
  const err = $("r-error");
  err.hidden = true;
  const bad = (m) => { err.textContent = m; err.hidden = false; };
  const toG = $("r-to").value.trim();
  const to = toG ? keyOfAccount(toG) : null;
  if (toG && !to) return bad(t("e_account"));
  const component = $("r-component").value.trim();
  if (!ORE.component.test(component)) return bad(t("err_component"));
  if (!$("r-scope").value.trim()) return bad(t("err_scope"));
  const btn = $("r-submit");
  btn.disabled = true;
  try {
    const f = { repo: $("r-repo").value, commit: $("r-commit").value, file: $("r-file").value, manifestUrl: $("r-manifest").value };
    const { artifact, preface } = await pin(ROOT, rKind, f, true, t, (m) => (btn.textContent = m));
    const requestId = requestID();
    const { priv, key } = await orderKey(me.seedKey, requestId);
    const q = {
      requestVersion: 1, requestId, to, subject: component, methodologyClass: classOf(rKind), artifact,
      scopeText: preface + $("r-scope").value.trim() + "\n", requester: key, issuedAt: nowISO(), expiresAt: addDays(14),
    };
    await api("requests", { request: JSON.parse(await signDoc(q, priv)) });
    await saveRequest({ ...q, account: me.account, createdAt: q.issuedAt });
    $("c-rfp").hidden = true;
    toast(t("r_sent"));
    renderRequests();
  } catch (e) {
    bad(e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = t("r_submit");
  }
}));

async function renderRequests() {
  const box = $("c-reqs");
  const mine = (await myRequests()).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  if (!mine.length) return box.replaceChildren(el("p", { class: "empty", text: t("r_none") }));
  box.replaceChildren(...mine.map((q) => {
    const list = el("div", {}, el("p", { class: "small muted", text: t("loading") }));
    loadResponses(q, list).catch((e) => list.replaceChildren(el("p", { class: "small bad", text: e.message })));
    return el("article", { class: "entry" },
      el("div", { class: "entry-side" }, el("span", { class: "stamp", text: t("r_stamp") }), el("span", { class: "state", text: q.to ? t("r_to", { who: accountOfKey(q.to).slice(0, 6) + "…" }) : t("r_public") })),
      el("div", {}, el("h3", { text: q.subject }),
        el("p", { class: "who", text: `${t("m_" + q.methodologyClass)} · ${tr("kind_", q.artifact.kind)} · ${t("r_until", { date: q.expiresAt.slice(0, 10) })}` }),
        el("p", { class: "small mono", text: `${q.requestId} · ${q.artifact.source} @ ${q.artifact.revision}` }), list));
  }));
}

// loadResponses shows the auditors who answered, to the request's own key;
// choosing one orders under the offer it made.
async function loadResponses(q, box) {
  const { priv } = await orderKey(me.seedKey, q.requestId);
  const res = await ask(`requests/${q.requestId}/mine`, { action: "responses", requestId: q.requestId }, priv);
  if (!res.responses.length) return box.replaceChildren(el("p", { class: "small muted", text: res.open ? t("r_waiting") : t("r_closed") }));
  box.replaceChildren(...res.responses.map((r) => {
    const o = r.offer;
    const contact = el("input", { placeholder: t("contact_ph"), maxlength: "256", autocomplete: "email" });
    const terms = el("input", { type: "checkbox" });
    const go = el("button", { class: "btn btn-ink small-btn", type: "button", text: t("r_choose"), disabled: !res.open, onclick: guard(() => chooseResponse(q, r, contact.value.trim(), terms.checked, go)) });
    return el("div", { class: "response" },
      el("p", {}, el("b", {}, el("a", { href: r.page, target: "_blank", rel: "noopener", text: r.name })), ` · ${r.fingerprint} · ${t("c_facts", { orders: r.completedOrders, customers: r.customers, atts: "–" })}`),
      el("p", { class: "small", text: `${feeText(o, t)} · ${t("due_days", { n: o.timelineDays })} · ${t("fee_same")} · ${t("embargo_days", { n: o.disclosure.embargoDays })}` }),
      res.open ? el("p", { class: "row-inline" }, contact, el("label", { class: "check small" }, terms, " ", t("r_accept")), go) : null);
  }));
}

async function chooseResponse(q, r, contact, accepted, btn) {
  if (!accepted) throw new Error(t("err_checks"));
  btn.disabled = true;
  try {
    // The auditor and its offer are verified here, as for any order.
    const a = await loadAuditor({ slug: r.slug, base: new URL(`a/${r.slug}/`, ROOT).href, endpoint: new URL(`a/${r.slug}/orders`, ROOT).href, only: [] });
    const offerText = canonText(r.offer);
    const o = plain(parseStrict(offerText));
    if (o.auditorKey !== a.manifest.operator || o.auditor !== a.manifest.componentId || !(await verifySig(offerText, o.auditorKey))) throw new Error(t("r_bad_offer"));
    const orderId = newOrderID();
    const { priv, key } = await orderKey(me.seedKey, orderId);
    const signed = await signOrder({ auditor: a, offer: o, artifact: q.artifact, scopeText: q.scopeText, component: q.subject, orderId, key, priv });
    const reply = await sendOrder(a.endpoint, signed, q.scopeText, contact).catch((e) => { throw new Error(t("err_server", { err: e.message })); });
    await saveOrder({ orderId, account: me.account, auditor: a.manifest.displayName, slug: r.slug, base: a.base, subject: q.subject, kind: q.artifact.kind, source: q.artifact.source, createdAt: nowISO(), digest: reply.digest });
    toast(t("c_sent", { id: orderId }));
    customer();
  } finally {
    btn.disabled = false;
  }
}

// The auditor's side: open public requests and those addressed to this
// key; answering signs an offer made for that request alone.
async function loadRequests() {
  const box = $("d-requests");
  const [pub, mine] = await Promise.all([api("requests"), requestsFor()]);
  const all = [...mine, ...pub];
  $("pipe-requests").textContent = all.length;
  if (!all.length) return box.replaceChildren(el("p", { class: "empty", text: t("rq_none") }));
  const m = plain(parseStrict(await getText(me.base + "manifest.json")));
  const classes = new Set(m.methodologies.map((x) => x.class));
  box.replaceChildren(...await Promise.all(all.map(async (q) => {
    const oid = "rsp-" + q.requestId.slice(4);
    const answered = await fetch(loc(me.base + `offers/${oid}.json`), { method: "HEAD", cache: "no-cache" }).then((r) => r.ok, () => false);
    const action = el("div", {});
    if (answered) action.append(el("p", { class: "small ok-line", text: t("rq_answered") }));
    else if (!classes.has(q.methodologyClass)) action.append(el("p", { class: "small muted", text: t("rq_not_offered") }));
    else action.append(el("button", { class: "btn btn-ink small-btn", text: t("rq_answer"), onclick: () => respondForm(q, action) }));
    return el("article", { class: "entry" },
      el("div", { class: "entry-side" }, el("span", { class: "stamp", text: q.to ? t("rq_to_you") : t("r_public") }), el("span", { class: "state", text: t("rq_responses", { n: q.responses }) })),
      el("div", {}, el("h3", { text: q.subject }),
        el("p", { class: "who", text: `${t("m_" + q.methodologyClass)} · ${tr("kind_", q.artifact.kind)} · ${t("r_until", { date: q.expiresAt.slice(0, 10) })}` }),
        el("p", { class: "small mono", text: `${q.artifact.source} @ ${q.artifact.revision}${q.artifact.artifactHash ? " · " + q.artifact.artifactHash : ""}` }),
        el("pre", { class: "quote", text: q.scopeText }), action));
  })));
}

function respondForm(q, box) {
  const holder = el("div");
  const fee = feeFields(holder, "rq-" + q.requestId);
  const send = el("button", { class: "btn btn-ink small-btn", type: "button", text: t("rq_send"), onclick: guard(async () => {
    const f = fee.read();
    const spec = await sharedRef(q.methodologyClass === "conformance-run" ? "hub/methodology/conformance-run-v1.md" : "hub/methodology/manual-review-v1.md");
    const offer = {
      offerVersion: 1, offerId: "rsp-" + q.requestId.slice(4), auditor: me.componentId, auditorKey: me.key, methodologyClass: q.methodologyClass, scope: spec,
      fee: { model: f.model, amount: f.amount, currency: f.currency }, timelineDays: f.days, disclosure: DISCLOSURE[q.methodologyClass], validUntil: addDays(30),
    };
    await api(`requests/${q.requestId}/responses`, { slug: me.slug, offer: JSON.parse(await signDoc(offer, me.priv)) });
    toast(t("rq_sent"));
    loadRequests();
  }) });
  box.replaceChildren(el("div", { class: "respond-box" }, holder, send));
}

// ---------------------------------------------------------------- library

let LIB = null, libFilter = "all";
const libPage = (e) => (e.auditorSlug ? e.auditorBase : new URL(LANG_PATH, ROOT).href);

async function library() {
  const q = decodeURIComponent((location.hash.match(/^#att=(.+)$/) || [])[1] || "");
  if (q) $("lib-q").value = q;
  $("lib-list").replaceChildren(el("p", { class: "muted", text: t("loading") }));
  LIB = await api("library");
  renderLibrary();
}

function renderLibrary() {
  const q = $("lib-q").value.trim().toLowerCase();
  const rows = LIB.filter((e) => (!q || [e.attestationId, e.subject, e.auditor, e.source].some((x) => x.toLowerCase().includes(q)))
    && (libFilter === "all" || (libFilter === "revoked" ? e.state !== "active" : e.state === "active" && e.result === libFilter)));
  $("lib-count").textContent = t("lib_count", { n: rows.length, all: LIB.length });
  if (!rows.length) return $("lib-list").replaceChildren(el("p", { class: "empty", text: LIB.length ? t("lib_none") : t("lib_empty") }));
  $("lib-list").replaceChildren(...rows.slice(0, 200).map((e) => {
    const verdict = el("p", { class: "small muted", text: t("lib_checking") });
    const row = el("article", { class: "entry", id: "att-" + e.attestationId },
      el("div", { class: "entry-side" }, el("span", { class: `stamp r-${e.result}`, text: e.result.toUpperCase() }), el("span", { class: "state", text: tr("state_", e.state) })),
      el("div", {}, el("h3", {}, el("a", { href: verdictPage(e.attestationId, e.auditorSlug), text: e.subject })),
        el("p", { class: "who" }, el("a", { href: libPage(e), text: e.auditor }), ` · ${e.fingerprint} · ${tr("m_", e.methodologyClass)} · ${tr("eng_", e.engagement)} · ${e.issuedAt.slice(0, 10)}`),
        el("p", { class: "small mono", text: `${e.attestationId} · ${e.kind} · ${e.source}` }),
        verdict,
        el("p", { class: "links" }, el("a", { href: verdictPage(e.attestationId, e.auditorSlug), text: t("l_verdict") }), el("a", { href: e.uri, text: t("l_att") }))));
    verifyEntry(e, verdict);
    return row;
  }));
}

// verifyEntry checks an entry in this browser: the manifest, the status
// list, and the attestation's signatures. Trust in the auditor stays the
// reader's decision; the library only says whether the bytes verify.
const anchors = new Map(); // auditor base -> promise of its anchor state
async function verifyEntry(e, out) {
  try {
    const [manifestText, statusText, attText] = await Promise.all(["manifest.json", "status.json"].map((f) => getText(e.auditorBase + f)).concat(getText(e.uri)));
    const d = await verifyAttestation({ manifestText, attText, statusText, target: null, credited: false });
    const good = d.display === "uncredited" || d.display === "attested";
    out.className = "small " + (good ? "ok-line" : "bad");
    out.textContent = good ? t("lib_ok") : t("lib_state", { state: tr("d_", d.display) });
    // The register's anchor, asked of a public Stellar node, once per auditor.
    if (!anchors.has(e.auditorBase)) anchors.set(e.auditorBase, anchorState(accountOfKey(plain(parseStrict(manifestText)).operator), statusText).catch(() => ({ state: "unknown" })));
    const a = await anchors.get(e.auditorBase);
    if (a.state === "match" || a.state === "stale") out.append(" · ", el("span", { text: t("lib_anchor_" + a.state, { at: (a.at || "").slice(0, 10) }) }));
  } catch (err) {
    out.className = "small bad";
    out.textContent = t("lib_state", { state: t("lib_unavailable") });
  }
}

$("lib-q").addEventListener("input", () => LIB && renderLibrary());
for (const b of document.querySelectorAll("#lib-filters .chip")) b.addEventListener("click", () => {
  libFilter = b.dataset.f;
  for (const x of document.querySelectorAll("#lib-filters .chip")) x.classList.toggle("on", x === b);
  renderLibrary();
});
window.addEventListener("hashchange", () => {
  if (/^#(library|att=)/.test(location.hash)) return show("library");
  if (/^#(auditor|customer)$/.test(location.hash)) {
    wantTab = location.hash.slice(1);
    home();
  }
});

// ---------------------------------------------------------------- start

(async () => {
  fillTemplates(true);
  const saved = await loadIdentity();
  if (saved && saved.priv && saved.account) {
    me = saved;
    // The hub may have taken the auditor down, or the holder registered
    // from another browser: ask it which auditor this key is.
    const mine = await api("auditors").then((all) => all.find((a) => a.operator === me.key), () => undefined);
    if (mine === undefined && me.slug) ["slug", "componentId", "name", "base"].forEach((k) => delete me[k]);
    else if (mine) Object.assign(me, { slug: mine.slug, componentId: "onym:component:" + mine.slug, name: mine.name, base: mine.page });
    if (me.base) setPub(me.base);
  }
  if (/^#(library|att=)/.test(location.hash)) return show("library");
  if (location.hash === "#customer") wantTab = "customer";
  home();
})().catch((e) => toast(e.message, true));
