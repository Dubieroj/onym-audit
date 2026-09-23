// Onym audit studio: take the audit seat from a browser. The auditor key is
// an Ed25519 key kept in this browser's IndexedDB as a non-extractable
// CryptoKey (plus a backup file the auditor downloads); the hub never sees
// it. Every document is built to the static-Ed25519 profile, canonicalized
// by the same code that verifies attestations, and signed here.
import { parseStrict, canonical, plain, digest, fingerprint, verifySig } from "../verify.js";

const $ = (id) => document.getElementById(id);
const ROOT = new URL("../", import.meta.url); // …/audit/
const HUB = new URL("hub/api/", ROOT);
const T = JSON.parse($("strings")?.textContent || "{}");
const t = (k, v = {}) => (T[k] ?? k).replace(/\{(\w+)\}/g, (_, x) => v[x] ?? "");
const enc = new TextEncoder();
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
const unhex = (h) => Uint8Array.from(h.match(/../g).map((b) => parseInt(b, 16)));
const b64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b)));
const PKCS8 = unhex("302e020100300506032b657004220420");
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
  try { data = JSON.parse(text); } catch { data = { error: text || "HTTP " + r.status }; }
  if (!r.ok) throw new Error(data.error || "HTTP " + r.status);
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
    const req = indexedDB.open("onym-audit-studio", 1);
    req.onupgradeneeded = () => req.result.createObjectStore("identity");
    req.onsuccess = () => res(req.result);
    req.onerror = () => rej(req.error);
  });
}
async function idbDo(mode, fn) {
  const d = await idb();
  return new Promise((res, rej) => {
    const tx = d.transaction("identity", mode);
    const r = fn(tx.objectStore("identity"));
    tx.oncomplete = () => res(r?.result);
    tx.onerror = () => rej(tx.error);
  });
}
const loadIdentity = () => idbDo("readonly", (s) => s.get("me")).catch(() => null);
const saveIdentity = (v) => idbDo("readwrite", (s) => s.put(v, "me"));
const forgetIdentity = () => idbDo("readwrite", (s) => s.delete("me"));

async function keyFromSeed(seed) {
  const pk = new Uint8Array([...PKCS8, ...seed]);
  const probe = await crypto.subtle.importKey("pkcs8", pk, { name: "Ed25519" }, true, ["sign"]);
  const jwk = await crypto.subtle.exportKey("jwk", probe);
  const pub = Uint8Array.from(atob(jwk.x.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
  const priv = await crypto.subtle.importKey("pkcs8", pk, { name: "Ed25519" }, false, ["sign"]);
  return { priv, key: "onym:key:" + hex(pub) };
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
  box.replaceChildren(radio("pro-bono", t("fee_probono")), radio("fixed-verdict-independent", t("fee_fixed_l")),
    el("div", { class: "row-inline" }, amount, currency),
    el("label", {}, t("fee_days"), days),
    el("p", { class: "hint", text: t("fee_h") }));
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

let me = null; // {slug, key, componentId, name, priv}
const views = ["welcome", "onboard", "dash", "audit"];
function show(v) {
  for (const x of views) $("v-" + x).hidden = x !== v;
  window.scrollTo(0, 0);
  if (v === "dash") dash();
  if (v === "audit") startAudit();
  if (v === "welcome") listAuditors();
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
  const name = $("ob-name").value.trim(), slug = $("ob-slug").value.trim(), email = $("ob-email").value.trim();
  const bad = (m) => { err.textContent = m; err.hidden = false; err.scrollIntoView({ block: "center" }); };
  if (!name) return bad(t("e_name"));
  if (!/^[a-z][a-z0-9-]{2,31}$/.test(slug)) return bad(t("e_slug"));
  if (!/^[^\s@<>()",;:]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$/.test(email)) return bad(t("e_email"));
  if (!$("ob-m-manual").checked && !$("ob-m-conf").checked) return bad(t("e_methods"));
  if (!$("ob-terms").checked) return bad(t("e_terms"));
  let fee = null;
  try { fee = $("ob-orders").checked ? obFee.read() : null; } catch (e) { return bad(e.message); }
  if (!(await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign"]).then(() => true, () => false))) return bad(t("e_crypto"));
  const btn = $("ob-submit");
  btn.disabled = true;
  btn.textContent = t("working");
  try {
    const claim = await api("claim", { slug });
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const { priv, key } = await keyFromSeed(seed);
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
      version: 1, componentId: claim.componentId, seat: "audit", operator: key, displayName: name, contact: "mailto:" + email,
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
    me = { slug, key, componentId: claim.componentId, name, priv, base };
    await saveIdentity(me);
    const backup = JSON.stringify({ onymAuditorBackup: 1, slug, componentId: claim.componentId, name, key, seed: hex(seed), base, createdAt: nowISO() }, null, 2);
    $("ob-dl").href = URL.createObjectURL(new Blob([backup + "\n"], { type: "application/json" }));
    $("ob-dl").download = `onym-auditor-${slug}.json`;
    $("ob-form").hidden = true;
    $("ob-done").hidden = false;
    $("ob-done").scrollIntoView({ behavior: "smooth" });
  } finally {
    btn.disabled = false;
    btn.textContent = t("ob_submit");
  }
}));
$("ob-saved").addEventListener("change", () => ($("ob-continue").disabled = !$("ob-saved").checked));
$("ob-continue").addEventListener("click", () => show("dash"));

$("restore-file").addEventListener("change", guard(async (e) => {
  const f = e.target.files[0];
  if (!f) return;
  const b = JSON.parse(await f.text());
  if (b.onymAuditorBackup !== 1 || !/^[0-9a-f]{64}$/.test(b.seed || "")) throw new Error(t("e_backup"));
  const { priv, key } = await keyFromSeed(unhex(b.seed));
  if (key !== b.key) throw new Error(t("e_backup"));
  setPub(b.base);
  const m = plain(parseStrict(await getText(b.base + "manifest.json")));
  if (m.operator !== key) throw new Error(t("e_backup_mismatch"));
  me = { slug: b.slug, key, componentId: b.componentId, name: m.displayName, priv, base: b.base };
  await saveIdentity(me);
  toast(t("restored", { name: m.displayName }));
  show("dash");
}));

// ---------------------------------------------------------------- dashboard

async function dash() {
  $("who").hidden = false;
  $("who").textContent = me.name + " · " + (await fingerprint(me.key));
  $("d-name").textContent = me.name;
  $("d-page").href = me.base;
  $("d-page").textContent = me.base.replace(/^https:\/\//, "");
  $("d-key").textContent = `${await fingerprint(me.key)} (${me.key})`;
  loadOrders().catch((e) => $("d-orders").replaceChildren(el("p", { class: "bad", text: e.message })));
  const box = $("d-atts");
  box.replaceChildren(el("p", { class: "muted", text: t("loading") }));
  try {
    const manifestText = await getText(me.base + "manifest.json");
    const statusText = await getText(me.base + "status.json");
    const st = plain(parseStrict(statusText));
    if (!(await verifySig(statusText, plain(parseStrict(manifestText)).statusKey))) throw new Error(t("e_status"));
    if (!st.entries.length) return box.replaceChildren(el("p", { class: "empty", text: t("no_atts") }));
    const rows = [];
    for (const e of st.entries) {
      const a = plain(parseStrict(await getText(e.attestation.uri)));
      const row = el("article", { class: "entry" },
        el("div", { class: "entry-side" }, el("span", { class: `stamp r-${a.result}`, text: a.result.toUpperCase() }), el("span", { class: "state", text: e.state })),
        el("div", {}, el("h3", { text: a.subject }),
          el("p", { class: "who", text: `${a.methodologyClass} · ${a.artifact.kind} · ${a.issuedAt.slice(0, 10)}` }),
          el("p", { class: "small mono", text: a.artifact.source }),
          el("p", { class: "links" }, el("a", { href: e.attestation.uri, text: t("l_att") }), a.findingsReport ? el("a", { href: a.findingsReport.uri, text: t("l_report") }) : null)));
      if (e.state === "active") {
        const reason = el("select", {}, ["withdrawal", "new-information", "methodology-error", "compromise-of-auditor-key"].map((r) => el("option", { value: r, text: r })));
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
    $("d-offers").open = true;
    return box.replaceChildren(el("p", { class: "empty", text: t("orders_off") }));
  }
  const res = await inboxCall("list");
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
        el("p", { class: "who", text: `${t("m_" + o.methodologyClass)} · ${o.artifact.kind} · ${o.fee.model} · ${o.fee.offerId}` }),
        el("p", { class: "small mono", text: `${o.artifact.source} @ ${o.artifact.revision}` }),
        el("pre", { class: "quote", text: q.scopeText }),
        el("p", { class: "small" }, el("a", { href: q.contact, text: q.contact.replace(/^mailto:/, "") }), ` · ${t("sponsor_fp", { fp: await fingerprint(o.sponsor) })} · ${o.orderId} · ${t("received", { date: q.receivedAt.slice(0, 10) })}`),
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

async function revoke(id, reason) {
  if (!confirm(t("confirm_revoke", { id }))) return;
  const now = nowISO();
  const rv = { revocationVersion: 1, attestationId: id, auditor: me.componentId, auditorKey: me.key, issuedAt: now, statusEpoch: Math.floor(Date.now() / 1000), effectiveFrom: now, reason, detail: null };
  await api(`a/${me.slug}/revoke`, { revocation: JSON.parse(await signDoc(rv, me.priv)) });
  toast(t("revoked"));
  dash();
}

$("d-backup").addEventListener("click", () => toast(t("backup_note")));
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
$("d-forget").addEventListener("click", guard(async () => {
  if (!confirm(t("confirm_forget"))) return;
  await forgetIdentity();
  me = null;
  $("who").hidden = true;
  show("welcome");
}));

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
  for (const b of document.querySelectorAll(".choice")) b.disabled = false;
  for (const s of ["a-step2", "a-step3", "a-step4"]) $(s).hidden = true;
  $("a-step1").hidden = false;
  $("a-done").hidden = true;
  $("a-publish").disabled = false;
  $("a-notified").value = nowISO();
  for (const id of ["a-cov-sum", "a-cov-ex", "a-cov-nx", "a-contact"]) $(id).value = "";
  $("a-cov-complete").checked = false;
  $("a-rel").value = "none";
  for (const b of document.querySelectorAll(".choice")) b.classList.remove("on");
}

// takeOrder starts an examination bound to a queued order: the target and
// the scope are the order's, and signing countersigns it.
function takeOrder(q) {
  show("audit");
  A.order = q;
  const o = q.order;
  const kind = o.methodologyClass === "conformance-run" ? "discovery" : o.artifact.kind;
  const banner = $("a-order-banner");
  banner.replaceChildren(el("p", {}, el("b", { text: t("order_banner", { id: o.orderId }) }), " ", t("order_banner_h")),
    el("p", { class: "mono small", text: [o.artifact.source, o.artifact.revision, o.artifact.artifactHash].filter(Boolean).join(" · ") }));
  banner.hidden = false;
  $("a-unsol").hidden = true;
  $("a-comm").hidden = false;
  $("a-comm-contact").href = q.contact;
  $("a-comm-contact").textContent = q.contact.replace(/^mailto:/, "");
  $("a-sent").closest("label").hidden = !o.disclosure.findingsToSubjectFirst;
  for (const b of document.querySelectorAll(".choice")) b.disabled = b.dataset.kind !== kind;
  document.querySelector(`.choice[data-kind="${kind}"]`).click();
}

for (const b of document.querySelectorAll(".choice")) {
  b.addEventListener("click", () => {
    for (const x of document.querySelectorAll(".choice")) x.classList.toggle("on", x === b);
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
    parts.commit = field(t("f_commit"), { placeholder: "40 hex", class: "mono" });
    parts.owner = field(t("f_owner"), { placeholder: "https://…/manifest.json", class: "mono" }, t("f_owner_h"));
  } else if (A.kind === "deployment" || A.kind === "discovery") {
    parts.url = field(A.kind === "discovery" ? t("f_provider") : t("f_manifest"), { placeholder: "https://…/manifest.json", class: "mono" }, A.kind === "discovery" ? t("f_provider_h") : t("f_manifest_h"));
  } else {
    parts.file = field(t("f_file"), { placeholder: "https://github.com/org/repo/releases/download/v1/app.apk", class: "mono" });
    parts.repo = field(t("f_repo"), { placeholder: "https://github.com/org/repo", class: "mono" });
    parts.commit = field(t("f_commit"), { placeholder: "40 hex", class: "mono" });
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
  const sev = el("select", {}, ["critical", "high", "medium", "low", "informational"].map((s) => el("option", { value: s, text: s })));
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
    el("div", { class: "entry-side" }, el("span", { class: `stamp sev-${f.severity}`, text: f.severity.toUpperCase() })),
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
    if (!/^(mailto:|https:\/\/)\S+$/.test(contact)) return bad(t("e_contact"));
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
  const res = await api(`a/${me.slug}/publish`, { attestation: JSON.parse(signed), docs });
  const done = $("a-done");
  done.replaceChildren(
    el("p", { class: "kicker", text: res.held ? t("held_kicker") : t("published_kicker") }),
    el("h2", { text: res.held ? t("held_h", { date: res.releaseAt.slice(0, 10) }) : t("published_h") }),
    el("p", {}, el("a", { href: res.uri, target: "_blank", rel: "noopener", text: res.uri })),
    el("p", { class: "mono small", text: res.digest }),
    el("p", { class: "cta" }, el("a", { class: "btn btn-ink", href: me.base, target: "_blank", rel: "noopener", text: t("see_page") }), el("button", { class: "btn btn-line", "data-go": "dash", text: t("to_dash") })));
  done.hidden = false;
  done.scrollIntoView({ behavior: "smooth" });
}));

// ---------------------------------------------------------------- start

(async () => {
  fillTemplates(true);
  const saved = await loadIdentity();
  if (saved && saved.priv) {
    me = saved;
    setPub(me.base);
    show("dash");
  } else show("welcome");
})().catch((e) => toast(e.message, true));
