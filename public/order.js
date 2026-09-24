// Order page: order an examination from any auditor — this site's operator
// or any auditor on the hub — under one of the offers the auditor signed.
// The browser pins the exact bytes, builds the AuditOrder from the offer,
// signs it as subject and sponsor with an Ed25519 key that never leaves the
// page, and queues it with the auditor (the envelope form of profile §5.3).
import { RE, auditors, load, kindsOf, feeText, pin, subjectOf, newOrderID, sign, send } from "./order-core.js";

const $ = (id) => document.getElementById(id);
const ROOT = new URL(".", import.meta.url);
const T = JSON.parse($("strings")?.textContent || "{}");
const t = (k, v = {}) => (T[k] ?? k).replace(/\{(\w+)\}/g, (_, x) => v[x] ?? "");
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
const unhex = (h) => Uint8Array.from(h.match(/../g).map((b) => parseInt(b, 16)));
const PKCS8_ED25519 = unhex("302e020100300506032b657004220420");
const SEED = /^[0-9a-f]{64}$/;

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

let keyFileURL = null;
let auditor = null; // an entry of auditors(), loaded
let offer = null;
let kind = null;

function fail(msg) {
  const e = $("form-error");
  e.textContent = msg;
  e.hidden = false;
  e.scrollIntoView({ block: "center", behavior: "smooth" });
}

// ---------------------------------------------------------------- auditors and offers

async function listAuditors() {
  const list = await auditors(ROOT);
  const box = $("auditors");
  box.replaceChildren();
  const wanted = new URLSearchParams(location.search).get("auditor") || "";
  for (const a of list) {
    const card = el("button", { type: "button", class: "choice", role: "radio", "aria-checked": "false", onclick: () => pickAuditor(a, card) }, el("b", { text: a.name }), el("span", { text: t("loading") }));
    box.append(card);
    load(a).then(() => {
      card.lastChild.textContent = t("auditor_line", { fp: a.print, n: a.offerDocs.length });
      if (!a.offerDocs.length) card.disabled = true;
      if (a.slug === wanted && a.offerDocs.length) pickAuditor(a, card);
    }, () => {
      card.lastChild.textContent = t("err_auditor");
      card.disabled = true;
    });
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
  for (const o of a.offerDocs) {
    const c = el("button", { type: "button", class: "choice", role: "radio", "aria-checked": "false", onclick: () => pickOffer(o, c) },
      el("b", { text: t("m_" + o.methodologyClass) }), el("span", { text: `${feeText(o, t)} · ${t("due_days", { n: o.timelineDays })}` }), el("code", { class: "small", text: o.offerId }));
    box.append(c);
  }
  if (box.firstChild) box.firstChild.click();
}

function pickOffer(o, card) {
  offer = o;
  select($("offers"), card);
  $("offer-code").textContent = o.offerId;
  $("t-fee").textContent = feeText(o, t) + " — " + t("fee_same");
  $("t-due").textContent = t("due_days", { n: o.timelineDays });
  $("t-first").textContent = o.disclosure.findingsToSubjectFirst ? t("first_yes") : t("first_no");
  $("t-embargo").textContent = o.disclosure.embargoDays > 0 ? t("embargo_days", { n: o.disclosure.embargoDays }) : t("embargo_none");
  $("t-publish").textContent = o.disclosure.failPublication === "public-after-embargo" ? t("publish_embargo") : t("publish_now");
  const m = auditor.manifest;
  const link = (href, text) => el("a", { href, text, target: "_blank", rel: "noopener" });
  $("t-links").replaceChildren(t("links"), " ", link(o.scope.uri, t("l_method")), " · ", link(m.independencePolicy.uri, t("l_indep")), " · ", link(m.liability.uri, t("l_liab")), " · ", link(m.privacyProfile.uri, t("l_priv")));
  const box = $("kinds");
  box.replaceChildren();
  const ks = kindsOf(m, o);
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
    if (!SEED.test(h)) throw new Error(t("err_seed"));
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

async function submit(ev) {
  ev.preventDefault();
  $("form-error").hidden = true;
  if (!auditor || !offer) return fail(t("err_offer"));
  const component = $("component").value.trim();
  const contact = $("email").value.trim();
  if (!RE.component.test(component)) return fail(t("err_component"));
  if (!$("scope").value.trim()) return fail(t("err_scope"));
  if (!$("authority").checked || !$("terms").checked) return fail(t("err_checks"));

  const btn = $("submit");
  btn.disabled = true;
  btn.textContent = t("signing");
  try {
    const f = { repo: $("repo").value, commit: $("commit").value, file: $("file").value, manifestUrl: $("manifest-url").value };
    const { artifact, preface } = await pin(ROOT, kind, f, !auditor.only, t, (msg) => (btn.textContent = msg));
    const scopeText = preface + $("scope").value.trim() + "\n";
    if (new TextEncoder().encode(scopeText).length > 8000) throw new Error(t("err_scope"));
    btn.textContent = t("signing");
    const { priv, seedHex, key } = await keypair(document.querySelector('input[name="keymode"]:checked').value);
    const id = newOrderID();
    const signed = await sign({ auditor, offer, artifact, scopeText, component, orderId: id, key, priv });
    btn.textContent = t("sending");
    const reply = await send(auditor.endpoint, signed, scopeText, contact).catch((e) => { throw new Error(t("err_server", { err: e.message })); });

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
  const id = await subjectOf(ROOT, url).catch(() => null);
  if (id) $("component").value = id;
});
for (const r of document.querySelectorAll('input[name="keymode"]')) {
  r.addEventListener("change", () => { $("seed-wrap").hidden = r.value !== "existing" || !r.checked; });
}
$("order-form").addEventListener("submit", submit);
pickKind("source");
listAuditors();
