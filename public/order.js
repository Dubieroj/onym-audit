// Order page: builds an AuditOrder, signs it in the browser as subject and
// sponsor with an Ed25519 key that never leaves the page, and queues it with
// POST orders (the envelope form of profile §5.3).
import { parseStrict, canonical, plain, digest } from "./verify.js";

const $ = (id) => document.getElementById(id);
const ROOT = new URL(".", import.meta.url);
const T = JSON.parse($("strings")?.textContent || "{}");
const t = (k, v = {}) => (T[k] ?? k).replace(/\{(\w+)\}/g, (_, x) => v[x] ?? "");
const enc = new TextEncoder();
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
const unhex = (h) => Uint8Array.from(h.match(/../g).map((b) => parseInt(b, 16)));
const b64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b)));
const PKCS8_ED25519 = unhex("302e020100300506032b657004220420");

const RE = {
  repo: /^https:\/\/[A-Za-z0-9.-]+\.[A-Za-z]{2,}(\/[^\s?#:@]*)?$/,
  commit: /^[0-9a-f]{40}$/,
  component: /^onym:component:[a-z0-9-]{1,64}$/,
  email: /^[^\s@<>()",;:]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$/,
  seed: /^[0-9a-f]{64}$/,
};

let manifest = null;
let keyFileURL = null;

function fail(msg) {
  const e = $("form-error");
  e.textContent = msg;
  e.hidden = false;
  e.scrollIntoView({ block: "center", behavior: "smooth" });
}

async function loadManifest() {
  const r = await fetch(new URL("manifest.json", ROOT), { credentials: "omit", cache: "no-cache" });
  if (!r.ok) throw new Error("HTTP " + r.status);
  manifest = plain(parseStrict(await r.text()));
  $("brand-name").textContent = manifest.displayName;
}

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

const day = (d) => d.toISOString().slice(0, 10);

async function submit(ev) {
  ev.preventDefault();
  $("form-error").hidden = true;
  const repo = $("repo").value.trim().replace(/\/+$/, "").replace(/\.git$/, "");
  const commit = $("commit").value.trim().toLowerCase();
  const component = $("component").value.trim();
  const scopeText = $("scope").value.trim() + "\n";
  const email = $("email").value.trim();
  if (!RE.repo.test(repo)) return fail(t("err_repo"));
  if (!RE.commit.test(commit)) return fail(t("err_commit"));
  if (!RE.component.test(component)) return fail(t("err_component"));
  if (scopeText.trim().length === 0 || enc.encode(scopeText).length > 8000) return fail(t("err_scope"));
  if (!RE.email.test(email)) return fail(t("err_email"));
  if (!$("authority").checked || !$("terms").checked) return fail(t("err_checks"));

  const btn = $("submit");
  btn.disabled = true;
  btn.textContent = t("signing");
  try {
    if (!manifest) await loadManifest().catch((e) => { throw new Error(t("err_manifest", { err: e.message })); });
    const base = manifest.statusEndpoint.replace(/status\.json$/, "");
    const { priv, seedHex, key } = await keypair(document.querySelector('input[name="keymode"]:checked').value);
    const id = orderID();
    const now = new Date();
    const order = {
      orderVersion: 1,
      orderId: id,
      auditor: manifest.componentId,
      subject: component,
      sponsor: key,
      artifact: { kind: "source", source: repo, revision: commit, artifactHash: null },
      methodologyClass: "security-review",
      scope: { uri: `${base}scopes/order-${id}.md`, digest: await digest(enc.encode(scopeText)) },
      cooperation: "Public repository access only; the subject answers the auditor's questions at the contact given with the order.",
      disclosure: { findingsToSubjectFirst: true, embargoDays: 90, attestationPublication: "public-on-issuance", failPublication: "public-after-embargo" },
      timeline: { start: day(now), reportDue: day(new Date(now.getTime() + 7 * 864e5)) },
      fee: { model: "pro-bono", offerId: "security-review-llm-source" },
      signatures: [],
    };
    // Every party signs the canonical bytes with `signatures` removed.
    const unsigned = parseStrict(JSON.stringify(order));
    unsigned.delete("signatures");
    const msg = enc.encode(canonical(unsigned));
    const s = b64(await crypto.subtle.sign({ name: "Ed25519" }, priv, msg));
    order.signatures = [
      { role: "subject", key, signature: s },
      { role: "sponsor", key, signature: s },
    ];
    const signed = canonical(parseStrict(JSON.stringify(order)));

    btn.textContent = t("sending");
    const r = await fetch(new URL("orders", ROOT), {
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

// Suggest a component id from the repository name, until the holder edits it.
let componentEdited = false;
$("component").addEventListener("input", () => { componentEdited = true; });
$("repo").addEventListener("input", () => {
  if (componentEdited) return;
  const m = $("repo").value.trim().match(/\/([^/]+?)(?:\.git)?\/?$/);
  if (m) $("component").value = "onym:component:" + m[1].toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 64);
});
for (const r of document.querySelectorAll('input[name="keymode"]')) {
  r.addEventListener("change", () => { $("seed-wrap").hidden = r.value !== "existing" || !r.checked; });
}
$("order-form").addEventListener("submit", submit);
loadManifest().catch(() => {});
