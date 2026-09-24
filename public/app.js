import { verifyAttestation, verifySig, parseStrict, plain, fingerprint, digest } from "./verify.js";

const $ = (id) => document.getElementById(id);
// The auditor's root: a hosted auditor's page names its own tree with
// <meta name="auditor-root">; otherwise the tree this script is served from.
const rootMeta = document.querySelector('meta[name="auditor-root"]');
const ROOT = rootMeta ? new URL(rootMeta.content, document.baseURI) : new URL(".", import.meta.url);
const T = JSON.parse(document.getElementById("strings")?.textContent || "{}");
const t = (k, vars = {}) => (T[k] ?? k).replace(/\{(\w+)\}/g, (_, v) => vars[v] ?? "");
const at = (p) => new URL(p, ROOT).href;
// Each attestation's own page lives in the shared tree, in this page's language.
const LANG_PATH = { ru: "ru/", "sr-Latn-ME": "cnr/" }[document.documentElement.lang] || "";
const SLUG = rootMeta ? ROOT.pathname.split("/").filter(Boolean).pop() : "";
const verdictPage = (id) => new URL(`${LANG_PATH}verdict/?${SLUG ? `a=${encodeURIComponent(SLUG)}&` : ""}id=${encodeURIComponent(id)}`, new URL(".", import.meta.url)).href;
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text; // untrusted strings are only ever text
  return n;
};
const get = async (url) => {
  const r = await fetch(at(url), { credentials: "omit", cache: "no-cache" });
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  return r.text();
};
const ago = (iso) => {
  const h = Math.floor((Date.now() - Date.parse(iso)) / 3600000);
  if (h < 1) return t("ago_lt1h");
  if (h < 48) return t("ago_h", { n: h });
  return t("ago_d", { n: Math.floor(h / 24) });
};
// Documents are named by absolute URI under the manifest's base; fetch them
// from wherever this page is served.
let base = "";
const local = (u) => (base && u.startsWith(base) ? at(u.slice(base.length)) : u);

let manifestText, statusText, manifest;

function seal(state, print, epoch, caption) {
  const s = $("seal");
  s.classList.remove("verified", "failed");
  if (state === t("verified")) s.classList.add("verified");
  if (state === t("unverified")) s.classList.add("failed");
  $("seal-state").textContent = state;
  $("seal-print").textContent = print;
  $("seal-epoch").textContent = epoch;
  s.querySelector("title").textContent = state;
  if (caption) $("seal-caption").textContent = caption;
}

async function main() {
  try {
    manifestText = await get("manifest.json");
    manifest = plain(parseStrict(manifestText));
  } catch (e) {
    seal(t("unverified"), "—", "", t("no_manifest", { err: e.message }));
    $("atts").replaceChildren(el("p", "empty", t("reg_no_manifest")));
    return;
  }
  base = manifest.statusEndpoint.replace(/status\.json$/, "");
  const print = await fingerprint(manifest.operator);
  $("brand-name").textContent = manifest.displayName;
  if ($("h-name")) $("h-name").textContent = manifest.displayName;
  // A hosted auditor who publishes offers can be ordered from.
  if ($("order-cta") && manifest.offers.length) {
    $("order-link").search = "?auditor=" + encodeURIComponent(manifest.componentId.replace(/^onym:component:/, ""));
    $("order-cta").hidden = false;
  }
  // The ring's textLength spreads the words evenly around the circle.
  $("seal-ringtext").textContent = `${manifest.displayName.toUpperCase()} · ONYM AUDIT SEAT · ED25519 ·`;
  $("f-key").textContent = print;
  $("f-key").title = manifest.operator;
  const mail = manifest.contact.replace(/^mailto:/, "");
  const a = el("a", "", mail);
  // The contact is the auditor's own text: only mailto: and https: become links.
  if (/^(mailto:|https:\/\/)/i.test(manifest.contact)) a.href = manifest.contact;
  $("f-contact").replaceChildren(a);

  const manifestOK = await verifySig(manifestText, manifest.operator).catch(() => false);
  try { statusText = await get("status.json"); } catch { statusText = null; }
  let statusOK = false, st = null;
  if (statusText) {
    st = plain(parseStrict(statusText));
    statusOK = st.statusKey === manifest.statusKey && st.auditorKey === manifest.operator && (await verifySig(statusText, manifest.statusKey).catch(() => false));
    $("f-status").textContent = t("signed", { n: st.statusEpoch, ago: ago(st.issuedAt) });
    $("f-next").textContent = st.nextUpdate.replace("T", " ").replace("Z", " UTC");
  }
  const fresh = st && Date.parse(st.nextUpdate) > Date.now();
  if (manifestOK && statusOK && fresh) {
    seal(t("verified"), print.slice(0, 11), t("epoch", { n: st.statusEpoch }), t("cap_ok", { print, ago: ago(st.issuedAt) }));
  } else {
    const why = !manifestOK ? t("why_manifest") : !statusText ? t("why_nostatus") : !statusOK ? t("why_badsig") : t("why_stale");
    seal(t("unverified"), print.slice(0, 11), "", t("cap_fail", { why }));
  }
  $("credit").addEventListener("change", render);
  await render();
}

async function render() {
  const box = $("atts");
  if (!statusText) { box.replaceChildren(el("p", "empty", t("reg_no_status"))); return; }
  const st = plain(parseStrict(statusText));
  if (st.entries.length === 0) {
    const p = el("p", "empty");
    p.append(el("b", "", t("reg_empty_b")), document.createTextNode(t("reg_empty")));
    box.replaceChildren(p);
    return;
  }
  const rows = [];
  for (const e of st.entries) rows.push(await entry(e));
  box.replaceChildren(...rows);
}

async function entry(e) {
  const row = el("article", "entry");
  let attText;
  try { attText = await get(local(e.attestation.uri)); } catch (err) {
    row.append(el("p", "note", t("fetch_fail", { id: e.attestationId, err: err.message })));
    return row;
  }
  const credited = $("credit").checked;
  const d = await verifyAttestation({ manifestText, attText, statusText, target: null, credited });
  const a = d.att ?? plain(parseStrict(attText));

  const side = el("div", "entry-side");
  side.append(el("span", `stamp r-${a.result}`, a.result.toUpperCase()), el("span", `state s-${d.display}`, t("d_" + d.display)), el("span", "state", e.attestationId));
  const body = el("div");
  const title = el("a", "", a.subject);
  title.href = verdictPage(e.attestationId);
  const h3 = el("h3");
  h3.append(title);
  body.append(h3);
  body.append(el("p", "who", `${a.methodologyClass} · ${t("issued", { ago: ago(a.issuedAt) })}` + (a.expiresAt ? ` · ${t("expires", { date: a.expiresAt.slice(0, 10) })}` : "")));

  const dl = el("dl", "kv");
  const kv = (k, v) => { const w = el("div"); w.append(el("dt", "", k), el("dd", "", v)); dl.append(w); };
  kv(t("k_scope"), a.scopeSummary);
  kv(t("k_notexam"), a.exclusions.join("; ") || "—");
  kv(t("k_findings"), (Object.entries(a.findingsSummary).map(([k, v]) => `${v} ${k}`).join(", ") || t("none")) + (a.severityFloor ? ` (${t("floor", { f: a.severityFloor })})` : ""));
  kv(t("k_paid"), `${a.sponsorName} · ${await fingerprint(a.sponsor)}`);
  kv(t("k_rel"), a.relationships);
  if (a.unsolicited) kv(t("k_notice"), t("notice_v", { at: a.unsolicited.subjectNotifiedAt.replace("T", " ").replace("Z", " UTC"), via: a.unsolicited.subjectContact.replace(/^mailto:/, "") }));
  kv(t("k_applies"), t("applies_v", { src: a.artifact.source, rev: a.artifact.revision.slice(0, 19) + "…" }) + (a.artifact.artifactHash ? t("applies_pin", { pin: a.artifact.artifactHash.slice(0, 19) + "…" }) : ""));
  body.append(dl);

  const links = el("p", "links");
  const link = (href, text) => { const x = el("a", "", text); x.href = href; links.append(x); };
  link(verdictPage(e.attestationId), t("l_verdict"));
  link(local(e.attestation.uri), t("l_att"));
  if (a.findingsReport) link(local(a.findingsReport.uri), t("l_report"));
  link(local(a.methodology.uri), t("l_method"));
  link(local(a.scope.uri), t("l_scope"));
  body.append(links);

  for (const r of e.responses ?? []) {
    try {
      const txt = await get(local(r.uri));
      if ((await digest(new TextEncoder().encode(txt))) !== r.digest) continue;
      const resp = plain(parseStrict(txt));
      const q = el("blockquote", "reply");
      q.append(el("b", "", t("replied")), document.createTextNode(resp.text));
      body.append(q);
    } catch { /* a missing reply is shown as nothing, never as agreement */ }
  }
  if (d.error && !["status-unknown", "uncredited"].includes(d.display)) body.append(el("p", "note", `verify: ${d.error}`));
  for (const n of d.notes ?? []) body.append(el("p", "note", n));
  row.append(side, body);
  return row;
}

main();
