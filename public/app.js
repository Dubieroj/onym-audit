import { verifyAttestation, parseStrict, plain, fingerprint, digest } from "./verify.js";

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text; // untrusted strings are only ever text
  return n;
};
const get = async (url) => {
  const r = await fetch(url, { credentials: "omit", cache: "no-cache" });
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  return r.text();
};
const days = (iso) => Math.floor((Date.now() - Date.parse(iso)) / 86400000);

let manifestText, statusText, manifest;

async function main() {
  try {
    manifestText = await get("manifest.json");
    manifest = plain(parseStrict(manifestText));
  } catch (e) {
    $("atts").replaceChildren(el("p", "bad", "Could not load the auditor manifest: " + e.message));
    return;
  }
  document.title = `${manifest.displayName} · Onym auditor`;
  $("who").textContent = manifest.displayName;
  $("opkey").textContent = `${await fingerprint(manifest.operator)}  (${manifest.operator})`;
  try { statusText = await get("status.json"); } catch { statusText = null; }
  if (statusText) {
    const st = plain(parseStrict(statusText));
    $("statusline").textContent = `epoch ${st.statusEpoch}, signed ${st.issuedAt}, next update by ${st.nextUpdate}`;
  } else {
    $("statusline").textContent = "unavailable";
  }
  $("credit").addEventListener("change", render);
  await render();
}

async function render() {
  const box = $("atts");
  if (!statusText) { box.replaceChildren(el("p", "bad", "No status list: attestations cannot be checked as current.")); return; }
  const st = plain(parseStrict(statusText));
  if (st.entries.length === 0) { box.replaceChildren(el("p", "hint", "No attestations issued yet.")); return; }
  const cards = [];
  for (const e of st.entries) cards.push(await card(e));
  box.replaceChildren(...cards);
}

async function card(entry) {
  const c = el("article", "card");
  let attText;
  try { attText = await get(entry.attestation.uri.replace(/^.*\/attestations\//, "attestations/")); } catch (e) {
    c.append(el("p", "bad", `Attestation ${entry.attestationId} could not be fetched: ${e.message}`));
    return c;
  }
  const credited = $("credit").checked;
  const d = await verifyAttestation({ manifestText, attText, statusText, target: null, credited });
  const a = d.att ?? plain(parseStrict(attText));

  const head = el("div", "cardhead");
  head.append(el("span", `result r-${a.result}`, a.result.toUpperCase()), el("span", `state s-${d.display}`, d.display));
  c.append(head);
  c.append(el("h3", "", `${a.subject} — ${a.methodologyClass}`));
  const line = `${manifest.displayName} attested this ${days(a.issuedAt)} day(s) ago` + (a.expiresAt ? `; expires ${a.expiresAt}.` : ".");
  c.append(el("p", "who", line));

  const dl = el("dl", "kv");
  const row = (k, v) => { const w = el("div"); w.append(el("dt", "", k), el("dd", "", v)); dl.append(w); };
  row("Scope", a.scopeSummary);
  row("Not examined", a.exclusions.join("; ") || "—");
  row("Findings", (Object.entries(a.findingsSummary).map(([k, v]) => `${v} ${k}`).join(", ") || "none") + (a.severityFloor ? ` (floor: ${a.severityFloor})` : ""));
  row("Paid by", `${a.sponsorName} (${await fingerprint(a.sponsor)})`);
  row("Relationships", a.relationships);
  row("Engagement", a.engagement + (a.unsolicited ? ` — subject notified ${a.unsolicited.subjectNotifiedAt} via ${a.unsolicited.subjectContact}` : ""));
  row("Applies only to", `${a.artifact.source} with sha256 ${a.artifact.revision.slice(7, 23)}…` + (a.artifact.artifactHash ? ` and a pinned served document ${a.artifact.artifactHash.slice(7, 23)}…` : ""));
  c.append(dl);

  const links = el("p", "links");
  const link = (href, text) => { const x = el("a", "", text); x.href = href; links.append(x, document.createTextNode("  ")); };
  link(entry.attestation.uri.replace(/^.*\/attestations\//, "attestations/"), "attestation");
  if (a.findingsReport) link(a.findingsReport.uri.replace(/^.*\/reports\//, "reports/"), "findings report");
  link(a.methodology.uri.replace(/^.*\/methodology\//, "methodology/"), "methodology");
  c.append(links);

  for (const r of entry.responses ?? []) {
    try {
      const txt = await get(r.uri.replace(/^.*\/responses\//, "responses/"));
      if ((await digest(new TextEncoder().encode(txt))) !== r.digest) continue;
      const resp = plain(parseStrict(txt));
      const q = el("blockquote", "reply");
      q.append(el("strong", "", "Subject's reply: "), document.createTextNode(resp.text));
      c.append(q);
    } catch { /* a missing reply is shown as nothing, never as agreement */ }
  }
  if (d.error && d.display !== "status-unknown") c.append(el("p", "note", `verify: ${d.error}`));
  for (const n of d.notes ?? []) c.append(el("p", "note", n));
  return c;
}

main();
