// The page of one attestation: /verdict/?id=<attestationId> for this site's
// seat, /verdict/?a=<name>&id=<attestationId> for an auditor on the hub.
// Everything shown is fetched as signed bytes and checked in this browser —
// the manifest, the attestation, the status list, and every document the
// attestation pins by digest (scope, methodology, findings report,
// revocation, the subject's replies) — and the register's Stellar anchor is
// asked of a public Stellar node. Nothing is trusted because this server
// says so, and every string from those documents is shown as text only.
import { parseStrict, plain, digest, fingerprint, verifySig, verifyAttestation } from "./verify.js";
import { accountOfKey } from "./onym-id.js";
import { anchorState, NETWORK } from "./stellar.js";

const $ = (id) => document.getElementById(id);
const ROOT = new URL(".", import.meta.url);
const T = JSON.parse($("strings")?.textContent || "{}");
const t = (k, v = {}) => (T[k] ?? k).replace(/\{(\w+)\}/g, (_, x) => v[x] ?? "");
const enc = new TextEncoder();
const LANG_PATH = { ru: "ru/", "sr-Latn-ME": "cnr/" }[document.documentElement.lang] || "";

const el = (tag, props = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (v !== undefined && v !== null && v !== false) n.setAttribute(k, v === true ? "" : v);
  }
  for (const c of kids.flat()) if (c != null) n.append(c.nodeType ? c : document.createTextNode(String(c)));
  return n;
};
const kv = (rows) => el("dl", { class: "kv" }, rows.filter(Boolean).map(([k, v]) => el("div", {}, el("dt", { text: k }), el("dd", {}, v))));
// Links come partly from documents an auditor wrote: only https: or this
// site's own addresses become links; anything else is shown as text.
const safeHref = (href) => {
  try {
    const u = new URL(href, location.href);
    return u.protocol === "https:" || u.origin === location.origin ? u.href : null;
  } catch { return null; }
};
const link = (href, text) => {
  const h = safeHref(href);
  return h ? el("a", { href: h, text: text ?? href, rel: "noopener" }) : el("span", { class: "mono", text: text ?? href });
};
const ok = (good, text) => el("li", { class: good ? "ok" : "bad", text: (good ? "✓ " : "✗ ") + text });
const when = (iso) => (iso ? iso.replace("T", " ").replace("Z", " UTC") : "—");

const params = new URLSearchParams(location.search);
// The language links keep the attestation this page shows.
for (const l of document.querySelectorAll(".langs a")) l.search = location.search;
const slug = params.get("a") || "";
const id = params.get("id") || "";
const localBase = slug ? new URL(`a/${encodeURIComponent(slug)}/`, ROOT).href : ROOT.href;
let publicBase = "";
// Documents are named under the auditor's public base; fetch them from
// wherever this page is served.
const loc = (u) => (publicBase && u.startsWith(publicBase) ? localBase + u.slice(publicBase.length) : u);
const fetchText = async (u) => {
  const r = await fetch(loc(u), { credentials: "omit", cache: "no-cache" });
  if (!r.ok) throw new Error(`${u}: HTTP ${r.status}`);
  return r.text();
};
// pinned fetches a document an attestation names by digest and checks it.
async function pinned(ref) {
  const text = await fetchText(ref.uri);
  return { text, good: (await digest(enc.encode(text))) === ref.digest };
}
const verdictURL = (other) => `?${slug ? `a=${encodeURIComponent(slug)}&` : ""}id=${encodeURIComponent(other)}`;
const section = (title, ...kids) => el("section", { class: "verdict-sec" }, el("h2", { class: "sub-h", text: title }), ...kids);

async function main() {
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(id) || (slug && !/^[a-z][a-z0-9-]{2,31}$/.test(slug))) throw new Error(t("bad_link"));
  const [manifestText, statusText] = await Promise.all([fetchText(localBase + "manifest.json"), fetchText(localBase + "status.json").catch(() => null)]);
  const m = plain(parseStrict(manifestText));
  publicBase = m.statusEndpoint.replace(/status\.json$/, "");
  const attURI = publicBase + `attestations/${id}.json`;
  const attText = await fetchText(attURI).catch(() => { throw new Error(t("not_found", { id })); });
  const a = plain(parseStrict(attText));
  const d = await verifyAttestation({ manifestText, attText, statusText, target: null, credited: false });
  const st = statusText ? plain(parseStrict(statusText)) : null;
  const entry = st?.entries.find((e) => e.attestationId === id) || null;
  const print = await fingerprint(m.operator);
  const account = accountOfKey(m.operator);
  document.title = `${a.result.toUpperCase()} · ${a.subject} · ${m.displayName}`;
  const out = $("verdict");
  out.replaceChildren();

  // Head: the verdict and whose it is.
  const state = entry ? entry.state : "unknown";
  out.append(el("header", { class: "verdict-head" },
    el("div", { class: "entry-side" }, el("span", { class: `stamp r-${a.result}`, text: a.result.toUpperCase() }), el("span", { class: `state s-${state}`, text: t("state_" + state) })),
    el("div", {}, el("p", { class: "kicker", text: t("kicker", { cls: a.methodologyClass }) }),
      el("h1", { class: "verdict-h1", text: a.subject }),
      el("p", { class: "lede" }, t("by"), " ", link(slug ? publicBase : new URL(LANG_PATH, ROOT).href, m.displayName), ` · ${print} · ${t("issued", { at: when(a.issuedAt) })} · ${t("expires", { at: when(a.expiresAt) })}`),
      el("p", { class: "mono small", text: id }))));

  // Verification in this browser.
  const good = d.display === "attested" || d.display === "uncredited";
  const checks = el("ul", { class: "checks" },
    ok(!["auditor_manifest_invalid"].includes(d.error), t("c_manifest", { fp: print })),
    ok(d.error !== "attestation_invalid", t("c_attestation")),
    ok(!!entry && !["status_list_invalid", "status_unavailable"].includes(d.error), entry ? t("c_status", { state: t("state_" + entry.state), at: when(st.issuedAt) }) : t("c_status_missing")),
    ok(d.display !== "expired", t("c_expiry", { at: when(a.expiresAt) })));
  const anchorLine = el("li", { class: "muted", text: t("c_anchor_checking") });
  checks.append(anchorLine);
  out.append(section(t("h_verify"), el("p", { class: good ? "ok-line" : "bad", text: good ? t("verdict_ok") : t("verdict_bad", { state: d.display, err: d.error || "" }) }), checks));
  if (statusText) {
    anchorState(account, statusText).then((s) => {
      anchorLine.className = s.state === "match" ? "ok" : "";
      anchorLine.replaceChildren(t("anchor_" + s.state, { at: when(s.at) }), " ", link(NETWORK.explorer + account, "stellar.expert ↗"));
    }, () => (anchorLine.textContent = t("anchor_unknown")));
  }

  // What was examined, bound to which bytes, under which method.
  const x = a.artifact;
  const scopeBox = el("div", {}, el("p", { class: "small muted", text: t("loading") }));
  const methodBox = el("span", { text: "…" });
  out.append(section(t("h_what"),
    kv([
      [t("k_kind"), t("kind_" + x.kind)],
      [t("k_source"), link(x.source)],
      [x.kind === "deployment" ? t("k_manifest_digest") : t("k_revision"), el("span", { class: "mono", text: x.revision })],
      x.artifactHash ? [x.kind === "build" ? t("k_build_digest") : t("k_document_digest"), el("span", { class: "mono", text: x.artifactHash })] : null,
      [t("k_method"), methodBox],
      [t("k_scope_summary"), a.scopeSummary],
      [t("k_not_examined"), el("ul", { class: "judge-list" }, a.exclusions.map((e) => el("li", { text: e })))],
    ]), el("details", { class: "verdict-doc" }, el("summary", { text: t("h_scope") }), scopeBox)));
  pinned(a.methodology).then((p) => methodBox.replaceChildren(link(a.methodology.uri, a.methodologyClass), " ", el("span", { class: p.good ? "ok-line" : "bad", text: p.good ? t("pinned_ok") : t("pinned_bad") })), () => methodBox.replaceChildren(link(a.methodology.uri, a.methodologyClass)));
  pinned(a.scope).then((p) => scopeBox.replaceChildren(el("p", { class: "small " + (p.good ? "ok-line" : "bad"), text: p.good ? t("pinned_ok") : t("pinned_bad") }), el("pre", { class: "quote", text: p.text })), (e) => scopeBox.replaceChildren(el("p", { class: "bad", text: e.message })));

  // Findings.
  const counts = Object.entries(a.findingsSummary).map(([k, v]) => `${v} ${k}`).join(", ") || t("none");
  const findings = el("div", {}, el("p", {}, el("b", { text: t("summary") }), " ", counts, " ", el("span", { class: "muted", text: t("floor", { floor: a.severityFloor || "—" }) })));
  out.append(section(t("h_findings"), findings));
  let report = Promise.resolve(null);
  if (!a.findingsReport) findings.append(el("p", { class: "note", text: t("report_withheld") }));
  else {
    const box = el("div", {}, el("p", { class: "small muted", text: t("loading") }));
    findings.append(box);
    report = pinned(a.findingsReport).then((p) => ({ good: p.good, r: plain(parseStrict(p.text)) }));
    report.then(({ good, r }) => renderReport(box, r, good, a.findingsReport.uri), (e) => box.replaceChildren(el("p", { class: "bad", text: e.message })));
  }

  // Who paid, who is related, who was told.
  const u = a.unsolicited;
  out.append(section(t("h_engagement"), kv([
    [t("k_engagement"), t("eng_" + a.engagement)],
    [t("k_sponsor"), `${a.sponsorName} · ${await fingerprint(a.sponsor)}`],
    [t("k_relationships"), a.relationships],
    u ? [t("k_notice"), t("notice", { contact: u.subjectContact, at: when(u.subjectNotifiedAt) })] : null,
    u ? [t("k_policy"), link(m.unsolicitedPolicy.uri, t("policy_link"))] : null,
    u && u.embargoUntil ? [t("k_embargo"), when(u.embargoUntil)] : null,
    a.orderRef ? [t("k_order"), el("span", { class: "mono", text: a.orderRef })] : null,
    [t("k_subject_key"), el("span", { class: "mono", text: `${await fingerprint(a.subjectOperator)} (${accountOfKey(a.subjectOperator)})` })],
  ])));

  // Status: revocation, supersession, replies.
  const statusBox = el("div");
  out.append(section(t("h_status"), statusBox));
  if (!entry) statusBox.append(el("p", { class: "note", text: t("c_status_missing") }));
  else {
    statusBox.append(kv([[t("k_state"), t("state_" + entry.state)], entry.supersededBy ? [t("k_superseded"), link(verdictURL(entry.supersededBy), entry.supersededBy)] : null]));
    if (entry.revocation) {
      const r = await pinned(entry.revocation).catch(() => null);
      if (r) {
        const rv = plain(parseStrict(r.text));
        statusBox.append(el("p", { class: "reply" }, t("revoked", { at: when(rv.effectiveFrom), reason: rv.reason })));
      }
    }
    const replies = entry.responses || [];
    statusBox.append(el("h3", { text: t("h_replies") }));
    if (!replies.length) statusBox.append(el("p", { class: "small muted", text: t("no_replies") }));
    for (const ref of replies) {
      const p = await pinned(ref).catch(() => null);
      if (!p) continue;
      const r = plain(parseStrict(p.text));
      const signed = p.good && r.respondent === a.subjectOperator && (await verifySig(p.text, r.respondent).catch(() => false));
      statusBox.append(el("div", { class: "reply" }, el("p", { class: "small " + (signed ? "ok-line" : "bad"), text: signed ? t("reply_ok", { at: when(r.issuedAt) }) : t("reply_bad") }), el("p", { text: r.text })));
    }
  }

  // Documents, and how to check it without this page.
  const target = x.kind === "source" || x.kind === "build" ? ` \\\n  -target ${x.source} -target-commit ${x.revision}` : ` \\\n  -target ${x.source}`;
  const pinsDoc = x.kind === "deployment" && !!x.artifactHash;
  const cmd = (doc) => `bin/onym-audit verify \\\n  -manifest ${publicBase}manifest.json \\\n  -attestation ${attURI}${target}`
    + (pinsDoc ? ` \\\n  -target-document ${doc}` : "") + ` \\\n  -credit ${m.operator}`;
  const code = el("code", { text: cmd("<document>") });
  out.append(section(t("h_documents"),
    el("p", { class: "links" }, link(attURI, t("l_attestation")), link(publicBase + "manifest.json", t("l_manifest")), link(m.statusEndpoint, t("l_status")), a.findingsReport ? link(a.findingsReport.uri, t("l_report")) : null),
    el("p", { class: "small muted", text: t("cli_h") }),
    el("div", { class: "terminal" }, el("pre", {}, code))));
  // A deployment attestation may also pin a further served document (a
  // catalog snapshot); the findings report names where it was fetched.
  if (pinsDoc) report.then((rp) => {
    const doc = rp?.r.suiteReport?.documents?.find((x2) => x2.digest === x.artifactHash);
    if (doc) code.textContent = cmd(doc.uri);
  }, () => {});
}

// renderReport shows a findings report: a conformance run's failing checks
// and observations, or a review's findings with the lines they quote.
function renderReport(box, r, good, uri) {
  box.replaceChildren(el("p", { class: "small " + (good ? "ok-line" : "bad"), text: good ? t("report_ok") : t("pinned_bad") }));
  if (r.suiteReport) {
    const s = r.suiteReport;
    const counts = {};
    for (const c of s.checks) counts[c.outcome] = (counts[c.outcome] || 0) + 1;
    box.append(el("p", {}, el("b", { text: `${s.suite} ${s.suiteVersion}` }), ` · ${when(s.runAt)} · `, el("span", { class: `stamp r-${s.result}`, text: s.result.toUpperCase() }), " ", Object.entries(counts).map(([k, v]) => `${v} ${k}`).join(", ")));
    const bad = s.checks.filter((c) => c.outcome === "fail" || c.outcome === "inconclusive");
    box.append(...bad.map((c) => el("article", { class: "entry" },
      el("div", { class: "entry-side" }, el("span", { class: `stamp sev-${c.level === "MUST" ? "high" : "low"}`, text: `${c.outcome.toUpperCase()} · ${c.level}` })),
      el("div", {}, el("h3", { text: c.title || c.id }), el("p", { class: "small mono", text: `${c.id} · ${c.clause}` }), el("p", { text: c.detail })))));
    for (const o of r.observations || []) {
      box.append(el("article", { class: "entry" },
        el("div", { class: "entry-side" }, el("span", { class: `stamp sev-${o.severity}`, text: o.severity.toUpperCase() })),
        el("div", {}, el("h3", { text: o.title }), el("p", { text: o.detail }), el("p", { class: "links" }, (o.evidence || []).map((e) => link(e.uri, e.uri.split("/").pop()))))));
    }
    box.append(el("details", {}, el("summary", { text: t("all_checks", { n: s.checks.length }) }),
      el("ul", { class: "checks" }, s.checks.map((c) => el("li", { class: c.outcome === "pass" ? "ok" : c.outcome === "fail" ? "bad" : "", text: `${c.outcome} · ${c.level} · ${c.id} — ${c.detail}` })))));
    box.append(el("details", {}, el("summary", { text: t("documents_fetched", { n: s.documents.length }) }),
      el("ul", { class: "checks" }, s.documents.map((x) => el("li", {}, `${x.role} · `, link(x.uri), ` · ${x.digest}`)))));
    return;
  }
  const list = r.findings || [];
  if (r.coverage) {
    const cv = r.coverage;
    box.append(kv([
      cv.summary ? [t("k_coverage"), cv.summary] : null,
      cv.examined?.length ? [t("k_examined"), el("ul", { class: "judge-list" }, cv.examined.map((x) => el("li", { text: typeof x === "string" ? x : JSON.stringify(x) })))] : null,
      cv.notExamined?.length ? [t("k_not_examined"), el("ul", { class: "judge-list" }, cv.notExamined.map((x) => el("li", { text: typeof x === "string" ? x : JSON.stringify(x) })))] : null,
    ]));
  }
  if (!list.length) box.append(el("p", { class: "empty", text: t("no_findings") }));
  box.append(...list.map((f) => el("article", { class: "entry" },
    el("div", { class: "entry-side" }, el("span", { class: `stamp sev-${f.severity}`, text: f.severity.toUpperCase() }), el("span", { class: "state", text: f.id })),
    el("div", {}, el("h3", { text: f.title }),
      f.path ? el("p", { class: "small mono", text: `${f.path}:${f.lineStart}-${f.lineEnd}` }) : null,
      f.quote ? el("pre", { class: "quote", text: f.quote }) : null,
      el("p", { text: f.description }),
      f.recommendation ? el("p", { class: "small" }, el("b", { text: t("fix") }), " ", f.recommendation) : null))));
  const dropped = r.auditorReview?.dropped || [];
  if (dropped.length) box.append(el("details", {}, el("summary", { text: t("dropped", { n: dropped.length }) }), el("ul", { class: "judge-list" }, dropped.map((x) => el("li", { text: `${x.id} · ${x.title} — ${x.reason}` })))));
  if (r.engine) box.append(el("p", { class: "note", text: t("engine", { model: r.engine.model, provider: r.engine.provider }) }), r.transcript ? el("p", { class: "links" }, link(r.transcript.uri, t("l_transcript"))) : null);
  box.append(el("p", { class: "links" }, link(uri, t("l_report"))));
}

main().catch((e) => $("verdict").replaceChildren(el("p", { class: "bad", text: e.message }), el("p", {}, link(new URL(`${LANG_PATH}app/#library`, ROOT).href, t("to_library")))));
