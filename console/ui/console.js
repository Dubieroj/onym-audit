// Auditor console. Every string that comes from a repository, an order, or
// the engine is rendered as text, never as markup.
const TOKEN = document.querySelector('meta[name="console-token"]').content;
const $ = (id) => document.getElementById(id);
const el = (tag, props = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null && v !== false) n.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids.flat()) if (k != null) n.append(k.nodeType ? k : document.createTextNode(String(k)));
  return n;
};

async function api(path, body) {
  const opts = body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json", "X-Console-Token": TOKEN }, body: JSON.stringify(body) };
  const r = await fetch(path, opts);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
  return data;
}

let toastTimer;
function toast(msg, bad = false) {
  const t = $("toast");
  t.textContent = msg;
  t.className = "toast" + (bad ? " bad" : "");
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), bad ? 9000 : 3500);
}
const guard = (fn) => async (...a) => { try { await fn(...a); } catch (e) { toast(e.message, true); } };

let S = null;          // /api/state
let current = null;    // selected review
let tab = "findings";
let poll = null;

// ---------------------------------------------------------------- sidebar

async function refresh() {
  S = await api("/api/state");
  $("who").textContent = S.auditor.name;
  $("fp").textContent = " · " + S.auditor.fingerprint;
  const e = S.engine;
  $("engine-state").textContent = e.ready ? `engine: ${e.provider} ✓` : `engine: ${e.provider} — no key`;
  $("engine-state").className = "chip " + (e.ready ? "ok" : "warn");
  $("engine-state").title = e.problem || "";
  $("orders-count").textContent = S.orders.length || "";
  $("reviews-count").textContent = S.reviews.length || "";
  $("orders").replaceChildren(...(S.orders.length ? S.orders.map(orderItem) : [el("li", { class: "muted small", text: "No orders pulled yet." })]));
  $("reviews").replaceChildren(...(S.reviews.length ? S.reviews.map(reviewItem) : [el("li", { class: "muted small", text: "No reviews yet." })]));
}

function orderItem(o) {
  const li = el("li", { class: "item" + (o.valid ? "" : " invalid") },
    el("div", { class: "item-title mono", text: o.id }),
    el("div", { class: "small", text: o.valid ? `${o.repo.replace(/^https:\/\//, "")} @ ${o.commit.slice(0, 10)}` : o.problem }),
    el("div", { class: "small muted", text: `${o.contact.replace(/^mailto:/, "")} · ${o.receivedAt}` }));
  if (o.reviewId) li.append(el("button", { class: "link", text: "open review →", onclick: () => openReview(o.reviewId) }));
  else if (o.valid) li.append(el("div", { class: "row" },
    el("button", { class: "small-btn", text: "Start LLM review", onclick: guard(() => startFromOrder(o, "llm")) }),
    el("button", { class: "small-btn ghost", text: "Manual", onclick: guard(() => startFromOrder(o, "manual")) })));
  li.append(el("details", {}, el("summary", { text: "scope" }), el("pre", { class: "scope", text: o.scope })));
  if (o.terms) li.append(el("details", {}, el("summary", { text: "terms you countersign" }), el("pre", { class: "scope", text: o.terms })));
  return li;
}

function reviewItem(r) {
  const state = r.signed ? (r.signed.heldUntil ? "held" : "signed") : r.blockers.length ? "open" : "ready";
  return el("li", { class: "item clickable" + (current && current.id === r.id ? " active" : ""), onclick: () => openReview(r.id) },
    el("div", { class: "row" }, el("span", { class: "item-title mono", text: r.id }), el("span", { class: `chip s-${state}`, text: state })),
    el("div", { class: "small", text: `${r.kind === "llm" ? "LLM" : "manual"} · ${r.repo.replace(/^https:\/\//, "")} @ ${r.commit.slice(0, 10)}` }),
    r.orderId ? el("div", { class: "small muted", text: "order " + r.orderId }) : null);
}

async function startFromOrder(o, kind) {
  toast("Checking out " + o.commit.slice(0, 10) + "…");
  const r = await api("/api/reviews", { kind, orderId: o.id });
  await refresh();
  openReview(r.id);
}

$("new-review").addEventListener("submit", guard(async (ev) => {
  ev.preventDefault();
  const f = new FormData(ev.target);
  toast("Checking out…");
  const r = await api("/api/reviews", { kind: f.get("kind"), repo: f.get("repo").trim(), commit: f.get("commit").trim().toLowerCase(), scope: f.get("scope") });
  ev.target.reset();
  await refresh();
  openReview(r.id);
}));

$("pull").addEventListener("click", guard(async () => {
  toast("Pulling orders from " + S.deployHost + "…");
  S = await api("/api/orders/pull", {});
  await refresh();
  toast(`${S.orders.length} order(s) in the local inbox`);
}));

$("publish").addEventListener("click", guard(async () => {
  if (!confirm("Run deploy/deploy.sh now? It runs every test, then pushes the public tree and restarts the server.")) return;
  const { job } = await api("/api/publish", {});
  $("job-out").textContent = "running…";
  $("job").showModal();
  const tick = async () => {
    const j = await api("/api/jobs/" + job);
    $("job-out").textContent = j.output || "running…";
    if (j.state === "running") setTimeout(tick, 2000);
    else toast(j.state === "done" ? "Published." : "Publish failed — see the log.", j.state !== "done");
  };
  tick();
}));

// ---------------------------------------------------------------- review

async function openReview(id) {
  clearTimeout(poll);
  if (!current || current.id !== id) {
    files = [];
    fileState = { path: null, lines: [], sel: null };
  }
  current = await api("/api/reviews/" + id);
  render();
  refresh();
  if (current.agent && current.agent.state === "running") poll = setTimeout(() => openReview(id), 3000);
}

function render() {
  const r = current;
  const head = el("div", { class: "rhead" },
    el("div", {},
      el("h1", { class: "mono", text: r.repo.replace(/^https:\/\//, "") }),
      el("div", { class: "muted mono small", text: `${r.commit} · ${r.kind === "llm" ? "security-review-llm-v1" : "security-review-manual-v1"}${r.orderId ? " · order " + r.orderId : ""}` }),
      el("pre", { class: "scope", text: r.scope })),
    el("div", { class: "verdict" },
      el("div", { class: "small muted", text: r.signed ? "signed result" : "result if signed now" }),
      el("div", { class: `stamp r-${r.signed ? r.signed.result : r.resultClass}`, text: (r.signed ? r.signed.result : r.resultClass).toUpperCase() }),
      r.blockers.length && !r.signed ? el("ul", { class: "blockers" }, r.blockers.map((b) => el("li", { text: b }))) : null));
  const avail = ["findings", "code", r.kind === "llm" ? "engine" : "coverage", "sign"];
  if (!avail.includes(tab)) tab = "findings";
  const tabs = el("nav", { class: "tabs" }, avail.map((t) =>
    el("button", { class: t === tab ? "on" : "", text: t, onclick: () => { tab = t; render(); } })));
  const body = { findings: findingsView, code: codeView, engine: engineView, coverage: coverageView, sign: signView }[tab]();
  $("main").replaceChildren(head, tabs, body);
}

const sevRank = (s) => (S?.severities || []).indexOf(s);

function findingsView() {
  const r = current;
  const wrap = el("div", { class: "findings" });
  if (!r.findings.length) wrap.append(el("p", { class: "muted", text: r.kind === "llm" ? "No findings yet. Run the engine from the engine tab." : "No findings yet. Open the code tab, select lines, and record a finding." }));
  for (const f of [...r.findings].sort((a, b) => sevRank(a.severity) - sevRank(b.severity))) {
    const card = el("article", { class: `finding st-${f.status}` },
      el("div", { class: "row" },
        el("span", { class: `sev sev-${f.severity}`, text: f.severity }),
        el("b", { text: `${f.id} · ${f.title}` }),
        el("span", { class: "chip", text: f.source }),
        el("span", { class: `chip st-${f.status}`, text: f.status })),
      el("button", { class: "link mono small", text: `${f.path}:${f.lineStart}-${f.lineEnd}`, onclick: () => { tab = "code"; showFile(f.path, f.lineStart, f.lineEnd); } }),
      el("pre", { class: "quote", text: f.quote }),
      el("p", { text: f.description }),
      el("p", { class: "small muted", text: "Fix: " + f.recommendation + " · confidence " + f.confidence }),
      f.dropReason ? el("p", { class: "small drop", text: "Dropped: " + f.dropReason }) : null);
    if (!r.signed) {
      const reason = el("input", { placeholder: "reason for dropping (published)", class: "grow" });
      card.append(el("div", { class: "row decide" },
        el("button", { class: "small-btn", text: "Keep", onclick: guard(() => decide(f.id, "keep")) }),
        reason,
        el("button", { class: "small-btn ghost", text: "Drop", onclick: guard(() => decide(f.id, "drop", reason.value)) }),
        f.source === "auditor" ? el("button", { class: "small-btn ghost", text: "Delete", onclick: guard(() => decide(f.id, "delete")) }) : null));
    }
    wrap.append(card);
  }
  if (r.rejected?.length) {
    wrap.append(el("details", { class: "rejected" }, el("summary", { text: `${r.rejected.length} engine finding(s) rejected by the evidence check` }),
      el("ul", {}, r.rejected.map((f) => el("li", { class: "small", text: `${f.title} — ${f.rejection}` })))));
  }
  return wrap;
}

async function decide(id, action, reason = "") {
  current = await api(`/api/reviews/${current.id}/findings/${id}`, { action, reason });
  render();
}

// ---------------------------------------------------------------- code

let files = [];
let fileState = { path: null, lines: [], sel: null };

function codeView() {
  const filter = el("input", { placeholder: "filter files", class: "filter" });
  const list = el("ul", { class: "tree" });
  const viewer = el("div", { class: "viewer", id: "viewer" }, el("p", { class: "muted", text: "Pick a file." }));
  const fill = () => {
    const q = filter.value.toLowerCase();
    list.replaceChildren(...files.filter((f) => f.toLowerCase().includes(q)).slice(0, 800).map((f) =>
      el("li", { class: f === fileState.path ? "on" : "", text: f, onclick: () => showFile(f) })));
  };
  filter.addEventListener("input", fill);
  (files.length ? Promise.resolve(files) : api(`/api/reviews/${current.id}/tree`)).then((fs) => { files = fs; fill(); if (fileState.path) drawFile(); });
  return el("div", { class: "code" }, el("div", { class: "tree-col" }, filter, list), viewer);
}

async function showFile(path, from, to) {
  if (tab !== "code") { tab = "code"; render(); }
  const lines = await api(`/api/reviews/${current.id}/file?path=` + encodeURIComponent(path));
  fileState = { path, lines, sel: from ? [from, to || from] : null };
  drawFile();
}

function drawFile() {
  const v = $("viewer");
  if (!v || !fileState.path) return;
  const [a, b] = fileState.sel || [0, -1];
  const rows = fileState.lines.map((text, i) => {
    const n = i + 1;
    return el("div", { class: "ln" + (n >= a && n <= b ? " sel" : ""), "data-n": n, onclick: (ev) => select(n, ev.shiftKey) },
      el("span", { class: "num", text: n }), el("span", { class: "src", text: text || " " }));
  });
  const pre = el("div", { class: "src-view" }, rows);
  v.replaceChildren(el("div", { class: "row file-head" }, el("b", { class: "mono", text: fileState.path }), el("span", { class: "small muted", text: current.kind === "manual" && !current.signed ? "click a line, shift-click to extend, then record a finding" : "read-only" })), pre, findingForm());
  const first = pre.querySelector(".sel");
  if (first) first.scrollIntoView({ block: "center" });
}

function select(n, extend) {
  if (extend && fileState.sel) fileState.sel = [Math.min(fileState.sel[0], n), Math.max(fileState.sel[1], n)];
  else fileState.sel = [n, n];
  drawFile();
}

function findingForm() {
  if (current.kind !== "manual" || current.signed || !fileState.sel) return null;
  const [a, b] = fileState.sel;
  if (b - a + 1 > 60) return el("p", { class: "warn", text: "Cite at most 60 lines." });
  const quote = fileState.lines.slice(a - 1, b).join("\n");
  const sev = el("select", {}, (S.severities || []).map((s) => el("option", { value: s, text: s })));
  const conf = el("select", {}, ["high", "medium", "low"].map((s) => el("option", { value: s, text: "confidence: " + s })));
  const title = el("input", { placeholder: "title — one line naming the defect", class: "grow" });
  const desc = el("textarea", { rows: 3, placeholder: "what is wrong, why it matters, how it is reached" });
  const rec = el("textarea", { rows: 2, placeholder: "what would fix it" });
  return el("form", { class: "finding-form", onsubmit: guard(async (ev) => {
      ev.preventDefault();
      current = await api(`/api/reviews/${current.id}/findings`, { severity: sev.value, confidence: conf.value, title: title.value, path: fileState.path, lineStart: a, lineEnd: b, quote, description: desc.value, recommendation: rec.value });
      toast("Finding recorded — evidence verified");
      fileState.sel = null;
      render();
    }) },
    el("div", { class: "small muted", text: `Record a finding at ${fileState.path}:${a}-${b}` }),
    el("div", { class: "row" }, sev, conf, title), desc, rec, el("button", { type: "submit", text: "Record finding" }));
}

// ---------------------------------------------------------------- engine / coverage

function engineView() {
  const r = current, a = r.agent;
  const box = el("div", { class: "panel" });
  if (!a) {
    box.append(
      el("p", { text: `The engine reads the checkout through read-only tools and reports findings with verbatim quotes. It runs on this machine through ${S.engine.provider}; its prompt is the published one.` }),
      S.engine.ready ? null : el("p", { class: "warn", text: S.engine.problem }),
      el("div", { class: "row" },
        el("button", { disabled: !S.engine.ready, text: "Run the engine", onclick: guard(async () => { current = await api(`/api/reviews/${r.id}/agent`, {}); openReview(r.id); }) })));
    return box;
  }
  box.append(el("dl", { class: "kv" },
    ...[["state", a.state], ["provider", a.provider], ["model", a.model], ["effort", a.effort], ["started", a.started], ["finished", a.finished || "—"], ["turns", a.iterations], ["stop", a.stopReason || "—"], ["prompt", a.promptDigest], ["transcript", a.transcriptDigest || "—"]]
      .map(([k, v]) => el("div", {}, el("dt", { text: k }), el("dd", { class: "mono small", text: String(v) })))));
  if (a.state === "running") box.append(el("p", { class: "muted", text: "Running — this view refreshes every few seconds." }));
  if (a.state === "error") box.append(el("p", { class: "warn", text: a.error }));
  if (a.state === "done") box.append(el("h3", { text: "Engine's coverage statement" }), coverageSummary(r.coverage));
  return box;
}

function coverageSummary(c) {
  return el("div", { class: "cov" },
    el("p", { text: c.summary || "—" }),
    el("p", { class: "small", text: `complete: ${c.complete ? "yes" : "no"}` }),
    el("p", { class: "small", text: "examined: " + (c.examined || []).join(", ") }),
    el("p", { class: "small", text: "not examined: " + (c.notExamined || []).join("; ") }));
}

function coverageView() {
  const c = current.coverage;
  if (current.signed) return coverageSummary(c);
  const summary = el("textarea", { rows: 3, placeholder: "two or three sentences on what the examination found" }); summary.value = c.summary || "";
  const ex = el("textarea", { rows: 3, placeholder: "examined: one file or area per line" }); ex.value = (c.examined || []).join("\n");
  const nx = el("textarea", { rows: 3, placeholder: "not examined, and why: one per line" }); nx.value = (c.notExamined || []).join("\n");
  const complete = el("input", { type: "checkbox" }); complete.checked = !!c.complete;
  const lines = (t) => t.value.split("\n").map((s) => s.trim()).filter(Boolean);
  return el("form", { class: "panel stack", onsubmit: guard(async (ev) => {
      ev.preventDefault();
      current = await api(`/api/reviews/${current.id}/coverage`, { summary: summary.value, examined: lines(ex), notExamined: lines(nx), complete: complete.checked });
      toast("Coverage recorded");
      render();
    }) },
    el("p", { class: "muted", text: "State plainly what you examined and what you did not. An honest “not examined” is worth more than a thin claim of coverage." }),
    summary, ex, nx, el("label", { class: "row" }, complete, " The whole stated scope was examined"), el("button", { type: "submit", text: "Save coverage" }));
}

// ---------------------------------------------------------------- sign

function signView() {
  const r = current;
  if (r.signed) {
    const s = r.signed;
    const held = s.heldUntil ? el("div", { class: "panel" },
      el("p", { class: "warn", text: `Held until ${s.heldUntil}: ${Object.keys(s.held || {}).join(", ")}` }),
      el("button", { text: "Release held files", onclick: guard(async () => { current = await api(`/api/reviews/${r.id}/release`, {}); toast("Released — now publish"); render(); }) })) : null;
    return el("div", { class: "stack" },
      el("div", { class: "panel" },
        el("p", {}, "Signed ", el("b", { class: "mono", text: s.attestationId }), " — result ", el("b", { text: s.result })),
        el("p", { class: "mono small", text: s.attestation.uri }),
        el("p", { class: "mono small muted", text: s.attestation.digest }),
        el("p", { class: "small", text: s.heldUntil ? "The attestation or its report is held; publish after release." : "Written to the public tree and the local status list. Press Publish to push it to the server." })),
      held);
  }
  const f = {};
  const input = (name, props = {}) => (f[name] = el("input", { name, ...props }));
  const nowISO = new Date().toISOString().slice(0, 19) + "Z";
  const order = S.orders.find((o) => o.id === r.orderId);
  const fields = [
    field("Attestation id", input("attestationId", { value: "att-" + r.id, class: "mono" })),
    field("Relationships with the subject", input("relationships", { value: "none" }), "published verbatim; “none” when none"),
  ];
  if (order) {
    fields.push(el("p", { class: "small", text: `Commissioned by order ${order.id}: subject ${order.subject}, subject key ${order.subjectKey.slice(0, 22)}…. The order will be countersigned and published with these terms:` }));
    fields.push(el("pre", { class: "scope", text: order.terms }));
    fields.push(field("Findings sent to the subject at", input("findingsSentAt", { value: nowISO, class: "mono" }), "the order requires findings to reach the subject first — RFC 3339 UTC"));
  } else {
    fields.push(field("Subject component", input("subject", { placeholder: "onym:component:…", class: "mono" })));
    fields.push(field("Subject operator key", input("subjectOperator", { placeholder: "onym:key:… — whose signed reply you will accept", class: "mono" })));
    fields.push(field("Subject contact notified", input("contact", { placeholder: "mailto:security@…" })));
    fields.push(field("Notified at", input("notifiedAt", { value: nowISO, class: "mono" }), "must be before publication — RFC 3339 UTC"));
  }
  fields.push(field("Hold the findings report until", input("holdReportUntil", { placeholder: "empty = publish the report now", class: "mono" }), "for exploitable findings: the attestation circulates with counts and the report's digest"));
  return el("form", { class: "panel stack", onsubmit: guard(async (ev) => {
      ev.preventDefault();
      const body = Object.fromEntries(Object.entries(f).map(([k, v]) => [k, v.value.trim()]));
      if (!confirm(`Sign ${body.attestationId} with result ${r.resultClass.toUpperCase()} using your auditor key?\n\nAttestations are immutable: corrections are supersessions or revocations.`)) return;
      current = await api(`/api/reviews/${r.id}/sign`, body);
      toast("Signed. Press Publish to push it.");
      refresh();
      render();
    }) },
    r.blockers.length ? el("ul", { class: "blockers" }, r.blockers.map((b) => el("li", { text: b }))) : el("p", { text: `Ready to sign: result ${r.resultClass.toUpperCase()}.` }),
    ...fields,
    el("button", { type: "submit", disabled: r.blockers.length > 0, text: "Sign with the auditor key" }));
}

function field(label, input, hint) {
  return el("label", { class: "field" }, el("span", { text: label }), input, hint ? el("small", { class: "muted", text: hint }) : null);
}

refresh().catch((e) => toast(e.message, true));
