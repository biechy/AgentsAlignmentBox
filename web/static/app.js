// AgentsAlignmentBox dashboard. Polls /api/snapshot and shows the agents as trees
// (one per session = top-level agent), an alert queue, the event stream and the
// monitor; stops (kill switch), revives and launches agents.
"use strict";

const state = {
  snap: null, view: "agents", session: null, selected: null, detail: null, detailKey: null,
  tab: "timeline", sessionFilter: "all", alertStatus: "open", alertSev: "", eventFilter: "",
};
const $ = (id) => document.getElementById(id);
const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

// -- helpers ---------------------------------------------------------------------
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}
const icon = (name) => `<svg class="ic"><use href="#i-${name}"/></svg>`;
function ago(ts) {
  if (!ts) return "never";
  const s = Math.max(0, (Date.now() - new Date(ts).getTime()) / 1000);
  if (s < 60) return `${Math.round(s)}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}
const hhmmss = (ts) => (ts ? new Date(ts).toLocaleTimeString([], { hour12: false }) : "");
function tokens(n) {
  n = n || 0;
  return n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e3 ? `${(n / 1e3).toFixed(1)}k` : `${n}`;
}
function short(s, n = 140) {
  s = String(s ?? "").replace(/\s+/g, " ").trim();
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}
function pretty(s) {
  try { return JSON.stringify(JSON.parse(s), null, 2); } catch { return s ?? ""; }
}
const statusLabel = (s) => (s === "killed" ? "stopped" : s || "");
const prov = (p) => (p === "openai"
  ? `<b class="prov cx" title="Codex">CX</b>` : `<b class="prov cc" title="Claude Code">CC</b>`);
const sevChip = (s) => `<span class="sev ${esc(s)}">${esc(s)}</span>`;
function riskColor(v) {
  return v >= 80 ? "var(--sev-critical)" : v >= 55 ? "var(--sev-high)" : v >= 30 ? "var(--flagged)" : "var(--done)";
}
const riskRing = (v, title = "risk") =>
  `<span class="risk" style="--v:${v || 0};--c:${riskColor(v || 0)}" data-v="${v || 0}" title="${title} ${v || 0}/100"></span>`;
function anomTag(score, reasons) {
  if (score == null) return "";
  const cls = score >= 0.6 ? "anom-hi" : score >= 0.3 ? "anom-mid" : "";
  const why = reasons && reasons.length ? ": " + reasons.join(", ") : "";
  return `<span class="tag ${cls}" title="tabular anomaly score${esc(why)}">${icon("cpu")}${Number(score).toFixed(2)}</span>`;
}
function toolIcon(name) {
  if (/^(Bash|shell|local_shell|exec_command|shell_command|BashOutput)$/.test(name)) return "terminal";
  if (/Web|web_/.test(name)) return "globe";
  if (/^(Write|Edit|MultiEdit|NotebookEdit|apply_patch)$/.test(name)) return "edit";
  if (/^(Agent|Task|spawn_agent)$/.test(name)) return "branch";
  if (/^(Grep|Glob|ToolSearch)$/.test(name)) return "search";
  if (/^(Read|LS|NotebookRead)$/.test(name)) return "file";
  return "tool";
}
function toolSummary(input) {
  try {
    const j = JSON.parse(input);
    return j.command ? (Array.isArray(j.command) ? j.command.join(" ") : j.command)
      : j.file_path || j.url || j.query || j.pattern || j.description || j.prompt || j.cmd || input;
  } catch { return input; }
}

async function api(path, body) {
  const opts = body === undefined ? {} : {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  };
  const r = await fetch(path, opts);
  let data = {};
  try { data = await r.json(); } catch { /* empty body */ }
  if (!r.ok && !data.error) data.error = `HTTP ${r.status}`;
  return data;
}

// -- derived data ------------------------------------------------------------------
function index() {
  const agents = state.snap?.agents || [];
  const byId = new Map(agents.map((a) => [a.agent_id, a]));
  const children = new Map();
  for (const a of agents) {
    const k = a.parent_id || "";
    if (!children.has(k)) children.set(k, []);
    children.get(k).push(a);
  }
  const rootOf = (id) => {
    let a = byId.get(id);
    const seen = new Set();
    while (a && a.parent_id && byId.has(a.parent_id) && !seen.has(a.agent_id)) {
      seen.add(a.agent_id);
      a = byId.get(a.parent_id);
    }
    return a ? a.agent_id : null;
  };
  const tree = (id) => [byId.get(id), ...(children.get(id) || []).flatMap((c) => tree(c.agent_id))].filter(Boolean);
  const roots = (children.get("") || []).slice().sort((x, y) => new Date(y.last_seen) - new Date(x.last_seen));
  return { agents, byId, children, rootOf, tree, roots };
}
function dur(s) {
  s = s || 0;
  return s < 60 ? `${s}s` : s < 3600 ? `${Math.floor(s / 60)}m` : `${Math.floor(s / 3600)}h${String(Math.floor((s % 3600) / 60)).padStart(2, "0")}`;
}
const cliBadge = (cli) => (cli === "codex" ? `<b class="prov cx">CX</b>` : `<b class="prov cc">CC</b>`);
// What runs in the sandbox right now (SSH terminals, claude / codex processes), even
// before an agent's first model call makes it appear in the log.
function liveBlock() {
  const sb = state.snap.sandbox;
  if (!sb) return "";
  const clis = sb.clis || [], ssh = sb.sessions || [];
  if (!clis.length && !ssh.length) return "";
  return `<div class="live"><div class="live-head">${icon("terminal")}Live in the sandbox
      <span class="muted">${ssh.length} SSH</span></div>
    ${clis.map((c) => `<div class="live-row"><span class="dot running"></span>${cliBadge(c.cli)}
      <span>${esc(c.cli)}${c.headless ? " (headless)" : ""}</span>
      <span class="muted mono">${c.tty && c.tty !== "?" ? esc(c.tty) : "no tty"}</span>
      <span class="muted" style="margin-left:auto">${dur(c.since_s)}</span></div>`).join("")}
    ${clis.length ? `<div class="live-note">An agent appears below at its first prompt (first model call).</div>`
      : `<div class="live-note">No claude or codex running yet: type <code>claude</code> or <code>codex</code> in your SSH terminal.</div>`}
  </div>`;
}

function agentLabel(id) {
  const a = state.snap?.agents.find((x) => x.agent_id === id);
  return a ? short(a.first_prompt, 60) : id ? id.slice(0, 8) : "sandbox";
}

// -- polling and routing ----------------------------------------------------------
async function refresh() {
  try {
    const snap = await api("/api/snapshot");
    if (snap.error) throw new Error(snap.error);
    state.snap = snap;
    $("banner").hidden = true;
    render();
  } catch (e) {
    $("banner").hidden = false;
    $("banner").innerHTML = `${icon("alert")}<span>Cannot read the log: ${esc(e.message)}. Is the stack running? <code>docker compose ps</code></span>`;
  }
  if (state.view === "agents" && state.selected) await loadDetail();
}
setInterval(refresh, 2500);

function setView(view, push = true) {
  state.view = view;
  document.querySelectorAll(".rail-btn[data-view]").forEach((b) => b.classList.toggle("active", b.dataset.view === view));
  document.querySelectorAll(".view").forEach((v) => (v.hidden = v.dataset.view !== view));
  $("view-title").textContent = { agents: "Agents", alerts: "Alert queue", activity: "Event stream", monitor: "Monitor" }[view];
  if (push) history.replaceState(null, "", view === "agents" && state.selected ? `#agent=${state.selected}` : `#view=${view}`);
  render();
}
document.querySelectorAll(".rail-btn[data-view]").forEach((b) => (b.onclick = () => setView(b.dataset.view)));

function openAgent(id) {
  if (!id) return;
  const { rootOf } = index();
  state.session = rootOf(id) || id;
  if (state.view !== "agents") setView("agents", false);
  select(id);
  renderSessions();
}

function render() {
  if (!state.snap) return;
  renderKpis();
  if (state.view === "agents") {
    renderSessions();
    if (!state.selected && state.session) return select(state.session);   // open the session's root
    renderTree();
    if (!state.selected) renderInspectorEmpty();
  }
  if (state.view === "alerts") renderAlerts();
  if (state.view === "activity") renderEvents();
  if (state.view === "monitor") renderMonitor();
}

// -- KPIs ------------------------------------------------------------------------------
function renderKpis() {
  const { agents, flags, monitor } = state.snap;
  const { roots } = index();
  const running = agents.filter((a) => a.status === "running").length;
  const stopped = agents.filter((a) => a.status === "killed").length;
  const open = flags.filter((f) => f.status === "open");
  const bySev = ["critical", "high", "medium", "low", "info"].map((s) => [s, open.filter((f) => f.severity === s).length]);
  const worst = open.reduce((m, f) => Math.max(m, SEV_RANK[f.severity] || 0), -1);
  $("alert-count").hidden = !open.length;
  $("alert-count").textContent = open.length;
  const mon = monitor
    ? (monitor.error ? `<span class="v" style="font-size:13px;color:var(--sev-critical)">error</span>`
      : `<span class="v" style="font-size:13px">${esc(monitor.backend)}<small>${esc(monitor.model || "")} · ${ago(monitor.last_review)}</small></span>`)
    : `<span class="v" style="font-size:13px">starting</span>`;
  $("kpis").innerHTML = `
    <div class="kpi"><span class="k">${icon("activity")}Running</span><span class="v">${running}<small>/ ${agents.length} agents</small></span></div>
    <div class="kpi ${state.snap.sandbox ? "" : "warn"}" title="SSH terminals and claude / codex processes in the sandbox"><span class="k">${icon("terminal")}Sandbox</span>
      <span class="v" style="font-size:13px">${state.snap.sandbox
        ? `${(state.snap.sandbox.clis || []).length} CLI<small>${(state.snap.sandbox.sessions || []).length} SSH</small>`
        : `unreachable`}</span></div>
    <div class="kpi"><span class="k">${icon("session")}Sessions</span><span class="v">${roots.length}</span></div>
    <div class="kpi ${worst >= 3 ? "bad" : open.length ? "warn" : ""}"><span class="k">${icon("alert")}Open alerts</span>
      <span class="v">${open.length}<span class="sevbar">${bySev.filter(([, n]) => n).map(([s, n]) =>
        `<i style="background:var(--sev-${s})" title="${s}">${n}</i>`).join("")}</span></span></div>
    <div class="kpi"><span class="k">${icon("stop")}Stopped</span><span class="v">${stopped}</span></div>
    <div class="kpi ${monitor && monitor.error ? "bad" : ""}" title="${esc(monitor?.error || monitor?.summary || "")}"><span class="k">${icon("shield")}Reviewer</span>${mon}</div>
    <div class="kpi"><span class="k">${icon("cpu")}Tabular</span><span class="v" style="font-size:13px">${esc(monitor?.tabular_model || "—")}<small>${monitor?.n_scored ?? 0} scored</small></span></div>`;
  if (monitor && monitor.error && /log(ged)? in|\/login/i.test(monitor.error)) {
    $("banner").hidden = false;
    $("banner").innerHTML = `${icon("shield")}<span><b>The reviewer cannot run yet.</b> ${esc(monitor.error)}</span>`;
  }
}

// -- sessions ---------------------------------------------------------------------------
function renderSessions() {
  const { roots, tree } = index();
  if (!state.session || !roots.some((r) => r.agent_id === state.session)) state.session = roots[0]?.agent_id || null;
  const rows = roots.map((r) => {
    const t = tree(r.agent_id);
    return { r, t, running: t.some((a) => a.status === "running"), flags: t.reduce((n, a) => n + (a.open_flags || 0), 0) };
  }).filter(({ r, running }) =>
    state.sessionFilter === "all" || (state.sessionFilter === "active" ? running : (r.tree_risk || 0) >= 30));
  $("sessions").innerHTML = liveBlock() + (rows.length ? rows.map(({ r, t, running, flags }) => {
    const st = running ? "running" : t.some((a) => a.status === "killed") ? "killed" : flags ? "flagged" : "done";
    return `<div class="session ${state.session === r.agent_id ? "on" : ""}" data-session="${esc(r.agent_id)}">
      <div class="session-top"><span class="dot ${st}"></span><div class="session-title">${esc(short(r.first_prompt, 160)) || "<span class='muted'>(no task text)</span>"}</div>${prov(r.provider)}</div>
      <div class="riskbar" title="highest risk in this session: ${r.tree_risk || 0}/100"><i style="width:${Math.max(r.tree_risk || 0, 2)}%;background:${riskColor(r.tree_risk || 0)}"></i></div>
      <div class="session-meta"><span>${t.length} agent${t.length > 1 ? "s" : ""}</span>
        ${flags ? `<span class="tag flag">${icon("flag")}${flags}</span>` : ""}
        <span>${tokens(t.reduce((n, a) => n + a.input_tokens + a.output_tokens, 0))} tok</span>
        <span style="margin-left:auto">${ago(r.last_seen)}</span></div>
    </div>`;
  }).join("") : (state.snap.sandbox?.clis || []).length ? ""
    : `<p class="empty">No agent yet.<br><code>ssh -p ${esc(state.snap.config?.ssh_port || 2222)} agent@localhost</code>, then <code>claude</code> or <code>codex</code>.</p>`);
}
$("sessions").addEventListener("click", (ev) => {
  const s = ev.target.closest("[data-session]");
  if (!s) return;
  state.session = s.dataset.session;
  select(s.dataset.session);
  renderSessions();
});
document.querySelectorAll("#session-filter button").forEach((b) => (b.onclick = () => {
  state.sessionFilter = b.dataset.f;
  document.querySelectorAll("#session-filter button").forEach((x) => x.classList.toggle("on", x === b));
  renderSessions();
}));

// -- agent tree ----------------------------------------------------------------------------
const NODE_W = 236, NODE_H = 98, GAP_X = 44, GAP_Y = 14, PAD = 18;

function renderTree() {
  const { byId, children } = index();
  const root = state.session && byId.get(state.session);
  const canvas = $("canvas");
  if (!root) {
    $("graph-title").textContent = "Agent tree";
    canvas.style.width = canvas.style.height = canvas.style.transform = "";
    $("canvas-sizer").style.width = $("canvas-sizer").style.height = "";
    canvas.innerHTML = `<p class="empty">The agents of the selected session appear here as a tree:
      the orchestrator on the left, the sub-agents it starts on the right.</p>`;
    return;
  }
  $("graph-title").textContent = short(root.first_prompt, 80) || "Agent tree";
  // Tidy tree, left to right: leaves take one row each, a parent sits between its children.
  const pos = new Map();
  let row = 0, depthMax = 0;
  const walk = (a, depth) => {
    depthMax = Math.max(depthMax, depth);
    const kids = (children.get(a.agent_id) || []).slice().sort((x, y) => new Date(x.first_seen) - new Date(y.first_seen));
    if (!kids.length) { pos.set(a.agent_id, { d: depth, y: row++ }); return pos.get(a.agent_id).y; }
    const ys = kids.map((k) => walk(k, depth + 1));
    pos.set(a.agent_id, { d: depth, y: (ys[0] + ys[ys.length - 1]) / 2 });
    return pos.get(a.agent_id).y;
  };
  walk(root, 0);
  const X = (d) => PAD + d * (NODE_W + GAP_X), Y = (y) => PAD + y * (NODE_H + GAP_Y);
  const W = X(depthMax) + NODE_W + PAD, H = Y(row - 1) + NODE_H + PAD;
  const edges = [], nodes = [];
  for (const [id, p] of pos) {
    const a = byId.get(id);
    if (a.parent_id && pos.has(a.parent_id)) {
      const q = pos.get(a.parent_id);
      const x1 = X(q.d) + NODE_W, y1 = Y(q.y) + NODE_H / 2, x2 = X(p.d), y2 = Y(p.y) + NODE_H / 2, mx = (x1 + x2) / 2;
      const cls = a.status === "killed" ? "killed" : (a.risk || 0) >= 55 ? "risk"
        : a.status === "flagged" ? "flagged" : a.status === "running" ? "running" : "";
      edges.push(`<path class="${cls}" d="M${x1} ${y1} C${mx} ${y1} ${mx} ${y2} ${x2 - 2} ${y2}"/>`);
    }
    const kids = (children.get(id) || []).length;
    nodes.push(`<div class="node ${a.status} ${state.selected === id ? "on" : ""}" data-id="${esc(id)}" style="left:${X(p.d)}px;top:${Y(p.y)}px">
      <div class="node-top"><span class="dot ${a.status}" title="${statusLabel(a.status)}"></span>${prov(a.provider)}
        <span class="node-role" title="${esc(a.role)}${kids ? ` with ${kids} sub-agent(s)` : ""}">${esc(a.role === "orchestrator" ? "orchestr." : a.role)}${kids ? ` · ${kids}↳` : ""}</span>
        <span class="node-act">${riskRing(a.risk)}${a.status === "killed"
          ? `<button class="icon-btn ok" data-revive="${esc(id)}" title="Revive">${icon("revive")}</button>`
          : `<button class="icon-btn danger" data-kill="${esc(id)}" title="Stop">${icon("stop")}</button>`}</span></div>
      <div class="node-task" title="${esc(short(a.first_prompt, 600))}">${esc(short(a.first_prompt, 120)) || "<span class='muted'>(no task text)</span>"}</div>
      <div class="node-meta"><span title="tool calls">${icon("tool")} ${a.n_tool_calls}</span>
        <span title="requests from the sandbox attributed to this agent${a.n_http_possible ? `, + ${a.n_http_possible} it may have made (several agents were running tools at that moment)` : ""}">${icon("globe")} ${a.n_http}${a.n_http_possible ? `<span class="muted">+${a.n_http_possible}?</span>` : ""}</span>
        ${a.n_web ? `<span title="web searches and fetches (WebSearch runs at the model provider, so it makes no request from the sandbox)">${icon("search")} ${a.n_web}</span>` : ""}
        <span title="tokens">${tokens(a.input_tokens + a.output_tokens)}</span>
        ${a.open_flags ? `<span class="tag flag">${icon("flag")}${a.open_flags}</span>` : ""}
        ${a.anomaly != null ? anomTag(a.anomaly) : ""}</div>
    </div>`);
  }
  // Fit the tree to the panel's width (down to 60%), then scroll.
  const avail = $("canvas-wrap").clientWidth - 4;
  const k = Math.max(0.6, Math.min(1, avail / W));
  canvas.style.width = `${W}px`;
  canvas.style.height = `${H}px`;
  canvas.style.transform = k < 1 ? `scale(${k})` : "";
  $("canvas-sizer").style.width = `${Math.ceil(W * k)}px`;
  $("canvas-sizer").style.height = `${Math.ceil(H * k)}px`;
  canvas.innerHTML = `<svg class="edges" width="${W}" height="${H}">${edges.join("")}</svg>${nodes.join("")}`;
}
window.addEventListener("resize", () => { if (state.view === "agents") renderTree(); });
$("canvas").addEventListener("click", (ev) => {
  const k = ev.target.closest("[data-kill]"), r = ev.target.closest("[data-revive]");
  if (k) return killAgent(k.dataset.kill);
  if (r) return reviveAgent(r.dataset.revive);
  const n = ev.target.closest(".node");
  if (n) select(n.dataset.id);
});

// -- actions ------------------------------------------------------------------------------
async function killAgent(id, subtree = null) {
  const { children } = index();
  const kids = (children.get(id) || []).length;
  if (subtree === null) {
    if (kids) {
      subtree = confirm("Stop this agent AND its sub-agents?\n\nOK: the whole sub-tree.  Cancel: choose again.");
      if (!subtree && !confirm("Stop only this agent? Its sub-agents keep running.")) return;
    } else if (!confirm("Stop this agent? Its next model calls get a final 'stopped' answer and its requests are refused.")) {
      return;
    }
  }
  const reason = prompt("Reason (optional):", "drifting from its task") ?? "";
  const r = await api(`/api/agents/${encodeURIComponent(id)}/kill`, { subtree, reason });
  if (!r.ok) alert(r.error || "failed");
  state.detailKey = null;
  refresh();
}
async function reviveAgent(id, subtree = false) {
  const r = await api(`/api/agents/${encodeURIComponent(id)}/revive`, { subtree });
  if (!r.ok) alert(r.error || "failed");
  state.detailKey = null;
  refresh();
}
async function reviewFlag(id, status) {
  await api(`/api/flags/${id}`, { status });
  state.detailKey = null;
  refresh();
}
document.addEventListener("click", (ev) => {
  const fl = ev.target.closest("[data-flag]");
  if (fl) return reviewFlag(fl.dataset.flag, fl.dataset.status);
  const k = ev.target.closest("[data-stop]");
  if (k) return killAgent(k.dataset.stop, k.dataset.subtree === undefined ? null : k.dataset.subtree === "1");
  const rv = ev.target.closest("[data-revive-tree]");
  if (rv) return reviveAgent(rv.dataset.reviveTree, rv.dataset.subtree === "1");
  const open = ev.target.closest("[data-open]");
  if (open && !ev.target.closest("button")) return openAgent(open.dataset.open);
});

// -- inspector ---------------------------------------------------------------------------
function select(id) {
  if (location.hash !== `#agent=${id}`) history.replaceState(null, "", `#agent=${id}`);
  state.selected = id;
  state.detail = null;
  state.detailKey = null;
  renderTree();
  $("inspector").innerHTML = `<p class="empty">Loading…</p>`;
  loadDetail();
}
function renderInspectorEmpty() {
  $("inspector").innerHTML = `<p class="empty">Select an agent in the tree to see what it did.</p>`;
}
async function loadDetail() {
  const id = state.selected;
  if (!id) return;
  const d = await api(`/api/agents/${encodeURIComponent(id)}`);
  if (state.selected !== id) return;
  if (d.error) { $("inspector").innerHTML = `<p class="empty">${esc(d.error)}</p>`; return; }
  const a = state.snap?.agents.find((x) => x.agent_id === id) || {};
  const key = JSON.stringify(d) + JSON.stringify(a) + state.tab;
  if (key === state.detailKey) return;  // unchanged: keep scroll positions and open rows
  const open = new Set([...document.querySelectorAll("#inspector details[open]")].map((e) => e.dataset.k));
  const body = document.querySelector("#inspector .tab-body");
  const scroll = body ? body.scrollTop : 0;
  state.detailKey = key;
  state.detail = d;
  renderInspector(a, open);
  const nb = document.querySelector("#inspector .tab-body");
  if (nb) nb.scrollTop = scroll;
}
function renderInspector(a, open = new Set()) {
  const d = state.detail;
  const { children } = index();
  const kids = children.get(d.agent_id) || [];
  const tabs = [["timeline", "activity", "Timeline", d.llm_calls.length + d.tool_calls.length],
    ["alerts", "alert", "Alerts", d.flags.length], ["network", "globe", "Network", d.http.length], ["prompt", "prompt", "Prompt", null]];
  $("inspector").innerHTML = `
    <div class="insp-head">
      <div class="insp-ids"><span class="dot ${esc(a.status || "")}"></span><b style="color:var(--text)">${esc(statusLabel(a.status))}</b>
        ${prov(d.provider)}<span>${esc(d.model || "")}</span><span class="mono">${esc(d.agent_id)}</span><span>${ago(d.first_seen)}</span></div>
      <p class="insp-task">${esc(d.task || "(no task text)")}</p>
      <div class="insp-ids">${a.parent_id ? `<span>parent <span class="link" data-open="${esc(a.parent_id)}">${esc(short(agentLabel(a.parent_id), 50))}</span></span>` : "<span>top-level agent</span>"}
        ${kids.length ? `<span>· ${kids.length} sub-agent${kids.length > 1 ? "s" : ""}</span>` : ""}</div>
      <div class="stats">
        <div class="stat"><b>${d.tool_calls.length}</b><span>tools</span></div>
        <div class="stat" title="attributed / possible (ambiguous) requests from the sandbox"><b>${d.http.filter((h) => h.certain).length}${d.http.some((h) => !h.certain) ? `<span class="muted" style="font-size:12px"> +${d.http.filter((h) => !h.certain).length}?</span>` : ""}</b><span>requests</span></div>
        <div class="stat"><b>${tokens((a.input_tokens || 0) + (a.output_tokens || 0))}</b><span>tokens</span></div>
        <div class="stat" style="display:flex;align-items:center;gap:8px">${riskRing(a.risk)}<span>risk</span></div>
      </div>
      <div class="insp-actions">${d.killed
        ? `<span class="stopped-note">${icon("stop")}Stopped ${ago(d.killed.ts)} by ${esc(d.killed.requested_by)}${d.killed.reason ? ": " + esc(d.killed.reason) : ""}</span>
           <button class="btn small" data-revive-tree="${esc(d.agent_id)}" data-subtree="0">${icon("revive")}Revive</button>
           ${kids.length ? `<button class="btn small" data-revive-tree="${esc(d.agent_id)}" data-subtree="1">${icon("revive")}Revive with sub-agents</button>` : ""}`
        : `<button class="btn small danger" data-stop="${esc(d.agent_id)}" data-subtree="0">${icon("stop")}Stop agent</button>
           ${kids.length ? `<button class="btn small danger" data-stop="${esc(d.agent_id)}" data-subtree="1">${icon("stop")}Stop with sub-agents</button>` : ""}`}
      </div>
    </div>
    <div class="tabs">${tabs.map(([k, ic, l, n]) => `<button class="tab ${state.tab === k ? "on" : ""}" data-tab="${k}">${icon(ic)}${l}${n != null ? ` <span class="muted">${n}</span>` : ""}</button>`).join("")}</div>
    <div class="tab-body">${tabBody(d)}</div>`;
  document.querySelectorAll("#inspector .tab").forEach((t) => (t.onclick = () => { state.tab = t.dataset.tab; state.detailKey = null; loadDetail(); }));
  document.querySelectorAll("#inspector details[data-k]").forEach((e) => { if (open.has(e.dataset.k)) e.open = true; });
}
function alertCard(f, withAgent = true) {
  const closed = f.status !== "open";
  return `<div class="alert ${esc(f.severity)} ${closed ? "closed" : ""}">
    <div class="alert-head">${sevChip(f.severity)}<span>${esc(f.category || "")}</span><span class="mono">${esc(f.detector || "")}</span>
      <span>${hhmmss(f.ts)}</span>${closed ? `<span class="tag">${esc(f.status)}</span>` : ""}
      ${withAgent && f.agent_id ? `<span class="link" data-open="${esc(f.agent_id)}">${esc(short(agentLabel(f.agent_id), 50))}</span>` : ""}</div>
    <div>${esc(f.summary)}</div>
    <div class="alert-actions">${closed
      ? `<button class="btn small" data-flag="${f.id}" data-status="open">${icon("revive")}Reopen</button>`
      : `<button class="btn small" data-flag="${f.id}" data-status="confirmed">${icon("check")}Confirm</button>
         <button class="btn small" data-flag="${f.id}" data-status="dismissed">${icon("x")}Dismiss</button>`}</div>
  </div>`;
}
function tabBody(d) {
  if (state.tab === "alerts") {
    return d.flags.length ? d.flags.map((f) => alertCard(f, false)).join("")
      : `<p class="empty">No alert on this agent. Confirming or dismissing alerts also teaches the tabular model.</p>`;
  }
  if (state.tab === "prompt") {
    return `<details class="ev" open data-k="task"><summary>${icon("prompt")}<span class="kind">Task</span><span></span><span></span></summary><pre>${esc(d.task)}</pre></details>
      <details class="ev" data-k="system"><summary>${icon("prompt")}<span class="kind">System prompt</span><span class="sum">${esc(short(d.system_prompt, 80))}</span><span></span></summary><pre>${esc(d.system_prompt || "(none)")}</pre></details>`;
  }
  if (state.tab === "network") {
    const unsure = d.http.filter((h) => !h.certain).length;
    return d.http.length ? `${unsure ? `<p class="muted small" style="margin:4px 4px 8px">${unsure} request${unsure > 1 ? "s" : ""} marked <i>possible</i>: several agents were running tools at that moment and nothing in the request tells which one sent it.</p>` : ""}<table class="grid"><tr><th>Time</th><th>Request</th><th>Status</th><th>Attribution</th></tr>${d.http.map((h) =>
      `<tr class="${h.blocked ? "blocked" : ""}" style="${h.certain ? "" : "opacity:.7"}"><td class="nowrap mono">${hhmmss(h.ts)}</td>
        <td class="wrap"><b>${esc(h.method)}</b> ${esc(h.host)}<div class="muted small">${esc(short(h.url, 140))}</div>${h.body ? `<div class="muted small mono">${esc(short(h.body, 160))}</div>` : ""}</td>
        <td class="nowrap">${h.blocked ? `<span class="tag killed">${icon("ban")}blocked</span>` : esc(h.status_code ?? "")}</td>
        <td class="nowrap muted">${h.certain ? esc(h.attribution || "") : `<span class="tag">possible · 1 of ${h.n_candidates}</span>`}</td></tr>`).join("")}</table>`
      : `<p class="empty">No web request from this agent.</p>`;
  }
  const items = [
    ...d.llm_calls.map((c) => {
      const stop = (c.error || "").includes("kill switch");
      const first = short(c.text || c.thinking || c.error || "", 120);
      return { ts: c.ts, html: `<details class="ev ${stop ? "stop" : c.error ? "err" : ""}" data-k="${esc(c.call_id)}">
        <summary>${icon(stop ? "stop" : "chat")}<span class="kind">${stop ? "Stopped" : "Model"}</span><span class="sum">${esc(first)}</span>
          <span class="t">${tokens(c.output_tokens)} out · ${hhmmss(c.ts)}</span></summary>
        ${c.thinking ? `<pre class="result">${esc(c.thinking)}</pre>` : ""}${c.text ? `<pre>${esc(c.text)}</pre>` : ""}
        ${c.error && !stop ? `<pre class="result">${esc(c.error)}</pre>` : ""}</details>` };
    }),
    ...d.tool_calls.map((t) => ({ ts: t.ts, html: `<details class="ev ${t.result_is_error ? "err" : ""}" data-k="${esc(t.tool_use_id)}">
      <summary>${icon(toolIcon(t.tool_name))}<span class="kind">${esc(t.tool_name)}</span><span class="sum">${esc(short(toolSummary(t.input), 120))}</span>
        <span class="t">${anomTag(t.anomaly, t.anomaly_reasons)}${t.result == null && !t.is_server_tool ? "running · " : ""}${hhmmss(t.ts)}</span></summary>
      <pre>${esc(pretty(t.input))}</pre>
      ${t.result != null ? `<pre class="result">${esc(t.result)}</pre>` : ""}
      ${t.anomaly_reasons && t.anomaly_reasons.length ? `<div class="why">${icon("cpu")} ${esc(t.anomaly_model || "tabular")}: ${esc(t.anomaly_reasons.join(" · "))}</div>` : ""}</details>` })),
  ].sort((x, y) => new Date(y.ts) - new Date(x.ts));
  return items.length ? items.map((i) => i.html).join("") : `<p class="empty">No activity yet.</p>`;
}

// -- alert queue -------------------------------------------------------------------------
function renderAlerts() {
  const min = { critical: 4, high: 3, medium: 2 }[state.alertSev] || 0;
  const flags = state.snap.flags.slice().reverse()
    .filter((f) => (state.alertStatus === "all" || f.status === "open") && (SEV_RANK[f.severity] || 0) >= min);
  $("alerts-table").innerHTML = `<tr><th>Severity</th><th>Time</th><th>Agent</th><th>Detector</th><th>Summary</th><th>Status</th><th></th></tr>` +
    (flags.length ? flags.map((f) => {
      const a = state.snap.agents.find((x) => x.agent_id === f.agent_id);
      return `<tr class="${f.agent_id ? "click" : ""} ${f.status !== "open" ? "closed" : ""}" ${f.agent_id ? `data-open="${esc(f.agent_id)}"` : ""}>
        <td>${sevChip(f.severity)}</td><td class="nowrap mono">${hhmmss(f.ts)}<div class="muted small">${ago(f.ts)}</div></td>
        <td class="trunc">${a ? `${prov(a.provider)} ${esc(short(a.first_prompt, 50))}` : `<span class="muted">${f.agent_id ? esc(f.agent_id.slice(0, 8)) : "sandbox"}</span>`}</td>
        <td class="nowrap mono muted">${esc(f.detector || "")}<div class="small">${esc(f.category || "")}</div></td>
        <td class="wrap">${esc(f.summary)}</td><td class="nowrap">${esc(f.status)}</td>
        <td><div class="row-actions">${f.status === "open"
          ? `<button class="icon-btn ok" title="Confirm" data-flag="${f.id}" data-status="confirmed">${icon("check")}</button>
             <button class="icon-btn" title="Dismiss" data-flag="${f.id}" data-status="dismissed">${icon("x")}</button>
             ${a && a.status !== "killed" ? `<button class="icon-btn danger" title="Stop the agent" data-stop="${esc(a.agent_id)}">${icon("stop")}</button>` : ""}`
          : `<button class="icon-btn" title="Reopen" data-flag="${f.id}" data-status="open">${icon("revive")}</button>`}</div></td></tr>`;
    }).join("") : `<tr><td colspan="7" class="muted">No alert. Rules, the tabular model and the reviewer raise alerts when an agent drifts from its task.</td></tr>`);
}
function segment(id, key, after) {
  document.querySelectorAll(`#${id} button`).forEach((b) => (b.onclick = () => {
    state[key] = b.dataset.f;
    document.querySelectorAll(`#${id} button`).forEach((x) => x.classList.toggle("on", x === b));
    after();
  }));
}
segment("alert-status", "alertStatus", renderAlerts);
segment("alert-sev", "alertSev", renderAlerts);

// -- event stream ------------------------------------------------------------------------
function renderEvents() {
  const evIcon = { llm_call: "chat", server_tool: "globe", http: "globe", http_blocked: "ban" };
  const rows = state.snap.timeline.slice().reverse()
    .filter((e) => !state.eventFilter || e.event === state.eventFilter || (state.eventFilter === "tool" && e.event === "server_tool"))
    .slice(0, 400);
  $("events-table").innerHTML = `<tr><th>Time</th><th>Event</th><th>Agent</th><th>What</th><th>Detail</th></tr>` +
    (rows.length ? rows.map((e) => `<tr class="${e.agent_id ? "click" : ""} ${e.event === "http_blocked" ? "blocked" : ""}" ${e.agent_id ? `data-open="${esc(e.agent_id)}"` : ""}>
      <td class="nowrap mono">${hhmmss(e.ts)}</td>
      <td class="nowrap">${icon(e.event === "tool" ? toolIcon(e.what || "") : evIcon[e.event] || "activity")} ${esc(e.event.replace("_", " "))}</td>
      <td class="trunc">${esc(short(agentLabel(e.agent_id), 40))}</td><td class="nowrap">${esc(e.what || "")}</td>
      <td class="trunc muted">${esc(short(e.detail, 200))}</td></tr>`).join("")
      : `<tr><td colspan="5" class="muted">Nothing yet.</td></tr>`);
}
segment("event-filter", "eventFilter", renderEvents);

// -- monitor ------------------------------------------------------------------------------
function renderMonitor() {
  const m = state.snap.monitor, cycles = state.snap.monitor_runs || [];
  const flags = state.snap.flags;
  const by = (p) => flags.filter((f) => (f.detector || "").startsWith(p)).length;
  $("monitor-cards").innerHTML = `
    <div class="mcard ${m && m.error ? "bad" : ""}"><h3>${icon("shield")}Reviewer</h3>
      <div class="big">${esc(m ? m.backend : "starting")} <span class="muted">${esc(m?.model || "")}</span></div>
      <div class="muted">Last review ${ago(m?.last_review)} · ${by("agent:")} alerts raised</div>
      ${m && m.error ? `<div style="color:var(--sev-critical)">${esc(m.error)}</div>` : ""}
      ${m && m.summary ? `<div class="muted small">${esc(short(m.summary, 300))}</div>` : ""}</div>
    <div class="mcard"><h3>${icon("cpu")}Tabular model</h3>
      <div class="big">${esc(m?.tabular_model || "—")}</div>
      <div class="muted">Scores every finished tool call on CPU; unusual calls go to the reviewer.
        Confirming or dismissing alerts gives it labelled examples.</div></div>
    <div class="mcard"><h3>${icon("flag")}Detectors</h3>
      <div class="big">${by("rule:")} <span class="muted">rules</span> · ${by("tabular:")} <span class="muted">tabular</span> · ${by("agent:")} <span class="muted">reviewer</span></div>
      <div class="muted">${flags.filter((f) => f.status === "confirmed").length} confirmed · ${flags.filter((f) => f.status === "dismissed").length} dismissed</div></div>`;
  $("cycles-table").innerHTML = `<tr><th>Started</th><th>Backend</th><th>Rules</th><th>Tabular</th><th>Reviewer</th><th>Outcome</th></tr>` +
    (cycles.length ? cycles.map((c) => `<tr class="${c.error ? "blocked" : ""}">
      <td class="nowrap mono">${hhmmss(c.ts_start)}<div class="muted small">${ago(c.ts_start)}</div></td>
      <td class="nowrap">${esc(c.backend)}<div class="muted small">${esc(c.model || "")}</div></td>
      <td class="nowrap">${c.n_signals ?? 0} signals · ${c.n_rule_flags ?? 0} new</td>
      <td class="nowrap">${esc(c.tabular_model || "—")}<div class="muted small">${c.n_scored ?? 0} scored · ${c.n_tabular_alerts ?? 0} unusual</div></td>
      <td class="nowrap">${c.reviewed ? `reviewed · ${c.n_model_flags ?? 0} alerts` : `<span class="muted">skipped</span>`}</td>
      <td class="wrap ${c.error ? "" : "muted"}">${esc(short(c.error || c.summary || "", 300))}</td></tr>`).join("")
      : `<tr><td colspan="6" class="muted">No cycle yet.</td></tr>`);
}

// -- headless runs -----------------------------------------------------------------------
let engine = "claude";
document.querySelectorAll("#engine button").forEach((b) => (b.onclick = () => {
  engine = b.dataset.f;
  document.querySelectorAll("#engine button").forEach((x) => x.classList.toggle("on", x === b));
}));
function renderRuns() {
  const runs = state.snap?.runs;
  $("runs").innerHTML = runs && runs.length
    ? `<div class="small muted">Headless agents still running</div>` + runs.map((r) =>
      `<div class="run-row"><span class="dot running"></span><span class="mono">${esc(r.run)}</span>
        <button class="btn small danger" type="button" data-stop-run="${esc(r.run)}">${icon("stop")}Stop process</button></div>`).join("")
    : "";
}
$("new-run").onclick = () => { $("run-error").hidden = true; renderRuns(); $("run-dialog").showModal(); $("run-prompt").focus(); };
$("runs").addEventListener("click", async (ev) => {
  const b = ev.target.closest("[data-stop-run]");
  if (!b) return;
  b.disabled = true;
  await api(`/api/runs/${encodeURIComponent(b.dataset.stopRun)}/stop`, {});
  setTimeout(() => refresh().then(renderRuns), 800);
});
$("run-go").onclick = async (ev) => {
  ev.preventDefault();
  const prompt = $("run-prompt").value.trim();
  if (!prompt) return;
  $("run-go").disabled = true;
  const r = await api("/api/run", { prompt, engine });
  $("run-go").disabled = false;
  if (!r.ok) {
    $("run-error").hidden = false;
    $("run-error").textContent = r.error || "failed";
    return;
  }
  $("run-prompt").value = "";
  $("run-dialog").close();
  setView("agents");
  refresh();
};

// -- start -------------------------------------------------------------------------------
const linked = decodeURIComponent(location.hash);
const linkedAgent = linked.match(/^#agent=(.+)$/), linkedView = linked.match(/^#view=(\w+)$/);
if (linkedView && ["agents", "alerts", "activity", "monitor"].includes(linkedView[1])) setView(linkedView[1], false);
refresh().then(() => { if (linkedAgent) openAgent(linkedAgent[1]); });
