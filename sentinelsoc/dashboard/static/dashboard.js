/* SentinelSOC dashboard client.
 *
 * Deliberately builds table rows with createElement/textContent rather
 * than innerHTML string concatenation for any value that can come from
 * monitored system data (process names, command lines, file paths,
 * account names, etc). This is a security tool parsing untrusted
 * telemetry — the one place a raw string must never land is directly
 * into innerHTML.
 */
(function () {
  "use strict";

  const REFRESH_MS = (window.SENTINELSOC_REFRESH_SECONDS || 10) * 1000;

  async function api(path, options) {
    const resp = await fetch(path, Object.assign({ credentials: "same-origin" }, options || {}));
    if (resp.status === 401) {
      window.location.href = "/login";
      throw new Error("unauthorized");
    }
    if (!resp.ok) {
      let detail = resp.statusText;
      try { detail = (await resp.json()).detail || detail; } catch (_) { /* ignore */ }
      throw new Error(detail);
    }
    return resp.json();
  }

  function apiJSON(path, method, body) {
    return api(path, {
      method,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
  }

  function el(tag, opts) {
    opts = opts || {};
    const node = document.createElement(tag);
    if (opts.class) node.className = opts.class;
    if (opts.text !== undefined && opts.text !== null) node.textContent = opts.text;
    if (opts.html !== undefined) node.innerHTML = opts.html; // only ever for trusted, static fragments
    if (opts.attrs) Object.entries(opts.attrs).forEach(([k, v]) => node.setAttribute(k, v));
    if (opts.onClick) node.addEventListener("click", opts.onClick);
    (opts.children || []).forEach((c) => c && node.appendChild(c));
    return node;
  }

  function td(value, opts) {
    opts = opts || {};
    const cell = document.createElement("td");
    if (opts.mono) cell.classList.add("mono");
    if (opts.muted) cell.classList.add("muted");
    if (opts.node) {
      cell.appendChild(opts.node);
    } else {
      cell.textContent = value === null || value === undefined || value === "" ? "—" : String(value);
    }
    return cell;
  }

  function row(cells, onClick) {
    const r = document.createElement("tr");
    if (onClick) {
      r.classList.add("clickable");
      r.addEventListener("click", onClick);
    }
    cells.forEach((c) => r.appendChild(c));
    return r;
  }

  function emptyRow(colspan, message) {
    return row([el("td", { attrs: { colspan: String(colspan) }, class: "empty-state", text: message })]);
  }

  function sevBadgeCell(sev) {
    const cell = document.createElement("td");
    const span = el("span", { class: `sev-badge sev-${sev}`, text: sev });
    cell.appendChild(span);
    return cell;
  }

  function fmtTime(iso) {
    if (!iso) return "—";
    try {
      return new Date(iso).toLocaleString();
    } catch (_) {
      return iso;
    }
  }

  function setBody(tableId, rows, colspan, emptyMessage) {
    const tbody = document.querySelector(`#${tableId} tbody`);
    tbody.innerHTML = "";
    if (!rows.length) {
      tbody.appendChild(emptyRow(colspan, emptyMessage || "Nothing here right now."));
      return;
    }
    rows.forEach((r) => tbody.appendChild(r));
  }

  async function refreshStatusDot() {
    try {
      const data = await api("/api/system/status");
      const dot = document.getElementById("status-dot");
      if (!dot) return;
      const critical = (data.alerts_last_24h && data.alerts_last_24h.CRITICAL) || 0;
      const pending = data.pending_response_actions || 0;
      dot.classList.toggle("attention", critical > 0 || pending > 0);
      return data;
    } catch (_) {
      return null;
    }
  }

  function describeTarget(action) {
    if (action.action_type === "TERMINATE_PROCESS") return `PID ${action.target}`;
    return action.target;
  }

  async function decideAction(actionId, approve, onDone) {
    const analyst = window.prompt("Your name/handle, for the audit log:", "");
    if (!analyst) return;
    let notes = "";
    if (!approve) notes = window.prompt("Reason for rejecting (optional):", "") || "";
    try {
      await apiJSON(`/api/response/actions/${actionId}/decide`, "POST", { analyst, approve, notes });
      if (onDone) onDone();
    } catch (err) {
      alert("Failed: " + err.message);
    }
  }

  // ------------------------------------------------------------- pages

  async function overview() {
    refreshStatusDot();
    const hostline = document.getElementById("hostline");

    async function loadStatus() {
      const data = await api("/api/system/status");
      if (hostline) {
        hostline.textContent = `uptime ${Math.floor(data.uptime_seconds / 60)}m · ${data.rules_enabled}/${data.rules_loaded} rules enabled`;
      }
      const strip = document.getElementById("status-strip");
      strip.innerHTML = "";
      Object.entries(data.collectors || {}).forEach(([name, state]) => {
        strip.appendChild(
          el("div", {
            class: "status-item",
            children: [
              el("span", { class: "label", text: name.replace(/_/g, " ") }),
              el("span", { class: `value ${state === "running" ? "ok" : "warn"}`, text: state }),
            ],
          })
        );
      });
      const sevOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
      sevOrder.forEach((sev) => {
        const count = (data.alerts_last_24h || {})[sev] || 0;
        strip.appendChild(
          el("div", {
            class: "status-item",
            children: [
              el("span", { class: "label", text: `${sev} (24h)` }),
              el("span", { class: "value", text: String(count) }),
            ],
          })
        );
      });
    }

    async function loadPending() {
      const data = await api("/api/response/actions?status=PENDING&limit=10");
      const rows = data.actions.map((a) =>
        row([
          td(a.action_type),
          td(describeTarget(a), { mono: true }),
          td(a.reason),
          td(a.requested_by),
          td(fmtTime(a.created_at), { muted: true }),
          td(null, {
            node: el("div", {
              class: "action-row",
              children: [
                el("button", {
                  class: "btn btn-accent btn-sm",
                  text: "Approve",
                  onClick: () => decideAction(a.id, true, () => { loadPending(); refreshStatusDot(); }),
                }),
                el("button", {
                  class: "btn btn-danger btn-sm",
                  text: "Reject",
                  onClick: () => decideAction(a.id, false, () => { loadPending(); refreshStatusDot(); }),
                }),
              ],
            }),
          }),
        ])
      );
      setBody("pending-table", rows, 6, "No actions waiting on you.");
    }

    async function loadRecent() {
      const data = await api("/api/alerts?limit=15");
      const rows = data.alerts.map((a) =>
        row(
          [
            (() => { const c = document.createElement("td"); c.appendChild(el("span", { class: `sev-badge sev-${a.severity}`, text: a.severity })); return c; })(),
            td(a.rule_name),
            td(a.process_name || a.account_name),
            td(a.risk_score, { mono: true }),
            td(a.status),
            td(fmtTime(a.timestamp), { muted: true }),
          ],
          () => { window.location.href = `/alerts/${a.id}`; }
        )
      );
      setBody("recent-alerts-table", rows, 6, "No alerts yet.");
    }

    await Promise.all([loadStatus(), loadPending(), loadRecent()]);
    setInterval(() => { loadStatus(); loadPending(); loadRecent(); refreshStatusDot(); }, REFRESH_MS);
  }

  async function alertsList() {
    refreshStatusDot();
    async function load() {
      const severity = document.getElementById("filter-severity").value;
      const status = document.getElementById("filter-status").value;
      const params = new URLSearchParams({ limit: "200" });
      if (severity) params.set("severity", severity);
      if (status) params.set("status", status);
      const data = await api(`/api/alerts?${params.toString()}`);
      const rows = data.alerts.map((a) =>
        row(
          [
            (() => { const c = document.createElement("td"); c.appendChild(el("span", { class: `sev-badge sev-${a.severity}`, text: a.severity })); return c; })(),
            td(a.rule_name),
            td(a.category),
            td(a.process_name || a.account_name),
            td(a.risk_score, { mono: true }),
            td(a.status),
            td(fmtTime(a.timestamp), { muted: true }),
          ],
          () => { window.location.href = `/alerts/${a.id}`; }
        )
      );
      setBody("alerts-table", rows, 7, "No alerts match this filter.");
    }
    document.getElementById("filter-severity").addEventListener("change", load);
    document.getElementById("filter-status").addEventListener("change", load);
    window.SentinelSOC.pages.alertsList = load; // let the Refresh button re-trigger without re-binding
    await load();
  }

  async function alertDetail(alertId) {
    refreshStatusDot();
    const container = document.getElementById("alert-body");
    const data = await api(`/api/alerts/${alertId}`);
    const a = data.alert;
    const rec = data.recommendation;

    container.innerHTML = "";

    const sevSpan = el("span", { class: `sev-badge sev-${a.severity}`, text: a.severity });
    const header = el("div", {
      class: "panel",
      children: [
        el("div", { class: "action-row", children: [sevSpan, el("strong", { text: a.title })] }),
        el("p", { class: "muted", text: a.description || "" }),
        el("dl", {
          class: "kv",
          children: [
            el("dt", { text: "Rule" }), el("dd", { text: `${a.rule_id} — ${a.rule_name}` }),
            el("dt", { text: "Category" }), el("dd", { text: a.category || "—" }),
            el("dt", { text: "ATT&CK technique" }), el("dd", { text: rec.technique_id ? `${rec.technique_id} ${rec.technique_name || ""}` : "—" }),
            el("dt", { text: "Risk score" }), el("dd", { text: String(a.risk_score) }),
            el("dt", { text: "Process" }), el("dd", { text: a.process_name || "—" }),
            el("dt", { text: "PID" }), el("dd", { text: a.pid != null ? String(a.pid) : "—" }),
            el("dt", { text: "Account" }), el("dd", { text: a.account_name || "—" }),
            el("dt", { text: "File path" }), el("dd", { text: a.file_path || "—" }),
            el("dt", { text: "Remote address" }), el("dd", { text: a.remote_addr || "—" }),
            el("dt", { text: "Time" }), el("dd", { text: fmtTime(a.timestamp) }),
            el("dt", { text: "Status" }), el("dd", { text: a.status }),
          ],
        }),
      ],
    });
    container.appendChild(header);

    const statusPanel = el("div", {
      class: "panel",
      children: [
        el("h2", { text: "Triage" }),
        el("div", {
          class: "action-row",
          children: [
            el("button", { class: "btn btn-sm", text: "Acknowledge", onClick: () => setStatus("ACKNOWLEDGED") }),
            el("button", { class: "btn btn-sm", text: "Mark in progress", onClick: () => setStatus("IN_PROGRESS") }),
            el("button", { class: "btn btn-accent btn-sm", text: "Resolve", onClick: () => setStatus("RESOLVED") }),
            el("button", { class: "btn btn-ghost btn-sm", text: "False positive", onClick: () => setStatus("FALSE_POSITIVE") }),
          ],
        }),
      ],
    });
    container.appendChild(statusPanel);

    async function setStatus(status) {
      await apiJSON(`/api/alerts/${alertId}`, "PATCH", { status });
      alertDetail(alertId);
    }

    const stepsList = el("ul", { class: "recommend-list", children: rec.recommended_steps.map((s) => el("li", { text: s })) });
    container.appendChild(el("div", { class: "panel", children: [el("h2", { text: "Recommended next steps" }), stepsList] }));

    const responsePanel = el("div", { class: "panel", children: [el("h2", { text: "Response" })] });
    const actionRow = el("div", { class: "action-row" });
    if (a.pid) {
      actionRow.appendChild(
        el("button", {
          class: "btn btn-danger btn-sm",
          text: `Propose terminating PID ${a.pid}`,
          onClick: async () => {
            const reason = window.prompt("Reason for this proposal:", `From alert #${a.id}: ${a.title}`);
            if (reason === null) return;
            await apiJSON("/api/response/actions/terminate", "POST", { pid: a.pid, reason, alert_id: a.id });
            alert("Proposed. Approve it from the Response tab.");
          },
        })
      );
    }
    if (a.file_path) {
      actionRow.appendChild(
        el("button", {
          class: "btn btn-danger btn-sm",
          text: "Propose quarantining the implicated file",
          onClick: async () => {
            const reason = window.prompt("Reason for this proposal:", `From alert #${a.id}: ${a.title}`);
            if (reason === null) return;
            await apiJSON("/api/response/actions/quarantine", "POST", { file_path: a.file_path, reason, alert_id: a.id });
            alert("Proposed. Approve it from the Response tab.");
          },
        })
      );
    }
    if (!a.pid && !a.file_path) actionRow.appendChild(el("span", { class: "muted", text: "No process or file target on this alert." }));
    responsePanel.appendChild(actionRow);
    container.appendChild(responsePanel);

    const relAlerts = rec.related_alerts.map((ra) =>
      row([
        (() => { const c = document.createElement("td"); c.appendChild(el("span", { class: `sev-badge sev-${ra.severity}`, text: ra.severity })); return c; })(),
        td(ra.rule_name),
        td(fmtTime(ra.timestamp), { muted: true }),
      ], () => { window.location.href = `/alerts/${ra.id}`; })
    );
    const relAlertsTable = el("table", {
      children: [
        el("thead", { html: "<tr><th>Severity</th><th>Rule</th><th>When</th></tr>" }),
        el("tbody", { children: relAlerts.length ? relAlerts : [emptyRow(3, "No related alerts in this window.")] }),
      ],
    });
    container.appendChild(el("div", { class: "panel", children: [el("h2", { text: "Related alerts (same process/account)" }), el("div", { class: "table-scroll", children: [relAlertsTable] })] }));

    const relEvents = rec.related_events.map((e) =>
      row([td(e.source), td(e.event_type), td(fmtTime(e.timestamp), { muted: true })])
    );
    const relEventsTable = el("table", {
      children: [
        el("thead", { html: "<tr><th>Source</th><th>Event type</th><th>When</th></tr>" }),
        el("tbody", { children: relEvents.length ? relEvents : [emptyRow(3, "No related raw events in this window.")] }),
      ],
    });
    container.appendChild(el("div", { class: "panel", children: [el("h2", { text: "Related raw events (±15 min)" }), el("div", { class: "table-scroll", children: [relEventsTable] })] }));
  }

  async function monitoring() {
    refreshStatusDot();
    async function loadProcesses() {
      const data = await api("/api/processes");
      const rows = data.processes.slice(0, 150).map((p) =>
        row([
          td(p.pid, { mono: true }),
          td(p.name),
          td(p.username, { muted: true }),
          td(p.cpu_percent != null ? p.cpu_percent.toFixed(1) : "—", { mono: true }),
          td(p.memory_mb != null ? p.memory_mb.toFixed(1) : "—", { mono: true }),
          td(p.exe, { mono: true, muted: true }),
        ])
      );
      setBody("processes-table", rows, 6, "No process data.");
    }
    async function loadNetwork() {
      const data = await api("/api/network");
      const rows = data.connections.map((c) =>
        row([
          td(c.process_name),
          td(c.pid, { mono: true }),
          td(`${c.local_addr}:${c.local_port}`, { mono: true }),
          td(`${c.remote_addr}:${c.remote_port}`, { mono: true }),
          td(c.protocol),
          td(c.status, { muted: true }),
          td(null, {
            node: el("button", {
              class: "btn btn-danger btn-sm",
              text: "Terminate owner",
              onClick: async () => {
                if (!c.pid) return;
                const reason = window.prompt("Reason:", `Suspicious connection to ${c.remote_addr}:${c.remote_port}`);
                if (reason === null) return;
                await apiJSON("/api/response/actions/terminate", "POST", { pid: c.pid, reason });
                alert("Proposed. Approve it from the Response tab.");
              },
            }),
          }),
        ])
      );
      setBody("network-table", rows, 7, "No active connections with a remote peer.");
    }
    await Promise.all([loadProcesses(), loadNetwork()]);
    setInterval(() => { loadProcesses(); loadNetwork(); refreshStatusDot(); }, REFRESH_MS);
  }

  async function response() {
    refreshStatusDot();

    async function loadPending() {
      const data = await api("/api/response/actions?status=PENDING&limit=50");
      const rows = data.actions.map((a) =>
        row([
          td(a.action_type),
          td(describeTarget(a), { mono: true }),
          td(a.reason),
          td(a.requested_by),
          td(fmtTime(a.created_at), { muted: true }),
          td(null, {
            node: el("div", {
              class: "action-row",
              children: [
                el("button", { class: "btn btn-accent btn-sm", text: "Approve", onClick: () => decideAction(a.id, true, reloadAll) }),
                el("button", { class: "btn btn-danger btn-sm", text: "Reject", onClick: () => decideAction(a.id, false, reloadAll) }),
              ],
            }),
          }),
        ])
      );
      setBody("pending-actions-table", rows, 6, "Nothing pending.");
    }

    async function loadHistory() {
      const data = await api("/api/response/actions?limit=50");
      const done = data.actions.filter((a) => a.status !== "PENDING");
      const rows = done.map((a) =>
        row([
          td(a.action_type),
          td(describeTarget(a), { mono: true }),
          td(a.status),
          td(a.approved_by),
          td(a.result_message, { muted: true }),
        ])
      );
      setBody("action-history-table", rows, 5, "No decided actions yet.");
    }

    async function loadQuarantine() {
      const data = await api("/api/response/quarantine");
      const rows = data.items.map((item) =>
        row([
          td(item.original_path, { mono: true }),
          td(item.sha256 ? item.sha256.slice(0, 16) + "…" : "—", { mono: true, muted: true }),
          td(item.size_bytes != null ? `${item.size_bytes} B` : "—"),
          td(fmtTime(item.quarantined_at), { muted: true }),
          td(null, {
            node: item.restored
              ? el("span", { class: "muted", text: "restored" })
              : el("button", {
                  class: "btn btn-sm",
                  text: "Restore",
                  onClick: async () => {
                    if (!window.confirm(`Restore ${item.original_path}?`)) return;
                    await api(`/api/response/quarantine/${item.id}/restore`, { method: "POST" });
                    reloadAll();
                  },
                }),
          }),
        ])
      );
      setBody("quarantine-table", rows, 5, "Nothing quarantined.");
    }

    function reloadAll() {
      loadPending();
      loadHistory();
      loadQuarantine();
      refreshStatusDot();
    }

    window.SentinelSOC.pages.proposeTerminate = async function () {
      const pid = parseInt(document.getElementById("tp-pid").value, 10);
      const reason = document.getElementById("tp-reason").value;
      if (!pid || !reason) { alert("PID and reason are required."); return; }
      await apiJSON("/api/response/actions/terminate", "POST", { pid, reason });
      document.getElementById("tp-pid").value = "";
      document.getElementById("tp-reason").value = "";
      reloadAll();
    };
    window.SentinelSOC.pages.proposeQuarantine = async function () {
      const file_path = document.getElementById("qf-path").value;
      const reason = document.getElementById("qf-reason").value;
      if (!file_path || !reason) { alert("File path and reason are required."); return; }
      await apiJSON("/api/response/actions/quarantine", "POST", { file_path, reason });
      document.getElementById("qf-path").value = "";
      document.getElementById("qf-reason").value = "";
      reloadAll();
    };

    reloadAll();
    setInterval(reloadAll, REFRESH_MS);
  }

  window.SentinelSOC = {
    pages: { overview, alertsList, alertDetail, monitoring, response },
  };
})();
