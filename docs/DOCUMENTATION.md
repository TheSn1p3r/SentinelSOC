# SentinelSOC — Technical Documentation

1. [Architecture](#architecture)
2. [Configuration reference](#configuration-reference)
3. [Detection rules reference](#detection-rules-reference)
4. [API reference](#api-reference)
5. [Dashboard guide](#dashboard-guide)
6. [Installation & deployment](#installation--deployment)
7. [Validating on real Windows](#validating-on-real-windows)
8. [Troubleshooting](#troubleshooting)
9. [Security considerations](#security-considerations)
10. [Known limitations & future work](#known-limitations--future-work)

---

## Architecture

### Context & goals

SentinelSOC is a single-host agent for a Windows 10/11 machine: collect
telemetry, detect suspicious patterns locally (no cloud dependency), let an
analyst investigate with context instead of raw logs, and let that analyst
— not the software — decide whether to terminate a process or quarantine a
file. It's sized for one machine and one (or a small number of) analysts,
not a multi-tenant fleet-management product.

### High-level design

```
 ┌─────────────────────────────────────────────────────────────────┐
 │                         SentinelAgent                             │
 │                                                                     │
 │  ┌───────────────┐ ┌────────────────┐ ┌───────────────────┐       │
 │  │ EventLog      │ │ Process        │ │ Network            │       │
 │  │ Collector     │ │ Monitor        │ │ Monitor            │       │
 │  │ (pywin32)     │ │ (psutil)       │ │ (psutil)           │       │
 │  └──────┬────────┘ └───────┬────────┘ └─────────┬──────────┘       │
 │         │  normalized records (dicts), one callback per record     │
 │         └──────────────────┼───────────────────────┘              │
 │                             ▼                                      │
 │                   DetectionEngine.evaluate()                       │
 │                 (rules.py matches → scoring.py scores)             │
 │                             │                                      │
 │                 ┌───────────┴────────────┐                        │
 │                 ▼                        ▼                        │
 │         DBManager (SQLite)      ResponseManager.auto_propose_*     │
 │     events / alerts / incidents    (CRITICAL alerts only, and      │
 │     / response_actions / audit      only ever creates a PENDING    │
 │                 ▲                   row — see below)               │
 │                 │                        │                        │
 └─────────────────┼────────────────────────┼────────────────────────┘
                    │                        │
             ┌──────┴────────────────────────┴──────┐
             │          FastAPI app (api/app.py)      │
             │  pages (HTML, session cookie)          │
             │  /api/* (JSON, cookie or X-API-Key)    │
             └──────────────────┬──────────────────────┘
                                 │
                        Browser dashboard
                 (templates + dashboard.js, polling)
```

`SentinelAgent` (`sentinelsoc/agent.py`) is the one object that owns
everything: the database, the detection engine, the response manager, and
the collector threads. Both entry points — `main.py` (foreground/dev) and
`sentinelsoc/service_win.py` (the Windows Service) — build one
`SentinelAgent`, call `.start()`, and hand it to `create_app()` so the
FastAPI layer is just a thin view over an already-running agent. Nothing
about the detection or response logic is HTTP-specific.

### Data flow

1. A collector observes something (a new process, a new outbound
   connection, an Event Log record) and normalizes it into a plain dict
   with at least `source`, `event_type`, and `timestamp`.
2. It calls `SentinelAgent._on_record()`, which stores the raw record
   (`events` table) and hands it to `DetectionEngine.evaluate()`.
3. The engine runs every rule whose `domain` matches the record's
   `source`, via a `DetectionContext` that can query recent history (e.g.
   "how many failed logons for this account in the last 5 minutes?").
4. Each match becomes an alert dict, scored by `RiskScorer`, and stored
   (`alerts` table). HIGH/CRITICAL alerts are passed to
   `ResponseManager.auto_propose_from_alert()`.
5. A background loop periodically runs `correlate_incidents()`, grouping
   recent un-incidented alerts that share a PID or account into an
   `incidents` row.
6. The dashboard polls `/api/*` on a timer (`dashboard.refresh_seconds`)
   and renders tables; nothing is pushed server→client.

### Decisions & trade-offs

- **SQLite with short-lived connections (WAL mode) instead of one shared
  connection or an ORM.** Several threads (collectors, the detection/
  correlation loop, the API server) touch the database. A fresh
  `sqlite3.connect()` per call with WAL + a busy timeout is simpler to
  reason about than coordinating one long-lived connection across threads,
  and is far more throughput than this agent's telemetry volume needs.
  Trade-off: not the fastest possible pattern under very high write
  concurrency, which was never the design point.
- **Rule-based detection, not ML/behavioral.** Every alert traces to a
  named rule an analyst can read, tune, or disable — important for a tool
  that recommends killing processes. The cost is the usual one for
  signature/heuristic detection: it catches known patterns and won't catch
  a genuinely novel technique with no matching rule.
- **Analyst approval is structural, not a UI nicety.** `ResponseManager`
  has no code path that both creates and executes an action in the same
  call — `propose_*()` only ever inserts a `PENDING` row;
  `decide(approve=True)` is the only thing that calls `_execute()`. This
  was deliberate: even `auto_propose_from_alert()`, triggered automatically
  on a CRITICAL alert, stops at proposing.
- **One API key, not per-analyst accounts.** This is a single-host tool for
  a small team, not a multi-tenant product — see "Security considerations"
  below for exactly what this does and doesn't protect against.
- **In-memory sessions.** Session tokens live in a process-local dict, not
  the database. They're meant to be ephemeral; losing them on a service
  restart (re-login required) is an acceptable trade for not persisting
  session secrets to disk.
- **Windowed correlation, not graph-based.** `correlate_incidents()` groups
  by a shared PID or account name within `correlation_window_seconds`. It's
  simple and cheap, and it's deliberately a starting point — see
  "Known limitations" for where a real case-management/graph correlation
  model would do better.

---

## Configuration reference

All configuration lives in `config/config.yaml`, created automatically on
first run (with a freshly generated API key) from the tracked
`config/config.yaml.example` template — `config.yaml` itself is gitignored
so a generated key never ends up in version control. Copy the example
yourself first if you want to set non-default values before the first run;
otherwise just run the app and edit the generated file afterwards. Paths
are resolved
relative to the config file's parent directory unless given as absolute
paths (see `Config.resolve_path` in `sentinelsoc/config.py`).

| Key | Default | Meaning |
|---|---|---|
| `agent.name` | `SentinelSOC` | Display name used in logs and the dashboard title. |
| `agent.poll_interval_seconds` | `5` | Not currently read directly — each collector has its own interval below; kept for a future shared default. |
| `database.path` | `./data/sentinelsoc.db` | SQLite file. Created automatically, including parent directories. |
| `logging.level` | `INFO` | Python logging level name. |
| `logging.log_dir` | `./logs` | Rotating file handler target (`sentinelsoc.log`, plus `.1`, `.2`, …). |
| `logging.max_bytes` / `backup_count` | `10 MB` / `5` | Rotation settings. |
| `collectors.event_log.enabled` | `true` | Toggle the Event Log collector. |
| `collectors.event_log.logs` | `[Security, System, Application]` | Classic event logs to tail. |
| `collectors.event_log.sysmon_log` | `Microsoft-Windows-Sysmon/Operational` | Read automatically if present (optional — see below). |
| `collectors.event_log.use_sysmon_if_available` | `true` | Set `false` to skip even checking for Sysmon. |
| `collectors.*.poll_interval_seconds` | `5` | Per-collector poll interval. |
| `collectors.process_monitor.enabled` / `network_monitor.enabled` | `true` | Toggle each collector independently. |
| `detection.correlation_window_seconds` | `300` | Window used both by correlation rules (e.g. brute-force) and incident grouping. |
| `detection.suspicious_path_segments` | temp/downloads/public/programdata | Lower-cased substrings checked against a process's `exe_path`. |
| `detection.blocklist_ips_file` | `./config/blocklist_ips.txt` | One IP or CIDR per line, `#` comments allowed. Empty by default — see that file's header. |
| `detection.rules_overrides_file` | `null` | Optional YAML mapping `rule_id: {enabled: bool, severity: STR}` to tune the built-in rules without editing `rules.py`. |
| `response.auto_propose_on_critical` | `true` | Whether CRITICAL alerts with a `suggested_response` auto-create a `PENDING` action. **Never** auto-executes anything regardless of this setting. |
| `response.quarantine_dir` | `./quarantine` | Where quarantined files are moved (renamed to a random UUID). |
| `api.host` | `127.0.0.1` | Change deliberately — see "Exposing the dashboard beyond localhost" below. |
| `api.port` | `8765` | Dashboard/API port. |
| `api.api_key` | `null` → auto-generated | The one credential this tool has. Rotate by editing the file and restarting the service. |
| `dashboard.title` | `SentinelSOC` | Shown in the page title and sidebar. |
| `dashboard.refresh_seconds` | `10` | Client-side polling interval. |

### Tuning a built-in rule without editing code

Create a file (e.g. `config/rule_overrides.yaml`):

```yaml
R-NET-001:         # outbound connection to an uncommon high port — noisy on a dev box
  enabled: false
R-EVT-001:          # brute-force-then-success — tighten to CRITICAL
  severity: CRITICAL
```

Point `detection.rules_overrides_file` at it and restart the service.

### Exposing the dashboard beyond localhost

Every request — page or API — still requires the session cookie or
`X-API-Key`, so changing `api.host` to `0.0.0.0` doesn't remove
authentication. It does mean anything that can reach the port can attempt
to log in, and an unencrypted HTTP login form on an untrusted network is a
real exposure. If you need remote access, put it behind something that
terminates TLS (e.g. a reverse proxy, or a VPN into the host) rather than
exposing port 8765 directly.

---

## Detection rules reference

All rules are defined in `sentinelsoc/detection/rules.py`. "Domain" is
which collector's records a rule evaluates against.

| ID | Domain | Name | Severity | ATT&CK |
|---|---|---|---|---|
| R-EVT-001 | eventlog | Successful logon after repeated failures | HIGH | T1110 |
| R-EVT-002 | eventlog | Security event log cleared | CRITICAL | T1070.001 |
| R-EVT-003 | eventlog | New service installed | MEDIUM | T1543.003 |
| R-EVT-003B | eventlog | Service installed from a suspicious path | HIGH | T1543.003 |
| R-EVT-004 | eventlog | Scheduled task created | MEDIUM | T1053.005 |
| R-EVT-005 | eventlog | Account added to a privileged local group | HIGH | T1098 |
| R-EVT-006 | eventlog | Audit policy changed | HIGH | T1562.002 |
| R-EVT-007 | eventlog | Suspicious PowerShell content | HIGH | T1059.001 |
| R-EVT-009 | eventlog | Account lockout | LOW | T1110 |
| R-EVT-010 | eventlog | Endpoint protection disabled or degraded | HIGH | T1562.001 |
| R-EVT-011 | eventlog | Registry Run key persistence (Sysmon) | MEDIUM | T1547.001 |
| R-PROC-001 | process | Process launched from a suspicious directory | MEDIUM | T1036 |
| R-PROC-002 | process | Living-off-the-land binary used suspiciously | HIGH | T1218 |
| R-PROC-003 | process | Office application spawned a command shell | HIGH | T1566 |
| R-PROC-004 | process | PowerShell launched with suspicious arguments | HIGH | T1059.001 |
| R-PROC-006 | process | Likely process masquerading | CRITICAL | T1036.005 |
| R-PROC-007 | process | Backup/recovery tampering (ransomware precursor) | CRITICAL | T1490 |
| R-PROC-008 | process | Credential dumping tool indicators | CRITICAL | T1003 |
| R-NET-001 | network | Outbound connection to an uncommon high port | MEDIUM | T1571 |
| R-NET-002 | network | Network connection from an unidentifiable process | HIGH | T1036 |
| R-NET-003 | network | Many distinct destinations from one process | MEDIUM | T1571 |
| R-NET-004 | network | Connection to a locally blocklisted address | HIGH | T1071 |

Risk scoring (`sentinelsoc/detection/scoring.py`): each severity has a base
weight (INFO 5, LOW 20, MEDIUM 40, HIGH 65, CRITICAL 90), plus up to +20 for
context (execution from a suspicious path, encoded/hidden PowerShell
flags), capped at 100. Incident scores take the highest member alert's
score plus +10 per additional correlated alert, also capped at 100.

---

## API reference

All `/api/*` routes require either the session cookie (set by `/login`) or
an `X-API-Key: <key>` header, and return JSON. Interactive docs are also
available at `/api/docs` (Swagger UI) once logged in.

| Method | Path | Body | Notes |
|---|---|---|---|
| `GET`  | `/api/alerts` | — | Query: `status`, `severity`, `limit`, `offset` |
| `GET`  | `/api/alerts/{id}` | — | Includes `recommendation` (see below) |
| `PATCH`| `/api/alerts/{id}` | `{status}` | `NEW\|ACKNOWLEDGED\|IN_PROGRESS\|RESOLVED\|FALSE_POSITIVE` |
| `GET`  | `/api/events` | — | Query: `source`, `event_type`, `limit`, `offset` |
| `GET`  | `/api/incidents` | — | Query: `status`, `limit` |
| `GET`  | `/api/processes` | — | Live `psutil` snapshot |
| `GET`  | `/api/processes/history` | — | From the `processes_seen` table |
| `GET`  | `/api/network` | — | Live `psutil` snapshot (connections with a remote peer) |
| `GET`  | `/api/network/history` | — | From the `network_connections` table |
| `GET`  | `/api/response/actions` | — | Query: `status`, `limit` |
| `POST` | `/api/response/actions/terminate` | `{pid, reason, alert_id?}` | Creates a `PENDING` action — does not execute |
| `POST` | `/api/response/actions/quarantine` | `{file_path, reason, alert_id?}` | Creates a `PENDING` action — does not execute |
| `POST` | `/api/response/actions/{id}/decide` | `{analyst, approve, notes?}` | The only call that executes anything |
| `GET`  | `/api/response/quarantine` | — | Quarantine records |
| `POST` | `/api/response/quarantine/{id}/restore` | — | Query: `analyst` |
| `GET`  | `/api/audit` | — | Full audit trail |
| `GET`  | `/api/system/status` | — | Uptime, collector states, 24h severity counts, rule counts |
| `GET`  | `/api/system/config` | — | Sanitized config (API key masked) |

`GET /api/alerts/{id}`'s `recommendation` object:

```json
{
  "technique_id": "T1059.001",
  "technique_name": "Command and Scripting Interpreter: PowerShell",
  "explanation": "…the rule's description…",
  "recommended_steps": ["…", "…"],
  "related_alerts": [ /* same pid/account, any time */ ],
  "related_events": [ /* same pid/account, within ±15 min */ ],
  "incident": { /* if linked to one */ }
}
```

---

## Dashboard guide

- **Overview** — collector health, 24h alert counts by severity, actions
  awaiting your decision, and the most recent alerts.
- **Alerts** — the full alert list, filterable by severity/status. Click a
  row for detail.
- **Alert detail** — full alert fields, ATT&CK technique, recommended
  investigation steps, related alerts/events in the surrounding window,
  triage buttons (Acknowledge / In progress / Resolve / False positive),
  and — if the alert has a PID or file path — buttons to propose a response
  action from right there.
- **Monitoring** — live process table and live network-connections table
  (connections only, not listeners), each refreshing on a timer. You can
  propose terminating the owning process directly from a network row.
- **Response** — propose an action manually (by PID or file path), approve
  or reject anything pending, see history, and manage quarantined files
  (including restoring one).

---

## Installation & deployment

See the Quick Start in `README.md` for the common path. Beyond that:

- **Upgrading**: stop the service (`scripts\service_control.ps1 stop`),
  replace the application files (leave `config\`, `data\`, `logs\`,
  `quarantine\`, and `.venv\` in place unless you specifically want to
  reset them), run `.venv\Scripts\python.exe -m pip install -r
  requirements.txt` if dependencies changed, then start it again.
- **Permissions**: `install.ps1` disables inheritance on the install
  directory and grants Administrators + SYSTEM full control. The service
  itself runs as `LocalSystem` by default (pywin32's install default),
  which is included in that grant. This keeps a non-admin local user from
  reading the database, logs, or quarantined samples directly off disk —
  it has no effect on who can reach the dashboard over HTTP, which is
  controlled by `api.host`/`api.port` and the API key.
- **Uninstalling**: `scripts\uninstall.ps1` stops and removes the service.
  It leaves `data\`, `logs\`, and `quarantine\` in place unless you pass
  `-RemoveData` — quarantined samples might still matter for an open
  investigation, so deleting them isn't the default.

---

## Validating on real Windows

This was built and integration-tested in a Linux sandbox, which covers
everything except two Windows-only modules. Both are written to
well-documented pywin32 patterns, but **please specifically validate these
on your target Windows build before relying on this in production**:

1. **`sentinelsoc/service_win.py`** — install it
   (`scripts\install.ps1`), confirm it shows as `Running` in
   `services.msc`, confirm `scripts\service_control.ps1 stop`/`start` work,
   and confirm it survives a reboot (`StartType` should be Automatic).
2. **`sentinelsoc/collectors/eventlog_collector.py`** — specifically, the
   end-of-log behavior of `win32evtlog.ReadEventLog()`. The module treats
   certain exceptions as "caught up, nothing new" (see the `_BENIGN_EOF_WINERRORS`
   comment in that file) rather than errors; this is the one piece of Win32
   API behavior that couldn't be exercised without a real Windows Event
   Log. After installing, trigger a few events (e.g. a failed logon, or
   install a test service) and confirm a matching alert appears within a
   few poll cycles. If events are being missed or `sentinelsoc.log` shows
   repeated read errors on a log, that's the first place to look.

A quick manual check for #2 that exercises several rules at once: from an
elevated PowerShell on the monitored machine, run
`powershell.exe -nop -w hidden -enc <anything>` (even garbage base64) and
confirm an R-PROC-004 alert (and likely R-EVT-007, if PowerShell script
block logging is enabled) shows up in the dashboard within a few seconds.

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `install.ps1` fails at "Registering the SentinelSOC Windows Service" | pywin32's post-install step didn't run. Try `<path>\.venv\Scripts\python.exe -m pywin32_postinstall -install` (as Administrator), then re-run `install.ps1`. |
| Dashboard won't load | Confirm the service is `Running` (`scripts\service_control.ps1 status`), and that nothing else is using the configured port (`netstat -ano \| findstr 8765`). |
| Logged in but no alerts ever appear | Check `logs\sentinelsoc.log` for collector errors. Event Log collection needs the service running with sufficient rights to read the Security log (`LocalSystem`, the default, has this) — a manually-started `run_desktop.ps1` session as a non-admin user may not. |
| Network tab is empty / warns about privileges | `psutil.net_connections()` needs elevated rights to see connections owned by other users' processes; the service (running as SYSTEM) has this, a non-admin `run_desktop.ps1` session may not. |
| Forgot the API key | It's in `config\config.yaml` under `api.api_key` in plain text (readable by Administrators/SYSTEM per the installer's ACLs). There's no recovery flow by design — edit the file to set a new value and restart the service to pick it up. |
| Want to start over with a clean database | Stop the service, delete `data\sentinelsoc.db*`, start the service — the schema is recreated automatically. |

---

## Security considerations

- **Data collected**: Windows Event Log records (from the configured
  logs), process metadata (name, path, command line, user, parent) for
  newly created processes, and network connection tuples (local/remote
  address and port, protocol, owning process) for new outbound
  connections. All of it stays in the local SQLite database; nothing is
  transmitted anywhere.
- **Secrets**: the single API key, stored in plaintext in
  `config/config.yaml`. Treat that file's filesystem permissions as the
  real security boundary (see "Permissions" above).
- **Quarantined files** are moved, renamed, and have their write bit
  cleared, but are not encrypted or otherwise rendered inert beyond that —
  the quarantine folder should be covered by the same restricted ACLs as
  the rest of the install directory (it is, by default).
- **What this tool deliberately does not do**: it does not add Windows
  Defender (or any other security product) exclusions, does not disable or
  weaken any other security control, and does not hide its own process,
  service, or window from anything — it is named `SentinelSOC`
  consistently in Task Manager, `services.msc`, and the dashboard.

---

## Known limitations & future work

- **Classic Event Log API vs ETW.** `win32evtlog`'s classic API is simpler
  and well-documented but has higher latency and less detail than modern
  Event Tracing for Windows (ETW) subscriptions. Installing
  [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) and
  leaving `use_sysmon_if_available` on is the easiest way to raise
  fidelity without changing this codebase.
- **Correlation is windowed, not case-based.** `correlate_incidents()`
  groups by a shared PID or account within a fixed time window. A real
  investigation often spans process trees and multiple accounts over
  longer periods than one window — a graph-based correlation model (or at
  minimum, chaining PID → parent PID lineage) would do better.
- **No kernel-level tamper resistance.** This agent runs as an ordinary
  (if privileged) Windows process; a sufficiently privileged attacker who
  already has SYSTEM-level code execution could kill or blind it. That's
  true of most agent-based tooling without kernel driver support, which is
  out of scope here.
- **Single host, single credential.** No fleet management, no per-analyst
  accounts/roles, no SIEM export. For a team, the natural next step is
  forwarding `events`/`alerts` to a central SIEM rather than rebuilding
  multi-tenancy into this agent.
- **No live threat intelligence.** `blocklist_ips.txt` is manually
  maintained by design, consistent with this agent's "local/offline
  analysis" scope (see the Confirmed Specifications) — wiring in a feed is
  a deliberate choice left to you, not an oversight.
