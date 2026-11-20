"""Built-in detection rules.

Each Rule's `match` function receives a normalized record (a dict — see
collectors/*.py for the shapes produced per source) and a
DetectionContext (detection/engine.py) that can query recent history
for correlation (e.g. "how many failed logons for this account in the
last 5 minutes?").

Rules are deliberately pattern/heuristic based on locally observable
data (process metadata, command lines, event log fields, connection
tuples) — this agent does local/offline analysis only, so there is no
cloud reputation lookup or live threat feed involved. Categories and
technique IDs follow the public MITRE ATT&CK framework, used here
purely as a defensive classification scheme.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional

Severity = str  # "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"


@dataclass
class Rule:
    id: str
    name: str
    domain: str  # "eventlog" | "process" | "network"
    category: str
    mitre_technique: str
    severity: Severity
    description: str
    match: Callable[[dict, "object"], bool]
    enabled: bool = True
    suggested_response: Optional[str] = None  # "TERMINATE_PROCESS" | "QUARANTINE_FILE" | None


def _lower(record: dict, *keys: str) -> str:
    for k in keys:
        v = record.get(k)
        if v:
            return str(v).lower()
    return ""


POWERSHELL_SUSPICIOUS_TOKENS = (
    "-enc ", "-encodedcommand", "downloadstring", "downloadfile", "iex ",
    "invoke-expression", "-nop", "-noprofile", "-windowstyle hidden", "-w hidden",
    "bypass", "frombase64string", "net.webclient", "-exec bypass",
)

LOLBIN_PATTERNS = (
    (re.compile(r"certutil(\.exe)?.*(-urlcache|-decode|-decodehex)", re.I), "certutil"),
    (re.compile(r"mshta(\.exe)?\s+https?://", re.I), "mshta"),
    (re.compile(r"regsvr32(\.exe)?.*(/i:https?://|scrobj\.dll)", re.I), "regsvr32"),
    (re.compile(r"rundll32(\.exe)?.*(javascript:|\.dll,\s*\w+)", re.I), "rundll32"),
    (re.compile(r"bitsadmin(\.exe)?.*\/transfer", re.I), "bitsadmin"),
    (re.compile(r"wmic(\.exe)?.*process\s+call\s+create", re.I), "wmic"),
)

CREDENTIAL_DUMP_PATTERNS = (
    re.compile(r"mimikatz", re.I),
    re.compile(r"procdump.*lsass", re.I),
    re.compile(r"comsvcs\.dll.*minidump", re.I),
    re.compile(r"ntdsutil.*ifm", re.I),
)

MASQUERADE_NAMES = {
    "svch0st.exe", "scvhost.exe", "lsas.exe", "lsass.exe", "csrs.exe",
    "explore.exe", "svchost.exe", "winlogon.exe",
}
# Names that, if NOT running from a System32-ish path, are suspicious.
SYSTEM_PROCESS_EXPECTED_PATH = {
    "lsass.exe": "system32",
    "svchost.exe": "system32",
    "winlogon.exe": "system32",
    "csrss.exe": "system32",
    "services.exe": "system32",
}


def _in_suspicious_path(path: str, suspicious_segments: list[str]) -> bool:
    p = (path or "").lower()
    return any(seg in p for seg in suspicious_segments)


def build_default_rules() -> list[Rule]:
    rules: list[Rule] = []

    # ---------------------------------------------------------- Event Log
    def m_brute_force_success(record, ctx):
        if record.get("event_type") != "logon_success":
            return False
        account = record.get("account_name")
        if not account or account in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
            return False
        failures = ctx.recent_eventlog_count("logon_failure", account_name=account, seconds=300)
        return failures >= 5

    rules.append(Rule(
        id="R-EVT-001", name="Successful logon after repeated failures",
        domain="eventlog", category="Credential Access", mitre_technique="T1110",
        severity="HIGH",
        description="An account logged on successfully after 5+ failed attempts in the "
                     "preceding 5 minutes — consistent with a brute-force or password-"
                     "spraying attempt that eventually succeeded.",
        match=m_brute_force_success,
    ))

    rules.append(Rule(
        id="R-EVT-002", name="Security event log cleared",
        domain="eventlog", category="Defense Evasion", mitre_technique="T1070.001",
        severity="CRITICAL",
        description="The Security event log was cleared. This is a strong anti-forensic "
                     "indicator and is rarely done for a legitimate reason outside planned "
                     "maintenance.",
        match=lambda r, ctx: r.get("event_type") == "log_cleared",
    ))

    rules.append(Rule(
        id="R-EVT-003", name="New service installed",
        domain="eventlog", category="Persistence", mitre_technique="T1543.003",
        severity="MEDIUM",
        description="A new Windows service was installed. Services are a common "
                     "persistence mechanism; verify the binary path and publisher.",
        match=lambda r, ctx: r.get("event_type") == "service_installed",
    ))

    def m_suspicious_service_path(record, ctx):
        if record.get("event_type") != "service_installed":
            return False
        path = record.get("service_image_path") or ""
        return _in_suspicious_path(path, ctx.suspicious_path_segments)

    rules.append(Rule(
        id="R-EVT-003B", name="Service installed from a suspicious path",
        domain="eventlog", category="Persistence", mitre_technique="T1543.003",
        severity="HIGH",
        description="A new Windows service points at a binary in a temp/download/"
                     "world-writable directory — uncommon for legitimate software.",
        match=m_suspicious_service_path,
    ))

    rules.append(Rule(
        id="R-EVT-004", name="Scheduled task created",
        domain="eventlog", category="Persistence", mitre_technique="T1053.005",
        severity="MEDIUM",
        description="A scheduled task was created. Scheduled tasks are a common way to "
                     "achieve persistence or periodic execution.",
        match=lambda r, ctx: r.get("event_type") == "scheduled_task_created",
    ))

    rules.append(Rule(
        id="R-EVT-005", name="Account added to a privileged local group",
        domain="eventlog", category="Privilege Escalation", mitre_technique="T1098",
        severity="HIGH",
        description="An account was added to a privileged local group (e.g. "
                     "Administrators). Confirm this was an intentional, authorized change.",
        match=lambda r, ctx: r.get("event_type") == "added_to_security_group",
    ))

    rules.append(Rule(
        id="R-EVT-006", name="Audit policy changed",
        domain="eventlog", category="Defense Evasion", mitre_technique="T1562.002",
        severity="HIGH",
        description="The system audit policy was changed. Attackers sometimes disable or "
                     "narrow auditing to reduce the telemetry they generate.",
        match=lambda r, ctx: r.get("event_type") == "audit_policy_changed",
    ))

    def m_powershell_suspicious(record, ctx):
        if record.get("event_type") not in ("powershell_script_block", "process_create_evt"):
            return False
        blob = _lower(record, "script_block_text", "cmdline", "message")
        return any(tok in blob for tok in POWERSHELL_SUSPICIOUS_TOKENS)

    rules.append(Rule(
        id="R-EVT-007", name="Suspicious PowerShell content",
        domain="eventlog", category="Execution", mitre_technique="T1059.001",
        severity="HIGH",
        description="PowerShell activity contains indicators commonly seen in malicious "
                     "scripts: encoded commands, download cradles, or hidden/bypass "
                     "execution flags.",
        match=m_powershell_suspicious,
    ))

    rules.append(Rule(
        id="R-EVT-009", name="Account lockout",
        domain="eventlog", category="Credential Access", mitre_technique="T1110",
        severity="LOW",
        description="An account was locked out after too many failed logon attempts.",
        match=lambda r, ctx: r.get("event_type") == "account_lockout",
    ))

    rules.append(Rule(
        id="R-EVT-010", name="Endpoint protection disabled or degraded",
        domain="eventlog", category="Defense Evasion", mitre_technique="T1562.001",
        severity="HIGH",
        description="Windows Defender (or another monitored protection component) "
                     "reported real-time protection being disabled or a similar "
                     "degradation.",
        match=lambda r, ctx: r.get("event_type") == "defender_protection_disabled",
    ))

    def m_sysmon_registry_run_key(record, ctx):
        if record.get("event_type") != "sysmon_registry_set":
            return False
        target = _lower(record, "registry_target")
        return "\\currentversion\\run" in target or "\\currentversion\\runonce" in target

    rules.append(Rule(
        id="R-EVT-011", name="Registry Run key persistence (Sysmon)",
        domain="eventlog", category="Persistence", mitre_technique="T1547.001",
        severity="MEDIUM",
        description="A value was written to a Run/RunOnce registry key — a very common "
                     "way for malware to persist across reboots. Requires Sysmon.",
        match=m_sysmon_registry_run_key,
    ))

    # ------------------------------------------------------------- Process
    def m_proc_suspicious_path(record, ctx):
        if record.get("event_type") != "process_create":
            return False
        return _in_suspicious_path(record.get("exe_path", ""), ctx.suspicious_path_segments)

    rules.append(Rule(
        id="R-PROC-001", name="Process launched from a suspicious directory",
        domain="process", category="Defense Evasion", mitre_technique="T1036",
        severity="MEDIUM",
        description="A process started from a temp, downloads, or other "
                     "world-writable directory — a common staging location for "
                     "dropped malware.",
        match=m_proc_suspicious_path,
        suggested_response="TERMINATE_PROCESS",
    ))

    def m_lolbin(record, ctx):
        if record.get("event_type") != "process_create":
            return False
        cmdline = record.get("cmdline") or ""
        return any(pattern.search(cmdline) for pattern, _ in LOLBIN_PATTERNS)

    rules.append(Rule(
        id="R-PROC-002", name="Living-off-the-land binary used suspiciously",
        domain="process", category="Defense Evasion", mitre_technique="T1218",
        severity="HIGH",
        description="A built-in Windows utility (certutil, mshta, regsvr32, rundll32, "
                     "bitsadmin, wmic) was invoked in a pattern commonly used to download "
                     "or execute payloads while evading simpler detections.",
        match=m_lolbin,
        suggested_response="TERMINATE_PROCESS",
    ))

    def m_office_spawns_shell(record, ctx):
        if record.get("event_type") != "process_create":
            return False
        parent = _lower(record, "parent_name")
        name = _lower(record, "name")
        office_parents = ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "mspub.exe")
        shells = ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe")
        return parent in office_parents and name in shells

    rules.append(Rule(
        id="R-PROC-003", name="Office application spawned a command shell",
        domain="process", category="Execution", mitre_technique="T1566",
        severity="HIGH",
        description="A Microsoft Office application directly spawned a shell or "
                     "scripting interpreter — a classic signature of a malicious "
                     "document/macro.",
        match=m_office_spawns_shell,
        suggested_response="TERMINATE_PROCESS",
    ))

    def m_powershell_cmdline(record, ctx):
        if record.get("event_type") != "process_create":
            return False
        name = _lower(record, "name")
        if name not in ("powershell.exe", "pwsh.exe"):
            return False
        cmd = _lower(record, "cmdline")
        return any(tok in cmd for tok in POWERSHELL_SUSPICIOUS_TOKENS)

    rules.append(Rule(
        id="R-PROC-004", name="PowerShell launched with suspicious arguments",
        domain="process", category="Execution", mitre_technique="T1059.001",
        severity="HIGH",
        description="powershell.exe/pwsh.exe was launched with an encoded command, a "
                     "download cradle, or hidden/bypass flags on the command line.",
        match=m_powershell_cmdline,
        suggested_response="TERMINATE_PROCESS",
    ))

    def m_masquerade(record, ctx):
        if record.get("event_type") != "process_create":
            return False
        name = _lower(record, "name")
        if name in MASQUERADE_NAMES and name not in ("svchost.exe", "lsass.exe", "winlogon.exe"):
            return True  # a typosquatted name is suspicious regardless of path
        expected = SYSTEM_PROCESS_EXPECTED_PATH.get(name)
        if expected:
            path = _lower(record, "exe_path")
            return expected not in path
        return False

    rules.append(Rule(
        id="R-PROC-006", name="Likely process masquerading",
        domain="process", category="Defense Evasion", mitre_technique="T1036.005",
        severity="CRITICAL",
        description="A process name mimics a core Windows system process (e.g. "
                     "svchost.exe, lsass.exe) but is either misspelled or not running "
                     "from the expected system directory.",
        match=m_masquerade,
        suggested_response="TERMINATE_PROCESS",
    ))

    def m_shadow_copy_deletion(record, ctx):
        if record.get("event_type") != "process_create":
            return False
        cmd = _lower(record, "cmdline")
        patterns = (
            "vssadmin" in cmd and "delete" in cmd and "shadow" in cmd,
            "wbadmin" in cmd and "delete" in cmd and "catalog" in cmd,
            "bcdedit" in cmd and ("recoveryenabled" in cmd or "bootstatuspolicy" in cmd),
        )
        return any(patterns)

    rules.append(Rule(
        id="R-PROC-007", name="Backup/recovery tampering (ransomware precursor)",
        domain="process", category="Impact", mitre_technique="T1490",
        severity="CRITICAL",
        description="A command commonly used to delete shadow copies, wipe backup "
                     "catalogs, or disable recovery options was executed — frequently "
                     "seen immediately before ransomware encryption begins.",
        match=m_shadow_copy_deletion,
        suggested_response="TERMINATE_PROCESS",
    ))

    def m_credential_dumping(record, ctx):
        if record.get("event_type") != "process_create":
            return False
        cmd = record.get("cmdline") or ""
        name = record.get("name") or ""
        return any(p.search(cmd) or p.search(name) for p in CREDENTIAL_DUMP_PATTERNS)

    rules.append(Rule(
        id="R-PROC-008", name="Credential dumping tool indicators",
        domain="process", category="Credential Access", mitre_technique="T1003",
        severity="CRITICAL",
        description="Process name or command line matches well-known credential-dumping "
                     "tooling or technique signatures (e.g. targeting lsass memory).",
        match=m_credential_dumping,
        suggested_response="TERMINATE_PROCESS",
    ))

    # ------------------------------------------------------------- Network
    def m_unexpected_listener_outbound(record, ctx):
        if record.get("event_type") != "network_connection":
            return False
        proc = _lower(record, "process_name")
        port = record.get("remote_port") or 0
        if not proc or not record.get("remote_addr"):
            return False
        common_browsers = ("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe")
        common_ports = {80, 443, 53, 123}
        return proc not in common_browsers and port not in common_ports and port >= 1024

    rules.append(Rule(
        id="R-NET-001", name="Outbound connection to an uncommon high port",
        domain="network", category="Command and Control", mitre_technique="T1571",
        severity="MEDIUM",
        description="A non-browser process connected outbound to a high, non-standard "
                     "port. Not inherently malicious, but worth correlating with the "
                     "process's reputation and path.",
        match=m_unexpected_listener_outbound,
    ))

    def m_no_exe_path_network(record, ctx):
        if record.get("event_type") != "network_connection":
            return False
        return bool(record.get("pid")) and not record.get("process_name")

    rules.append(Rule(
        id="R-NET-002", name="Network connection from an unidentifiable process",
        domain="network", category="Defense Evasion", mitre_technique="T1036",
        severity="HIGH",
        description="A process holding a network connection could not be identified "
                     "(name/path unavailable) — can indicate a short-lived or "
                     "deliberately hidden process.",
        match=m_no_exe_path_network,
    ))

    def m_blocklisted_ip(record, ctx):
        if record.get("event_type") != "network_connection":
            return False
        remote = record.get("remote_addr")
        return bool(remote) and ctx.ip_is_blocklisted(remote)

    rules.append(Rule(
        id="R-NET-004", name="Connection to a locally blocklisted address",
        domain="network", category="Command and Control", mitre_technique="T1071",
        severity="HIGH",
        description="A connection matched an entry in the local IP/CIDR blocklist "
                     "(config/blocklist_ips.txt).",
        match=m_blocklisted_ip,
        suggested_response="TERMINATE_PROCESS",
    ))

    def m_beaconing(record, ctx):
        if record.get("event_type") != "network_connection":
            return False
        pid = record.get("pid")
        if not pid:
            return False
        distinct_ips = ctx.recent_distinct_remote_ips(pid, seconds=120)
        return distinct_ips >= 5

    rules.append(Rule(
        id="R-NET-003", name="Many distinct destinations from one process",
        domain="network", category="Command and Control", mitre_technique="T1571",
        severity="MEDIUM",
        description="A single process contacted five or more distinct remote "
                     "addresses within two minutes — consistent with beaconing, "
                     "scanning, or C2 domain-fronting behavior.",
        match=m_beaconing,
    ))

    return rules
