"""Incident investigation recommendations.

Deliberately rule-based and deterministic rather than generative: an
analyst needs to know *why* a recommendation was made, and this agent
does local/offline analysis only (no model or cloud call involved).
For a given alert, this pulls together:

  * a plain-language explanation of what was detected and why it matters
  * a category-specific checklist of what to look at next
  * related events/alerts that share the same process or account in a
    surrounding time window, so the analyst doesn't have to go hunting
    for them manually
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

GENERIC_GUIDANCE = [
    "Confirm whether the account or process owner intended this activity.",
    "Check whether the same process/account triggered any other alerts recently.",
    "If a process is involved, review its parent process and command line.",
    "Decide whether to isolate the host from the network while you investigate.",
]

CATEGORY_GUIDANCE = {
    "Credential Access": [
        "Identify the source host/IP of the logon attempts, if available.",
        "Check whether the account has multi-factor authentication enabled.",
        "Review what the account did immediately after the successful logon.",
        "Consider forcing a password reset and reviewing active sessions for this account.",
    ],
    "Defense Evasion": [
        "Treat this host as higher priority — evasion attempts often mean an "
        "intrusion is already in progress, not just being attempted.",
        "Check whether endpoint protection (e.g. Windows Defender) is still "
        "enabled and up to date on this host.",
        "Look for other activity around the same timestamp — evasion steps "
        "rarely happen in isolation.",
    ],
    "Persistence": [
        "Inspect the new service, task, or registry entry for the binary/script "
        "it actually runs, and where that file lives on disk.",
        "Check whether the binary is signed and from a known-good publisher.",
        "If unauthorized, remove the persistence mechanism and quarantine the "
        "associated file via the Response tab.",
    ],
    "Privilege Escalation": [
        "Confirm with IT/identity management whether this privilege change was requested.",
        "Review the account's recent activity both before and after the change.",
        "If unauthorized, revert the group membership and investigate how it happened.",
    ],
    "Execution": [
        "Review the full command line for the process, not just the executable name.",
        "Identify the parent process — how did this get launched?",
        "If this came from a document or email attachment, trace back to the "
        "delivery vector and check whether other users received the same file.",
    ],
    "Command and Control": [
        "Look up the remote address's ownership/ASN if you have internet access "
        "from an analysis workstation (this agent does not do that lookup itself).",
        "Check how long this process has been making connections, and whether "
        "the pattern is periodic (beaconing).",
        "Consider blocking the destination at the firewall while you investigate.",
    ],
    "Impact": [
        "This category includes ransomware precursors — treat as urgent.",
        "Check backup integrity and whether Volume Shadow Copies are still intact.",
        "Strongly consider isolating the host from the network immediately.",
    ],
}

TECHNIQUE_LINKS = {
    # MITRE ATT&CK technique IDs referenced by the built-in rules, for an
    # analyst who wants to read the public technique page.
    "T1110": "Brute Force",
    "T1070.001": "Indicator Removal: Clear Windows Event Logs",
    "T1543.003": "Create or Modify System Process: Windows Service",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1098": "Account Manipulation",
    "T1562.002": "Impair Defenses: Disable Windows Event Logging",
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys",
    "T1036": "Masquerading",
    "T1036.005": "Masquerading: Match Legitimate Name or Location",
    "T1218": "System Binary Proxy Execution",
    "T1566": "Phishing",
    "T1490": "Inhibit System Recovery",
    "T1003": "OS Credential Dumping",
    "T1571": "Non-Standard Port",
    "T1071": "Application Layer Protocol",
}


def _parse_ts(ts: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None


class RecommendationEngine:
    def __init__(self, db, context_window_seconds: int = 900):
        self.db = db
        self.context_window_seconds = context_window_seconds

    def recommend(self, alert_id: int) -> dict:
        alert = self.db.get_alert(alert_id)
        if not alert:
            raise ValueError(f"No such alert: {alert_id}")

        guidance = list(CATEGORY_GUIDANCE.get(alert.get("category") or "", GENERIC_GUIDANCE))
        if alert.get("category") in CATEGORY_GUIDANCE:
            guidance = guidance + [
                g for g in GENERIC_GUIDANCE if g not in guidance
            ][:1]  # keep one generic reminder without flooding the list

        related_alerts = self._related_alerts(alert)
        related_events = self._related_events(alert)
        incident = self.db.get_alert(alert_id)  # re-read in case incident linked since
        incident_info = None
        if incident and incident.get("incident_id"):
            incidents = [i for i in self.db.get_incidents(limit=200) if i["id"] == incident["incident_id"]]
            incident_info = incidents[0] if incidents else None

        technique = alert.get("mitre_technique")
        return {
            "alert": alert,
            "technique_id": technique,
            "technique_name": TECHNIQUE_LINKS.get(technique),
            "explanation": alert.get("description"),
            "recommended_steps": guidance,
            "related_alerts": related_alerts,
            "related_events": related_events,
            "incident": incident_info,
        }

    def _related_alerts(self, alert: dict) -> list[dict]:
        candidates = []
        if alert.get("pid"):
            candidates = self.db.get_alerts(limit=50)
            candidates = [a for a in candidates if a["pid"] == alert["pid"] and a["id"] != alert["id"]]
        elif alert.get("account_name"):
            candidates = self.db.get_alerts(limit=50)
            candidates = [
                a for a in candidates
                if a.get("account_name") == alert["account_name"] and a["id"] != alert["id"]
            ]
        return candidates[:10]

    def _related_events(self, alert: dict) -> list[dict]:
        ts = _parse_ts(alert["timestamp"])
        if ts is None:
            return []
        window = timedelta(seconds=self.context_window_seconds)
        lo, hi = ts - window, ts + window

        events = self.db.get_events(limit=500)
        related = []
        for e in events:
            e_ts = _parse_ts(e.get("timestamp", ""))
            if e_ts is None or not (lo <= e_ts <= hi):
                continue
            details = e.get("details", {})
            same_pid = alert.get("pid") and details.get("pid") == alert.get("pid")
            same_acct = alert.get("account_name") and (
                details.get("account_name") == alert.get("account_name")
                or details.get("username") == alert.get("account_name")
            )
            if same_pid or same_acct:
                related.append(e)
        related.sort(key=lambda e: e.get("timestamp", ""))
        return related[:25]
