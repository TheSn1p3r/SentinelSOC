"""Risk scoring and incident correlation.

Scoring is a transparent, explainable weighted model (by design — SOC
analysts need to trust and audit a score, not just accept a black box):
each severity has a base weight, with small additive bonuses for
context that independently raises suspicion (execution from a
suspicious path, encoded/hidden PowerShell flags, etc).

Incident correlation is a simple time-windowed grouping of otherwise
unlinked alerts that share a process ID or account name — enough to
turn "5 separate medium alerts" into "1 incident", which is what an
analyst actually wants to triage.
"""

from __future__ import annotations

import logging

from sentinelsoc.detection.rules import Rule

logger = logging.getLogger("sentinelsoc.detection")

SEVERITY_BASE = {"INFO": 5, "LOW": 20, "MEDIUM": 40, "HIGH": 65, "CRITICAL": 90}

_SUSPICIOUS_CMD_TOKENS = (
    "-enc", "-encodedcommand", "downloadstring", "downloadfile", "iex ",
    "bypass", "hidden", "frombase64string",
)


class RiskScorer:
    def score(self, rule: Rule, record: dict, config) -> int:
        base = SEVERITY_BASE.get(rule.severity, 30)
        bonus = 0

        path = (record.get("exe_path") or "").lower()
        suspicious_segments = config.get("detection.suspicious_path_segments", [])
        if path and any(seg in path for seg in suspicious_segments):
            bonus += 10

        cmdline = (record.get("cmdline") or "").lower()
        if cmdline and any(tok in cmdline for tok in _SUSPICIOUS_CMD_TOKENS):
            bonus += 10

        if record.get("event_type") in ("process_create", "network_connection") and not record.get("username"):
            bonus += 0  # reserved for future context signals

        return min(100, base + bonus)


def correlate_incidents(db, config) -> int:
    """Group recent alerts that share a pid or account into incidents.

    Called periodically by the agent loop. Returns the number of
    incidents created/updated on this pass.
    """
    window = int(config.get("detection.correlation_window_seconds", 300))
    alerts = db.get_alerts(without_incident=True, since_seconds=window, limit=500)
    if not alerts:
        return 0

    buckets: dict[str, list[dict]] = {}
    for a in alerts:
        key = None
        if a.get("pid"):
            key = f"pid:{a['pid']}"
        elif a.get("account_name"):
            key = f"acct:{a['account_name']}"
        if key:
            buckets.setdefault(key, []).append(a)

    touched = 0
    for key, group in buckets.items():
        if len(group) < 2:
            continue
        scores = [g["risk_score"] for g in group]
        combined = min(100, max(scores) + 10 * (len(group) - 1))
        first_seen = min(g["timestamp"] for g in group)
        last_seen = max(g["timestamp"] for g in group)
        subject = key.split(":", 1)[1]
        title = f"Correlated activity: {len(group)} alerts linked to {subject}"
        incident_id = db.create_incident(title, combined, first_seen)
        db.update_incident(incident_id, last_seen=last_seen, alert_count=len(group))
        for g in group:
            db.update_alert(g["id"], incident_id=incident_id)
        touched += 1
        logger.info("Created incident #%s (%s, score=%s)", incident_id, title, combined)
    return touched
