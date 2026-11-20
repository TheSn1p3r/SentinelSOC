"""The detection engine: evaluates normalized telemetry records against
the rule set and turns matches into alert dicts ready for DBManager.insert_alert.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from typing import Optional

import yaml

from sentinelsoc.detection.rules import Rule, build_default_rules
from sentinelsoc.detection.scoring import RiskScorer

logger = logging.getLogger("sentinelsoc.detection")


class DetectionContext:
    """Query helpers passed into each rule's match() function.

    Keeps rules.py free of direct SQL — a rule asks a question
    ("how many failed logons for this account recently?") and the
    context answers it from the database or the loaded blocklist.
    """

    def __init__(self, db, suspicious_path_segments: list[str], blocklist: list):
        self.db = db
        self.suspicious_path_segments = suspicious_path_segments
        self._blocklist = blocklist

    def recent_eventlog_count(self, event_type: str, account_name: Optional[str] = None, seconds: int = 300) -> int:
        events = self.db.get_events(source="eventlog", event_type=event_type, since_seconds=seconds, limit=1000)
        if account_name:
            events = [e for e in events if e.get("details", {}).get("account_name") == account_name]
        return len(events)

    def recent_distinct_remote_ips(self, pid: int, seconds: int = 120) -> int:
        events = self.db.get_events(source="network", event_type="network_connection", since_seconds=seconds, limit=1000)
        ips = {
            e.get("details", {}).get("remote_addr")
            for e in events
            if e.get("details", {}).get("pid") == pid
        }
        ips.discard(None)
        return len(ips)

    def ip_is_blocklisted(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._blocklist)


class DetectionEngine:
    def __init__(self, config, db):
        self.config = config
        self.db = db
        self.rules: list[Rule] = self._load_rules()
        self.blocklist = self._load_blocklist()
        self.scorer = RiskScorer()
        self._suspicious_path_segments = config.get("detection.suspicious_path_segments", [])

    def _load_rules(self) -> list[Rule]:
        rules = build_default_rules()
        overrides_path = self.config.get("detection.rules_overrides_file")
        if overrides_path and os.path.isfile(overrides_path):
            try:
                with open(overrides_path, "r", encoding="utf-8") as fh:
                    overrides = yaml.safe_load(fh) or {}
                by_id = {r.id: r for r in rules}
                for rule_id, changes in overrides.items():
                    r = by_id.get(rule_id)
                    if not r or not isinstance(changes, dict):
                        continue
                    if "enabled" in changes:
                        r.enabled = bool(changes["enabled"])
                    if "severity" in changes:
                        r.severity = str(changes["severity"]).upper()
            except (OSError, yaml.YAMLError):
                logger.exception("Failed to load rule overrides from %s", overrides_path)
        logger.info("Loaded %d detection rules (%d enabled)", len(rules), sum(r.enabled for r in rules))
        return rules

    def _load_blocklist(self) -> list:
        path = self.config.resolve_path("detection.blocklist_ips_file")
        nets = []
        if path and os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        nets.append(ipaddress.ip_network(line, strict=False))
                    except ValueError:
                        logger.warning("Ignoring invalid blocklist entry: %s", line)
        return nets

    def reload_blocklist(self) -> int:
        self.blocklist = self._load_blocklist()
        return len(self.blocklist)

    def evaluate(self, record: dict) -> list[dict]:
        domain = record.get("source")
        ctx = DetectionContext(self.db, self._suspicious_path_segments, self.blocklist)
        alerts = []
        for rule in self.rules:
            if not rule.enabled or rule.domain != domain:
                continue
            try:
                if rule.match(record, ctx):
                    alerts.append(self._build_alert(rule, record))
            except Exception:
                logger.exception("Rule %s raised while evaluating a %s record", rule.id, domain)
        return alerts

    def _build_alert(self, rule: Rule, record: dict) -> dict:
        score = self.scorer.score(rule, record, self.config)
        proc = record.get("name") or record.get("process_name")
        title = f"{rule.name} ({proc})" if proc else rule.name
        return {
            "rule_id": rule.id,
            "rule_name": rule.name,
            "category": rule.category,
            "mitre_technique": rule.mitre_technique,
            "severity": rule.severity,
            "risk_score": score,
            "status": "NEW",
            "title": title,
            "description": rule.description,
            "pid": record.get("pid"),
            "process_name": proc,
            "account_name": record.get("account_name") or record.get("username"),
            "remote_addr": record.get("remote_addr"),
            "file_path": record.get("exe_path"),
            "timestamp": record.get("timestamp"),
            "suggested_response": rule.suggested_response,
        }
