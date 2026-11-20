"""Database layer + detection engine tests.

These exercise exactly the scenarios manually verified while building
SentinelSOC: a suspicious-path process, an obfuscated PowerShell command,
process masquerading, and a brute-force-then-success logon pattern — then
confirm incident correlation groups the related alerts.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sentinelsoc.detection.engine import DetectionEngine
from sentinelsoc.detection.scoring import correlate_incidents


def _now():
    return datetime.now(timezone.utc)


def test_database_round_trip(db):
    event_id = db.insert_event({
        "source": "process", "event_type": "process_create",
        "timestamp": "2026-01-01T00:00:00+00:00", "name": "test.exe",
    })
    assert event_id > 0

    alert_id = db.insert_alert({
        "rule_id": "R-TEST", "rule_name": "Test rule", "severity": "HIGH",
        "risk_score": 65, "title": "Test alert", "pid": 123, "process_name": "test.exe",
    })
    alert = db.get_alert(alert_id)
    assert alert["rule_id"] == "R-TEST"
    assert alert["status"] == "NEW"

    db.update_alert(alert_id, status="ACKNOWLEDGED")
    assert db.get_alert(alert_id)["status"] == "ACKNOWLEDGED"

    assert db.counts_by_severity()["HIGH"] == 1


def test_suspicious_path_process_triggers_rule(config, db):
    engine = DetectionEngine(config, db)
    record = {
        "source": "process", "event_type": "process_create", "pid": 4321, "ppid": 1,
        "name": "update.exe", "exe_path": r"C:\Users\alice\AppData\Local\Temp\update.exe",
        "cmdline": "update.exe /silent", "username": "alice",
        "timestamp": "2026-11-19T00:00:00+00:00",
    }
    alerts = engine.evaluate(record)
    rule_ids = {a["rule_id"] for a in alerts}
    assert "R-PROC-001" in rule_ids


def test_encoded_powershell_triggers_rule(config, db):
    engine = DetectionEngine(config, db)
    record = {
        "source": "process", "event_type": "process_create", "pid": 555, "ppid": 600,
        "name": "powershell.exe",
        "exe_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "cmdline": "powershell.exe -nop -w hidden -enc SQBFAFgA",
        "username": "alice", "timestamp": "2026-11-19T00:00:05+00:00",
    }
    alerts = engine.evaluate(record)
    assert any(a["rule_id"] == "R-PROC-004" for a in alerts)


def test_process_masquerade_is_critical_and_scores_high(config, db):
    engine = DetectionEngine(config, db)
    record = {
        "source": "process", "event_type": "process_create", "pid": 4322, "ppid": 1,
        "name": "svch0st.exe", "exe_path": r"C:\Users\alice\AppData\Local\Temp\svch0st.exe",
        "cmdline": "svch0st.exe", "username": "alice", "timestamp": "2026-11-19T00:00:06+00:00",
    }
    alerts = engine.evaluate(record)
    by_rule = {a["rule_id"]: a for a in alerts}
    assert "R-PROC-006" in by_rule
    assert by_rule["R-PROC-006"]["severity"] == "CRITICAL"
    assert by_rule["R-PROC-006"]["risk_score"] == 100  # 90 base + 10 suspicious-path bonus, capped


def test_brute_force_then_success(config, db):
    # Timestamps are relative to "now", not hardcoded — the brute-force rule
    # looks back a rolling 300 seconds via SQL's datetime('now', ...), so a
    # fixed past date would (and did, during development) silently drift
    # out of that window as real time passes.
    engine = DetectionEngine(config, db)
    now = _now()
    for i in range(5):
        db.insert_event({
            "source": "eventlog", "event_type": "logon_failure", "account_name": "bob",
            "timestamp": (now - timedelta(seconds=60 - i)).isoformat(),
        })
    success = {
        "source": "eventlog", "event_type": "logon_success", "account_name": "bob",
        "timestamp": now.isoformat(),
    }
    alerts = engine.evaluate(success)
    assert any(a["rule_id"] == "R-EVT-001" for a in alerts)


def test_incident_correlation_groups_same_pid(config, db):
    # Same reasoning as above: correlate_incidents() only looks at alerts
    # within the last `correlation_window_seconds`, so this needs to be "now".
    engine = DetectionEngine(config, db)
    record = {
        "source": "process", "event_type": "process_create", "pid": 777, "ppid": 1,
        "name": "svch0st.exe", "exe_path": r"C:\Users\alice\Downloads\svch0st.exe",
        "cmdline": "svch0st.exe", "username": "alice", "timestamp": _now().isoformat(),
    }
    for alert in engine.evaluate(record):
        db.insert_alert(alert)

    created = correlate_incidents(db, config)
    assert created >= 1

    incidents = db.get_incidents()
    assert len(incidents) >= 1
    linked_alerts = db.get_alerts(incident_id=incidents[0]["id"])
    assert len(linked_alerts) >= 2
