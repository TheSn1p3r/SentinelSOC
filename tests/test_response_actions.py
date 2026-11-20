"""Response-action tests.

The core invariant under test: ResponseManager only ever executes
anything after an explicit decide(approve=True) call. A rejected action
must leave its target untouched, and every step must be audited.
"""

from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path

from sentinelsoc.response.actions import ResponseManager


def test_approved_termination_actually_kills_the_process(config, db):
    rm = ResponseManager(config, db)
    proc = subprocess.Popen(["sleep", "30"])
    time.sleep(0.2)
    try:
        action_id = rm.propose_terminate_process(proc.pid, "unit test")
        assert db.get_response_action(action_id)["status"] == "PENDING"

        result = rm.decide(action_id, analyst="alice", approve=True)
        assert result["status"] == "EXECUTED"

        proc.wait(timeout=5)
        assert proc.poll() is not None
    finally:
        if proc.poll() is None:
            proc.terminate()


def test_rejected_termination_leaves_the_process_running(config, db):
    rm = ResponseManager(config, db)
    proc = subprocess.Popen(["sleep", "30"])
    time.sleep(0.2)
    try:
        action_id = rm.propose_terminate_process(proc.pid, "should be rejected")
        result = rm.decide(action_id, analyst="bob", approve=False, notes="false positive")
        assert result["status"] == "REJECTED"
        time.sleep(0.2)
        assert proc.poll() is None  # still alive
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def test_quarantine_moves_and_hashes_the_file(config, db):
    rm = ResponseManager(config, db)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
        f.write(b"not actually malware, just test bytes")
        target = Path(f.name)

    action_id = rm.propose_quarantine_file(str(target), "suspicious dropped file")
    result = rm.decide(action_id, analyst="alice", approve=True)
    assert result["status"] == "EXECUTED"
    assert not target.exists()

    items = db.get_quarantine_items()
    assert len(items) == 1
    assert items[0]["original_path"] == str(target)
    assert items[0]["sha256"] is not None


def test_every_decision_is_audited(config, db):
    rm = ResponseManager(config, db)
    proc = subprocess.Popen(["sleep", "30"])
    time.sleep(0.2)
    try:
        action_id = rm.propose_terminate_process(proc.pid, "audit check")
        rm.decide(action_id, analyst="alice", approve=True)
        actions_logged = {entry["action"] for entry in db.get_audit_log()}
        assert "PROPOSE_TERMINATE_PROCESS" in actions_logged
        assert "APPROVE_ACTION" in actions_logged
        assert "EXECUTE_ACTION" in actions_logged
    finally:
        if proc.poll() is None:
            proc.terminate()
