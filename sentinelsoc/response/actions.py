"""Analyst-approved response actions: process termination and file quarantine.

Design invariant (do not weaken this): the detection engine may only
PROPOSE an action (status=PENDING). Nothing in this module executes a
termination or quarantine until ResponseManager.decide() is called
with approve=True by a named analyst — there is no automatic-execution
path, by design, regardless of how severe the triggering alert is.
Every proposal and decision is written to audit_log.
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import uuid
from typing import Optional

import psutil

from sentinelsoc.database import DBManager, now_iso

logger = logging.getLogger("sentinelsoc.response")


def _sha256_of_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def _snapshot_process(pid: int) -> dict:
    try:
        p = psutil.Process(pid)
        with p.oneshot():
            return {
                "pid": pid,
                "name": p.name(),
                "exe": _safe(p.exe),
                "cmdline": _safe(lambda: " ".join(p.cmdline())),
                "username": _safe(p.username),
                "create_time": p.create_time(),
            }
    except psutil.Error:
        return {"pid": pid, "name": None}


def _safe(fn):
    try:
        return fn()
    except psutil.Error:
        return None


class ResponseManager:
    def __init__(self, config, db: DBManager):
        self.config = config
        self.db = db
        self.quarantine_dir = config.resolve_path("response.quarantine_dir", "./quarantine")

    # --------------------------------------------------------------- propose
    def propose_terminate_process(
        self, pid: int, reason: str, requested_by: str = "analyst", alert_id: Optional[int] = None
    ) -> int:
        meta = _snapshot_process(pid)
        action_id = self.db.create_response_action(
            action_type="TERMINATE_PROCESS",
            target=str(pid),
            reason=reason,
            requested_by=requested_by,
            alert_id=alert_id,
            target_meta=meta,
        )
        self.db.write_audit(requested_by, "PROPOSE_TERMINATE_PROCESS", str(pid), reason)
        logger.info("Proposed TERMINATE_PROCESS pid=%s action_id=%s by=%s", pid, action_id, requested_by)
        return action_id

    def propose_quarantine_file(
        self, file_path: str, reason: str, requested_by: str = "analyst", alert_id: Optional[int] = None
    ) -> int:
        meta = {"exists": os.path.isfile(file_path)}
        action_id = self.db.create_response_action(
            action_type="QUARANTINE_FILE",
            target=file_path,
            reason=reason,
            requested_by=requested_by,
            alert_id=alert_id,
            target_meta=meta,
        )
        self.db.write_audit(requested_by, "PROPOSE_QUARANTINE_FILE", file_path, reason)
        logger.info("Proposed QUARANTINE_FILE path=%s action_id=%s by=%s", file_path, action_id, requested_by)
        return action_id

    def auto_propose_from_alert(self, alert: dict, alert_id: int) -> Optional[int]:
        """Called by the agent right after a CRITICAL alert, if configured.

        This only ever creates a PENDING proposal for an analyst to review —
        see the module docstring. It never executes anything itself.
        """
        if not self.config.get("response.auto_propose_on_critical", True):
            return None
        suggested = alert.get("suggested_response")
        reason = f"Auto-proposed by detection engine from alert: {alert.get('title')}"
        if suggested == "TERMINATE_PROCESS" and alert.get("pid"):
            return self.propose_terminate_process(
                alert["pid"], reason, requested_by="detection-engine", alert_id=alert_id
            )
        if suggested == "QUARANTINE_FILE" and alert.get("file_path"):
            return self.propose_quarantine_file(
                alert["file_path"], reason, requested_by="detection-engine", alert_id=alert_id
            )
        return None

    # ---------------------------------------------------------------- decide
    def decide(self, action_id: int, analyst: str, approve: bool, notes: str = "") -> dict:
        action = self.db.get_response_action(action_id)
        if action is None:
            raise ValueError(f"No such response action: {action_id}")
        if action["status"] != "PENDING":
            raise ValueError(f"Action {action_id} is not pending (status={action['status']})")

        if not approve:
            self.db.update_response_action(
                action_id, status="REJECTED", approved_by=analyst, notes=notes, decided_at=now_iso()
            )
            self.db.write_audit(analyst, "REJECT_ACTION", action["target"], notes)
            return self.db.get_response_action(action_id)

        self.db.update_response_action(
            action_id, status="APPROVED", approved_by=analyst, notes=notes, decided_at=now_iso()
        )
        self.db.write_audit(analyst, "APPROVE_ACTION", action["target"], notes)
        self._execute(action_id)
        return self.db.get_response_action(action_id)

    # --------------------------------------------------------------- execute
    def _execute(self, action_id: int) -> None:
        action = self.db.get_response_action(action_id)
        try:
            if action["action_type"] == "TERMINATE_PROCESS":
                result = self._terminate_process(int(action["target"]))
            elif action["action_type"] == "QUARANTINE_FILE":
                result = self._quarantine_file(action["target"], action_id)
            else:
                raise ValueError(f"Unknown action_type: {action['action_type']}")
            self.db.update_response_action(
                action_id, status="EXECUTED", executed_at=now_iso(), result_message=result
            )
            self.db.write_audit(action["approved_by"] or "system", "EXECUTE_ACTION", action["target"], result)
        except Exception as exc:  # noqa: BLE001 - record the failure, don't crash the agent
            logger.exception("Failed to execute response action %s", action_id)
            self.db.update_response_action(
                action_id, status="FAILED", executed_at=now_iso(), result_message=str(exc)
            )
            self.db.write_audit(action["approved_by"] or "system", "EXECUTE_ACTION_FAILED", action["target"], str(exc))

    def _terminate_process(self, pid: int) -> str:
        p = psutil.Process(pid)  # raises psutil.NoSuchProcess if already gone
        name = p.name()
        p.terminate()
        try:
            p.wait(timeout=5)
        except psutil.TimeoutExpired:
            p.kill()
            p.wait(timeout=5)
        return f"Process {pid} ({name}) terminated."

    def _quarantine_file(self, file_path: str, action_id: int) -> str:
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"File not found (may already be gone): {file_path}")
        sha256 = _sha256_of_file(file_path)
        size = os.path.getsize(file_path)
        os.makedirs(self.quarantine_dir, exist_ok=True)
        quarantine_name = f"{uuid.uuid4().hex}.quarantine"
        quarantine_path = os.path.join(self.quarantine_dir, quarantine_name)
        shutil.move(file_path, quarantine_path)
        try:
            os.chmod(quarantine_path, 0o400)
        except OSError:
            pass  # best-effort; on Windows this clears the write bit
        self.db.create_quarantine_item(action_id, file_path, quarantine_path, sha256, size)
        return f"File quarantined: {file_path} -> {quarantine_path} (sha256={sha256})"

    # ---------------------------------------------------------------- restore
    def restore_quarantined_file(self, item_id: int, analyst: str) -> str:
        item = self.db.get_quarantine_item(item_id)
        if not item:
            raise ValueError(f"No such quarantine item: {item_id}")
        if item["restored"]:
            raise ValueError("Already restored")
        os.makedirs(os.path.dirname(item["original_path"]) or ".", exist_ok=True)
        shutil.move(item["quarantine_path"], item["original_path"])
        self.db.mark_quarantine_restored(item_id)
        self.db.write_audit(analyst, "RESTORE_QUARANTINED_FILE", item["original_path"], "")
        return f"Restored {item['original_path']}"
