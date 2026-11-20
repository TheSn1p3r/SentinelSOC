"""Windows Event Log collection via pywin32.

Tails the configured classic event logs (Security, System,
Application) and, if present, the Sysmon operational log, mapping a
curated set of event IDs to the normalized event_type values the
detection rules look for. Windows-only: importing this module on a
non-Windows platform does not crash (pywin32 is imported defensively),
but constructing EventLogCollector raises a clear ImportError.

Known limitation (flagged honestly rather than hidden): the exact
exception/return behavior of win32evtlog.ReadEventLog() at end-of-log
can vary across Windows/pywin32 versions. This module treats the
common "no more data" outcomes as benign and keeps going; this should
be validated on your target Windows build during installation
(see docs/DOCUMENTATION.md, "Validating the Event Log collector").
"""

from __future__ import annotations

import logging
import threading
from typing import Optional

from sentinelsoc.database import now_iso

logger = logging.getLogger("sentinelsoc.collectors.eventlog")

try:
    import win32evtlog
    import win32security

    _PYWIN32_AVAILABLE = True
except ImportError:  # pragma: no cover - expected on non-Windows dev machines
    _PYWIN32_AVAILABLE = False

# EventID -> normalized event_type (Security log unless noted otherwise).
EVENT_ID_MAP = {
    4624: "logon_success",
    4625: "logon_failure",
    4740: "account_lockout",
    4720: "user_created",
    4732: "added_to_security_group",
    4719: "audit_policy_changed",
    4697: "service_installed",
    7045: "service_installed",  # System log
    4698: "scheduled_task_created",
    1102: "log_cleared",
    4104: "powershell_script_block",  # Microsoft-Windows-PowerShell/Operational
}

DEFENDER_EVENT_IDS = {5001, 5010, 5012}

SYSMON_EVENT_ID_MAP = {
    1: "sysmon_process_create",
    3: "sysmon_network_connect",
    7: "sysmon_image_load",
    11: "sysmon_file_create",
    13: "sysmon_registry_set",
}

# win32evtlog winerror values observed to mean "nothing new to read" rather
# than a real failure. Treated as benign; see module docstring.
_BENIGN_EOF_WINERRORS = {38, 122}


def _require_pywin32() -> None:
    if not _PYWIN32_AVAILABLE:
        raise ImportError(
            "pywin32 is required for Windows Event Log collection and only "
            "works on Windows. Install with: pip install pywin32"
        )


def _resolve_account(sid) -> Optional[str]:
    if sid is None:
        return None
    try:
        name, domain, _type = win32security.LookupAccountSid(None, sid)
        return f"{domain}\\{name}"
    except Exception:
        return str(sid)


def _extract_fields(event, log_name: str) -> dict:
    event_id = event.EventID & 0xFFFF  # low word carries the ID shown in Event Viewer
    inserts = list(event.StringInserts or [])
    record = {
        "source": "eventlog",
        "log": log_name,
        "raw_event_id": event_id,
        "provider": event.SourceName,
        "computer": getattr(event, "ComputerName", None),
        "timestamp": (
            event.TimeGenerated.isoformat()
            if hasattr(event.TimeGenerated, "isoformat")
            else now_iso()
        ),
        "account_name": _resolve_account(getattr(event, "Sid", None)),
        "message_inserts": inserts,
    }

    if log_name.lower().startswith("microsoft-windows-sysmon"):
        record["event_type"] = SYSMON_EVENT_ID_MAP.get(event_id, f"sysmon_{event_id}")
        if event_id == 13 and len(inserts) >= 5:
            record["registry_target"] = inserts[4]
        if event_id == 1 and len(inserts) >= 5:
            record["name"] = inserts[4]
            record["cmdline"] = inserts[10] if len(inserts) > 10 else None
    elif event.SourceName and "defender" in event.SourceName.lower() and event_id in DEFENDER_EVENT_IDS:
        record["event_type"] = "defender_protection_disabled"
    else:
        record["event_type"] = EVENT_ID_MAP.get(event_id, f"event_{event_id}")

    if record["event_type"] == "service_installed" and inserts:
        for ins in inserts:
            if isinstance(ins, str) and (".exe" in ins.lower() or ".dll" in ins.lower()):
                record["service_image_path"] = ins
                break

    if record["event_type"] == "powershell_script_block" and inserts:
        record["script_block_text"] = " ".join(str(i) for i in inserts)

    if not record.get("account_name"):
        for ins in inserts:
            if isinstance(ins, str) and "\\" in ins and len(ins) < 100:
                record["account_name"] = ins
                break

    return record


class EventLogCollector:
    def __init__(self, config, callback):
        _require_pywin32()
        self.callback = callback
        self.poll_interval = config.get("collectors.event_log.poll_interval_seconds", 5)
        self.logs = list(config.get("collectors.event_log.logs", ["Security", "System", "Application"]))
        if config.get("collectors.event_log.use_sysmon_if_available", True):
            sysmon_log = config.get("collectors.event_log.sysmon_log")
            if sysmon_log and sysmon_log not in self.logs:
                self.logs.append(sysmon_log)
        self._last_record_number: dict[str, int] = {}
        self._handles: dict[str, object] = {}

    def _open(self, log_name: str):
        try:
            return win32evtlog.OpenEventLog(None, log_name)
        except Exception:
            logger.warning(
                "Could not open event log '%s' (not present or access denied) — skipping",
                log_name,
            )
            return None

    def _seek_to_end(self, handle, log_name: str) -> None:
        """Position so the first poll only picks up NEW events, not the
        entire historical backlog."""
        try:
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            self._last_record_number[log_name] = events[0].RecordNumber if events else 0
        except Exception:
            logger.exception("Failed seeking to end of log '%s'; starting from 0", log_name)
            self._last_record_number[log_name] = 0

    def _poll_log(self, log_name: str, handle) -> None:
        flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        try:
            events = win32evtlog.ReadEventLog(handle, flags, 0)
        except Exception as exc:
            if getattr(exc, "winerror", None) in _BENIGN_EOF_WINERRORS:
                return  # caught up, nothing new — not an error
            logger.exception("Failed reading log '%s'", log_name)
            return
        if not events:
            return

        last_seen = self._last_record_number.get(log_name, 0)
        new_max = last_seen
        for event in events:
            if event.RecordNumber <= last_seen:
                continue
            new_max = max(new_max, event.RecordNumber)
            try:
                record = _extract_fields(event, log_name)
            except Exception:
                logger.exception("Failed to parse an event from '%s'", log_name)
                continue
            self.callback(record)
        self._last_record_number[log_name] = new_max

    def run(self, stop_event: threading.Event) -> None:
        logger.info("Event log collector starting for logs: %s", self.logs)
        for log_name in self.logs:
            handle = self._open(log_name)
            if handle is not None:
                self._handles[log_name] = handle
                self._seek_to_end(handle, log_name)

        if not self._handles:
            logger.warning("No event logs could be opened; event log collection is effectively disabled.")

        while not stop_event.is_set():
            for log_name, handle in list(self._handles.items()):
                try:
                    self._poll_log(log_name, handle)
                except Exception:
                    logger.exception("Error polling log '%s'", log_name)
            stop_event.wait(self.poll_interval)

        for handle in self._handles.values():
            try:
                win32evtlog.CloseEventLog(handle)
            except Exception:
                pass
        logger.info("Event log collector stopped")
