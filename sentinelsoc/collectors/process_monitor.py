"""Process creation/exit monitoring via psutil.

Polls the process table on a fixed interval and emits a normalized
'process_create' record for any PID not present in the previous
snapshot (matched on (pid, create_time) so a reused PID for a new
process is correctly treated as a new process), plus a lightweight
'process_exit' record for PIDs that disappeared. The first poll after
startup is used only to build a baseline and does not emit records,
so the agent doesn't flood alerts for every process already running.
"""

from __future__ import annotations

import logging
import threading

import psutil

from sentinelsoc.database import now_iso

logger = logging.getLogger("sentinelsoc.collectors.process")

_PROC_ATTRS = ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]


class ProcessMonitor:
    def __init__(self, config, callback):
        self.callback = callback
        self.poll_interval = config.get("collectors.process_monitor.poll_interval_seconds", 5)
        self._known: dict[int, dict] = {}

    def _snapshot(self) -> dict[int, dict]:
        out = {}
        for p in psutil.process_iter(_PROC_ATTRS):
            try:
                out[p.info["pid"]] = p.info
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return out

    def run(self, stop_event: threading.Event) -> None:
        logger.info("Process monitor starting (interval=%ss)", self.poll_interval)
        self._known = self._snapshot()  # baseline only, no emission
        while not stop_event.is_set():
            try:
                current = self._snapshot()
                for pid, info in current.items():
                    prev = self._known.get(pid)
                    if prev and prev.get("create_time") == info.get("create_time"):
                        continue
                    parent = current.get(info.get("ppid")) or self._known.get(info.get("ppid"))
                    record = {
                        "source": "process",
                        "event_type": "process_create",
                        "pid": pid,
                        "ppid": info.get("ppid"),
                        "name": info.get("name"),
                        "exe_path": info.get("exe"),
                        "cmdline": " ".join(info.get("cmdline") or []),
                        "username": info.get("username"),
                        "parent_name": parent.get("name") if parent else None,
                        "create_time": info.get("create_time"),
                        "timestamp": now_iso(),
                    }
                    self.callback(record)
                for pid, info in self._known.items():
                    if pid not in current:
                        self.callback({
                            "source": "process",
                            "event_type": "process_exit",
                            "pid": pid,
                            "name": info.get("name"),
                            "timestamp": now_iso(),
                        })
                self._known = current
            except Exception:
                logger.exception("Process monitor poll failed")
            stop_event.wait(self.poll_interval)
        logger.info("Process monitor stopped")
