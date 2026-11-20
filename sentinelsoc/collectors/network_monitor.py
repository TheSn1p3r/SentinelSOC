"""Network connection monitoring via psutil.

Polls active inet connections and emits a normalized
'network_connection' record only for connection tuples that are NEW
since the last poll, so a single long-lived connection doesn't
re-trigger detection on every cycle. Only connections with a remote
peer (raddr) are considered — listening sockets aren't "connections"
in the sense this agent's rules care about.
"""

from __future__ import annotations

import logging
import threading

import psutil

from sentinelsoc.database import now_iso

logger = logging.getLogger("sentinelsoc.collectors.network")


def _proc_name(pid):
    if not pid:
        return None
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


class NetworkMonitor:
    def __init__(self, config, callback):
        self.callback = callback
        self.poll_interval = config.get("collectors.network_monitor.poll_interval_seconds", 5)
        self._known: set[tuple] = set()

    def _snapshot(self):
        try:
            raw = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            logger.warning(
                "Insufficient privileges to list network connections for all "
                "processes; run the service as Administrator/SYSTEM for full visibility."
            )
            return []
        out = []
        for c in raw:
            if not c.raddr:
                continue
            proto = "tcp" if c.type == 1 else "udp"
            # Identity is the network 4-tuple + protocol, deliberately NOT
            # including pid: the owning pid can briefly resolve differently
            # (or to None) across polls for what is the same underlying
            # connection (e.g. around a state change), which would
            # otherwise cause the same connection to be reported twice.
            key = (
                c.laddr.ip if c.laddr else None,
                c.laddr.port if c.laddr else None,
                c.raddr.ip,
                c.raddr.port,
                proto,
            )
            out.append((key, c, proto))
        return out

    def run(self, stop_event: threading.Event) -> None:
        logger.info("Network monitor starting (interval=%ss)", self.poll_interval)
        baseline = self._snapshot()
        self._known = {k for k, _, _ in baseline}
        while not stop_event.is_set():
            try:
                current = self._snapshot()
                current_keys = {k for k, _, _ in current}
                for key, c, proto in current:
                    if key in self._known:
                        continue
                    record = {
                        "source": "network",
                        "event_type": "network_connection",
                        "pid": c.pid,
                        "process_name": _proc_name(c.pid),
                        "local_addr": c.laddr.ip if c.laddr else None,
                        "local_port": c.laddr.port if c.laddr else None,
                        "remote_addr": c.raddr.ip,
                        "remote_port": c.raddr.port,
                        "protocol": proto,
                        "status": c.status,
                        "timestamp": now_iso(),
                    }
                    self.callback(record)
                self._known = current_keys
            except Exception:
                logger.exception("Network monitor poll failed")
            stop_event.wait(self.poll_interval)
        logger.info("Network monitor stopped")
