"""SentinelAgent: wires collectors, the detection engine, and the
response manager together, and runs everything as background threads.

This class is deliberately UI-agnostic — it's used identically by
main.py (desktop/dev mode) and service_win.py (the Windows Service),
with the FastAPI app attaching to an already-running agent instance
rather than owning it.
"""

from __future__ import annotations

import logging
import threading
import time

from sentinelsoc.config import Config
from sentinelsoc.database import DBManager
from sentinelsoc.detection.engine import DetectionEngine
from sentinelsoc.detection.scoring import correlate_incidents
from sentinelsoc.response.actions import ResponseManager

logger = logging.getLogger("sentinelsoc.agent")


class SentinelAgent:
    def __init__(self, config: Config):
        self.config = config
        self.db = DBManager(config)
        self.engine = DetectionEngine(config, self.db)
        self.response_manager = ResponseManager(config, self.db)

        self.collectors = []
        self._collector_status: dict[str, str] = {}
        self._build_collectors()

        self._stop_event = threading.Event()
        self._threads: list[threading.Thread] = []
        self._correlation_thread: threading.Thread | None = None
        self.started_at: float | None = None

    def _build_collectors(self) -> None:
        if self.config.get("collectors.process_monitor.enabled", True):
            from sentinelsoc.collectors.process_monitor import ProcessMonitor
            self.collectors.append(("process_monitor", ProcessMonitor(self.config, self._on_record)))

        if self.config.get("collectors.network_monitor.enabled", True):
            from sentinelsoc.collectors.network_monitor import NetworkMonitor
            self.collectors.append(("network_monitor", NetworkMonitor(self.config, self._on_record)))

        if self.config.get("collectors.event_log.enabled", True):
            try:
                from sentinelsoc.collectors.eventlog_collector import EventLogCollector
                self.collectors.append(("event_log", EventLogCollector(self.config, self._on_record)))
            except ImportError as exc:
                logger.warning("Event log collector disabled: %s", exc)
                self._collector_status["event_log"] = "unavailable (not Windows / no pywin32)"

    # ------------------------------------------------------------- pipeline
    def _on_record(self, record: dict) -> None:
        try:
            event_id = self.db.insert_event(record)
            record.setdefault("_event_id", event_id)
            alerts = self.engine.evaluate(record)
            for alert in alerts:
                alert["source_event_id"] = event_id
                alert_id = self.db.insert_alert(alert)
                logger.info(
                    "ALERT #%s [%s/%s] %s", alert_id, alert["severity"], alert["rule_id"], alert["title"]
                )
                if alert["severity"] in ("HIGH", "CRITICAL"):
                    try:
                        self.response_manager.auto_propose_from_alert(alert, alert_id)
                    except Exception:
                        logger.exception("Failed to auto-propose a response action for alert %s", alert_id)
        except Exception:
            logger.exception("Failed to process an incoming %s record", record.get("source"))

    def _correlation_loop(self) -> None:
        interval = max(30, int(self.config.get("detection.correlation_window_seconds", 300)) // 4)
        while not self._stop_event.is_set():
            try:
                correlate_incidents(self.db, self.config)
            except Exception:
                logger.exception("Incident correlation pass failed")
            self._stop_event.wait(interval)

    # ----------------------------------------------------------- lifecycle
    def start(self) -> None:
        logger.info("SentinelAgent starting with %d collector(s)", len(self.collectors))
        self.started_at = time.time()
        self._stop_event.clear()
        for name, collector in self.collectors:
            t = threading.Thread(target=self._run_collector, args=(name, collector), daemon=True, name=f"collector-{name}")
            t.start()
            self._threads.append(t)
            self._collector_status[name] = "running"
        self._correlation_thread = threading.Thread(
            target=self._correlation_loop, daemon=True, name="incident-correlation"
        )
        self._correlation_thread.start()

    def _run_collector(self, name: str, collector) -> None:
        try:
            collector.run(self._stop_event)
        except Exception:
            logger.exception("Collector '%s' crashed", name)
            self._collector_status[name] = "crashed"
        else:
            self._collector_status[name] = "stopped"

    def stop(self) -> None:
        logger.info("SentinelAgent stopping")
        self._stop_event.set()
        for t in self._threads:
            t.join(timeout=5)
        if self._correlation_thread:
            self._correlation_thread.join(timeout=5)

    def status(self) -> dict:
        uptime = (time.time() - self.started_at) if self.started_at else 0
        return {
            "uptime_seconds": int(uptime),
            "collectors": dict(self._collector_status),
            "alerts_last_24h": self.db.counts_by_severity(86400),
            "pending_response_actions": self.db.pending_response_count(),
            "rules_loaded": len(self.engine.rules),
            "rules_enabled": sum(1 for r in self.engine.rules if r.enabled),
        }
