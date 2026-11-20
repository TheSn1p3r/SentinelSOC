"""Windows Service wrapper for SentinelSOC.

Install / start / stop / remove this service via scripts/install.ps1,
scripts/service_control.ps1 and scripts/uninstall.ps1, which drive the
standard pywin32 service CLI this module exposes:

    python service_win.py install
    python service_win.py start
    python service_win.py stop
    python service_win.py remove

The service runs the same SentinelAgent used in desktop mode (see
main.py), plus an embedded uvicorn server for the dashboard/API, both
on background threads, and waits on a stop event that SvcStop()
signals.

This module is Windows-only. It is not imported by anything that also
needs to run on non-Windows platforms (main.py uses agent.py directly).
"""

from __future__ import annotations

import logging
import threading

import servicemanager
import win32event
import win32service
import win32serviceutil

import uvicorn

from sentinelsoc.agent import SentinelAgent
from sentinelsoc.api.app import create_app
from sentinelsoc.config import Config
from sentinelsoc.logging_setup import setup_logging

logger = logging.getLogger("sentinelsoc.service")


class SentinelSOCService(win32serviceutil.ServiceFramework):
    _svc_name_ = "SentinelSOC"
    _svc_display_name_ = "SentinelSOC - Windows SOC Agent"
    _svc_description_ = (
        "Collects Windows telemetry, runs local threat detection and risk "
        "scoring, and serves the SentinelSOC dashboard for analyst-approved "
        "response actions."
    )

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.agent: SentinelAgent | None = None
        self.server: uvicorn.Server | None = None
        self._server_thread: threading.Thread | None = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        logger.info("Stop requested")
        if self.server is not None:
            self.server.should_exit = True
        if self.agent is not None:
            self.agent.stop()
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        try:
            self.main()
        except Exception:
            logger.exception("SentinelSOC service crashed")
            servicemanager.LogErrorMsg("SentinelSOC service terminated unexpectedly; see sentinelsoc.log")

    def main(self):
        config = Config.load()
        setup_logging(config)
        logger.info("SentinelSOC service starting")

        self.agent = SentinelAgent(config)
        self.agent.start()

        app = create_app(self.agent)
        host = config.get("api.host", "127.0.0.1")
        port = int(config.get("api.port", 8765))
        uconfig = uvicorn.Config(app, host=host, port=port, log_level="info")
        self.server = uvicorn.Server(uconfig)
        self._server_thread = threading.Thread(target=self.server.run, daemon=True, name="uvicorn")
        self._server_thread.start()
        logger.info("Dashboard/API listening on http://%s:%s", host, port)

        win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)
        logger.info("SentinelSOC service stopped")


if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(SentinelSOCService)
