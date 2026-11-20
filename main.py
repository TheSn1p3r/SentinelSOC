#!/usr/bin/env python3
"""SentinelSOC — desktop/dev entry point.

For production deployment on an end-user's machine, install and run
SentinelSOC as a Windows Service instead (see scripts/install.ps1);
this script is for running it in the foreground, e.g. for development,
testing, or a quick manual check before installing the service.

Usage:
    python main.py
"""

from __future__ import annotations

import logging
import signal
import sys

import uvicorn

from sentinelsoc.agent import SentinelAgent
from sentinelsoc.api.app import create_app
from sentinelsoc.config import Config
from sentinelsoc.logging_setup import setup_logging

logger = logging.getLogger("sentinelsoc.main")


def main() -> int:
    config = Config.load()
    setup_logging(config)

    app_name = config.get("agent.name", "SentinelSOC")
    logger.info("%s starting in desktop/dev mode", app_name)

    agent = SentinelAgent(config)
    agent.start()

    host = config.get("api.host", "127.0.0.1")
    port = int(config.get("api.port", 8765))
    app = create_app(agent)

    print(f"\n{app_name} dashboard: http://{host}:{port}/")
    print("API key (first-run login credential) is in config/config.yaml under api.api_key\n")

    uconfig = uvicorn.Config(app, host=host, port=port, log_level="info")
    server = uvicorn.Server(uconfig)

    def _handle_sigint(signum, frame):
        logger.info("Shutdown signal received")
        server.should_exit = True

    signal.signal(signal.SIGINT, _handle_sigint)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handle_sigint)

    try:
        server.run()
    finally:
        agent.stop()
        logger.info("%s stopped", app_name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
