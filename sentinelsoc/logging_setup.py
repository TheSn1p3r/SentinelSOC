"""Central logging configuration for SentinelSOC.

Logs go to a rotating file under the configured log directory, and also
to stdout (useful when running via `python main.py` for development; the
Windows Service wrapper redirects stdout to the Event Log via
servicemanager for anything logged at warning level or above).
"""

from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler

from sentinelsoc.config import Config


def setup_logging(config: Config) -> None:
    level_name = str(config.get("logging.level", "INFO")).upper()
    level = getattr(logging, level_name, logging.INFO)
    log_dir = config.resolve_path("logging.log_dir", "./logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "sentinelsoc.log")

    max_bytes = int(config.get("logging.max_bytes", 10 * 1024 * 1024))
    backup_count = int(config.get("logging.backup_count", 5))

    fmt = logging.Formatter(
        "%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root = logging.getLogger()
    root.setLevel(level)
    # Avoid duplicate handlers if setup_logging is called more than once
    # (e.g. in tests, or if the service restarts internally).
    root.handlers = []

    file_handler = RotatingFileHandler(
        log_path, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
    )
    file_handler.setFormatter(fmt)
    root.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(fmt)
    root.addHandler(stream_handler)

    # Quiet down noisy third-party loggers at INFO; SentinelSOC's own
    # loggers (sentinelsoc.*) still respect the configured level.
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
