"""Shared pytest fixtures.

Everything runs against a fresh temp directory per test — no test touches
the real config/ or data/ in the repo.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sentinelsoc.config import Config  # noqa: E402
from sentinelsoc.database import DBManager  # noqa: E402


@pytest.fixture
def project_dir(tmp_path):
    """A temp directory laid out like a real install: config/config.yaml
    (copied from the example) + config/blocklist_ips.txt."""
    (tmp_path / "config").mkdir()
    shutil.copy(ROOT / "config" / "config.yaml.example", tmp_path / "config" / "config.yaml")
    shutil.copy(ROOT / "config" / "blocklist_ips.txt", tmp_path / "config" / "blocklist_ips.txt")
    return tmp_path


@pytest.fixture
def config(project_dir):
    return Config.load(str(project_dir / "config" / "config.yaml"))


@pytest.fixture
def db(config):
    return DBManager(config)
