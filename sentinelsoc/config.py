"""Configuration loading for SentinelSOC.

Loads config/config.yaml (or a path given via the SENTINELSOC_CONFIG
environment variable), merges it over sane built-in defaults, and
exposes dotted-key access, e.g. config.get("response.quarantine_dir").

On first run, if no API key is set, one is generated and written back
to the config file so the dashboard/API have something to authenticate
against.
"""

from __future__ import annotations

import copy
import os
import secrets
import threading
from pathlib import Path
from typing import Any, Optional

import yaml

# Built-in defaults. These are intentionally relative-path-friendly so the
# agent also runs out of a plain checkout for development/testing — the
# shipped config/config.yaml mirrors these but is the file normally edited.
DEFAULTS: dict[str, Any] = {
    "agent": {
        "name": "SentinelSOC",
        "poll_interval_seconds": 5,
    },
    "database": {
        "path": "./data/sentinelsoc.db",
    },
    "logging": {
        "level": "INFO",
        "log_dir": "./logs",
        "max_bytes": 10 * 1024 * 1024,
        "backup_count": 5,
    },
    "collectors": {
        "event_log": {
            "enabled": True,
            "logs": ["Security", "System", "Application"],
            "sysmon_log": "Microsoft-Windows-Sysmon/Operational",
            "use_sysmon_if_available": True,
            "poll_interval_seconds": 5,
        },
        "process_monitor": {
            "enabled": True,
            "poll_interval_seconds": 5,
        },
        "network_monitor": {
            "enabled": True,
            "poll_interval_seconds": 5,
        },
    },
    "detection": {
        "correlation_window_seconds": 300,
        "suspicious_path_segments": [
            "\\temp\\",
            "\\appdata\\local\\temp\\",
            "\\users\\public\\",
            "\\downloads\\",
            "\\programdata\\",
        ],
        "blocklist_ips_file": "./config/blocklist_ips.txt",
        "rules_overrides_file": None,
    },
    "response": {
        "auto_propose_on_critical": True,
        "quarantine_dir": "./quarantine",
    },
    "api": {
        "host": "127.0.0.1",
        "port": 8765,
        "api_key": None,
        # No-login convenience mode for single-user local use. Only safe
        # when the dashboard is reachable by the owner alone (loopback
        # binding or a trusted gateway in front) — never expose this
        # combination to a LAN.
        "auth_disabled": False,
    },
    "dashboard": {
        "title": "SentinelSOC",
        "refresh_seconds": 10,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    result = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _candidate_paths() -> list[str]:
    env_path = os.environ.get("SENTINELSOC_CONFIG")
    repo_default = str(Path(__file__).resolve().parent.parent / "config" / "config.yaml")
    candidates = []
    if env_path:
        candidates.append(env_path)
    candidates.append(repo_default)
    return candidates


class Config:
    """Loaded configuration with dotted-key access.

    Safe to share across threads for reads; writes (API key generation)
    are serialized with a lock.
    """

    def __init__(self, data: dict, path: str):
        self._data = data
        self._path = path
        self._lock = threading.Lock()

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Config":
        chosen = path
        if not chosen:
            for candidate in _candidate_paths():
                if candidate and os.path.isfile(candidate):
                    chosen = candidate
                    break
        data = copy.deepcopy(DEFAULTS)
        if chosen and os.path.isfile(chosen):
            with open(chosen, "r", encoding="utf-8") as fh:
                user_cfg = yaml.safe_load(fh) or {}
            data = _deep_merge(DEFAULTS, user_cfg)
        else:
            # Nothing on disk yet — fall back to the repo-relative default
            # location so a generated API key has somewhere to be saved.
            chosen = _candidate_paths()[-1]

        cfg = cls(data, chosen)
        cfg._ensure_api_key()
        return cfg

    def get(self, dotted_key: str, default: Any = None) -> Any:
        node: Any = self._data
        for part in dotted_key.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def as_dict(self) -> dict:
        return copy.deepcopy(self._data)

    def resolve_path(self, dotted_key: str, default: Optional[str] = None) -> str:
        """Resolve a configured path relative to the config file's directory."""
        raw = self.get(dotted_key, default)
        if raw is None:
            return raw
        p = Path(raw)
        if p.is_absolute():
            return str(p)
        base = Path(self._path).resolve().parent.parent
        return str((base / p).resolve())

    def _ensure_api_key(self) -> None:
        if self.get("api.api_key"):
            return
        with self._lock:
            if self.get("api.api_key"):
                return
            key = secrets.token_hex(24)
            self._data.setdefault("api", {})["api_key"] = key
            self._save()

    def _save(self) -> None:
        try:
            os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
            with open(self._path, "w", encoding="utf-8") as fh:
                yaml.safe_dump(self._data, fh, default_flow_style=False, sort_keys=False)
        except OSError:
            # Non-fatal: a fresh key is generated in memory for this run
            # even if it can't be persisted (e.g. read-only install dir).
            pass
