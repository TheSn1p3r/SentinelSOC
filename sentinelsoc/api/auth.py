"""Minimal authentication for the SentinelSOC dashboard/API.

This is a local, single-analyst security tool, not a multi-tenant
product — so the design goal here is "don't ship a security dashboard
with a kill-process button wide open to anything that can reach
127.0.0.1", not full RBAC. There is exactly one credential: the API
key in config.yaml (auto-generated on first run — see config.py).

  * Browser pages authenticate via a short-lived, in-memory session
    cookie set after POSTing the key to /login.
  * Programmatic/API clients may instead send `X-API-Key: <key>` on
    every request.

Sessions are kept in memory (not the database): they're meant to be
ephemeral, and clearing on a service restart is acceptable for a tool
with exactly one user.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Request

SESSION_COOKIE = "sentinelsoc_session"
SESSION_LIFETIME = timedelta(hours=12)

_sessions: dict[str, datetime] = {}


def create_session() -> str:
    token = secrets.token_urlsafe(32)
    _sessions[token] = datetime.now(timezone.utc) + SESSION_LIFETIME
    return token


def destroy_session(token: str) -> None:
    _sessions.pop(token, None)


def _session_valid(token: str | None) -> bool:
    if not token:
        return False
    expiry = _sessions.get(token)
    if not expiry:
        return False
    if expiry < datetime.now(timezone.utc):
        _sessions.pop(token, None)
        return False
    return True


def _auth_disabled(request: Request) -> bool:
    """True when `api.auth_disabled` is set in config.yaml.

    Convenience mode for single-user local deployments: opens every page
    and API route without the analyst key. Only sensible when the app is
    reachable by the owner alone (e.g. bound to 127.0.0.1 or behind a
    trusted gateway) — do NOT combine with a LAN-exposed host.
    """
    agent = getattr(request.app.state, "agent", None)
    if agent is None:
        return False
    return bool(agent.config.get("api.auth_disabled", False))


def has_valid_session(request: Request) -> bool:
    if _auth_disabled(request):
        return True
    return _session_valid(request.cookies.get(SESSION_COOKIE))


def _configured_api_key(request: Request) -> str | None:
    agent = request.app.state.agent
    return agent.config.get("api.api_key")


def check_api_key_header(request: Request) -> bool:
    supplied = request.headers.get("X-API-Key")
    expected = _configured_api_key(request)
    if not supplied or not expected:
        return False
    return secrets.compare_digest(supplied, expected)


async def require_page_auth(request: Request):
    """For HTML page routes: callers check the return value themselves and
    issue a redirect to /login, since raising here would produce a raw
    401 instead of a friendly redirect."""
    return has_valid_session(request)


async def require_api_auth(request: Request) -> None:
    """For JSON API routes: raises 401 so a fetch() call gets a clean
    status code to branch on."""
    if _auth_disabled(request):
        return
    if has_valid_session(request) or check_api_key_header(request):
        return
    raise HTTPException(status_code=401, detail="Unauthorized — log in or supply X-API-Key")
