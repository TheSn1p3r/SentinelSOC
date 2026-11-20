"""FastAPI application factory for the SentinelSOC dashboard/API.

create_app(agent) attaches an already-constructed, already-started
SentinelAgent to app.state and wires up the page routes (HTML,
session-cookie auth) and the JSON API routes (under /api, cookie or
X-API-Key auth). Kept separate from main.py / service_win.py so both
desktop mode and the Windows Service share exactly the same app.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from sentinelsoc.api.routers import detections, monitoring, pages, response, system

_DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"
_TEMPLATES_DIR = _DASHBOARD_DIR / "templates"
_STATIC_DIR = _DASHBOARD_DIR / "static"


def create_app(agent) -> FastAPI:
    app = FastAPI(title="SentinelSOC", docs_url="/api/docs", redoc_url=None)
    app.state.agent = agent
    app.state.templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    app.include_router(pages.router)
    app.include_router(detections.router, prefix="/api")
    app.include_router(monitoring.router, prefix="/api")
    app.include_router(response.router, prefix="/api")
    app.include_router(system.router, prefix="/api")

    return app
