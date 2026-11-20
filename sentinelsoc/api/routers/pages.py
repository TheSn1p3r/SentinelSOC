from __future__ import annotations

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse
from starlette.status import HTTP_303_SEE_OTHER

from sentinelsoc.api.auth import (
    SESSION_COOKIE,
    create_session,
    destroy_session,
    has_valid_session,
)

router = APIRouter()


def _templates(request: Request):
    return request.app.state.templates


def _render(request: Request, name: str, **ctx):
    agent = request.app.state.agent
    ctx.setdefault("title", agent.config.get("dashboard.title", "SentinelSOC"))
    ctx.setdefault("refresh_seconds", agent.config.get("dashboard.refresh_seconds", 10))
    # Starlette's current Jinja2Templates.TemplateResponse takes `request`
    # as the first positional argument (not inside the context dict).
    return _templates(request).TemplateResponse(request, name, ctx)


@router.get("/login")
def login_page(request: Request):
    if has_valid_session(request):
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    return _render(request, "login.html", error=None)


@router.post("/login")
def login_submit(request: Request, api_key: str = Form(...)):
    configured = request.app.state.agent.config.get("api.api_key")
    if not configured or api_key != configured:
        return _render(request, "login.html", error="Incorrect key.")
    token = create_session()
    resp = RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    resp.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax")
    return resp


@router.post("/logout")
def logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        destroy_session(token)
    resp = RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    resp.delete_cookie(SESSION_COOKIE)
    return resp


def _require_or_redirect(request: Request):
    if not has_valid_session(request):
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    return None


@router.get("/")
def index(request: Request):
    redirect = _require_or_redirect(request)
    if redirect:
        return redirect
    return _render(request, "index.html", active_nav="overview")


@router.get("/alerts")
def alerts_page(request: Request):
    redirect = _require_or_redirect(request)
    if redirect:
        return redirect
    return _render(request, "alerts.html", active_nav="alerts")


@router.get("/alerts/{alert_id}")
def alert_detail_page(request: Request, alert_id: int):
    redirect = _require_or_redirect(request)
    if redirect:
        return redirect
    return _render(request, "alert_detail.html", alert_id=alert_id, active_nav="alerts")


@router.get("/monitoring")
def monitoring_page(request: Request):
    redirect = _require_or_redirect(request)
    if redirect:
        return redirect
    return _render(request, "monitoring.html", active_nav="monitoring")


@router.get("/response")
def response_page(request: Request):
    redirect = _require_or_redirect(request)
    if redirect:
        return redirect
    return _render(request, "response.html", active_nav="response")
