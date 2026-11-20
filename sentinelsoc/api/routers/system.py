from __future__ import annotations

import copy

from fastapi import APIRouter, Depends, Request

from sentinelsoc.api.auth import require_api_auth

router = APIRouter(dependencies=[Depends(require_api_auth)])


@router.get("/system/status")
def status(request: Request):
    agent = request.app.state.agent
    return {"app_name": agent.config.get("agent.name", "SentinelSOC"), **agent.status()}


@router.get("/system/config")
def sanitized_config(request: Request):
    cfg = copy.deepcopy(request.app.state.agent.config.as_dict())
    if "api" in cfg and "api_key" in cfg["api"]:
        cfg["api"]["api_key"] = "••••••••" if cfg["api"]["api_key"] else None
    return {"config": cfg}
