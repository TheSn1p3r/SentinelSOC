from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request

from sentinelsoc.api.auth import require_api_auth
from sentinelsoc.api.schemas import ProposeQuarantineRequest, ProposeTerminateRequest, ResponseDecision

router = APIRouter(dependencies=[Depends(require_api_auth)])


def _rm(request: Request):
    return request.app.state.agent.response_manager


@router.get("/response/actions")
def list_actions(request: Request, status: Optional[str] = None, limit: int = 100):
    return {"actions": request.app.state.agent.db.get_response_actions(status=status, limit=limit)}


@router.post("/response/actions/terminate")
def propose_terminate(request: Request, body: ProposeTerminateRequest):
    action_id = _rm(request).propose_terminate_process(
        body.pid, body.reason, requested_by="analyst", alert_id=body.alert_id
    )
    return {"action": request.app.state.agent.db.get_response_action(action_id)}


@router.post("/response/actions/quarantine")
def propose_quarantine(request: Request, body: ProposeQuarantineRequest):
    action_id = _rm(request).propose_quarantine_file(
        body.file_path, body.reason, requested_by="analyst", alert_id=body.alert_id
    )
    return {"action": request.app.state.agent.db.get_response_action(action_id)}


@router.post("/response/actions/{action_id}/decide")
def decide_action(request: Request, action_id: int, body: ResponseDecision):
    try:
        result = _rm(request).decide(action_id, analyst=body.analyst, approve=body.approve, notes=body.notes or "")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"action": result}


@router.get("/response/quarantine")
def list_quarantine(request: Request, limit: int = 100):
    return {"items": request.app.state.agent.db.get_quarantine_items(limit=limit)}


@router.post("/response/quarantine/{item_id}/restore")
def restore_quarantine(request: Request, item_id: int, analyst: str = "analyst"):
    try:
        message = _rm(request).restore_quarantined_file(item_id, analyst=analyst)
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"message": message}


@router.get("/audit")
def audit_log(request: Request, limit: int = 200):
    return {"entries": request.app.state.agent.db.get_audit_log(limit=limit)}
