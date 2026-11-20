from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request

from sentinelsoc.api.auth import require_api_auth
from sentinelsoc.api.schemas import AlertStatusUpdate
from sentinelsoc.investigate.recommendations import RecommendationEngine

router = APIRouter(dependencies=[Depends(require_api_auth)])


def _db(request: Request):
    return request.app.state.agent.db


@router.get("/alerts")
def list_alerts(
    request: Request,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
):
    return {"alerts": _db(request).get_alerts(status=status, severity=severity, limit=limit, offset=offset)}


@router.get("/alerts/{alert_id}")
def get_alert(request: Request, alert_id: int):
    db = _db(request)
    alert = db.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    engine = RecommendationEngine(db)
    recommendation = engine.recommend(alert_id)
    return {"alert": alert, "recommendation": recommendation}


@router.patch("/alerts/{alert_id}")
def update_alert_status(request: Request, alert_id: int, body: AlertStatusUpdate):
    db = _db(request)
    if not db.get_alert(alert_id):
        raise HTTPException(status_code=404, detail="Alert not found")
    db.update_alert(alert_id, status=body.status)
    return {"alert": db.get_alert(alert_id)}


@router.get("/events")
def list_events(
    request: Request,
    source: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
):
    return {"events": _db(request).get_events(source=source, event_type=event_type, limit=limit, offset=offset)}


@router.get("/incidents")
def list_incidents(request: Request, status: Optional[str] = None, limit: int = 50):
    return {"incidents": _db(request).get_incidents(status=status, limit=limit)}
