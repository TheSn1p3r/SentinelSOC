"""Pydantic request models for the SentinelSOC API.

Responses are returned as plain dicts from DBManager (already JSON-
serializable), so only request bodies are modeled here.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    api_key: str


class AlertStatusUpdate(BaseModel):
    status: str = Field(..., pattern="^(NEW|ACKNOWLEDGED|IN_PROGRESS|RESOLVED|FALSE_POSITIVE)$")


class ProposeTerminateRequest(BaseModel):
    pid: int
    reason: str
    alert_id: Optional[int] = None


class ProposeQuarantineRequest(BaseModel):
    file_path: str
    reason: str
    alert_id: Optional[int] = None


class ResponseDecision(BaseModel):
    analyst: str
    approve: bool
    notes: Optional[str] = ""
