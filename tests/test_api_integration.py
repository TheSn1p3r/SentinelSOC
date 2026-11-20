"""End-to-end API/dashboard integration tests.

Builds a real SentinelAgent (collector threads not started — nothing
under test here needs them) wired into a real FastAPI app, and drives it
with Starlette's TestClient exactly the way a browser or API client would:
through HTTP, with cookies, not by calling Python functions directly.
"""

from __future__ import annotations

import subprocess
import time

import pytest
from fastapi.testclient import TestClient

from sentinelsoc.agent import SentinelAgent
from sentinelsoc.api.app import create_app


@pytest.fixture
def agent(config):
    a = SentinelAgent(config)
    yield a
    a.stop()


@pytest.fixture
def client(agent):
    return TestClient(create_app(agent))


@pytest.fixture
def api_key(agent):
    return agent.config.get("api.api_key")


def test_unauthenticated_page_redirects_to_login(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code in (302, 303)
    assert r.headers["location"] == "/login"


def test_unauthenticated_api_is_rejected(client):
    r = client.get("/api/system/status")
    assert r.status_code == 401


def test_login_with_wrong_key_shows_error(client):
    r = client.post("/login", data={"api_key": "wrong"})
    assert r.status_code == 200
    assert "Incorrect key" in r.text


def test_login_then_every_page_and_core_api_route(client, api_key):
    r = client.post("/login", data={"api_key": api_key}, follow_redirects=False)
    assert r.status_code == 303
    assert "sentinelsoc_session" in r.cookies

    for path in ["/", "/alerts", "/monitoring", "/response"]:
        assert client.get(path).status_code == 200

    status = client.get("/api/system/status")
    assert status.status_code == 200
    assert "rules_loaded" in status.json()

    assert client.get("/api/processes").status_code == 200
    assert client.get("/api/network").status_code == 200

    r = client.post("/logout", follow_redirects=False)
    assert r.status_code == 303
    assert client.get("/api/system/status").status_code == 401


def test_alert_lifecycle_through_the_api(client, api_key, agent):
    client.post("/login", data={"api_key": api_key})

    alert_id = agent.db.insert_alert({
        "rule_id": "R-TEST", "rule_name": "Test Rule", "category": "Execution",
        "mitre_technique": "T1059.001", "severity": "HIGH", "risk_score": 70,
        "title": "Test alert", "description": "desc", "process_name": "test.exe",
        "account_name": "alice", "timestamp": "2026-11-19T00:00:00+00:00",
    })

    detail = client.get(f"/api/alerts/{alert_id}")
    assert detail.status_code == 200
    assert "recommended_steps" in detail.json()["recommendation"]

    assert client.get(f"/alerts/{alert_id}").status_code == 200

    patched = client.patch(f"/api/alerts/{alert_id}", json={"status": "ACKNOWLEDGED"})
    assert patched.status_code == 200
    assert patched.json()["alert"]["status"] == "ACKNOWLEDGED"

    listed = client.get("/api/alerts", params={"limit": 10})
    assert any(a["id"] == alert_id for a in listed.json()["alerts"])


def test_response_action_full_cycle_via_http(client, api_key):
    client.post("/login", data={"api_key": api_key})

    proc = subprocess.Popen(["sleep", "30"])
    time.sleep(0.2)
    try:
        proposed = client.post(
            "/api/response/actions/terminate", json={"pid": proc.pid, "reason": "api test"}
        )
        assert proposed.status_code == 200
        assert proposed.json()["action"]["status"] == "PENDING"
        action_id = proposed.json()["action"]["id"]

        decided = client.post(
            f"/api/response/actions/{action_id}/decide",
            json={"analyst": "alice", "approve": True},
        )
        assert decided.status_code == 200
        assert decided.json()["action"]["status"] == "EXECUTED"

        proc.wait(timeout=5)
        assert proc.poll() is not None

        audit = client.get("/api/audit").json()["entries"]
        assert len(audit) > 0
    finally:
        if proc.poll() is None:
            proc.terminate()
