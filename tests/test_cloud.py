"""Tests for unified Azure Cloud ASGI application spindle.cloud:app."""

import hashlib
import json
import os
import pytest
from starlette.testclient import TestClient

from spindle.cloud import app


@pytest.fixture
def client():
    return TestClient(app, raise_server_exceptions=False)


def test_site_endpoint(client):
    """Verifies that /site serves the project landing page."""
    response = client.get("/site/")
    assert response.status_code == 200
    assert "Spindle" in response.text
    assert "Privacy Gateway" in response.text


def test_mcp_unauthenticated_returns_401(client):
    """Verifies that /mcp requires authentication and returns 401 for unauthorized callers."""
    response = client.get("/mcp")
    assert response.status_code == 401
    assert "Unauthorized" in response.text


def test_mcp_authenticated_with_key(client, monkeypatch):
    """Verifies that /mcp authenticates callers using Bearer keys hashed in SPINDLE_AGENT_KEYS."""
    agent_key = "spindle-secret-test-key-12345"
    key_hash = hashlib.sha256(agent_key.encode("utf-8")).hexdigest()
    keys_map = {key_hash: "work-agent"}
    monkeypatch.setenv("SPINDLE_AGENT_KEYS", json.dumps(keys_map))

    response = client.get(
        "/mcp",
        headers={"Authorization": f"Bearer {agent_key}"},
    )
    # MCP streamable http handler should accept the request (405 or 200/404 depending on HTTP method, not 401)
    assert response.status_code != 401


def test_dashboard_unauthenticated_post_fails(client):
    """Verifies that POST /approve/1 without login or token is rejected with 401."""
    response = client.post("/approve/1", data={"token": "invalid"})
    assert response.status_code == 401


def test_dashboard_entra_unauthorized_user_forbidden(client):
    """Verifies that an unauthorized Microsoft Entra account is blocked with 403."""
    response = client.get(
        "/",
        headers={"X-MS-CLIENT-PRINCIPAL-NAME": "hacker@evilcorp.com"},
    )
    assert response.status_code == 403
    assert "Forbidden" in response.text


def test_dashboard_entra_authorized_user_allowed(client):
    """Verifies that Gabriel's Microsoft Entra account gets access and receives a session cookie."""
    response = client.get(
        "/",
        headers={"X-MS-CLIENT-PRINCIPAL-NAME": "linero@usc.edu"},
    )
    assert response.status_code == 200
    assert "spindle_token" in response.cookies
