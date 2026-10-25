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


def test_dashboard_entra_spoofed_header_without_platform_auth_fails(client, monkeypatch):
    """Verifies that forged X-MS-CLIENT-PRINCIPAL headers are ignored when WEBSITE_AUTH_ENABLED is unset."""
    monkeypatch.delenv("WEBSITE_AUTH_ENABLED", raising=False)
    response = client.get(
        "/",
        headers={"X-MS-CLIENT-PRINCIPAL-NAME": "linero@usc.edu"},
    )
    # Should be treated as unauthenticated and rejected with 401
    assert response.status_code == 401


def test_dashboard_entra_unauthorized_user_forbidden(client, monkeypatch):
    """Verifies that an unauthorized Microsoft Entra account is blocked with 403 when auth is enabled."""
    monkeypatch.setenv("WEBSITE_AUTH_ENABLED", "True")
    response = client.get(
        "/",
        headers={"X-MS-CLIENT-PRINCIPAL-NAME": "hacker@evilcorp.com"},
    )
    assert response.status_code == 403
    assert "Forbidden" in response.text


def test_dashboard_entra_authorized_user_allowed(client, monkeypatch):
    """Verifies that Gabriel's Microsoft Entra account gets access and receives a session cookie when auth is enabled."""
    monkeypatch.setenv("WEBSITE_AUTH_ENABLED", "True")
    response = client.get(
        "/",
        headers={"X-MS-CLIENT-PRINCIPAL-NAME": "linero@usc.edu"},
    )
    assert response.status_code == 200
    assert "spindle_token" in response.cookies


def test_docs_and_openapi_disabled_return_404(client):
    """Verifies that FastAPI Swagger UI, Redoc, and OpenAPI schema endpoints return 404."""
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 404


@pytest.mark.anyio
async def test_mcp_concurrent_per_call_agent_isolation(monkeypatch):
    """Verifies that 20 interleaved concurrent MCP calls between work-agent and strict-agent resolve per-call identity."""
    import asyncio
    import httpx2
    from mcp.client.session import ClientSession
    from mcp.client.streamable_http import streamable_http_client
    from spindle.cloud import lifespan

    work_key = "test-work-key-concurrent"
    strict_key = "test-strict-key-concurrent"
    keys_map = {
        hashlib.sha256(work_key.encode()).hexdigest(): "work-agent",
        hashlib.sha256(strict_key.encode()).hexdigest(): "strict-agent",
    }
    monkeypatch.setenv("SPINDLE_AGENT_KEYS", json.dumps(keys_map))

    async def run_agent_client(agent_key: str, count: int):
        transport = httpx2.ASGITransport(app=app)
        results = []
        async with httpx2.AsyncClient(
            transport=transport,
            base_url="http://testserver",
            headers={"authorization": f"Bearer {agent_key}"},
        ) as http_client:
            async with streamable_http_client(
                "http://testserver/mcp/",
                http_client=http_client,
            ) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    for _ in range(count):
                        res = await session.call_tool("my_permissions", {})
                        results.append(res.content[0].text)
                        await asyncio.sleep(0.005)
        return results

    async with lifespan(app):
        work_res, strict_res = await asyncio.gather(
            run_agent_client(work_key, 10),
            run_agent_client(strict_key, 10),
        )

        assert len(work_res) == 10
        assert len(strict_res) == 10

        for text in work_res:
            assert "standard" in text
            assert "Max Results: 20" in text
            assert "work-agent" in text
        for text in strict_res:
            assert "strict" in text
            assert "Max Results: 5" in text
            assert "strict-agent" in text


def test_mcp_fail_closed_when_header_read_raises(monkeypatch):
    """Verifies A6: when SPINDLE_REMOTE is active and header read fails, fails closed to deny-all policy."""
    monkeypatch.setenv("SPINDLE_REMOTE", "1")
    monkeypatch.delenv("SPINDLE_AGENT", raising=False)

    class BrokenContext:
        @property
        def headers(self):
            raise RuntimeError("Corrupted transport header stream")

    from spindle.mcp_server import get_agent_from_context, my_permissions

    agent = get_agent_from_context(BrokenContext())
    assert agent == "__unauthenticated__"

    perms = my_permissions(BrokenContext())
    assert "Implicit policy for unknown agent '__unauthenticated__' (deny all)" in perms
    assert "travel: deny" in perms
    assert "work: deny" in perms
    assert "standard" not in perms

