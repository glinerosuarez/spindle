"""Unified ASGI application for Spindle Cloud deployment on Azure App Service.

Provides:
1. Spindle Dashboard at `/` (authenticated via Microsoft Entra ID or Spindle Token)
2. Public project page at `/site`
3. Model Context Protocol (MCP) server over Streamable HTTP at `/mcp`
   (authenticated via per-agent Bearer tokens mapped in SPINDLE_AGENT_KEYS)
"""

from __future__ import annotations

import base64
import contextlib
import contextvars
import hashlib
import hmac
import json
import logging
import os
import shutil
from pathlib import Path
from typing import Any, AsyncIterator, Callable

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from mcp.server.transport_security import TransportSecuritySettings

# Configure local non-shared disk storage for Azure
if "SPINDLE_HOME" not in os.environ:
    os.environ["SPINDLE_HOME"] = "/tmp/spindle"

from spindle.classifier import classify
from spindle.config import config
from spindle.dashboard.app import app as dashboard_app, get_token
from spindle.mcp_server import server as mcp_server
from spindle.models import Email
from spindle.sources import FixtureSource
from spindle.store import init_db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("spindle.cloud")

# Verify App Service authentication status
WEBSITE_AUTH_ENABLED = os.environ.get("WEBSITE_AUTH_ENABLED", "").lower() == "true"
if not WEBSITE_AUTH_ENABLED:
    logger.warning(
        "WEBSITE_AUTH_ENABLED is not 'True'. Client-provided X-MS-CLIENT-PRINCIPAL* headers will be ignored to prevent spoofing."
    )

APP_DIR = Path(__file__).resolve().parent.parent.parent


def initialize_cloud_environment() -> None:
    """Sets up local SQLite, policies, and warms cache on startup."""
    home_dir = config.home
    home_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    # Initialize default policy if not present
    policy_path = home_dir / "policies.yaml"
    if not policy_path.exists():
        default_policy = APP_DIR / "policies" / "default.yaml"
        if default_policy.exists():
            shutil.copyfile(default_policy, policy_path)
            logger.info("Copied default policy to %s", policy_path)

    # Initialize database
    init_db()
    logger.info("Initialized database at %s", config.db_path)

    # Warm classification cache for fixtures
    try:
        source = FixtureSource()
        emails = source.search("", limit=100)
        for email in emails:
            classify(email, use_cache=True)
        logger.info("Warmed classification cache for %d fixture emails", len(emails))
    except Exception as e:
        logger.warning("Cache warming encountered non-fatal error: %s", e)


# Run startup initialization
initialize_cloud_environment()

# Streamable HTTP MCP Server App (created before lifespan so _session_manager is set)
mcp_asgi_app = mcp_server.streamable_http_app(
    streamable_http_path="/",
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    initialize_cloud_environment()
    session_mgr = getattr(mcp_server._lowlevel_server, "_session_manager", None)
    if session_mgr is not None:
        async with session_mgr.run():
            yield
    else:
        yield


# Create top-level unified FastAPI app with docs disabled
app = FastAPI(
    title="Spindle Cloud Gateway",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)

# Mount public site if available
site_dir = APP_DIR / "site"
if site_dir.exists():
    app.mount("/site", StaticFiles(directory=str(site_dir), html=True), name="site")


def get_authenticated_agent_from_key(auth_header: str | None) -> str | None:
    """Validates Authorization: Bearer <agent-key> against SPINDLE_AGENT_KEYS."""
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    raw_key = auth_header[len("Bearer ") :].strip()
    if not raw_key:
        return None

    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    keys_json = os.environ.get("SPINDLE_AGENT_KEYS", "{}")
    try:
        keys_map = json.loads(keys_json)  # {"<sha256>": "agent-name", ...}
    except Exception:
        logger.error("Invalid SPINDLE_AGENT_KEYS JSON format")
        return None

    for stored_hash, agent_name in keys_map.items():
        if hmac.compare_digest(stored_hash, key_hash):
            return agent_name
    return None


def is_website_auth_enabled() -> bool:
    """Returns True if Azure App Service EasyAuth platform authentication is active."""
    return os.environ.get("WEBSITE_AUTH_ENABLED", "").lower() == "true"


def get_entra_principal(request: Request) -> dict[str, Any] | None:
    """Extracts and verifies Microsoft Entra ID claims from App Service EasyAuth headers.

    Header spoofing protection: Only trust X-MS-CLIENT-PRINCIPAL* headers if
    Azure App Service platform authentication is actively enabled (WEBSITE_AUTH_ENABLED=True).
    """
    if not is_website_auth_enabled():
        return None

    # Direct username header from App Service
    username = request.headers.get("X-MS-CLIENT-PRINCIPAL-NAME")
    if username:
        return {"username": username}

    # Encoded principal payload
    encoded = request.headers.get("X-MS-CLIENT-PRINCIPAL")
    if encoded:
        try:
            raw = base64.b64decode(encoded).decode("utf-8")
            data = json.loads(raw)
            # Find preferred_username or email claim
            claims = data.get("claims", [])
            for c in claims:
                if c.get("typ") in (
                    "preferred_username",
                    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                    "name",
                ):
                    return {"username": c.get("val"), "raw": data}
            return {"username": data.get("name_typ"), "raw": data}
        except Exception:
            pass
    return None


# Middleware governing Entra ID access to dashboard and Bearer keys to /mcp
@app.middleware("http")
async def security_and_routing_middleware(request: Request, call_next: Callable) -> Response:
    path = request.url.path

    # 1. MCP Endpoint Security (/mcp and /mcp/*)
    if path == "/mcp" or path.startswith("/mcp/"):
        # Strip spoofed client principal headers on /mcp
        headers = [
            (k, v)
            for k, v in request.scope.get("headers", [])
            if not k.lower().startswith(b"x-ms-client-principal")
        ]
        request.scope["headers"] = headers

        # Rewrite /mcp to /mcp/ so both forms route to the mounted Streamable HTTP subapp
        if request.scope.get("path") == "/mcp":
            request.scope["path"] = "/mcp/"

        auth_header = request.headers.get("Authorization")
        agent_name = get_authenticated_agent_from_key(auth_header)
        if not agent_name:
            return JSONResponse(
                status_code=401,
                content={
                    "error": "Unauthorized",
                    "detail": "Missing or invalid agent Bearer key for remote MCP access.",
                },
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Agent identity is resolved per-call by tools via MCP Context; no global mutation
        return await call_next(request)

    # 2. Allow public static site without authentication
    if path.startswith("/site"):
        # Strip spoofed client principal headers on /site
        headers = [
            (k, v)
            for k, v in request.scope.get("headers", [])
            if not k.lower().startswith(b"x-ms-client-principal")
        ]
        request.scope["headers"] = headers
        return await call_next(request)

    # 3. Dashboard Endpoints: Check Microsoft Entra ID Authentication
    principal = get_entra_principal(request)
    allowed_users = os.environ.get("ALLOWED_ENTRA_USERS", "linero@usc.edu").split(",")
    allowed_users = [u.strip().lower() for u in allowed_users if u.strip()]

    if principal:
        user_name = principal.get("username", "").lower()
        if user_name not in allowed_users:
            logger.warning("Refused Entra login from unauthorized account: %s", user_name)
            return HTMLResponse(
                status_code=403,
                content="<h1>403 Forbidden</h1><p>Your Microsoft account is not authorized to access this Spindle instance.</p>",
            )

        # Authorized user via Entra: inject token header and set session cookie
        token_val = get_token()
        headers = list(request.scope.get("headers", []))
        headers.append((b"x-spindle-token", token_val.encode("utf-8")))
        request.scope["headers"] = headers

        response = await call_next(request)
        response.set_cookie(
            "spindle_token",
            token_val,
            httponly=True,
            samesite="lax",
            secure=True,
        )
        return response

    # If no Entra headers present (e.g. running outside EasyAuth or direct curl), let dashboard verify token
    return await call_next(request)


# Mount Streamable HTTP MCP Server App
app.mount("/mcp", mcp_asgi_app)

# Mount existing Dashboard app at root
app.mount("/", dashboard_app)
