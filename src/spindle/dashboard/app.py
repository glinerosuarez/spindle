from __future__ import annotations

import json
import logging
import os
import secrets
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Form, Header, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from spindle.config import config
from spindle.models import AgentPolicy, Level, PolicyFile
from spindle.policy import load_policy, save_policy
from spindle.redact import redact, scan
from spindle.sources import FixtureSource
from spindle.store import (
    decide_approval_request,
    get_connection,
    init_db,
)

logger = logging.getLogger("spindle.dashboard")

# Generate secure in-memory token on startup
_AUTH_TOKEN: str = os.environ.get("SPINDLE_DASHBOARD_TOKEN") or secrets.token_urlsafe(24)

dashboard_dir = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(dashboard_dir / "templates"))

app = FastAPI(title="Spindle Privacy Gateway Dashboard")
app.mount("/static", StaticFiles(directory=str(dashboard_dir / "static")), name="static")


def get_token() -> str:
    return _AUTH_TOKEN


def verify_auth(
    request: Request,
    token: Optional[str] = Query(None),
) -> str:
    # Check query param
    if token and token == _AUTH_TOKEN:
        return _AUTH_TOKEN

    # Check cookie
    cookie_token = request.cookies.get("spindle_token")
    if cookie_token and cookie_token == _AUTH_TOKEN:
        return _AUTH_TOKEN

    # Check header
    header_token = request.headers.get("X-Spindle-Token")
    if header_token and header_token == _AUTH_TOKEN:
        return _AUTH_TOKEN

    raise HTTPException(
        status_code=401,
        detail="Unauthorized: invalid or missing Spindle dashboard token",
    )


def verify_post_auth(
    request: Request,
    token: Optional[str] = Form(None),
) -> str:
    # Form field token check
    if token and token == _AUTH_TOKEN:
        return _AUTH_TOKEN

    # Header check
    header_token = request.headers.get("X-Spindle-Token")
    if header_token and header_token == _AUTH_TOKEN:
        return _AUTH_TOKEN

    # Cookie fallback if token matches
    cookie_token = request.cookies.get("spindle_token")
    if cookie_token and cookie_token == _AUTH_TOKEN:
        return _AUTH_TOKEN

    raise HTTPException(
        status_code=401,
        detail="Unauthorized: invalid or missing Spindle dashboard token in POST",
    )


@app.get("/", response_class=HTMLResponse)
async def index(
    request: Request,
    token: Optional[str] = Query(None),
):
    # If token passed in query, set cookie and redirect to clean URL
    if token == _AUTH_TOKEN:
        response = RedirectResponse(url="/", status_code=303)
        response.set_cookie(
            key="spindle_token",
            value=_AUTH_TOKEN,
            httponly=True,
            samesite="lax",
        )
        return response

    # Otherwise verify cookie / query auth
    verify_auth(request, token)

    init_db()
    policy_file = load_policy()
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "token": _AUTH_TOKEN,
            "policy_file": policy_file,
            "agent": config.agent,
        },
    )



@app.get("/feed", response_class=HTMLResponse)
async def get_feed(request: Request, auth: str = Depends(verify_auth)):
    init_db()
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT * FROM audit
        ORDER BY id DESC
        LIMIT 30
        """
    ).fetchall()
    conn.close()

    source = FixtureSource()
    audit_events: List[Dict[str, Any]] = []

    for r in rows:
        row_dict = dict(r)
        # Parse JSON fields
        try:
            row_dict["redactions"] = json.loads(row_dict["redactions_json"]) if row_dict.get("redactions_json") else []
        except Exception:
            row_dict["redactions"] = []

        try:
            row_dict["injection"] = json.loads(row_dict["injection_json"]) if row_dict.get("injection_json") else None
        except Exception:
            row_dict["injection"] = None

        # Look up email details if available
        email = source.get(row_dict["email_id"]) if row_dict.get("email_id") else None
        row_dict["email_sender"] = email.sender if email else ""
        row_dict["email_subject"] = email.subject if email else ""

        audit_events.append(row_dict)

    return templates.TemplateResponse(
        request=request,
        name="feed_partial.html",
        context={
            "audit_events": audit_events,
            "token": _AUTH_TOKEN,
        },
    )


@app.get("/approvals", response_class=HTMLResponse)
async def get_approvals(request: Request, auth: str = Depends(verify_auth)):
    init_db()
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT * FROM approval_requests
        WHERE status = 'pending'
        ORDER BY id DESC
        """
    ).fetchall()
    conn.close()

    source = FixtureSource()
    pending_requests: List[Dict[str, Any]] = []

    for r in rows:
        req_dict = dict(r)
        try:
            email_ids = json.loads(req_dict["email_ids_json"])
        except Exception:
            email_ids = []

        try:
            categories = json.loads(req_dict["categories_json"])
        except Exception:
            categories = []

        emails = [source.get(eid) for eid in email_ids]
        req_dict["emails"] = [e for e in emails if e is not None]
        req_dict["categories_str"] = ", ".join(sorted(set(categories)))
        pending_requests.append(req_dict)

    return templates.TemplateResponse(
        request=request,
        name="approvals_partial.html",
        context={
            "pending_requests": pending_requests,
            "token": _AUTH_TOKEN,
        },
    )



@app.post("/approve/{request_id}", response_class=HTMLResponse)
async def approve_request(
    request: Request,
    request_id: int,
    auth: str = Depends(verify_post_auth),
):
    init_db()
    decide_approval_request(request_id, "approved")
    return await get_approvals(request, auth=auth)


@app.post("/deny/{request_id}", response_class=HTMLResponse)
async def deny_request(
    request: Request,
    request_id: int,
    auth: str = Depends(verify_post_auth),
):
    init_db()
    decide_approval_request(request_id, "denied")
    return await get_approvals(request, auth=auth)


@app.get("/inspect/{audit_id}", response_class=HTMLResponse)
async def inspect_entry(
    request: Request,
    audit_id: int,
    auth: str = Depends(verify_auth),
):
    init_db()
    conn = get_connection()
    row = conn.execute("SELECT * FROM audit WHERE id = ?", (audit_id,)).fetchone()
    conn.close()

    if not row:
        return HTMLResponse("<p class='text-gray-400'>Audit record not found.</p>")

    audit_data = dict(row)
    source = FixtureSource()
    email = source.get(audit_data["email_id"]) if audit_data.get("email_id") else None

    # Redactions & injection
    try:
        audit_data["redactions"] = json.loads(audit_data["redactions_json"]) if audit_data.get("redactions_json") else []
    except Exception:
        audit_data["redactions"] = []

    try:
        audit_data["injection"] = json.loads(audit_data["injection_json"]) if audit_data.get("injection_json") else None
    except Exception:
        audit_data["injection"] = None

    # Calculate what agent saw
    what_agent_saw = ""
    if audit_data["action"] == "passthrough":
        what_agent_saw = email.body_text if email else ""
    elif audit_data["action"] == "quarantine":
        what_agent_saw = (
            f"[QUARANTINED BY SPINDLE]\n"
            f"Email from {email.sender if email else 'sender'} was quarantined.\n"
            f"Reason: {audit_data['reason']}\n\n"
            f"Content withheld from agent."
        )
    elif audit_data["action"] == "deny":
        what_agent_saw = (
            f"[WITHHELD BY USER POLICY]\n"
            f"Category '{audit_data['category']}' access denied for this agent."
        )
    elif audit_data["action"] == "ask":
        what_agent_saw = (
            f"[PENDING USER APPROVAL]\n"
            f"Access requires explicit user confirmation in the Spindle Dashboard."
        )
    elif audit_data["action"] == "allow":
        if email:
            policy_file = load_policy()
            agent_policy = policy_file.agents.get(audit_data["agent"], AgentPolicy())
            from spindle.injection import visible_text
            clean_body = visible_text(email)
            redacted_body, _ = redact(
                clean_body,
                level=agent_policy.protection_level,
                custom_rules=agent_policy.custom_rules,
            )
            what_agent_saw = redacted_body

    return templates.TemplateResponse(
        request=request,
        name="inspector_partial.html",
        context={
            "audit": audit_data,
            "email": email,
            "what_agent_saw": what_agent_saw,
        },
    )


@app.post("/policy/update_level", response_class=HTMLResponse)
async def update_policy_level(
    request: Request,
    agent_name: str = Form(...),
    level: str = Form(...),
    auth: str = Depends(verify_post_auth),
):
    policy_file = load_policy()
    if agent_name in policy_file.agents and level in ("light", "standard", "strict"):
        policy_file.agents[agent_name].protection_level = level  # type: ignore[assignment]
        save_policy(policy_file)
        logger.info("Updated protection level for agent '%s' to '%s'", agent_name, level)

    return await get_policies_partial(request, auth=auth)


@app.get("/policies", response_class=HTMLResponse)
async def get_policies_partial(request: Request, auth: str = Depends(verify_auth)):
    policy_file = load_policy()
    return templates.TemplateResponse(
        request=request,
        name="policy_partial.html",
        context={
            "policy_file": policy_file,
            "token": _AUTH_TOKEN,
        },
    )



def main():
    import uvicorn

    print(f"\n==================================================================")
    print(f"  Spindle Privacy Gateway Dashboard")
    print(f"  Startup Token: {_AUTH_TOKEN}")
    print(f"  Dashboard URL: http://127.0.0.1:{config.dashboard_port}/?token={_AUTH_TOKEN}")
    print(f"==================================================================\n")

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=config.dashboard_port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
