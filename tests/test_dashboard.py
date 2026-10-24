from fastapi.testclient import TestClient
from spindle.dashboard.app import app, get_token
from spindle.policy import load_policy
from spindle.store import (
    create_approval_request,
    get_approval_request,
    get_approval_status,
    get_connection,
    init_db,
    log_audit,
)


def setup_function():
    init_db()
    conn = get_connection()
    with conn:
        conn.execute("DELETE FROM audit;")
        conn.execute("DELETE FROM approval_requests;")
        conn.execute("DELETE FROM approvals;")
    conn.close()


def test_auth_enforcement():
    client = TestClient(app)
    token = get_token()

    # 1. Missing token -> 401
    res_no_auth = client.get("/", follow_redirects=False)
    assert res_no_auth.status_code == 401

    # 2. Query token sets cookie and redirects
    res_token_query = client.get(f"/?token={token}", follow_redirects=False)
    assert res_token_query.status_code == 303
    assert "spindle_token" in res_token_query.cookies

    # 3. Request with cookie -> 200 OK
    cookie_val = res_token_query.cookies["spindle_token"]
    res_cookie = client.get("/", cookies={"spindle_token": cookie_val})
    assert res_cookie.status_code == 200
    assert "Spindle" in res_cookie.text

    # 4. Request with invalid token on fresh client -> 401
    bad_client = TestClient(app)
    bad_client.cookies.set("spindle_token", "bad-token-value")
    res_bad = bad_client.get("/")
    assert res_bad.status_code == 401



def test_unauthorized_post_fails():
    client = TestClient(app)
    # POST without token -> 401
    res = client.post("/approve/999", data={"token": "wrong"})
    assert res.status_code == 401


def test_approve_and_deny_endpoints():
    client = TestClient(app)
    token = get_token()

    # Create two pending requests
    req1 = create_approval_request("work-agent", "search", "", ["e03"], ["finance"])
    req2 = create_approval_request("work-agent", "read", "e12", ["e12"], ["personal"])

    # Approve req1
    res1 = client.post(
        f"/approve/{req1}",
        data={"token": token},
        cookies={"spindle_token": token},
    )
    assert res1.status_code == 200
    assert get_approval_status("work-agent", "e03") == "approved"
    assert get_approval_request(req1)["status"] == "approved"

    # Deny req2
    res2 = client.post(
        f"/deny/{req2}",
        data={"token": token},
        cookies={"spindle_token": token},
    )
    assert res2.status_code == 200
    assert get_approval_status("work-agent", "e12") == "denied"
    assert get_approval_request(req2)["status"] == "denied"


def test_feed_and_inspector():
    client = TestClient(app)
    token = get_token()

    # Log an audit entry
    log_audit(
        agent="work-agent",
        tool="search",
        query="",
        email_id="e08",
        category="work",
        action="allow",
        reason="Work category allowed",
        redactions=[],
    )

    # Fetch feed
    res_feed = client.get("/feed", cookies={"spindle_token": token})
    assert res_feed.status_code == 200
    assert "work-agent" in res_feed.text
    assert "Atlas launch" in res_feed.text

    # Get latest audit row id
    conn = get_connection()
    row = conn.execute("SELECT id FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    audit_id = row["id"]

    # Inspect entry
    res_insp = client.get(f"/inspect/{audit_id}", cookies={"spindle_token": token})
    assert res_insp.status_code == 200
    assert "ORIGINAL INBOX EMAIL" in res_insp.text
    assert "WHAT THE AGENT SAW" in res_insp.text


def test_policy_level_update():
    client = TestClient(app)
    token = get_token()

    # Update work-agent to strict
    res = client.post(
        "/policy/update_level",
        data={"token": token, "agent_name": "work-agent", "level": "strict"},
        cookies={"spindle_token": token},
    )
    assert res.status_code == 200

    # Verify policy file was updated
    pol = load_policy()
    assert pol.agents["work-agent"].protection_level == "strict"

    # Revert to standard
    client.post(
        "/policy/update_level",
        data={"token": token, "agent_name": "work-agent", "level": "standard"},
        cookies={"spindle_token": token},
    )
    assert load_policy().agents["work-agent"].protection_level == "standard"
