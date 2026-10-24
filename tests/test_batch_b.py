import json
from starlette.testclient import TestClient

from spindle.dashboard.app import app, get_token
from spindle.gateway import read, search
from spindle.policy import load_policy, save_policy
from spindle.store import get_connection, log_audit


def test_b1_duplicate_approval_requests():
    # Calling search twice, then read, leaves exactly one pending row in approval_requests
    search("work-agent", "", timeout=0)
    search("work-agent", "", timeout=0)
    read("work-agent", "e03", timeout=0)

    conn = get_connection()
    pending_rows = conn.execute(
        "SELECT * FROM approval_requests WHERE agent = 'work-agent' AND status = 'pending'"
    ).fetchall()
    conn.close()

    assert len(pending_rows) == 1
    req = dict(pending_rows[0])
    email_ids = json.loads(req["email_ids_json"])
    assert "e03" in email_ids


def test_b3_audit_trail_records_what_agent_actually_saw():
    client = TestClient(app)
    token = get_token()

    # 1. Search at standard level
    policy = load_policy()
    assert policy.agents["work-agent"].protection_level == "standard"
    search("work-agent", "Atlas", timeout=0)

    # Find audit row for e08
    conn = get_connection()
    row = conn.execute(
        "SELECT id, returned_text FROM audit WHERE agent = 'work-agent' AND email_id = 'e08' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()

    assert row is not None
    audit_id = row["id"]
    stored_text = row["returned_text"]
    assert stored_text is not None
    assert "priya@northwind.io" in stored_text
    assert "[REDACTED:email]" not in stored_text

    # 2. Change level to strict
    policy.agents["work-agent"].protection_level = "strict"
    save_policy(policy)

    # 3. Open inspector for earlier row
    res = client.get(f"/inspect/{audit_id}", cookies={"spindle_token": token})
    assert res.status_code == 200
    # Inspector displays the original standard text (not re-redacted with strict)
    assert "priya@northwind.io" in res.text
    assert "[REDACTED:email]" not in res.text
    assert "(reconstructed)" not in res.text

    # 4. Also verify legacy row fallback with NULL returned_text
    log_audit(
        agent="work-agent",
        tool="search",
        query="",
        email_id="e08",
        category="work",
        action="allow",
        reason="Legacy row",
        redactions=[],
        returned_text=None,
    )
    conn = get_connection()
    legacy_row = conn.execute("SELECT id FROM audit WHERE returned_text IS NULL ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    legacy_id = legacy_row["id"]
    res_legacy = client.get(f"/inspect/{legacy_id}", cookies={"spindle_token": token})
    assert res_legacy.status_code == 200
    assert "(reconstructed)" in res_legacy.text


def test_b4_words_run_together_in_visible_text():
    res = read("work-agent", "e08")
    assert "Hi Alex," in res
    assert "Hi Alex,\n" in res or "Hi Alex,\nCan you" in res
    assert ",C" not in res


def test_b5_passthrough_returns_full_content():
    out = search("unprotected", "")

    # Contains OTP from e04
    assert "482913" in out
    # Contains full account number from e03
    assert "482910394821" in out
    # Contains MRN from e06
    assert "KP-849201-9" in out
    # Contains e15 hidden prompt injection sentence
    assert "verification codes" in out
    # Separated by ---
    assert "\n---\n" in out
