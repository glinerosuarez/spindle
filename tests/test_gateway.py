import subprocess
import threading
import time
from spindle.config import config
from spindle.gateway import check_approval, permissions, read, search
from spindle.store import decide_approval_request, get_approval_status, get_connection, init_db


def setup_function():
    # Ensure fresh DB tables for each test run
    init_db()
    conn = get_connection()
    with conn:
        conn.execute("DELETE FROM audit;")
        conn.execute("DELETE FROM approval_requests;")
        conn.execute("DELETE FROM approvals;")
    conn.close()



def test_work_agent_search():
    out = search("work-agent", "", timeout=0)

    # 1. Withheld by policy: e04, e05 (auth: 2), e06, e07, e13 (health: 3)
    assert "Withheld by policy:" in out
    assert "auth (denied by user policy)" in out
    assert "health (denied by user policy)" in out
    assert "[e04]" not in out
    assert "[e05]" not in out
    assert "[e06]" not in out
    assert "[e07]" not in out
    assert "[e13]" not in out

    # 2. Quarantines e15 and e17
    assert "Quarantined:" in out
    assert "it-compliance@northwind-it.co" in out
    assert "docs-share@notifications-docs.co" in out
    assert "[e15]" not in out
    assert "[e17]" not in out

    # 3. Pending approval: e03, e12, e16
    assert "Pending approval:" in out
    assert "request #" in out
    assert "email(s). Awaiting user approval" in out
    assert "[e03]" not in out
    assert "[e12]" not in out
    assert "[e16]" not in out

    # 4. Returns e08 with no redaction
    assert "[e08] 2026-10-22 | Priya Shah <priya@northwind.io> | Atlas launch: status for Friday?" in out
    assert "[REDACTED:" not in out.split("[e08]")[1].split("[e")[0]

    # Allowed list contains the allowed items (e01, e02, e08, e09, e10, e11, e14)
    assert "[e01]" in out
    assert "[e02]" in out
    assert "[e09]" in out
    assert "[e10]" in out
    assert "[e11]" in out
    assert "[e14]" in out

    # Custom rule was applied to e11 ($185,000 base)
    assert "[REDACTED:compensation]" in out


def test_unprotected_search():
    out = search("unprotected", "")

    assert 'unfiltered passthrough access for agent "unprotected"' in out
    # e04 verification code 482913 is present unredacted
    assert "482913" in out
    assert "[e04]" in out
    assert "[e15]" in out
    assert "Withheld by policy:" not in out


def test_audit_logging():
    search("work-agent", "Atlas", timeout=0)

    conn = get_connection()
    rows = conn.execute("SELECT * FROM audit WHERE agent = 'work-agent'").fetchall()
    conn.close()

    assert len(rows) > 0
    categories = {r["category"] for r in rows}
    assert "work" in categories


def test_gateway_read():
    # Read allowed email (e08)
    res_e08 = read("work-agent", "e08")
    assert "Email [e08]" in res_e08
    assert "Atlas launch: status for Friday?" in res_e08

    # Read denied auth email (e04)
    res_e04 = read("work-agent", "e04")
    assert "[WITHHELD]" in res_e04
    assert "access denied" in res_e04

    # Read quarantined email (e15)
    res_e15 = read("work-agent", "e15")
    assert "[QUARANTINED]" in res_e15

    # Read pending approval email (e03) with 0 timeout -> pending
    res_e03 = read("work-agent", "e03", timeout=0)
    assert "[PENDING APPROVAL]" in res_e03
    assert "request #" in res_e03


def test_gateway_permissions():
    perms = permissions("work-agent")
    assert "Spindle Privacy Policy for agent 'work-agent'" in perms
    assert "travel: allow" in perms
    assert "finance: ask" in perms
    assert "health: deny" in perms
    assert "compensation" in perms


def test_search_waiting_approval_success():
    def background_approver():
        time.sleep(1.0)
        conn = get_connection()
        row = conn.execute(
            "SELECT id FROM approval_requests WHERE status = 'pending' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        conn.close()
        if row:
            decide_approval_request(row["id"], "approved")

    t = threading.Thread(target=background_approver)
    t.start()

    # Search with 5s timeout; background approver fires after 1s
    out = search("work-agent", "statement", timeout=5)
    t.join()

    # e03 (Chase statement) was ask, but now approved!
    assert "[e03]" in out
    assert "(approved by user)" in out
    read_res = read("work-agent", "e03")
    assert "[REDACTED:bank_account]" in read_res



def test_search_waiting_approval_timeout():
    # Search with 1s timeout and no approver
    out = search("work-agent", "statement", timeout=1.0)
    assert "Pending approval:" in out
    assert "request #" in out
    assert "[e03]" not in out


def test_cli_approval_tool():
    # 1. Trigger pending read
    read_res = read("work-agent", "e03", timeout=0)
    assert "request #" in read_res
    req_id = int(read_res.split("request #")[1].split(")")[0])

    # 2. Run CLI approval in the isolated test home
    import os
    env = {**os.environ, "SPINDLE_HOME": str(config.home)}
    subprocess.run(
        ["uv", "run", "python", "-m", "spindle.store", "approve", str(req_id)],
        env=env,
        check=True,
    )

    # 3. Verify approval in store
    status = get_approval_status("work-agent", "e03")
    assert status == "approved"

    # 4. Read should now succeed immediately
    read_approved = read("work-agent", "e03")
    assert "Email [e03]" in read_approved
    assert "[REDACTED:bank_account]" in read_approved
