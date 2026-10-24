from spindle.config import config
from spindle.gateway import check_approval, permissions, read, search
from spindle.store import get_connection, init_db


def setup_function():
    # Ensure fresh DB for each test run
    init_db()


def test_work_agent_search():
    out = search("work-agent", "")

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
    # Run a search to generate audit rows
    search("work-agent", "Atlas")

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

    # Read pending approval email (e03)
    res_e03 = read("work-agent", "e03")
    assert "[PENDING APPROVAL]" in res_e03
    assert "request #" in res_e03


def test_gateway_permissions():
    perms = permissions("work-agent")
    assert "Spindle Privacy Policy for agent 'work-agent'" in perms
    assert "travel: allow" in perms
    assert "finance: ask" in perms
    assert "health: deny" in perms
    assert "compensation" in perms
