from spindle.gateway import read, search
from spindle.injection import inspect, visible_text
from spindle.sources import FixtureSource
from spindle.store import decide_approval_request, get_approval_request, get_connection


def test_fixture_html_matches_body_text():
    source = FixtureSource()
    fixtures = source.list()
    assert len(fixtures) == 17

    for email in fixtures:
        if email.id == "e15":
            continue
        vis = visible_text(email)
        norm_vis = " ".join(vis.split())
        norm_body = " ".join(email.body_text.split())
        assert norm_vis == norm_body, f"Mismatch in {email.id}: HTML visible text does not match body_text"


def test_e15_fixture_properties():
    source = FixtureSource()
    e15 = source.get("e15")
    assert e15 is not None

    report = inspect(e15)
    assert report.hidden_text is True
    assert report.quarantine is True

    vis = visible_text(e15)
    assert "template NW-2026-B" in vis


def test_read_e09_contains_full_body():
    source = FixtureSource()
    e09 = source.get("e09")
    assert e09 is not None

    out = read("work-agent", "e09")
    # All sentences or lines in body_text should be present
    for line in e09.body_text.splitlines():
        line = line.strip()
        if line:
            assert line in out, f"Missing line from e09 body_text: {line}"


def test_read_e03_after_approval_redacts_account():
    # 1. Search to trigger ask
    search("work-agent", "statement", timeout=0)

    # 2. Approve request
    conn = get_connection()
    row = conn.execute(
        "SELECT id FROM approval_requests WHERE agent = 'work-agent' AND status = 'pending' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    assert row is not None
    decide_approval_request(row["id"], "approved")

    # 3. Read e03
    out = read("work-agent", "e03")
    assert "[REDACTED:bank_account]" in out
    assert "482910394821" not in out
