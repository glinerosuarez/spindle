import json
import shutil
from pathlib import Path
import pytest

from spindle.config import config
from spindle.gateway import search
from spindle.sources import FixtureSource
from spindle.store import decide_approval_request, get_connection, init_db
from scripts.reset_demo import reset_demo


def test_reset_demo_clears_tables_and_resets_policy():
    conn = get_connection()
    init_db()

    # Seed classification cache with 17 entries to meet fixture count
    fixtures = FixtureSource().list()
    assert len(fixtures) == 17
    with conn:
        for f in fixtures:
            conn.execute(
                """
                INSERT OR REPLACE INTO classification_cache 
                (email_id, content_hash, model, classification_json, llm_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (f.id, "hash_" + f.id, "test-model", json.dumps({"category": "work", "sensitivity": "low"}), "{}"),
            )

    # 1. Do a work-agent search that triggers an approval request
    search("work-agent", "statement", timeout=0)

    # 2. Approve the request
    row = conn.execute(
        "SELECT id FROM approval_requests WHERE agent = 'work-agent' AND status = 'pending' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert row is not None
    decide_approval_request(row["id"], "approved")

    # Verify audit, requests, approvals are populated
    assert conn.execute("SELECT COUNT(*) FROM audit").fetchone()[0] > 0
    assert conn.execute("SELECT COUNT(*) FROM approval_requests").fetchone()[0] > 0
    assert conn.execute("SELECT COUNT(*) FROM approvals").fetchone()[0] > 0

    # Modify policy file to simulate edits during demo
    with open(config.policy_path, "a", encoding="utf-8") as f:
        f.write("\n# modified by test\n")

    # Record cache count
    cache_count_before = conn.execute("SELECT COUNT(*) FROM classification_cache").fetchone()[0]
    assert cache_count_before >= 17

    # 3. Run reset_demo()
    code = reset_demo()
    assert code == 0

    # 4. Verify tables are cleared and cache is kept
    assert conn.execute("SELECT COUNT(*) FROM audit").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM approval_requests").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM approvals").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM outbox").fetchone()[0] == 0

    cache_count_after = conn.execute("SELECT COUNT(*) FROM classification_cache").fetchone()[0]
    assert cache_count_after == cache_count_before

    # Verify policy was reset
    policy_text = config.policy_path.read_text(encoding="utf-8")
    assert "# modified by test" not in policy_text

    # 5. Calling search("work-agent", "", timeout=0) should create a new pending request instead of returning approved
    res = search("work-agent", "", timeout=0)
    # Because approvals were cleared, sensitive emails require approval again
    req_row = conn.execute(
        "SELECT id, status FROM approval_requests WHERE agent = 'work-agent' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert req_row is not None
    assert req_row["status"] == "pending"
    assert "(approved by user)" not in res


def test_reset_demo_exits_nonzero_when_cache_incomplete():
    conn = get_connection()
    init_db()

    # Clear cache so it has fewer entries than fixtures
    with conn:
        conn.execute("DELETE FROM classification_cache;")

    code = reset_demo()
    assert code != 0


def test_reset_demo_main_cli():
    from scripts.reset_demo import main

    conn = get_connection()
    init_db()
    with conn:
        conn.execute("DELETE FROM classification_cache;")

    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code != 0
