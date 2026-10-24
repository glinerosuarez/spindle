import stat
from spindle.config import Config
from spindle.gateway import check_approval
from spindle.mcp_server import server
from spindle.store import create_approval_request, get_connection


def test_c1_wording_compliance_clean():
    # Verify README and templates contain no raw HIPAA / GDPR / CCPA compliance wording
    with open("README.md", "r", encoding="utf-8") as f:
        readme = f.read()
    assert "Banking, Health IDs, Auth" in readme
    assert "Banking, HIPAA, Auth" not in readme

    with open("src/spindle/dashboard/templates/policy_partial.html", "r", encoding="utf-8") as f:
        tmpl = f.read()
    assert "HIPAA" not in tmpl


def test_c2_check_approval_agent_isolation():
    # Create request for work-agent
    req_id = create_approval_request(
        agent="work-agent",
        tool="read",
        query="e03",
        email_ids=["e03"],
        categories=["finance"],
    )

    # Calling check_approval with the correct agent returns status
    res_correct = check_approval("work-agent", req_id)
    assert f"Request #{req_id} is still pending" in res_correct

    # Calling check_approval with another agent returns not found
    res_wrong = check_approval("travel-agent", req_id)
    assert res_wrong == f"Request #{req_id} not found."


def test_c3_file_permissions(tmp_path, monkeypatch):
    test_dir = tmp_path / "spindle_perm_test"
    monkeypatch.setenv("SPINDLE_HOME", str(test_dir))

    _ = Config()
    assert test_dir.exists()
    mode = stat.S_IMODE(test_dir.stat().st_mode)
    assert mode == 0o700

    db_path = test_dir / "test.db"
    conn = get_connection(db_path)
    conn.close()
    assert db_path.exists()
    db_mode = stat.S_IMODE(db_path.stat().st_mode)
    assert db_mode == 0o600


def test_c4_mcp_tool_descriptions():
    tools = {t.name: t for t in server._tool_manager.list_tools()}
    expected = "Results are filtered by the user's Spindle privacy policy; withheld items are listed with reasons."

    assert "search_email" in tools
    assert expected in tools["search_email"].description

    assert "read_email" in tools
    assert expected in tools["read_email"].description
