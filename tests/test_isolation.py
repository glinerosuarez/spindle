import os
from pathlib import Path
from spindle.config import config
from spindle.models import AgentPolicy, PolicyFile
from spindle.policy import load_policy, save_policy


def test_isolation_does_not_touch_real_home(tmp_path):
    # Verify config paths are inside the isolated temporary directory
    assert str(tmp_path) in str(config.home)
    assert str(tmp_path) in str(config.policy_path)
    assert str(tmp_path) in str(config.db_path)
    assert config.llm_enabled is False

    # Check real ~/.spindle if it exists
    real_spindle = Path(os.path.expanduser("~/.spindle")).resolve()
    real_db = real_spindle / "spindle.db"
    real_policy = real_spindle / "policies.yaml"

    db_mtime_before = real_db.stat().st_mtime if real_db.exists() else None
    policy_mtime_before = real_policy.stat().st_mtime if real_policy.exists() else None

    # Perform mutations on policy and DB
    p = load_policy()
    p.agents["work-agent"].protection_level = "strict"
    save_policy(p)

    # Verify real ~/.spindle was untouched
    if db_mtime_before is not None:
        assert real_db.stat().st_mtime == db_mtime_before
    if policy_mtime_before is not None:
        assert real_policy.stat().st_mtime == policy_mtime_before
