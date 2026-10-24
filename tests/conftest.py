import shutil
from pathlib import Path
import pytest

from spindle.config import config
import spindle.policy
from spindle.store import init_db


@pytest.fixture(autouse=True)
def isolate_spindle_env(tmp_path, monkeypatch):
    test_home = tmp_path / "spindle_home"
    test_home.mkdir(parents=True, exist_ok=True)

    test_db = test_home / "spindle.db"
    test_policy = test_home / "policies.yaml"
    test_log = test_home / "spindle.log"
    test_incoming = test_home / "incoming.json"
    test_token = test_home / "token.json"
    test_credentials = test_home / "credentials.json"

    # Copy policies/default.yaml
    default_yaml = Path(__file__).resolve().parent.parent / "policies" / "default.yaml"
    if default_yaml.exists():
        shutil.copyfile(default_yaml, test_policy)

    monkeypatch.setattr(config, "home", test_home)
    monkeypatch.setattr(config, "db_path", test_db)
    monkeypatch.setattr(config, "policy_path", test_policy)
    monkeypatch.setattr(config, "log_path", test_log)
    monkeypatch.setattr(config, "incoming_path", test_incoming)
    monkeypatch.setattr(config, "token_path", test_token)
    monkeypatch.setattr(config, "credentials_path", test_credentials)
    monkeypatch.setattr(config, "llm_enabled", False)
    monkeypatch.setattr(config, "approval_timeout", 0)

    spindle.policy._LAST_GOOD_POLICY = None
    init_db(test_db)

    yield test_home

    spindle.policy._LAST_GOOD_POLICY = None
