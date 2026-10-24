import pytest
from spindle.models import (
    AgentPolicy,
    Classification,
    CustomRule,
    InjectionReport,
    PolicyFile,
)
from spindle.policy import decide, get_agent_policy, load_policy, save_policy, validate_policy_file


def test_decide_precedence():
    policy = AgentPolicy(
        description="Test",
        passthrough=False,
        protection_level="standard",
        access={"finance": "ask", "health": "deny", "travel": "allow"},
    )

    clean_inj = InjectionReport(
        hidden_text=False,
        hidden_text_excerpt="",
        heuristic_hits=[],
        llm_suspected=None,
        llm_confidence=None,
        quarantine=False,
        reason="Clean",
    )
    quarantine_inj = InjectionReport(
        hidden_text=True,
        hidden_text_excerpt="secret",
        heuristic_hits=["secret_request"],
        llm_suspected=None,
        llm_confidence=None,
        quarantine=True,
        reason="Hidden text",
    )

    travel_cls = Classification(category="travel", sensitivity="low", source="rules", reason="United")
    health_cls = Classification(category="health", sensitivity="high", source="rules", reason="Kaiser")
    finance_cls = Classification(category="finance", sensitivity="high", source="rules", reason="Chase")
    missing_cat_cls = Classification(category="other", sensitivity="high", source="rules", reason="Unknown")

    # 1. Passthrough bypasses quarantine and deny
    pass_policy = AgentPolicy(passthrough=True)
    d_pass = decide("unprotected", pass_policy, health_cls, quarantine_inj, None)
    assert d_pass.action == "passthrough"

    # 2. Quarantine takes precedence over allowed travel
    d_quar = decide("work-agent", policy, travel_cls, quarantine_inj, None)
    assert d_quar.action == "quarantine"

    # 3. Deny takes precedence
    d_deny = decide("work-agent", policy, health_cls, clean_inj, None)
    assert d_deny.action == "deny"

    # 4. Ask when unapproved
    d_ask = decide("work-agent", policy, finance_cls, clean_inj, None)
    assert d_ask.action == "ask"

    # 5. Ask when approved -> allow
    d_appr = decide("work-agent", policy, finance_cls, clean_inj, approval_status="approved")
    assert d_appr.action == "allow"

    # 6. Ask when denied -> deny
    d_user_deny = decide("work-agent", policy, finance_cls, clean_inj, approval_status="denied")
    assert d_user_deny.action == "deny"

    # 7. Allow
    d_allow = decide("work-agent", policy, travel_cls, clean_inj, None)
    assert d_allow.action == "allow"

    # 8. Missing category defaults to deny
    d_missing = decide("work-agent", policy, missing_cat_cls, clean_inj, None)
    assert d_missing.action == "deny"


def test_unknown_agent_denies_everything():
    policy_file = load_policy()
    unknown_policy = get_agent_policy(policy_file, "totally-unknown-agent-xyz")
    assert unknown_policy.passthrough is False

    cls = Classification(category="work", sensitivity="medium", source="rules", reason="Work")
    inj = InjectionReport(
        hidden_text=False,
        hidden_text_excerpt="",
        heuristic_hits=[],
        llm_suspected=None,
        llm_confidence=None,
        quarantine=False,
        reason="Clean",
    )
    d = decide("totally-unknown-agent-xyz", unknown_policy, cls, inj, None)
    assert d.action == "deny"


def test_invalid_regex_rejected(tmp_path):
    invalid_policy = PolicyFile(
        agents={
            "bad-agent": AgentPolicy(
                custom_rules=[CustomRule(name="bad", pattern="[unclosed-regex")]
            )
        }
    )
    with pytest.raises(ValueError, match="invalid regex"):
        validate_policy_file(invalid_policy)

    with pytest.raises(ValueError):
        save_policy(invalid_policy, policy_path=tmp_path / "policies.yaml")


def test_atomic_save_and_reload(tmp_path):
    path = tmp_path / "policies.yaml"
    policy_file = PolicyFile(
        agents={
            "custom-agent": AgentPolicy(
                description="Custom test agent",
                protection_level="strict",
                access={"work": "allow"},
                max_results=8,
                custom_rules=[CustomRule(name="code", pattern=r"CODE-\d+")],
            )
        }
    )
    save_policy(policy_file, policy_path=path)
    loaded = load_policy(policy_path=path)
    assert "custom-agent" in loaded.agents
    assert loaded.agents["custom-agent"].max_results == 8
    assert loaded.agents["custom-agent"].custom_rules[0].name == "code"
