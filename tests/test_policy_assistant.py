from unittest.mock import MagicMock, patch
import pytest
import anthropic
from spindle.models import (
    AgentPolicy,
    CustomRule,
    PolicyFile,
)
from spindle.policy_assistant import (
    AccessEntry,
    AgentDraft,
    PolicyAssistantError,
    PolicyDraft,
    compute_policy_diff,
    draft_policy_with_claude,
    draft_to_policy_file,
)


def make_sample_policy() -> PolicyFile:
    return PolicyFile(
        agents={
            "work-agent": AgentPolicy(
                description="Work assistant",
                passthrough=False,
                protection_level="standard",
                max_results=15,
                access={"work": "allow", "finance": "ask", "health": "deny"},
                custom_rules=[CustomRule(name="comp", pattern=r"\$\d+")],
            )
        }
    )


def test_loosening_detection_action():
    old_pol = make_sample_policy()

    # Loosening: health changed from deny to allow
    new_pol = make_sample_policy()
    new_pol.agents["work-agent"].access["health"] = "allow"
    changes = compute_policy_diff(old_pol, new_pol)
    assert any(c.field == "access.health" and c.is_loosening is True for c in changes)

    # Tightening: work changed from allow to ask
    new_pol_tight = make_sample_policy()
    new_pol_tight.agents["work-agent"].access["work"] = "ask"
    changes_tight = compute_policy_diff(old_pol, new_pol_tight)
    assert any(c.field == "access.work" and c.is_loosening is False for c in changes_tight)


def test_loosening_detection_protection_level():
    old_pol = make_sample_policy()

    # Loosening: standard -> light
    new_pol_light = make_sample_policy()
    new_pol_light.agents["work-agent"].protection_level = "light"
    changes_light = compute_policy_diff(old_pol, new_pol_light)
    assert any(c.field == "protection_level" and c.is_loosening is True for c in changes_light)

    # Tightening: standard -> strict
    new_pol_strict = make_sample_policy()
    new_pol_strict.agents["work-agent"].protection_level = "strict"
    changes_strict = compute_policy_diff(old_pol, new_pol_strict)
    assert any(c.field == "protection_level" and c.is_loosening is False for c in changes_strict)


def test_loosening_detection_passthrough_and_rules():
    old_pol = make_sample_policy()

    # Loosening: False -> True passthrough
    new_pol_pass = make_sample_policy()
    new_pol_pass.agents["work-agent"].passthrough = True
    changes_pass = compute_policy_diff(old_pol, new_pol_pass)
    assert any(c.field == "passthrough" and c.is_loosening is True for c in changes_pass)

    # Loosening: removed custom rule
    new_pol_no_rules = make_sample_policy()
    new_pol_no_rules.agents["work-agent"].custom_rules = []
    changes_rules = compute_policy_diff(old_pol, new_pol_no_rules)
    assert any(c.field == "custom_rule_removed" and c.is_loosening is True for c in changes_rules)

    # Loosening: max_results increased from 15 to 30
    new_pol_max = make_sample_policy()
    new_pol_max.agents["work-agent"].max_results = 30
    changes_max = compute_policy_diff(old_pol, new_pol_max)
    assert any(c.field == "max_results" and c.is_loosening is True for c in changes_max)


def test_invalid_regex_in_draft_is_rejected():
    invalid_draft = PolicyDraft(
        agents=[
            AgentDraft(
                name="bad-agent",
                description="desc",
                passthrough=False,
                protection_level="standard",
                max_results=10,
                access=[AccessEntry(category="work", action="allow")],
                custom_rules=[CustomRule(name="invalid", pattern="[unclosed-bracket")],
            )
        ],
        summary="Added rule with invalid regex syntax",
    )

    with pytest.raises(ValueError, match="invalid regex"):
        draft_to_policy_file(invalid_draft)


def test_refusal_handled():
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.stop_reason = "refusal"
    mock_client.messages.parse.return_value = mock_response

    current_pol = make_sample_policy()
    with pytest.raises(PolicyAssistantError, match="Claude declined this request"):
        draft_policy_with_claude("bypass all security", current_pol, client=mock_client)


def test_policy_unchanged_on_error():
    mock_client = MagicMock()
    mock_client.messages.parse.side_effect = anthropic.APIConnectionError(request=MagicMock())

    current_pol = make_sample_policy()
    with pytest.raises(PolicyAssistantError, match="Connection error"):
        draft_policy_with_claude("make changes", current_pol, client=mock_client)


def test_b2_policy_assistant_send_allow_and_diff_rules():
    # 1. Draft that copies work-agent preserves send_allow
    draft = PolicyDraft(
        agents=[
            AgentDraft(
                name="work-agent",
                description="Work assistant",
                passthrough=False,
                protection_level="standard",
                max_results=15,
                access=[
                    AccessEntry(category="work", action="allow"),
                    AccessEntry(category="finance", action="ask"),
                    AccessEntry(category="health", action="deny"),
                ],
                custom_rules=[CustomRule(name="comp", pattern=r"\$\d+")],
                send_allow=["@northwind.io"],
            )
        ],
        summary="Preserved work-agent",
    )
    pol = draft_to_policy_file(draft)
    assert pol.agents["work-agent"].send_allow == ["@northwind.io"]

    # 2. Changing the compensation regex -> a loosening change
    old_pol = make_sample_policy()
    old_pol.agents["work-agent"].custom_rules = [CustomRule(name="comp", pattern=r"\$\d+")]
    new_pol_regex = make_sample_policy()
    new_pol_regex.agents["work-agent"].custom_rules = [CustomRule(name="comp", pattern=r"\$\d{2,}")]
    changes = compute_policy_diff(old_pol, new_pol_regex)
    comp_change = next(c for c in changes if c.field == "custom_rules.comp")
    assert comp_change.is_loosening is True
    assert "redaction rule changed; verify it still matches" in comp_change.description

    # 3. Adding "@gmail.com" to send_allow -> a loosening change
    new_pol_send = make_sample_policy()
    new_pol_send.agents["work-agent"].send_allow = ["@gmail.com"]
    changes_send = compute_policy_diff(old_pol, new_pol_send)
    send_change = next(c for c in changes_send if c.field == "send_allow")
    assert send_change.is_loosening is True
    assert send_change.new_val == "@gmail.com"

    # Removing from send_allow -> tightening (not loosening)
    pol_with_send = make_sample_policy()
    pol_with_send.agents["work-agent"].send_allow = ["@northwind.io"]
    pol_no_send = make_sample_policy()
    pol_no_send.agents["work-agent"].send_allow = []
    changes_remove_send = compute_policy_diff(pol_with_send, pol_no_send)
    rem_send_change = next(c for c in changes_remove_send if c.field == "send_allow")
    assert rem_send_change.is_loosening is False

    # 4. Removing strict-agent -> listed with is_loosening=False
    multi_pol = make_sample_policy()
    multi_pol.agents["strict-agent"] = AgentPolicy(
        description="Strict assistant",
        passthrough=False,
        protection_level="strict",
        access={"work": "deny"},
    )
    single_pol = make_sample_policy()
    changes_remove_agent = compute_policy_diff(multi_pol, single_pol)
    removed_agent_change = next(c for c in changes_remove_agent if c.field == "agent_removed")
    assert removed_agent_change.agent == "strict-agent"
    assert removed_agent_change.is_loosening is False


def test_b2_unexplained_change_raises_error():
    old_pol = make_sample_policy()
    new_pol = make_sample_policy()

    # Verify normal description change passes
    new_pol.agents["work-agent"].description = "Changed description"
    d = compute_policy_diff(old_pol, new_pol)
    assert any(c.field == "description" for c in d)

    # Simulate an unexplained change by injecting an unhandled field into model_dump
    original_dump = AgentPolicy.model_dump

    def mock_dump(self, *args, **kwargs):
        res = original_dump(self, *args, **kwargs)
        if self.description == "TRIGGER_UNEXPLAINED":
            res["mystery_field"] = "unexpected_value"
        return res

    unexplained_pol = make_sample_policy()
    unexplained_pol.agents["work-agent"].description = "TRIGGER_UNEXPLAINED"

    with patch.object(AgentPolicy, "model_dump", mock_dump):
        with pytest.raises(PolicyAssistantError, match="Unexplained policy change"):
            compute_policy_diff(old_pol, unexplained_pol)
