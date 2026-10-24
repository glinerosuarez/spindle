from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Optional
import yaml

from spindle.config import config
from spindle.models import (
    Action,
    AgentPolicy,
    Classification,
    Decision,
    InjectionReport,
    PolicyFile,
)

_LAST_GOOD_POLICY: Optional[PolicyFile] = None


def validate_policy_file(policy_file: PolicyFile) -> None:
    """Validates that all custom rules have valid regex patterns."""
    for agent_name, agent_policy in policy_file.agents.items():
        for rule in agent_policy.custom_rules:
            try:
                re.compile(rule.pattern)
            except re.error as e:
                raise ValueError(
                    f"Agent '{agent_name}' has invalid regex pattern '{rule.pattern}': {e}"
                ) from e


def load_policy(policy_path: Optional[Path] = None) -> PolicyFile:
    global _LAST_GOOD_POLICY
    path = policy_path or config.policy_path

    if not path.exists():
        # If default policy template exists, copy or load it
        default_template = Path(__file__).resolve().parent.parent.parent / "policies" / "default.yaml"
        if default_template.exists():
            path = default_template

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw_data = yaml.safe_load(f)

        policy_file = PolicyFile.model_validate(raw_data)
        validate_policy_file(policy_file)
        _LAST_GOOD_POLICY = policy_file
        return policy_file
    except Exception as e:
        if _LAST_GOOD_POLICY is not None:
            return _LAST_GOOD_POLICY
        raise e


def save_policy(policy_file: PolicyFile, policy_path: Optional[Path] = None) -> None:
    global _LAST_GOOD_POLICY
    path = policy_path or config.policy_path

    # Validate before saving
    validate_policy_file(policy_file)

    data = policy_file.model_dump()
    yaml_str = yaml.dump(data, sort_keys=False)

    # Atomic write via temp file in the same directory
    parent_dir = path.parent
    parent_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile("w", dir=parent_dir, delete=False, encoding="utf-8") as tf:
        tf.write(yaml_str)
        temp_path = Path(tf.name)

    temp_path.replace(path)
    _LAST_GOOD_POLICY = policy_file


def get_agent_policy(policy_file: PolicyFile, agent: str) -> AgentPolicy:
    if agent in policy_file.agents:
        return policy_file.agents[agent]
    # Unknown agent -> implicit policy that denies everything
    return AgentPolicy(
        description=f"Implicit policy for unknown agent '{agent}' (deny all)",
        passthrough=False,
        protection_level="strict",
        access={},
        max_results=5,
        custom_rules=[],
    )


def decide(
    agent: str,
    policy: AgentPolicy,
    cls: Classification,
    inj: InjectionReport,
    approval_status: Optional[str] = None,
) -> Decision:
    """Evaluates policy decision in order: passthrough > quarantine > deny > ask > allow."""
    # 1. Passthrough mode
    if policy.passthrough:
        return Decision(action="passthrough", reason="Agent is configured in passthrough mode")

    # 2. Quarantine prompt injection
    if inj.quarantine:
        return Decision(action="quarantine", reason=f"Quarantined: {inj.reason}")

    # 3. Category access lookup (missing category defaults to deny)
    action: Action = policy.access.get(cls.category, "deny")

    # 4. Deny
    if action == "deny":
        return Decision(
            action="deny",
            reason=f"Access to '{cls.category}' emails is denied by policy for agent '{agent}'",
        )

    # 5. Ask
    if action == "ask":
        if approval_status == "approved":
            return Decision(
                action="allow",
                reason=f"Category '{cls.category}' approved by user",
            )
        elif approval_status == "denied":
            return Decision(
                action="deny",
                reason=f"Category '{cls.category}' denied by user",
            )
        else:
            return Decision(
                action="ask",
                reason=f"Category '{cls.category}' requires user approval",
            )

    # 6. Allow
    return Decision(
        action="allow",
        reason=f"Category '{cls.category}' is allowed by policy",
    )
