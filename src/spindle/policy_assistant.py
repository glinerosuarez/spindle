from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Literal, Optional, Tuple
import yaml
from pydantic import BaseModel, Field

import anthropic
from spindle.config import config
from spindle.models import (
    Action,
    AgentPolicy,
    Category,
    CustomRule,
    Level,
    PolicyFile,
)
from spindle.policy import validate_policy_file

ACTION_RANKS = {"deny": 0, "ask": 1, "allow": 2}
LEVEL_RANKS = {"light": 0, "standard": 1, "strict": 2}


class PolicyAssistantError(Exception):
    pass


class AccessEntry(BaseModel):
    category: Literal["travel", "finance", "auth", "health", "work", "personal", "promo", "other"]
    action: Literal["allow", "ask", "deny"]


class AgentDraft(BaseModel):
    name: str
    description: str = ""
    passthrough: bool = False
    protection_level: Literal["light", "standard", "strict"] = "standard"
    max_results: int = 15
    access: List[AccessEntry] = []
    custom_rules: List[CustomRule] = []
    send_allow: List[str] = Field(default_factory=list)


class PolicyDraft(BaseModel):
    agents: List[AgentDraft]
    summary: str  # Plain English explanation of what changed and why


class Change(BaseModel):
    agent: str
    field: str
    old_val: Any
    new_val: Any
    is_loosening: bool
    description: str


SYSTEM_PROMPT = """You are Spindle's policy assistant. Your job is to draft updates to the user's email privacy policies for AI agents based on plain English instructions.

Categories:
- travel: flights, hotel bookings, itineraries
- finance: bank statements, accounts, balances, invoices
- auth: OTP verification codes, password reset links
- health: doctor visits, lab results, prescriptions
- work: company emails, team standups, Jira, GitHub PRs
- personal: friends, family, social dinners, weekend plans
- promo: newsletters, marketing offers, discounts
- other: unclassified emails

Actions:
- allow: agent can read (with redactions applied)
- ask: agent requests access, user must approve in dashboard
- deny: access is withheld from the agent entirely (missing categories default to deny)

Protection Levels:
- light: redacts auth_links, OTP codes, API keys/passwords, credit cards, SSNs
- standard: adds routing numbers, bank accounts, medical records, insurance IDs, medication names, DOB, street address, phone
- strict: adds email addresses, URLs, zip codes

Send Allowlist:
- send_allow: list of addresses or @domains the agent may send to without approval (e.g. ['@northwind.io'])

Rules:
1. Modify ONLY what the user explicitly requested. Preserve all other agents, rules, and access configurations.
2. If the user asks for restrictions, tighten the access (e.g. from allow -> ask or deny).
3. Always provide a clear, concise plain English summary explaining the changes made.
"""


def compute_policy_diff(old_policy: PolicyFile, new_policy: PolicyFile) -> List[Change]:
    changes: List[Change] = []

    # Check for removed agents
    for agent_name, old_agent in old_policy.agents.items():
        if agent_name not in new_policy.agents:
            changes.append(
                Change(
                    agent=agent_name,
                    field="agent_removed",
                    old_val=agent_name,
                    new_val=None,
                    is_loosening=False,
                    description=f"Agent '{agent_name}' was removed",
                )
            )

    # Check agents in new_policy
    for agent_name, new_agent in new_policy.agents.items():
        if agent_name not in old_policy.agents:
            # New agent added
            has_allow = any(act == "allow" for act in new_agent.access.values())
            changes.append(
                Change(
                    agent=agent_name,
                    field="agent_added",
                    old_val=None,
                    new_val=agent_name,
                    is_loosening=has_allow,
                    description=f"Added new agent '{agent_name}'" + (" with allow permissions" if has_allow else ""),
                )
            )
            continue

        old_agent = old_policy.agents[agent_name]

        # 0. Description check
        if old_agent.description != new_agent.description:
            changes.append(
                Change(
                    agent=agent_name,
                    field="description",
                    old_val=old_agent.description,
                    new_val=new_agent.description,
                    is_loosening=False,
                    description=f"Agent '{agent_name}' description updated",
                )
            )

        # 1. Passthrough check
        if not old_agent.passthrough and new_agent.passthrough:
            changes.append(
                Change(
                    agent=agent_name,
                    field="passthrough",
                    old_val=False,
                    new_val=True,
                    is_loosening=True,
                    description=f"Agent '{agent_name}' passthrough changed from False to True (UNPROTECTED)",
                )
            )
        elif old_agent.passthrough and not new_agent.passthrough:
            changes.append(
                Change(
                    agent=agent_name,
                    field="passthrough",
                    old_val=True,
                    new_val=False,
                    is_loosening=False,
                    description=f"Agent '{agent_name}' protected mode enabled",
                )
            )

        # 2. Protection level check (strict > standard > light)
        old_lvl_rank = LEVEL_RANKS.get(old_agent.protection_level, 1)
        new_lvl_rank = LEVEL_RANKS.get(new_agent.protection_level, 1)
        if new_lvl_rank < old_lvl_rank:
            changes.append(
                Change(
                    agent=agent_name,
                    field="protection_level",
                    old_val=old_agent.protection_level,
                    new_val=new_agent.protection_level,
                    is_loosening=True,
                    description=f"Protection level lowered from {old_agent.protection_level} to {new_agent.protection_level}",
                )
            )
        elif new_lvl_rank > old_lvl_rank:
            changes.append(
                Change(
                    agent=agent_name,
                    field="protection_level",
                    old_val=old_agent.protection_level,
                    new_val=new_agent.protection_level,
                    is_loosening=False,
                    description=f"Protection level tightened from {old_agent.protection_level} to {new_agent.protection_level}",
                )
            )

        # 3. Max results check
        if new_agent.max_results > old_agent.max_results:
            changes.append(
                Change(
                    agent=agent_name,
                    field="max_results",
                    old_val=old_agent.max_results,
                    new_val=new_agent.max_results,
                    is_loosening=True,
                    description=f"Max results increased from {old_agent.max_results} to {new_agent.max_results}",
                )
            )
        elif new_agent.max_results < old_agent.max_results:
            changes.append(
                Change(
                    agent=agent_name,
                    field="max_results",
                    old_val=old_agent.max_results,
                    new_val=new_agent.max_results,
                    is_loosening=False,
                    description=f"Max results decreased from {old_agent.max_results} to {new_agent.max_results}",
                )
            )

        # 4. Category access checks (deny < ask < allow)
        all_cats = set(old_agent.access.keys()) | set(new_agent.access.keys())
        for cat in sorted(all_cats):
            old_act = old_agent.access.get(cat, "deny")
            new_act = new_agent.access.get(cat, "deny")
            if old_act != new_act:
                old_rank = ACTION_RANKS.get(old_act, 0)
                new_rank = ACTION_RANKS.get(new_act, 0)
                is_loosening = new_rank > old_rank
                changes.append(
                    Change(
                        agent=agent_name,
                        field=f"access.{cat}",
                        old_val=old_act,
                        new_val=new_act,
                        is_loosening=is_loosening,
                        description=f"Category '{cat}' access changed from {old_act} to {new_act}"
                        + (" (loosens privacy)" if is_loosening else " (tightens privacy)"),
                    )
                )

        # 5. Custom rules checks
        old_rules_by_name = {r.name: r.pattern for r in old_agent.custom_rules}
        new_rules_by_name = {r.name: r.pattern for r in new_agent.custom_rules}

        # Removed rules
        for r_name in sorted(set(old_rules_by_name) - set(new_rules_by_name)):
            changes.append(
                Change(
                    agent=agent_name,
                    field="custom_rule_removed",
                    old_val=r_name,
                    new_val=None,
                    is_loosening=True,
                    description=f"Custom redaction rule '{r_name}' was removed",
                )
            )

        # Added rules
        for r_name in sorted(set(new_rules_by_name) - set(old_rules_by_name)):
            changes.append(
                Change(
                    agent=agent_name,
                    field="custom_rule_added",
                    old_val=None,
                    new_val=r_name,
                    is_loosening=False,
                    description=f"Custom redaction rule '{r_name}' was added",
                )
            )

        # Pattern changed (same name, different pattern)
        for r_name in sorted(set(old_rules_by_name) & set(new_rules_by_name)):
            if old_rules_by_name[r_name] != new_rules_by_name[r_name]:
                changes.append(
                    Change(
                        agent=agent_name,
                        field=f"custom_rules.{r_name}",
                        old_val=old_rules_by_name[r_name],
                        new_val=new_rules_by_name[r_name],
                        is_loosening=True,
                        description="redaction rule changed; verify it still matches",
                    )
                )

        # 6. send_allow checks
        old_send = set(old_agent.send_allow)
        new_send = set(new_agent.send_allow)

        for entry in sorted(new_send - old_send):
            changes.append(
                Change(
                    agent=agent_name,
                    field="send_allow",
                    old_val=None,
                    new_val=entry,
                    is_loosening=True,
                    description=f"Allowed sending to '{entry}' without approval",
                )
            )

        for entry in sorted(old_send - new_send):
            changes.append(
                Change(
                    agent=agent_name,
                    field="send_allow",
                    old_val=entry,
                    new_val=None,
                    is_loosening=False,
                    description=f"Removed sending allowlist entry '{entry}'",
                )
            )

    # Safety check: if any agent present in both versions has a field that changed but isn't in the diff
    for agent_name, old_agent in old_policy.agents.items():
        if agent_name in new_policy.agents:
            new_agent = new_policy.agents[agent_name]
            old_dump = old_agent.model_dump()
            new_dump = new_agent.model_dump()

            # Normalize order-independent collections
            if "custom_rules" in old_dump:
                old_dump["custom_rules"] = {r["name"]: r["pattern"] for r in old_dump["custom_rules"]}
            if "custom_rules" in new_dump:
                new_dump["custom_rules"] = {r["name"]: r["pattern"] for r in new_dump["custom_rules"]}
            if "send_allow" in old_dump:
                old_dump["send_allow"] = sorted(old_dump["send_allow"])
            if "send_allow" in new_dump:
                new_dump["send_allow"] = sorted(new_dump["send_allow"])

            for k in set(old_dump.keys()) | set(new_dump.keys()):
                if old_dump.get(k) != new_dump.get(k):
                    covered = False
                    for c in changes:
                        if c.agent == agent_name:
                            if (
                                c.field == k
                                or c.field.startswith(f"{k}.")
                                or c.field.startswith(f"{k}_")
                                or (k == "custom_rules" and c.field.startswith("custom_rule"))
                            ):
                                covered = True
                                break
                    if not covered:
                        raise PolicyAssistantError("Unexplained policy change")

    return changes


def draft_to_policy_file(draft: PolicyDraft) -> PolicyFile:
    agents_map: Dict[str, AgentPolicy] = {}
    for agent_draft in draft.agents:
        access_map = {entry.category: entry.action for entry in agent_draft.access}
        agent_pol = AgentPolicy(
            description=agent_draft.description,
            passthrough=agent_draft.passthrough,
            protection_level=agent_draft.protection_level,
            max_results=agent_draft.max_results,
            access=access_map,
            custom_rules=agent_draft.custom_rules,
            send_allow=agent_draft.send_allow,
        )
        agents_map[agent_draft.name] = agent_pol

    policy_file = PolicyFile(agents=agents_map)
    validate_policy_file(policy_file)
    return policy_file


def draft_policy_with_claude(
    instruction: str,
    current_policy: PolicyFile,
    client: Optional[anthropic.Anthropic] = None,
) -> Tuple[PolicyFile, PolicyDraft, List[Change]]:
    yaml_text = yaml.dump(current_policy.model_dump(), sort_keys=False)

    try:
        cli = client or anthropic.Anthropic(api_key=config.anthropic_api_key or "none")
        model = os.environ.get("SPINDLE_CLAUDE_MODEL", config.claude_model)

        response = cli.messages.parse(
            model=model,
            max_tokens=16000,
            system=SYSTEM_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": f"<current_policy>\n{yaml_text}\n</current_policy>\n<request>\n{instruction}\n</request>",
                }
            ],
            output_format=PolicyDraft,
        )

        if getattr(response, "stop_reason", None) == "refusal":
            raise PolicyAssistantError("Claude declined this request")

        draft: PolicyDraft = response.parsed_output
        new_policy = draft_to_policy_file(draft)
        changes = compute_policy_diff(current_policy, new_policy)
        return new_policy, draft, changes

    except anthropic.APIConnectionError as e:
        raise PolicyAssistantError(f"Connection error reaching Claude: {e}") from e
    except anthropic.RateLimitError as e:
        raise PolicyAssistantError(f"Claude API rate limit reached: {e}") from e
    except anthropic.APIStatusError as e:
        raise PolicyAssistantError(f"Claude API returned status {e.status_code}: {e.message}") from e
    except Exception as e:
        if isinstance(e, PolicyAssistantError):
            raise e
        raise PolicyAssistantError(f"Failed to draft policy: {e}") from e
