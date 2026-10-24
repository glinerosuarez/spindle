from __future__ import annotations

from typing import List, Optional

from spindle.classifier import classify
from spindle.injection import inspect as inspect_injection, visible_text
from spindle.models import Category, Decision, Email, Redaction
from spindle.policy import get_agent_policy, load_policy, decide
from spindle.redact import redact, scan
from spindle.sources import FixtureSource, MailSource
from spindle.store import (
    create_approval_request,
    get_approval_request,
    get_approval_status,
    init_db,
    log_audit,
)


def get_mail_source() -> MailSource:
    return FixtureSource()


def search(
    agent: str,
    query: str = "",
    max_results: Optional[int] = None,
    source: Optional[MailSource] = None,
) -> str:
    """Executes an email search governed by Spindle privacy policies."""
    init_db()
    policy_file = load_policy()
    policy = get_agent_policy(policy_file, agent)

    if source is None:
        source = get_mail_source()

    limit = policy.max_results
    if max_results is not None:
        limit = min(max_results, policy.max_results)

    emails = source.search(query, limit=limit)

    # 1. Passthrough mode
    if policy.passthrough:
        output_lines = [
            f'Found {len(emails)} emails (unfiltered passthrough access for agent "{agent}").',
            "",
        ]
        for email in emails:
            output_lines.append(
                f"[{email.id}] {email.date[:10]} | {email.sender} | {email.subject}"
            )
            output_lines.append(f"      {email.snippet}")
            # Audit log
            exposed_redactions = scan(f"{email.subject}\n{email.body_text}")
            log_audit(
                agent=agent,
                tool="search",
                query=query,
                email_id=email.id,
                category="passthrough",
                action="passthrough",
                reason="Unfiltered passthrough connector",
                redactions=exposed_redactions,
            )
        return "\n".join(output_lines)

    # 2. Governed mode
    allowed_entries: List[tuple[Email, str, str, str, List[Redaction], bool]] = []
    withheld_by_cat: dict[Category, int] = {}
    quarantined_entries: List[tuple[Email, str]] = []
    ask_emails: List[Email] = []
    ask_categories: List[str] = []

    for email in emails:
        cls, llm_result = classify(email)
        inj = inspect_injection(email, llm_result)
        approval_status = get_approval_status(agent, email.id)
        decision: Decision = decide(agent, policy, cls, inj, approval_status)

        if decision.action == "passthrough":
            # Handled above, but safeguard
            allowed_entries.append((email, email.sender, email.subject, email.snippet, [], False))
            log_audit(agent, "search", query, email.id, cls.category, "passthrough", decision.reason, [])

        elif decision.action == "quarantine":
            quarantined_entries.append((email, inj.reason))
            log_audit(
                agent=agent,
                tool="search",
                query=query,
                email_id=email.id,
                category=cls.category,
                action="quarantine",
                reason=decision.reason,
                redactions=[],
                injection=inj,
            )

        elif decision.action == "deny":
            withheld_by_cat[cls.category] = withheld_by_cat.get(cls.category, 0) + 1
            log_audit(
                agent=agent,
                tool="search",
                query=query,
                email_id=email.id,
                category=cls.category,
                action="deny",
                reason=decision.reason,
                redactions=[],
                injection=inj,
            )

        elif decision.action == "ask":
            ask_emails.append(email)
            ask_categories.append(cls.category)
            log_audit(
                agent=agent,
                tool="search",
                query=query,
                email_id=email.id,
                category=cls.category,
                action="ask",
                reason=decision.reason,
                redactions=[],
                injection=inj,
            )

        elif decision.action == "allow":
            # Apply redactions to snippet and subject
            redacted_subj, r_subj = redact(
                email.subject,
                level=policy.protection_level,
                custom_rules=policy.custom_rules,
            )
            redacted_snip, r_snip = redact(
                email.snippet,
                level=policy.protection_level,
                custom_rules=policy.custom_rules,
            )
            sender_str = email.sender
            r_sender = []
            if policy.protection_level == "strict":
                sender_str, r_sender = redact(email.sender, level="strict")

            total_redactions = r_subj + r_snip + r_sender
            is_approved = approval_status == "approved"
            allowed_entries.append(
                (email, sender_str, redacted_subj, redacted_snip, total_redactions, is_approved)
            )
            log_audit(
                agent=agent,
                tool="search",
                query=query,
                email_id=email.id,
                category=cls.category,
                action="allow",
                reason=decision.reason,
                redactions=total_redactions,
                injection=inj,
            )

    # If there are ask emails, create approval request in store
    request_id = None
    if ask_emails:
        request_id = create_approval_request(
            agent=agent,
            tool="search",
            query=query,
            email_ids=[e.id for e in ask_emails],
            categories=ask_categories,
        )

    # Build output string
    lines: List[str] = [
        f'Found {len(allowed_entries)} emails (filtered by the user\'s Spindle privacy policy for agent "{agent}").',
        "",
    ]

    for email, sender_str, subj, snip, _, is_approved in allowed_entries:
        approved_tag = "   (approved by user)" if is_approved else ""
        lines.append(f"[{email.id}] {email.date[:10]} | {sender_str} | {subj}{approved_tag}")
        lines.append(f"      {snip}")

    if withheld_by_cat:
        lines.append("")
        lines.append("Withheld by policy:")
        for cat, cnt in withheld_by_cat.items():
            lines.append(f"- {cnt} email{'s' if cnt > 1 else ''}: {cat} (denied by user policy)")

    if quarantined_entries:
        lines.append("")
        lines.append("Quarantined:")
        for q_email, q_reason in quarantined_entries:
            lines.append(
                f"- 1 email from {q_email.sender} ({q_email.date[:10]}): possible prompt injection ({q_reason}). Content withheld."
            )

    if ask_emails and request_id is not None:
        lines.append("")
        lines.append("Pending approval:")
        cats_str = ", ".join(sorted(set(ask_categories)))
        lines.append(
            f"- request #{request_id}: {len(ask_emails)} {cats_str} email(s). Awaiting user approval; call check_approval({request_id}) later."
        )

    lines.append("")
    lines.append(
        "Do not try to obtain withheld emails another way. If the user needs them, tell them to change their Spindle policy."
    )

    return "\n".join(lines)


def read(agent: str, email_id: str, source: Optional[MailSource] = None) -> str:
    """Reads a single email governed by Spindle privacy policies."""
    init_db()
    policy_file = load_policy()
    policy = get_agent_policy(policy_file, agent)

    if source is None:
        source = get_mail_source()

    email = source.get(email_id)
    if email is None:
        return f"Email '{email_id}' not found."

    # 1. Passthrough mode
    if policy.passthrough:
        exposed = scan(f"{email.subject}\n{email.body_text}")
        log_audit(
            agent=agent,
            tool="read",
            query=email_id,
            email_id=email.id,
            category="passthrough",
            action="passthrough",
            reason="Unfiltered passthrough connector",
            redactions=exposed,
        )
        return (
            f"Email [{email.id}]\n"
            f"From: {email.sender}\n"
            f"To: {email.to}\n"
            f"Date: {email.date}\n"
            f"Subject: {email.subject}\n\n"
            f"{email.body_text}"
        )

    # 2. Governed mode
    cls, llm_result = classify(email)
    inj = inspect_injection(email, llm_result)
    approval_status = get_approval_status(agent, email.id)
    decision = decide(agent, policy, cls, inj, approval_status)

    if decision.action == "quarantine":
        log_audit(
            agent=agent,
            tool="read",
            query=email_id,
            email_id=email.id,
            category=cls.category,
            action="quarantine",
            reason=decision.reason,
            redactions=[],
            injection=inj,
        )
        return (
            f"[QUARANTINED] Email from {email.sender} ({email.date[:10]}) was quarantined: "
            f"{inj.reason}. Content withheld."
        )

    if decision.action == "deny":
        log_audit(
            agent=agent,
            tool="read",
            query=email_id,
            email_id=email.id,
            category=cls.category,
            action="deny",
            reason=decision.reason,
            redactions=[],
            injection=inj,
        )
        return (
            f"[WITHHELD] Email '{email_id}' access denied by user policy for category '{cls.category}'."
        )

    if decision.action == "ask":
        req_id = create_approval_request(
            agent=agent,
            tool="read",
            query=email_id,
            email_ids=[email.id],
            categories=[cls.category],
        )
        log_audit(
            agent=agent,
            tool="read",
            query=email_id,
            email_id=email.id,
            category=cls.category,
            action="ask",
            reason=decision.reason,
            redactions=[],
            injection=inj,
        )
        return (
            f"[PENDING APPROVAL] Email '{email_id}' ({cls.category}) requires user approval "
            f"(request #{req_id}). Call check_approval({req_id}) later."
        )

    # Allowed: strip hidden text and redact
    body = visible_text(email)
    redacted_subj, r_subj = redact(
        email.subject,
        level=policy.protection_level,
        custom_rules=policy.custom_rules,
    )
    redacted_body, r_body = redact(
        body,
        level=policy.protection_level,
        custom_rules=policy.custom_rules,
    )
    sender_str = email.sender
    r_sender = []
    if policy.protection_level == "strict":
        sender_str, r_sender = redact(email.sender, level="strict")

    all_redactions = r_subj + r_body + r_sender
    log_audit(
        agent=agent,
        tool="read",
        query=email_id,
        email_id=email.id,
        category=cls.category,
        action="allow",
        reason=decision.reason,
        redactions=all_redactions,
        injection=inj,
    )

    return (
        f"Email [{email.id}]\n"
        f"From: {sender_str}\n"
        f"To: {email.to}\n"
        f"Date: {email.date}\n"
        f"Subject: {redacted_subj}\n\n"
        f"{redacted_body}"
    )


def check_approval(agent: str, request_id: int) -> str:
    """Checks the status of an approval request."""
    init_db()
    req = get_approval_request(request_id)
    if not req:
        return f"Request #{request_id} not found."

    status = req["status"]
    if status == "pending":
        return f"Request #{request_id} is still pending user decision."
    elif status == "approved":
        return f"Request #{request_id} was approved by the user. You may now access the requested email(s)."
    elif status == "denied":
        return f"Request #{request_id} was denied by the user."
    return f"Request #{request_id} status: {status}."


def permissions(agent: str) -> str:
    """Returns plain-English summary of an agent's permissions."""
    policy_file = load_policy()
    policy = get_agent_policy(policy_file, agent)

    categories = ["travel", "finance", "auth", "health", "work", "personal", "promo", "other"]
    lines = [
        f"Spindle Privacy Policy for agent '{agent}':",
        f"- Description: {policy.description or 'None'}",
        f"- Passthrough: {'Yes' if policy.passthrough else 'No'}",
        f"- Protection Level: {policy.protection_level}",
        f"- Max Results: {policy.max_results}",
        "- Category Access:",
    ]
    for cat in categories:
        access_val = policy.access.get(cat, "deny")  # type: ignore[arg-type]
        lines.append(f"  * {cat}: {access_val}")

    if policy.custom_rules:
        rule_names = ", ".join(r.name for r in policy.custom_rules)
        lines.append(f"- Custom Rules: {len(policy.custom_rules)} active ({rule_names})")
    else:
        lines.append("- Custom Rules: none")

    return "\n".join(lines)
