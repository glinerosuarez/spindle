import logging
import time
from typing import List, Optional

logger = logging.getLogger("spindle.gateway")

from spindle.classifier import classify
from spindle.config import config
from spindle.injection import (
    extract_hidden_and_visible,
    inspect as inspect_injection,
    visible_text,
)
from spindle.models import Category, Decision, Email, Redaction
from spindle.policy import get_agent_policy, load_policy, decide
from spindle.redact import redact, scan
from spindle.sources import FixtureSource, MailSource
from spindle.store import (
    create_approval_request,
    create_outbox_message,
    find_pending_request,
    get_approval_request,
    get_approval_status,
    get_outbox_sends_last_hour,
    init_db,
    is_recipient_only_in_quarantined,
    log_audit,
    update_outbox_status,
)



def get_mail_source() -> MailSource:
    return FixtureSource()


def search(
    agent: str,
    query: str = "",
    max_results: Optional[int] = None,
    source: Optional[MailSource] = None,
    timeout: Optional[float] = None,
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
        blocks = []
        for email in emails:
            header = f"[{email.id}] {email.date[:10]} | {email.sender} | {email.subject}"
            hidden_part = ""
            if email.body_html:
                hidden, _ = extract_hidden_and_visible(email.body_html)
                if hidden.strip():
                    hidden_part = f"\n[hidden HTML text]: {hidden.strip()}"
            block = f"{header}\n{email.body_text}{hidden_part}"
            blocks.append(block)

            exposed_redactions = scan(block)
            log_audit(
                agent=agent,
                tool="search",
                query=query,
                email_id=email.id,
                category="passthrough",
                action="passthrough",
                reason="Unfiltered passthrough connector",
                redactions=exposed_redactions,
                returned_text=block,
            )
        output_lines = [
            f'Found {len(emails)} emails (unfiltered passthrough access for agent "{agent}").',
            "",
            "\n---\n".join(blocks),
        ]
        return "\n".join(output_lines)

    # 2. Governed mode
    allowed_entries: List[tuple[Email, str, str, str, List[Redaction], bool]] = []
    withheld_by_cat: dict[Category, int] = {}
    quarantined_entries: List[tuple[Email, str]] = []
    ask_emails: List[Email] = []
    ask_categories: List[str] = []

    for email in emails:
        try:
            cls, llm_result = classify(email)
            inj = inspect_injection(email, llm_result)
            approval_status = get_approval_status(agent, email.id)
            decision: Decision = decide(agent, policy, cls, inj, approval_status)
        except Exception:
            logger.exception("processing error for %s", email.id)
            quarantined_entries.append((email, "processing error"))
            agent_text = (
                f"- 1 email from {email.sender} ({email.date[:10]}): "
                f"possible prompt injection (processing error). Content withheld."
            )
            log_audit(
                agent=agent,
                tool="search",
                query=query,
                email_id=email.id,
                category="other",
                action="quarantine",
                reason="processing error",
                redactions=[],
                returned_text=agent_text,
            )
            continue

        if decision.action == "passthrough":
            # Handled above, but safeguard
            allowed_entries.append((email, email.sender, email.subject, email.snippet, [], False))
            log_audit(agent, "search", query, email.id, cls.category, "passthrough", decision.reason, [])

        elif decision.action == "quarantine":
            quarantined_entries.append((email, inj.reason))
            agent_text = (
                f"- 1 email from {email.sender} ({email.date[:10]}): "
                f"possible prompt injection ({inj.reason}). Content withheld."
            )
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
                returned_text=agent_text,
            )

        elif decision.action == "deny":
            withheld_by_cat[cls.category] = withheld_by_cat.get(cls.category, 0) + 1
            agent_text = f"- 1 email: {cls.category} (denied by user policy)"
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
                returned_text=agent_text,
            )

        elif decision.action == "ask":
            ask_emails.append(email)
            ask_categories.append(cls.category)

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
            approved_tag = "   (approved by user)" if is_approved else ""
            agent_text = (
                f"[{email.id}] {email.date[:10]} | {sender_str} | {redacted_subj}{approved_tag}\n"
                f"      {redacted_snip}"
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
                returned_text=agent_text,
            )

    # If there are ask emails, reuse or create approval request in store and wait
    request_id = None
    still_pending = True

    if ask_emails:
        ask_ids = [e.id for e in ask_emails]
        existing_id = find_pending_request(agent, "search", ask_ids)
        if existing_id is not None:
            request_id = existing_id
        else:
            request_id = create_approval_request(
                agent=agent,
                tool="search",
                query=query,
                email_ids=ask_ids,
                categories=ask_categories,
            )

        effective_timeout = timeout if timeout is not None else config.approval_timeout
        if effective_timeout > 0:
            t_end = time.time() + effective_timeout
            while time.time() < t_end:
                req = get_approval_request(request_id)
                if req and req["status"] in ("approved", "denied"):
                    if req["status"] == "approved":
                        still_pending = False
                        for email in ask_emails:
                            try:
                                cls, llm_result = classify(email)
                                inj = inspect_injection(email, llm_result)
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
                                allowed_entries.append(
                                    (email, sender_str, redacted_subj, redacted_snip, total_redactions, True)
                                )
                                agent_text = (
                                    f"[{email.id}] {email.date[:10]} | {sender_str} | {redacted_subj}   (approved by user)\n"
                                    f"      {redacted_snip}"
                                )
                                log_audit(
                                    agent=agent,
                                    tool="search",
                                    query=query,
                                    email_id=email.id,
                                    category=cls.category,
                                    action="allow",
                                    reason=f"Category '{cls.category}' approved by user",
                                    redactions=total_redactions,
                                    injection=inj,
                                    returned_text=agent_text,
                                )
                            except Exception:
                                logger.exception("processing error for %s", email.id)
                                quarantined_entries.append((email, "processing error"))
                                agent_text = (
                                    f"- 1 email from {email.sender} ({email.date[:10]}): "
                                    f"possible prompt injection (processing error). Content withheld."
                                )
                                log_audit(
                                    agent=agent,
                                    tool="search",
                                    query=query,
                                    email_id=email.id,
                                    category="other",
                                    action="quarantine",
                                    reason="processing error",
                                    redactions=[],
                                    returned_text=agent_text,
                                )
                    elif req["status"] == "denied":
                        still_pending = False
                        for email in ask_emails:
                            cls, _ = classify(email)
                            withheld_by_cat[cls.category] = withheld_by_cat.get(cls.category, 0) + 1
                            agent_text = f"- 1 email: {cls.category} (denied by user policy)"
                            log_audit(
                                agent=agent,
                                tool="search",
                                query=query,
                                email_id=email.id,
                                category=cls.category,
                                action="deny",
                                reason=f"Category '{cls.category}' denied by user",
                                redactions=[],
                                returned_text=agent_text,
                            )
                    break
                time.sleep(0.5)

        if still_pending and request_id is not None:
            cats_str = ", ".join(sorted(set(ask_categories)))
            agent_text = (
                f"- request #{request_id}: {len(ask_emails)} {cats_str} email(s). "
                f"Awaiting user approval; call check_approval({request_id}) later."
            )
            for email in ask_emails:
                cls, _ = classify(email)
                log_audit(
                    agent=agent,
                    tool="search",
                    query=query,
                    email_id=email.id,
                    category=cls.category,
                    action="ask",
                    reason=f"Category '{cls.category}' requires user approval (pending request #{request_id})",
                    redactions=[],
                    returned_text=agent_text,
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

    if ask_emails and still_pending and request_id is not None:
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



def read(
    agent: str,
    email_id: str,
    source: Optional[MailSource] = None,
    timeout: Optional[float] = None,
) -> str:
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
        hidden_part = ""
        if email.body_html:
            hidden, _ = extract_hidden_and_visible(email.body_html)
            if hidden.strip():
                hidden_part = f"\n[hidden HTML text]: {hidden.strip()}"
        ret = (
            f"Email [{email.id}]\n"
            f"From: {email.sender}\n"
            f"To: {email.to}\n"
            f"Date: {email.date}\n"
            f"Subject: {email.subject}\n\n"
            f"{email.body_text}{hidden_part}"
        )
        exposed = scan(ret)
        log_audit(
            agent=agent,
            tool="read",
            query=email_id,
            email_id=email.id,
            category="passthrough",
            action="passthrough",
            reason="Unfiltered passthrough connector",
            redactions=exposed,
            returned_text=ret,
        )
        return ret

    # 2. Governed mode
    try:
        cls, llm_result = classify(email)
        inj = inspect_injection(email, llm_result)
        approval_status = get_approval_status(agent, email.id)
        decision = decide(agent, policy, cls, inj, approval_status)
    except Exception:
        logger.exception("processing error for %s", email.id)
        agent_text = f"[QUARANTINED] Email from {email.sender} ({email.date[:10]}) was quarantined: processing error. Content withheld."
        log_audit(
            agent=agent,
            tool="read",
            query=email_id,
            email_id=email.id,
            category="other",
            action="quarantine",
            reason="processing error",
            redactions=[],
            returned_text=agent_text,
        )
        return agent_text

    if decision.action == "quarantine":
        agent_text = (
            f"[QUARANTINED] Email from {email.sender} ({email.date[:10]}) was quarantined: "
            f"{inj.reason}. Content withheld."
        )
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
            returned_text=agent_text,
        )
        return agent_text

    if decision.action == "deny":
        agent_text = f"[WITHHELD] Email '{email_id}' access denied by user policy for category '{cls.category}'."
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
            returned_text=agent_text,
        )
        return agent_text

    if decision.action == "ask":
        existing_id = find_pending_request(agent, "read", [email.id])
        if existing_id is not None:
            req_id = existing_id
        else:
            req_id = create_approval_request(
                agent=agent,
                tool="read",
                query=email_id,
                email_ids=[email.id],
                categories=[cls.category],
            )

        effective_timeout = timeout if timeout is not None else config.approval_timeout
        if effective_timeout > 0:
            t_end = time.time() + effective_timeout
            while time.time() < t_end:
                req = get_approval_request(req_id)
                if req and req["status"] in ("approved", "denied"):
                    if req["status"] == "approved":
                        # Approved! Proceed to allowed read
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
                        ret = (
                            f"Email [{email.id}]\n"
                            f"From: {sender_str}\n"
                            f"To: {email.to}\n"
                            f"Date: {email.date}\n"
                            f"Subject: {redacted_subj}\n\n"
                            f"{redacted_body}"
                        )
                        log_audit(
                            agent=agent,
                            tool="read",
                            query=email_id,
                            email_id=email.id,
                            category=cls.category,
                            action="allow",
                            reason=f"Category '{cls.category}' approved by user",
                            redactions=all_redactions,
                            injection=inj,
                            returned_text=ret,
                        )
                        return ret
                    elif req["status"] == "denied":
                        agent_text = f"[WITHHELD] Email '{email_id}' access denied by user."
                        log_audit(
                            agent=agent,
                            tool="read",
                            query=email_id,
                            email_id=email.id,
                            category=cls.category,
                            action="deny",
                            reason=f"Category '{cls.category}' denied by user",
                            redactions=[],
                            injection=inj,
                            returned_text=agent_text,
                        )
                        return agent_text
                    break
                time.sleep(0.5)

        agent_text = (
            f"[PENDING APPROVAL] Email '{email_id}' ({cls.category}) requires user approval "
            f"(request #{req_id}). Call check_approval({req_id}) later."
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
            returned_text=agent_text,
        )
        return agent_text

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
    ret = (
        f"Email [{email.id}]\n"
        f"From: {sender_str}\n"
        f"To: {email.to}\n"
        f"Date: {email.date}\n"
        f"Subject: {redacted_subj}\n\n"
        f"{redacted_body}"
    )
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
        returned_text=ret,
    )

    return ret


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


def send_email(
    agent: str,
    to: List[str],
    subject: str,
    body: str,
    timeout: Optional[float] = None,
) -> str:
    """Sends an email subject to Spindle outbound governance policies."""
    init_db()
    policy_file = load_policy()
    policy = get_agent_policy(policy_file, agent)

    if not to:
        return "Error: At least one recipient is required."

    # 1. Passthrough mode
    if policy.passthrough:
        outbox_id = create_outbox_message(
            agent=agent,
            to_addrs=to,
            subject=subject,
            body=body,
            status="sent",
            reason="Unfiltered passthrough connector",
        )
        return (
            f"Email successfully queued for delivery to {', '.join(to)} "
            f"(unfiltered passthrough connector, outbox #{outbox_id})."
        )

    # 2. Check 3: Secret Exfiltration Scan
    scanned_redactions = scan(f"{subject}\n{body}")
    forbidden_secret_types = {"otp", "auth_link", "card", "ssn", "bank_account", "routing_number"}
    found_secrets = [r.type for r in scanned_redactions if r.type in forbidden_secret_types]
    if found_secrets:
        reason = f"Outbound exfiltration prevented: sensitive secrets detected ({', '.join(sorted(set(found_secrets)))})"
        outbox_id = create_outbox_message(
            agent=agent,
            to_addrs=to,
            subject=subject,
            body=body,
            status="blocked",
            reason=reason,
        )
        return (
            f"[BLOCKED BY SPINDLE] Outbound email to {', '.join(to)} was blocked: "
            f"sensitive secrets detected in content ({', '.join(sorted(set(found_secrets)))}). "
            f"Exfiltration prevented (outbox #{outbox_id})."
        )

    # 3. Check 4: Rate limit (5 sends per agent per rolling hour)
    recent_sends = get_outbox_sends_last_hour(agent)
    if recent_sends >= 5:
        reason = f"Rate limit exceeded ({recent_sends}/5 sends in past hour)"
        outbox_id = create_outbox_message(
            agent=agent,
            to_addrs=to,
            subject=subject,
            body=body,
            status="blocked",
            reason=reason,
        )
        return (
            f"[BLOCKED BY SPINDLE] Rate limit exceeded for agent '{agent}' "
            f"({recent_sends}/5 sends used in past hour). Outbox #{outbox_id} blocked."
        )

    # 4. Check 2: Quarantine recipient block
    for recip in to:
        if is_recipient_only_in_quarantined(recip):
            reason = f"Recipient '{recip}' appears only in quarantined emails"
            outbox_id = create_outbox_message(
                agent=agent,
                to_addrs=to,
                subject=subject,
                body=body,
                status="blocked",
                reason=reason,
            )
            return (
                f"[BLOCKED BY SPINDLE] Outbound email to {', '.join(to)} was blocked: "
                f"recipient '{recip}' is associated only with suspicious quarantined emails. "
                f"No approval permitted (outbox #{outbox_id})."
            )

    # 5. Check 1: Recipient Allowlist
    all_allowed = True
    for recip in to:
        recip_lower = recip.lower().strip()
        if "<" in recip_lower and ">" in recip_lower:
            recip_lower = recip_lower.split("<")[1].split(">")[0].strip()

        matched = False
        for allowed in policy.send_allow:
            allow_entry = allowed.lower().strip()
            if allow_entry.startswith("@"):
                domain_part = recip_lower[recip_lower.rfind("@") :] if "@" in recip_lower else ""
                if domain_part == allow_entry:
                    matched = True
                    break
            elif recip_lower == allow_entry:
                matched = True
                break
        if not matched:
            all_allowed = False
            break

    if all_allowed:
        outbox_id = create_outbox_message(
            agent=agent,
            to_addrs=to,
            subject=subject,
            body=body,
            status="sent",
            reason="Recipients matched policy allowlist",
        )
        return f"Email successfully queued for delivery to {', '.join(to)} (outbox #{outbox_id})."

    # Needs user approval
    outbox_id = create_outbox_message(
        agent=agent,
        to_addrs=to,
        subject=subject,
        body=body,
        status="pending",
        reason="Recipients not on allowlist: awaiting user approval",
    )
    req_id = create_approval_request(
        agent=agent,
        tool="send_email",
        query=f"to: {', '.join(to)} | {subject}",
        email_ids=[str(outbox_id)],
        categories=["outbox"],
    )

    effective_timeout = timeout if timeout is not None else config.approval_timeout
    if effective_timeout > 0:
        t_end = time.time() + effective_timeout
        while time.time() < t_end:
            req = get_approval_request(req_id)
            if req and req["status"] in ("approved", "denied"):
                if req["status"] == "approved":
                    update_outbox_status(outbox_id, "sent", "Approved by user")
                    return (
                        f"Email successfully queued for delivery to {', '.join(to)} "
                        f"(approved by user, outbox #{outbox_id})."
                    )
                elif req["status"] == "denied":
                    update_outbox_status(outbox_id, "denied", "Denied by user")
                    return (
                        f"[DENIED BY USER] Outbound email to {', '.join(to)} was denied "
                        f"by user (outbox #{outbox_id})."
                    )
                break
            time.sleep(0.5)

    return (
        f"[PENDING APPROVAL] Outbound email to {', '.join(to)} requires user approval "
        f"(request #{req_id}). Call check_approval({req_id}) later."
    )
