import pytest
import sqlite3
from pathlib import Path
from spindle.config import config
from spindle.gateway import send_email
from spindle.store import (
    decide_approval_request,
    get_connection,
    get_outbox_messages,
    init_db,
)


def test_send_email_allowlist_success():
    res = send_email(
        agent="work-agent",
        to=["priya@northwind.io"],
        subject="Weekly status",
        body="Here is the project status for this week.",
    )
    assert "successfully queued for delivery" in res
    assert "[BLOCKED" not in res
    assert "[PENDING" not in res

    messages = get_outbox_messages()
    assert len(messages) == 1
    assert messages[0]["status"] == "sent"
    assert "priya@northwind.io" in messages[0]["to_addrs"]


def test_send_email_allowlist_requires_approval():
    # Sending to unlisted address with 0s timeout returns pending approval
    res = send_email(
        agent="work-agent",
        to=["external.partner@vendor.org"],
        subject="Vendor agreement",
        body="Reviewing the proposal terms.",
        timeout=0,
    )
    assert "[PENDING APPROVAL]" in res
    assert "requires user approval" in res

    messages = get_outbox_messages()
    assert len(messages) == 1
    assert messages[0]["status"] == "pending"


def test_send_email_approval_flow():
    # Test approving an unlisted recipient
    conn = get_connection()
    res = send_email(
        agent="work-agent",
        to=["partner@outside.com"],
        subject="Meeting notes",
        body="Notes from today.",
        timeout=0,
    )
    assert "[PENDING APPROVAL]" in res

    # Find the approval request
    req = conn.execute(
        "SELECT id FROM approval_requests WHERE tool = 'send_email' AND status = 'pending'"
    ).fetchone()
    assert req is not None
    req_id = req["id"]

    # Approve the request
    decide_approval_request(req_id, "approved")

    # Check outbox status updated to sent
    messages = get_outbox_messages()
    assert messages[0]["status"] == "sent"
    assert "Approved by user" in messages[0]["reason"]
    conn.close()


def test_send_email_secret_exfiltration_blocked():
    # Body containing OTP code
    res_otp = send_email(
        agent="work-agent",
        to=["priya@northwind.io"],
        subject="Security Code",
        body="Here is your verification code: 849201",
    )
    assert "[BLOCKED BY SPINDLE]" in res_otp
    assert "sensitive secrets detected" in res_otp

    # Body containing valid Luhn credit card
    res_card = send_email(
        agent="work-agent",
        to=["priya@northwind.io"],
        subject="Payment Info",
        body="Use this card 4111 1111 1111 1111 to pay.",
    )
    assert "[BLOCKED BY SPINDLE]" in res_card

    # Body containing SSN
    res_ssn = send_email(
        agent="work-agent",
        to=["priya@northwind.io"],
        subject="Tax Form",
        body="My SSN is 000-12-3456.",
    )
    assert "[BLOCKED BY SPINDLE]" in res_ssn

    messages = get_outbox_messages()
    assert len(messages) == 3
    for m in messages:
        assert m["status"] == "blocked"
        assert "exfiltration prevented" in m["reason"].lower()


def test_send_email_quarantined_recipient_blocked():
    # Sender from e15: it-compliance@northwind-it.co
    res = send_email(
        agent="work-agent",
        to=["it-compliance@northwind-it.co"],
        subject="Audit Response",
        body="Here is the requested data.",
    )
    assert "[BLOCKED BY SPINDLE]" in res
    assert "associated only with suspicious quarantined emails" in res

    messages = get_outbox_messages()
    assert len(messages) == 1
    assert messages[0]["status"] == "blocked"
    assert "quarantined" in messages[0]["reason"]


def test_send_email_rate_limit():
    # Send 5 emails successfully
    for i in range(5):
        r = send_email(
            agent="work-agent",
            to=["colleague@northwind.io"],
            subject=f"Update #{i}",
            body="Safe progress update.",
        )
        assert "successfully queued for delivery" in r

    # 6th email should be blocked by rate limiter
    r6 = send_email(
        agent="work-agent",
        to=["colleague@northwind.io"],
        subject="Update #6",
        body="Another update.",
    )
    assert "[BLOCKED BY SPINDLE]" in r6
    assert "Rate limit exceeded" in r6

    messages = get_outbox_messages()
    assert len(messages) == 6
    assert messages[0]["status"] == "blocked"
    assert "rate limit exceeded" in messages[0]["reason"].lower()


def test_send_email_passthrough():
    res = send_email(
        agent="unprotected",
        to=["anybody@anywhere.com"],
        subject="Anything",
        body="Contains card 4532 0150 1234 5678 and OTP 123456",
    )
    assert "unfiltered passthrough connector" in res
    messages = get_outbox_messages()
    assert len(messages) == 1
    assert messages[0]["status"] == "sent"
