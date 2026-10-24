from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional, Tuple

from spindle.config import config
from spindle.models import Classification, InjectionReport, Redaction


def get_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    path = db_path or config.db_path
    newly_created = not path.exists()
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    if newly_created and path.exists():
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
    return conn


def init_db(db_path: Optional[Path] = None) -> None:
    conn = get_connection(db_path)
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY,
                ts TEXT,
                agent TEXT,
                tool TEXT,
                query TEXT,
                email_id TEXT,
                category TEXT,
                action TEXT,
                reason TEXT,
                redactions_json TEXT,
                injection_json TEXT,
                returned_text TEXT
            );
        """)
        # Ensure returned_text column exists on audit (migration for existing DBs)
        cur = conn.execute("PRAGMA table_info(audit);")
        columns = [row["name"] for row in cur.fetchall()]
        if "returned_text" not in columns:
            conn.execute("ALTER TABLE audit ADD COLUMN returned_text TEXT;")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS approval_requests (
                id INTEGER PRIMARY KEY,
                ts TEXT,
                agent TEXT,
                tool TEXT,
                query TEXT,
                email_ids_json TEXT,
                categories_json TEXT,
                status TEXT CHECK(status IN ('pending','approved','denied')) DEFAULT 'pending',
                decided_ts TEXT
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS approvals (
                agent TEXT,
                email_id TEXT,
                status TEXT,
                request_id INTEGER,
                PRIMARY KEY (agent, email_id)
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS classification_cache (
                email_id TEXT,
                content_hash TEXT,
                model TEXT,
                classification_json TEXT,
                llm_json TEXT,
                PRIMARY KEY (email_id, content_hash, model)
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS outbox (
                id INTEGER PRIMARY KEY,
                ts TEXT,
                agent TEXT,
                to_addrs TEXT,
                subject TEXT,
                body TEXT,
                status TEXT,
                reason TEXT
            );
        """)
    conn.close()


def log_audit(
    agent: str,
    tool: str,
    query: str,
    email_id: str,
    category: str,
    action: str,
    reason: str,
    redactions: List[Redaction],
    injection: Optional[InjectionReport] = None,
    returned_text: Optional[str] = None,
    db_path: Optional[Path] = None,
) -> None:
    conn = get_connection(db_path)
    ts = datetime.now(timezone.utc).isoformat()
    redactions_json = json.dumps([r.model_dump() for r in redactions])
    injection_json = json.dumps(injection.model_dump()) if injection else None

    with conn:
        conn.execute(
            """
            INSERT INTO audit (
                ts, agent, tool, query, email_id, category, action, reason,
                redactions_json, injection_json, returned_text
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ts,
                agent,
                tool,
                query,
                email_id,
                category,
                action,
                reason,
                redactions_json,
                injection_json,
                returned_text,
            ),
        )
    conn.close()


def find_pending_request(
    agent: str,
    tool_kind: str,
    email_ids: List[str],
    db_path: Optional[Path] = None,
) -> Optional[int]:
    req_ids_set = set(email_ids)
    conn = get_connection(db_path)
    rows = conn.execute(
        """
        SELECT id, tool, email_ids_json FROM approval_requests
        WHERE agent = ? AND status = 'pending'
        ORDER BY id ASC
        """,
        (agent,),
    ).fetchall()
    conn.close()

    for row in rows:
        row_tool = row["tool"]
        if tool_kind in ("search", "read"):
            if row_tool not in ("search", "read"):
                continue
        elif row_tool != tool_kind:
            continue

        try:
            stored_ids = set(json.loads(row["email_ids_json"]))
        except Exception:
            continue

        if stored_ids.issuperset(req_ids_set):
            return row["id"]

    return None


def create_approval_request(
    agent: str,
    tool: str,
    query: str,
    email_ids: List[str],
    categories: List[str],
    db_path: Optional[Path] = None,
) -> int:
    conn = get_connection(db_path)
    ts = datetime.now(timezone.utc).isoformat()
    with conn:
        cur = conn.execute(
            """
            INSERT INTO approval_requests (
                ts, agent, tool, query, email_ids_json, categories_json, status
            ) VALUES (?, ?, ?, ?, ?, ?, 'pending')
            """,
            (
                ts,
                agent,
                tool,
                query,
                json.dumps(email_ids),
                json.dumps(categories),
            ),
        )
        req_id = cur.lastrowid
    conn.close()
    return req_id  # type: ignore[return-value]


def get_approval_request(request_id: int, db_path: Optional[Path] = None) -> Optional[dict]:
    conn = get_connection(db_path)
    row = conn.execute(
        "SELECT * FROM approval_requests WHERE id = ?", (request_id,)
    ).fetchone()
    conn.close()
    if row:
        return dict(row)
    return None


def decide_approval_request(
    request_id: int, status: str, db_path: Optional[Path] = None
) -> None:
    if status not in ("approved", "denied"):
        raise ValueError(f"Invalid approval status: {status}")

    conn = get_connection(db_path)
    ts = datetime.now(timezone.utc).isoformat()
    with conn:
        row = conn.execute(
            "SELECT agent, tool, email_ids_json FROM approval_requests WHERE id = ?",
            (request_id,),
        ).fetchone()
        if not row:
            conn.close()
            return

        agent = row["agent"]
        tool = row["tool"] if "tool" in row.keys() else "search"
        email_ids = json.loads(row["email_ids_json"])

        conn.execute(
            "UPDATE approval_requests SET status = ?, decided_ts = ? WHERE id = ?",
            (status, ts, request_id),
        )

        if tool == "send_email":
            outbox_status = "sent" if status == "approved" else "denied"
            for outbox_id_str in email_ids:
                try:
                    conn.execute(
                        "UPDATE outbox SET status = ?, reason = ? WHERE id = ?",
                        (outbox_status, f"{status.capitalize()} by user", int(outbox_id_str)),
                    )
                except Exception:
                    pass

        for eid in email_ids:
            conn.execute(
                """
                INSERT INTO approvals (agent, email_id, status, request_id)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(agent, email_id) DO UPDATE SET
                    status = excluded.status,
                    request_id = excluded.request_id
                """,
                (agent, eid, status, request_id),
            )
    conn.close()


def get_approval_status(
    agent: str, email_id: str, db_path: Optional[Path] = None
) -> Optional[str]:
    conn = get_connection(db_path)
    row = conn.execute(
        "SELECT status FROM approvals WHERE agent = ? AND email_id = ?",
        (agent, email_id),
    ).fetchone()
    conn.close()
    if row:
        return row["status"]
    return None


def get_cached_classification(
    email_id: str, content_hash: str, model: str, db_path: Optional[Path] = None
) -> Optional[Tuple[Classification, Any]]:
    conn = get_connection(db_path)
    row = conn.execute(
        """
        SELECT classification_json, llm_json FROM classification_cache
        WHERE email_id = ? AND content_hash = ? AND model = ?
        """,
        (email_id, content_hash, model),
    ).fetchone()
    conn.close()
    if row:
        cls_data = json.loads(row["classification_json"])
        llm_data = json.loads(row["llm_json"]) if row["llm_json"] else None
        return Classification.model_validate(cls_data), llm_data
    return None


def set_cached_classification(
    email_id: str,
    content_hash: str,
    model: str,
    classification: Classification,
    llm_result: Any,
    db_path: Optional[Path] = None,
) -> None:
    conn = get_connection(db_path)
    cls_json = json.dumps(classification.model_dump())
    llm_json = json.dumps(llm_result) if llm_result else None
    with conn:
        conn.execute(
            """
            INSERT INTO classification_cache (
                email_id, content_hash, model, classification_json, llm_json
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(email_id, content_hash, model) DO UPDATE SET
                classification_json = excluded.classification_json,
                llm_json = excluded.llm_json
            """,
            (email_id, content_hash, model, cls_json, llm_json),
        )
    conn.close()

def create_outbox_message(
    agent: str,
    to_addrs: List[str],
    subject: str,
    body: str,
    status: str,
    reason: str,
    db_path: Optional[Path] = None,
) -> int:
    conn = get_connection(db_path)
    ts = datetime.now(timezone.utc).isoformat()
    to_str = ", ".join(to_addrs)
    with conn:
        cur = conn.execute(
            """
            INSERT INTO outbox (ts, agent, to_addrs, subject, body, status, reason)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (ts, agent, to_str, subject, body, status, reason),
        )
        outbox_id = cur.lastrowid
    conn.close()
    return outbox_id


def get_outbox_messages(
    limit: int = 50,
    db_path: Optional[Path] = None,
) -> List[sqlite3.Row]:
    conn = get_connection(db_path)
    rows = conn.execute(
        """
        SELECT * FROM outbox
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()
    return rows


def update_outbox_status(
    outbox_id: int,
    status: str,
    reason: str,
    db_path: Optional[Path] = None,
) -> None:
    conn = get_connection(db_path)
    with conn:
        conn.execute(
            """
            UPDATE outbox
            SET status = ?, reason = ?
            WHERE id = ?
            """,
            (status, reason, outbox_id),
        )
    conn.close()


def get_outbox_sends_last_hour(
    agent: str,
    db_path: Optional[Path] = None,
) -> int:
    conn = get_connection(db_path)
    # Check sends in the last 3600 seconds
    # Status 'sent' or 'allowed'
    rows = conn.execute(
        """
        SELECT ts FROM outbox
        WHERE agent = ? AND status IN ('sent', 'approved')
        """,
        (agent,),
    ).fetchall()
    conn.close()

    now = datetime.now(timezone.utc)
    count = 0
    for r in rows:
        try:
            msg_ts = datetime.fromisoformat(r["ts"])
            if (now - msg_ts).total_seconds() <= 3600:
                count += 1
        except Exception:
            continue
    return count


def is_recipient_only_in_quarantined(
    recipient: str,
    db_path: Optional[Path] = None,
) -> bool:
    """Returns True if recipient appears in quarantined emails and nowhere in benign emails."""
    from spindle.sources import FixtureSource
    from spindle.injection import inspect as inspect_injection
    from spindle.classifier import classify

    source = FixtureSource()
    emails = source.search("", limit=100)
    
    clean_recip = recipient.lower().strip()
    # Handle angles like "Name <email@domain.com>"
    if "<" in clean_recip and ">" in clean_recip:
        clean_recip = clean_recip.split("<")[1].split(">")[0].strip()

    quarantined_senders = set()
    benign_senders = set()

    for em in emails:
        cls, llm_res = classify(em, use_cache=True)
        inj = inspect_injection(em, llm_res)
        
        sender_email = em.sender.lower().strip()
        if "<" in sender_email and ">" in sender_email:
            sender_email = sender_email.split("<")[1].split(">")[0].strip()

        if inj.quarantine:
            quarantined_senders.add(sender_email)
            # Also check if recipient appears in body of quarantined email (e.g. domain or address)
            if clean_recip in em.body_text.lower():
                quarantined_senders.add(clean_recip)
        else:
            benign_senders.add(sender_email)
            if clean_recip in em.body_text.lower() or clean_recip in em.to.lower():
                benign_senders.add(clean_recip)

    # If it is in quarantined_senders and NOT in benign_senders
    return (clean_recip in quarantined_senders) and (clean_recip not in benign_senders)


def main():
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m spindle.store [approve|deny|list] <id>")
        return

    cmd = sys.argv[1].lower()
    init_db()

    if cmd == "list":
        conn = get_connection()
        rows = conn.execute("SELECT * FROM approval_requests ORDER BY id DESC").fetchall()
        conn.close()
        for r in rows:
            print(f"#{r['id']} | {r['ts'][:19]} | {r['agent']} | {r['status']} | emails: {r['email_ids_json']}")
    elif cmd in ("approve", "deny") and len(sys.argv) >= 3:
        req_id = int(sys.argv[2])
        status = "approved" if cmd == "approve" else "denied"
        decide_approval_request(req_id, status)
        print(f"Request #{req_id} marked as {status}.")
    else:
        print("Usage: python -m spindle.store [approve|deny|list] <id>")


if __name__ == "__main__":
    main()

