from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional, Tuple

from spindle.config import config
from spindle.models import Classification, InjectionReport, Redaction


def get_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    path = db_path or config.db_path
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
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
                injection_json TEXT
            );
        """)
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
                redactions_json, injection_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            ),
        )
    conn.close()


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
            "SELECT agent, email_ids_json FROM approval_requests WHERE id = ?",
            (request_id,),
        ).fetchone()
        if not row:
            conn.close()
            return

        agent = row["agent"]
        email_ids = json.loads(row["email_ids_json"])

        conn.execute(
            "UPDATE approval_requests SET status = ?, decided_ts = ? WHERE id = ?",
            (status, ts, request_id),
        )

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

