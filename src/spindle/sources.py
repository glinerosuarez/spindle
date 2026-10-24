from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List, Optional, Protocol

from spindle.config import config
from spindle.models import Email


class MailSource(Protocol):
    def search(self, query: str, limit: int) -> List[Email]:
        ...

    def get(self, email_id: str) -> Optional[Email]:
        ...


class FixtureSource:
    def __init__(self, fixtures_path: Optional[Path] = None):
        if fixtures_path is None:
            # spindle-app/data/demo_inbox.json
            app_dir = Path(__file__).resolve().parent.parent.parent
            fixtures_path = app_dir / "data" / "demo_inbox.json"
        self.fixtures_path = fixtures_path
        self._emails: List[Email] = []
        self._load()

    def _load(self) -> None:
        emails_by_id = {}

        if self.fixtures_path.exists():
            with open(self.fixtures_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for item in data:
                    e = Email(
                        id=item["id"],
                        thread_id=item.get("thread_id", ""),
                        sender=item.get("sender", ""),
                        to=item.get("to", ""),
                        subject=item.get("subject", ""),
                        date=item.get("date", ""),
                        snippet=item.get("snippet", ""),
                        body_text=item.get("body_text", ""),
                        body_html=item.get("body_html"),
                        labels=item.get("labels", []),
                    )
                    emails_by_id[e.id] = e

        # Also load ~/.spindle/incoming.json if it exists
        if config.incoming_path.exists():
            try:
                with open(config.incoming_path, "r", encoding="utf-8") as f:
                    incoming_data = json.load(f)
                    for item in incoming_data:
                        e = Email(
                            id=item["id"],
                            thread_id=item.get("thread_id", ""),
                            sender=item.get("sender", ""),
                            to=item.get("to", ""),
                            subject=item.get("subject", ""),
                            date=item.get("date", ""),
                            snippet=item.get("snippet", ""),
                            body_text=item.get("body_text", ""),
                            body_html=item.get("body_html"),
                            labels=item.get("labels", []),
                        )
                        emails_by_id[e.id] = e
            except Exception:
                pass

        # Sort newest first by date string (ISO 8601 sorts lexicographically)
        self._emails = sorted(emails_by_id.values(), key=lambda e: e.date, reverse=True)

    def search(self, query: str, limit: int = 10) -> List[Email]:
        # Always reload in case incoming.json changed
        self._load()

        # 1. Remove Gmail-style operators (\b\w+:\S+)
        cleaned_query = re.sub(r"\b\w+:\S+", "", query).strip()
        words = [w.lower() for w in cleaned_query.split() if w]

        # 2. If no words are left, return all emails, newest first
        if not words:
            return self._emails[:limit]

        # 3. Otherwise return emails where ANY remaining word appears (case-insensitive) in sender, subject or body_text
        results = []
        for email in self._emails:
            searchable = f"{email.sender} {email.subject} {email.body_text}".lower()
            if any(w in searchable for w in words):
                results.append(email)

        # 4. Cap at limit
        return results[:limit]

    def get(self, email_id: str) -> Optional[Email]:
        self._load()
        for email in self._emails:
            if email.id == email_id:
                return email
        return None
