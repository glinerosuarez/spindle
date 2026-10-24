from __future__ import annotations

import hashlib
import re
from typing import Any, Optional, Tuple

from spindle.config import config
from spindle.models import Category, Classification, Email
from spindle.redact import scan
from spindle.store import get_cached_classification, set_cached_classification

# Domain to category mapping
DOMAIN_MAP = {
    "chase.com": "finance",
    "united.com": "travel",
    "hotelzephyrsf.com": "travel",
    "kp.org": "health",
    "blueshieldca.com": "health",
    "smiledental.com": "health",
    "github.com": "work",
    "northwind.io": "work",
    "figma.com": "promo",
    "accounts.google.com": "auth",
}

# Sender substring fallbacks
SENDER_KEYWORDS = [
    ("talentbridge", "work"),
]

# Keyword patterns for category detection
KEYWORD_RULES = [
    (re.compile(r"\b(?:itinerary|boarding|flight|hotel|reservation confirmed)\b", re.IGNORECASE), "travel"),
    (re.compile(r"\b(?:statement|balance|payment due|checking account)\b", re.IGNORECASE), "finance"),
    (re.compile(r"\b(?:lab results|appointment|prescription|medical|dental|doctor)\b", re.IGNORECASE), "health"),
    (re.compile(r"\b(?:standup|sprint|jira|launch|deliverables)\b", re.IGNORECASE), "work"),
]

PROMO_UNSUB = re.compile(r"\bunsubscribe\b", re.IGNORECASE)
PROMO_KW = re.compile(r"\b(?:sale|% off|what's new|discount|newsletter)\b", re.IGNORECASE)

SENSITIVITY_MAP = {
    "auth": "high",
    "health": "high",
    "finance": "high",
    "work": "medium",
    "personal": "medium",
    "travel": "low",
    "promo": "low",
    "other": "high",
}


def _match_rules(email: Email) -> Optional[Tuple[Category, str]]:
    # Check sender domain
    sender_lower = email.sender.lower()
    for domain, cat in DOMAIN_MAP.items():
        if f"@{domain}" in sender_lower or f"<{domain}>" in sender_lower or domain in sender_lower:
            return cat, f"Sender matched domain {domain}"

    for kw, cat in SENDER_KEYWORDS:
        if kw in sender_lower:
            return cat, f"Sender matched keyword {kw}"

    # Check subject & body keywords
    content = f"{email.subject}\n{email.body_text}"

    # Promo check: unsubscribe + promo keyword
    if PROMO_UNSUB.search(content) and PROMO_KW.search(content):
        return "promo", "Matched promo unsubscribe + offer keywords"

    for pattern, cat in KEYWORD_RULES:
        m = pattern.search(content)
        if m:
            return cat, f"Matched keyword: {m.group(0)}"

    return None


def classify(
    email: Email,
    llm_classifier: Any | None = None,
    use_cache: bool = True,
) -> Tuple[Classification, Any | None]:
    """Classifies an email using deterministic override, rules first, and LLM fallback."""
    content_str = f"{email.subject}\n{email.body_text}"
    content_hash = hashlib.sha256(content_str.encode("utf-8")).hexdigest()
    model_name = config.llm_model

    # 0. Check cache if enabled
    if use_cache:
        cached = get_cached_classification(email.id, content_hash, model_name)
        if cached:
            return cached

    # 1. Deterministic override: if scan() finds otp or auth_link -> auth
    redactions = scan(content_str)
    has_auth_indicator = any(r.type in ("otp", "auth_link") for r in redactions)
    if has_auth_indicator:
        cls = Classification(
            category="auth",
            sensitivity="high",
            source="override",
            reason="Deterministic override: OTP or auth link detected",
        )
        if use_cache:
            set_cached_classification(email.id, content_hash, model_name, cls, None)
        return cls, None

    # 2. Rules first
    rule_match = _match_rules(email)
    rule_category: Optional[Category] = None
    rule_reason: Optional[str] = None
    if rule_match:
        rule_category, rule_reason = rule_match

    # 3. LLM classification if enabled
    llm_result = None
    if config.llm_enabled and llm_classifier is not None:
        try:
            llm_result = llm_classifier(email)
        except Exception:
            llm_result = None

    # Determine final category
    if rule_category is not None:
        cls = Classification(
            category=rule_category,
            sensitivity=SENSITIVITY_MAP.get(rule_category, "medium"),  # type: ignore[arg-type]
            source="rules",
            reason=rule_reason or "Rule matched",
        )
    elif llm_result is not None and getattr(llm_result, "category", None):
        cat = llm_result.category
        sens = getattr(llm_result, "sensitivity", SENSITIVITY_MAP.get(cat, "high"))
        cls = Classification(
            category=cat,
            sensitivity=sens,
            source="llm",
            reason=getattr(llm_result, "reason", "Classified by LLM"),
        )
    else:
        # LLM disabled, failed, or no rules matched
        cls = Classification(
            category="other",
            sensitivity="high",
            source="llm_error",
            reason="No rule matched and LLM unavailable or disabled",
        )

    if use_cache:
        set_cached_classification(
            email.id,
            content_hash,
            model_name,
            cls,
            llm_result.model_dump() if hasattr(llm_result, "model_dump") else llm_result,
        )

    return cls, llm_result
