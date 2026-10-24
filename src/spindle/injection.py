from __future__ import annotations

import re
from typing import Any, List, Optional
from bs4 import BeautifulSoup
from spindle.models import Email, InjectionReport


# Heuristic patterns (case-insensitive)
HEURISTIC_PATTERNS = {
    "ignore_instructions": re.compile(
        r"\bignore\s+(?:all|any|previous|prior|above)\s+(?:instructions|rules)\b",
        re.IGNORECASE,
    ),
    "addresses_ai": re.compile(
        r"(?:\b(?:assistant|AI|agent|copilot|model)\s*[,:]|\bnote\s+(?:to|for)\s+(?:the\s+)?(?:assistant|AI|agent)\b)",
        re.IGNORECASE,
    ),
    "summary_hijack": re.compile(
        r"\bwhen\s+(?:summariz|compil|prepar)\w*(?:\s+\w+){0,3}\s+(?:this|the|your)\b",
        re.IGNORECASE,
    ),

    "secret_request": re.compile(
        r"\b(?:include|add|append|attach|list)\b.{0,40}\b(?:code|password|verification|otp|credential|token)s?\b",
        re.IGNORECASE | re.DOTALL,
    ),
    "exfil_link": re.compile(
        r"(?:\[[^\]]*\]\([^\)]*(?:\{|\?data=|\?q=|\?c=)[^\)]*\)|put\s+(?:data|codes?|tokens?|secrets?)\s+inside\s+a\s+link)",
        re.IGNORECASE,
    ),
    "concealment": re.compile(
        r"\b(?:do\s+not|don't)\s+(?:mention|tell|reveal|disclose)\b",
        re.IGNORECASE,
    ),
}

HIDDEN_STYLE_REGEXES = [
    re.compile(r"display\s*:\s*none", re.IGNORECASE),
    re.compile(r"visibility\s*:\s*hidden", re.IGNORECASE),
    re.compile(r"opacity\s*:\s*0(?:\.0*)?(?:;|$)", re.IGNORECASE),
    re.compile(r"font-size\s*:\s*(?:0(?:px|pt|em|rem)?|1px)", re.IGNORECASE),
    re.compile(r"color\s*:\s*(?:#ffffff|#fff|white|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))", re.IGNORECASE),
]


def _is_element_hidden(el: Any) -> bool:
    if el.has_attr("hidden"):
        return True
    style = el.get("style", "")
    if style:
        for r in HIDDEN_STYLE_REGEXES:
            if r.search(style):
                return True
    return False


def extract_hidden_and_visible(body_html: str) -> tuple[str, str]:
    """Parses HTML, extracts hidden text, and returns (hidden_text, visible_text)."""
    soup = BeautifulSoup(body_html, "html.parser")

    hidden_texts: List[str] = []
    # Find all elements and check if hidden
    # Iterate through elements; if an element is hidden, collect its text and decompose it
    for el in soup.find_all(True):
        if _is_element_hidden(el):
            text = el.get_text()
            if text:
                hidden_texts.append(text)
            el.decompose()

    hidden_combined = " ".join(hidden_texts).strip()
    visible_combined = soup.get_text().strip()
    return hidden_combined, visible_combined


def visible_text(email: Email) -> str:
    """Returns the email body without hidden text.

    If body_html is present, strips hidden elements. Otherwise returns body_text.
    """
    if email.body_html:
        _, vis = extract_hidden_and_visible(email.body_html)
        return vis
    return email.body_text


def inspect(email: Email, llm_result: Any | None = None) -> InjectionReport:
    """Inspects an email for prompt injection via hidden text, heuristics, and LLM signals."""
    hidden_text_found = False
    hidden_excerpt = ""
    hidden_len = 0

    if email.body_html:
        hid, _ = extract_hidden_and_visible(email.body_html)
        hidden_len = len(hid)
        if hidden_len >= 20:
            hidden_text_found = True
            hidden_excerpt = hid[:200]

    # Content to check for heuristics: subject + body_text + raw HTML (to catch hidden injections too)
    content_to_check = f"{email.subject}\n{email.body_text}"
    if email.body_html:
        content_to_check += f"\n{email.body_html}"

    heuristic_hits: List[str] = []
    for name, pattern in HEURISTIC_PATTERNS.items():
        if pattern.search(content_to_check):
            heuristic_hits.append(name)

    llm_suspected: Optional[bool] = None
    llm_confidence: Optional[float] = None
    if llm_result is not None:
        if isinstance(llm_result, dict):
            llm_suspected = llm_result.get("injection_suspected")
            llm_confidence = llm_result.get("injection_confidence")
        else:
            llm_suspected = getattr(llm_result, "injection_suspected", None)
            llm_confidence = getattr(llm_result, "injection_confidence", None)

    # Quarantine conditions:
    # 1. hidden_text (>= 20 chars)
    # 2. >= 2 heuristic hits
    # 3. llm_suspected and llm_confidence >= 0.7
    quarantine = False
    reasons: List[str] = []

    if hidden_text_found:
        quarantine = True
        reasons.append(f"Hidden text ({hidden_len} chars)")

    if len(heuristic_hits) >= 2:
        quarantine = True
        reasons.append(f"Heuristics: {', '.join(heuristic_hits)}")

    if llm_suspected and llm_confidence is not None and llm_confidence >= 0.7:
        quarantine = True
        reasons.append(f"LLM injection suspected ({llm_confidence:.2f})")

    if not reasons and heuristic_hits:
        reasons.append(f"Flagged heuristic: {', '.join(heuristic_hits)}")
    elif not reasons:
        reasons.append("Clean")

    return InjectionReport(
        hidden_text=hidden_text_found,
        hidden_text_excerpt=hidden_excerpt,
        heuristic_hits=heuristic_hits,
        llm_suspected=llm_suspected,
        llm_confidence=llm_confidence,
        quarantine=quarantine,
        reason=" + ".join(reasons),
    )
