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
    re.compile(r"(?<![\w-])display\s*:\s*none(?=[;\s!]|$|\")", re.IGNORECASE),
    re.compile(r"(?<![\w-])visibility\s*:\s*hidden(?=[;\s!]|$|\")", re.IGNORECASE),
    re.compile(r"(?<![\w-])opacity\s*:\s*0(?:\.0*)?(?=[;\s!]|$|\")", re.IGNORECASE),
    re.compile(r"(?<![\w-])font-size\s*:\s*(?:0(?:px|pt|em|rem)?(?=[;\s!]|$|\")|1px(?=[;\s!]|$|\"))", re.IGNORECASE),
    re.compile(r"(?<![\w-])color\s*:\s*(?:#ffffff|#fff|white|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))(?=[;\s!]|$|\")", re.IGNORECASE),
]


def _is_element_hidden(el: Any) -> bool:
    try:
        if el.has_attr("hidden"):
            return True
        style = el.get("style", "")
        if style:
            for r in HIDDEN_STYLE_REGEXES:
                if r.search(style):
                    return True
    except Exception:
        pass
    return False


def extract_hidden_and_visible(body_html: str) -> tuple[str, str]:
    """Parses HTML, extracts hidden text, and returns (hidden_text, visible_text)."""
    try:
        soup = BeautifulSoup(body_html, "html.parser")

        # 1. Find all hidden elements, keeping only top-level ones
        hidden_elements: List[Any] = []
        for el in soup.find_all(True):
            if _is_element_hidden(el):
                # Check if any ancestor is already in hidden_elements
                has_hidden_ancestor = False
                for parent in el.parents:
                    if parent in hidden_elements:
                        has_hidden_ancestor = True
                        break
                if not has_hidden_ancestor:
                    hidden_elements.append(el)

        # 2. Extract hidden text and decompose top-level hidden elements
        hidden_texts: List[str] = []
        for el in hidden_elements:
            text = el.get_text(separator=" ").strip()
            if text:
                hidden_texts.append(text)
            el.decompose()

        hidden_combined = " ".join(hidden_texts).strip()

        # 3. Extract visible text with separator="\n" and cleanup lines
        visible_raw = soup.get_text(separator="\n")
        lines = [line.rstrip() for line in visible_raw.splitlines()]
        visible_combined = re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()

        return hidden_combined, visible_combined
    except Exception:
        # Fail closed on any parse error
        return "[UNPARSEABLE_HTML_ERROR]", ""


def visible_text(email: Email) -> str:
    """Returns the email body without hidden text.

    If body_html is present, strips hidden elements. Otherwise returns body_text.
    """
    if email.body_html:
        try:
            hidden, vis = extract_hidden_and_visible(email.body_html)
            if hidden != "[UNPARSEABLE_HTML_ERROR]" and vis:
                return vis
        except Exception:
            pass
    return email.body_text


def inspect(email: Email, llm_result: Any | None = None) -> InjectionReport:
    """Inspects an email for prompt injection via hidden text, heuristics, and LLM signals."""
    hidden_text_found = False
    hidden_excerpt = ""
    hidden_len = 0

    if email.body_html:
        hid, _ = extract_hidden_and_visible(email.body_html)
        if hid == "[UNPARSEABLE_HTML_ERROR]":
            hidden_text_found = True
            hidden_excerpt = "HTML could not be parsed safely"
            hidden_len = 0
        else:
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
    # 1. hidden_text (>= 20 chars) or unparseable HTML
    # 2. >= 2 heuristic hits
    # 3. llm_suspected and llm_confidence >= 0.7
    quarantine = False
    reasons: List[str] = []

    if hidden_text_found:
        quarantine = True
        if hidden_excerpt == "HTML could not be parsed safely":
            reasons.append("HTML could not be parsed safely")
        else:
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
