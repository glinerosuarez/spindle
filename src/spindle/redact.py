# Note: The strict protection level is inspired by the HIPAA Safe Harbor identifier list.
# Personal names are not redacted as entity recognition is planned for a future release.
from __future__ import annotations

import re
from typing import List, Tuple
from spindle.models import CustomRule, Level, Redaction

# Common medication names list (~40)
COMMON_MEDICATIONS = [
    "acetaminophen", "albuterol", "amlodipine", "amoxicillin", "amphetamine",
    "atorvastatin", "azithromycin", "bupropion", "carvedilol", "cephalexin",
    "ciprofloxacin", "clonazepam", "doxycycline", "duloxetine", "escitalopram",
    "fluticasone", "furosemide", "gabapentin", "glipizide", "hydrochlorothiazide",
    "ibuprofen", "insulin", "levothyroxine", "lisinopril", "lorazepam",
    "losartan", "metformin", "methylphenidate", "metoprolol", "montelukast",
    "omeprazole", "pantoprazole", "prednisone", "pravastatin", "rosuvastatin",
    "sertraline", "simvastatin", "tramadol", "venlafaxine", "zolpidem"
]

US_STATES = (
    "AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|"
    "MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY"
)


def luhn_check(card_number_str: str) -> bool:
    digits = [int(c) for c in card_number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            if doubled > 9:
                doubled -= 9
            checksum += doubled
        else:
            checksum += d
    return checksum % 10 == 0


def redact(
    text: str,
    level: Level = "standard",
    custom_rules: List[CustomRule] | None = None,
) -> Tuple[str, List[Redaction]]:
    if not text:
        return text, []

    if custom_rules is None:
        custom_rules = []

    counts: dict[str, int] = {}

    def record(rtype: str, n: int = 1):
        if n > 0:
            counts[rtype] = counts.get(rtype, 0) + n

    current = text

    # 1. auth_link (all levels)
    # URL whose path or query contains reset, token, magic, verify, signin, login, confirm, otp
    auth_kw = re.compile(r"(?:reset|token|magic|verify|signin|login|confirm|otp)", re.IGNORECASE)
    url_re = re.compile(r"https?://[^\s<>\"']+")

    def replace_auth_link(match: re.Match) -> str:
        url = match.group(0)
        # Check path and query (strip scheme and domain)
        parts = url.split("://", 1)
        path_query = parts[1] if len(parts) > 1 else ""
        if "/" in path_query:
            path_query = path_query.split("/", 1)[1]
        else:
            path_query = ""

        if auth_kw.search(path_query):
            record("auth_link")
            return "[REDACTED:auth_link]"
        return url

    current = url_re.sub(replace_auth_link, current)

    # 2. otp (all levels)
    # Subject starting with ^\d{4,8} is your
    otp_subject_re = re.compile(r"^(\d{4,8})(\s+is\s+your)", re.IGNORECASE | re.MULTILINE)

    def replace_otp_subject(match: re.Match) -> str:
        record("otp")
        return f"[REDACTED:otp]{match.group(2)}"

    current = otp_subject_re.sub(replace_otp_subject, current)

    # Strong keywords required within 30 characters
    strong_otp_kw = re.compile(
        r"(?i)\b(?:verification|verify|otp|passcode|one-time|2fa|security\s+code|login\s+code|sign-in\s+code|your\s+code|code\s+is)\b|code\s*:",
        re.IGNORECASE,
    )
    # Preceding identifiers to skip: #, PR, order, invoice, ticket, flight, room, ext, suite, apt
    preceding_skip = re.compile(
        r"(?i)(?:#|pr|order|invoice|ticket|flight|room|ext|suite|apt)\s*#?\s*$",
        re.IGNORECASE,
    )

    def replace_otp(match: re.Match) -> str:
        digits = match.group(0)
        start, end = match.span()

        # 1. Skip 4-digit years (19xx, 20xx)
        if len(digits) == 4 and (digits.startswith("19") or digits.startswith("20")):
            return digits

        # 2. Skip if comes right after #, PR, order, invoice, ticket, flight, room, ext, suite, apt
        lookbehind = current[max(0, start - 30):start]
        if preceding_skip.search(lookbehind):
            return digits

        # 3. Check for strong keyword within 30 chars
        window_start = max(0, start - 30)
        window_end = min(len(current), end + 30)
        context = current[window_start:window_end]
        if strong_otp_kw.search(context):
            record("otp")
            return "[REDACTED:otp]"

        return digits

    current = re.sub(r"(?<![A-Za-z0-9_-])\d{4,8}(?![A-Za-z0-9_-])", replace_otp, current)

    # 3. api_key / password (all levels)
    # (?i)(password|passcode|api[_ -]?key|secret)[:\s]+\S{6,}
    def replace_api_key(match: re.Match) -> str:
        record("api_key")
        prefix = match.group(1)
        sep = match.group(2)
        return f"{prefix}{sep}[REDACTED:api_key]"

    current = re.sub(
        r"(?i)\b(password|passcode|api[_ -]?key|secret)([:\s]+)(\S{6,})",
        replace_api_key,
        current,
    )

    # 4. card (all levels)
    # \b(?:\d[ -]?){13,19}\b, only if Luhn passes
    def replace_card(match: re.Match) -> str:
        candidate = match.group(0)
        digits_only = re.sub(r"[^\d]", "", candidate)
        if 13 <= len(digits_only) <= 19 and luhn_check(digits_only):
            record("card")
            return "[REDACTED:card]"
        return candidate

    current = re.sub(r"\b(?:\d[ -]?){13,19}\b", replace_card, current)

    # 5. ssn (all levels)
    # \b\d{3}-\d{2}-\d{4}\b
    def replace_ssn(match: re.Match) -> str:
        record("ssn")
        return "[REDACTED:ssn]"

    current = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", replace_ssn, current)

    # Patterns for standard and strict levels
    if level in ("standard", "strict"):
        # 6. routing_number
        # 9 digits within 40 chars of routing
        routing_kw = re.compile(r"routing", re.IGNORECASE)

        def replace_routing(match: re.Match) -> str:
            val = match.group(0)
            start, end = match.span()
            window_start = max(0, start - 40)
            window_end = min(len(current), end + 40)
            if routing_kw.search(current[window_start:window_end]):
                record("routing_number")
                return "[REDACTED:routing_number]"
            return val

        current = re.sub(r"(?<!\d)\d{9}(?!\d)", replace_routing, current)

        # 7. bank_account
        # 6–17 digits within 40 chars of account, acct or checking
        acct_kw = re.compile(r"(?:account|acct|checking)", re.IGNORECASE)

        def replace_acct(match: re.Match) -> str:
            val = match.group(0)
            start, end = match.span()
            window_start = max(0, start - 40)
            window_end = min(len(current), end + 40)
            if acct_kw.search(current[window_start:window_end]):
                record("bank_account")
                return "[REDACTED:bank_account]"
            return val

        current = re.sub(r"(?<!\d)\d{6,17}(?!\d)", replace_acct, current)

        # 8. medical_record
        # value after MRN, Medical Record Number or Patient ID ([A-Z0-9-]{5,})
        def replace_mrn(match: re.Match) -> str:
            record("medical_record")
            prefix = match.group(1)
            return f"{prefix}[REDACTED:medical_record]"

        current = re.sub(
            r"(?i)\b((?:MRN|Medical Record Number|Patient ID)[:\s#]+)[A-Z0-9-]{5,}\b",
            replace_mrn,
            current,
        )

        # 9. insurance_id
        # value after Member ID, Subscriber ID or Policy (No|Number|#)
        def replace_ins(match: re.Match) -> str:
            record("insurance_id")
            prefix = match.group(1)
            return f"{prefix}[REDACTED:insurance_id]"

        current = re.sub(
            r"(?i)\b((?:Member ID|Subscriber ID|Policy\s*(?:No\.?|Number|#))[:\s#]+)[A-Z0-9-]{5,}\b",
            replace_ins,
            current,
        )

        # 10. medication
        # word list of ~40 drugs + optional dose
        med_pattern = r"(?i)\b(?:" + "|".join(COMMON_MEDICATIONS) + r")(?:\s*\d+\s*(?:mg|mcg|g|ml))?\b"

        def replace_med(match: re.Match) -> str:
            record("medication")
            return "[REDACTED:medication]"

        current = re.sub(med_pattern, replace_med, current)

        # 11. dob
        # date after DOB or Date of Birth
        def replace_dob(match: re.Match) -> str:
            record("dob")
            prefix = match.group(1)
            return f"{prefix}[REDACTED:dob]"

        current = re.sub(
            r"(?i)\b((?:DOB|Date of Birth)[:\s]+)(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\w+\s+\d{1,2},?\s+\d{4})\b",
            replace_dob,
            current,
        )

        # 12. street_address
        # \b\d{1,6}\s+(?:[A-Z][a-z]+\s){1,4}(?:St|Street|Ave|Avenue|Rd|Road|Blvd|Dr|Drive|Ln|Lane|Way|Ct|Court)\b\.?(?:,?\s*(?:Apt|Unit|#)\s*\w+)?
        def replace_addr(match: re.Match) -> str:
            record("street_address")
            return "[REDACTED:street_address]"

        street_re = (
            r"\b\d{1,6}\s+(?:[A-Z][a-z]+\s){1,4}"
            r"(?:St|Street|Ave|Avenue|Rd|Road|Blvd|Dr|Drive|Ln|Lane|Way|Ct|Court)\b\.?"
            r"(?:,?\s*(?:Apt|Unit|#)\s*\w+)?"
        )
        current = re.sub(street_re, replace_addr, current)

        # 13. phone
        # (?:\+1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}
        def replace_phone(match: re.Match) -> str:
            record("phone")
            return "[REDACTED:phone]"

        phone_re = r"(?:\+1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}"
        current = re.sub(phone_re, replace_phone, current)

    # Patterns for strict level only
    if level == "strict":
        # 14. email_address
        def replace_email(match: re.Match) -> str:
            record("email_address")
            return "[REDACTED:email_address]"

        current = re.sub(r"[\w.+-]+@[\w-]+\.[\w.]+", replace_email, current)

        # 15. url (remaining URLs)
        def replace_url(match: re.Match) -> str:
            record("url")
            return "[REDACTED:url]"

        current = re.sub(r"https?://[^\s<>\"']+", replace_url, current)

        # 16. zip
        # \b\d{5}(?:-\d{4})?\b after a two-letter US state
        def replace_zip(match: re.Match) -> str:
            record("zip")
            state = match.group(1)
            return f"{state} [REDACTED:zip]"

        zip_re = rf"\b({US_STATES})\s+(\d{{5}}(?:-\d{{4}})?)\b"
        current = re.sub(zip_re, replace_zip, current)

    # Custom rules run last
    for rule in custom_rules:
        rule_name = rule.name
        try:
            pattern = re.compile(rule.pattern)
            matches = list(pattern.finditer(current))
            if matches:
                record(rule_name, len(matches))
                current = pattern.sub(f"[REDACTED:{rule_name}]", current)
        except Exception:
            continue

    redactions = [Redaction(type=rtype, count=count) for rtype, count in counts.items()]
    return current, redactions


def scan(text: str) -> List[Redaction]:
    """Runs all redactors at strict level without modifying text."""
    _, redactions = redact(text, level="strict")
    return redactions
