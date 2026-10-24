import hashlib
from unittest.mock import MagicMock
from spindle.classifier import classify
from spindle.config import config
from spindle.models import Email, LLMResult
from spindle.sources import FixtureSource
from spindle.store import get_cached_classification, init_db


def setup_function():
    init_db()


def test_rule_hits():
    source = FixtureSource()

    # Domain match: United Airlines -> travel
    e01 = source.get("e01")
    assert e01 is not None
    cls01, _ = classify(e01, use_cache=False)
    assert cls01.category == "travel"
    assert cls01.source == "rules"

    # Domain match: Chase -> finance
    e03 = source.get("e03")
    assert e03 is not None
    cls03, _ = classify(e03, use_cache=False)
    assert cls03.category == "finance"
    assert cls03.source == "rules"

    # Domain match: Kaiser -> health
    e06 = source.get("e06")
    assert e06 is not None
    cls06, _ = classify(e06, use_cache=False)
    assert cls06.category == "health"
    assert cls06.source == "rules"

    # Domain match: GitHub -> work
    e10 = source.get("e10")
    assert e10 is not None
    cls10, _ = classify(e10, use_cache=False)
    assert cls10.category == "work"
    assert cls10.source == "rules"


def test_e16_classified_through_mocked_llm():
    source = FixtureSource()
    e16 = source.get("e16")
    assert e16 is not None

    mock_llm = MagicMock(
        return_value=LLMResult(
            category="personal",
            sensitivity="low",
            injection_suspected=False,
            injection_confidence=0.0,
            reason="Informal weekend plans with a friend",
        )
    )

    cls, llm_res = classify(e16, llm_classifier=mock_llm, use_cache=False)
    assert cls.category == "personal"
    assert cls.source == "llm"
    assert llm_res is not None
    assert llm_res.injection_suspected is False


def test_llm_failure_falls_closed_to_other_high():
    source = FixtureSource()
    e16 = source.get("e16")
    assert e16 is not None

    # LLM fails by raising exception or returning None
    failing_llm = MagicMock(side_effect=RuntimeError("API timeout"))
    cls, llm_res = classify(e16, llm_classifier=failing_llm, use_cache=False)
    assert cls.category == "other"
    assert cls.sensitivity == "high"
    assert cls.source == "llm_error"
    assert llm_res is None


def test_otp_override_forces_auth_even_when_llm_says_promo():
    otp_email = Email(
        id="test_override",
        thread_id="t",
        sender="Discount Store <promo@discountdeals.com>",
        to="alex.rivera@northwind.io",
        subject="Special offer just for you",
        date="2026-10-24T00:00:00Z",
        snippet="Your one-time passcode is 948102 to redeem.",
        body_text="Your one-time passcode is 948102 to redeem this 50% discount.",
    )

    # Even if LLM says promo, OTP override MUST force auth
    mock_llm = MagicMock(
        return_value=LLMResult(
            category="promo",
            sensitivity="low",
            injection_suspected=False,
            injection_confidence=0.0,
            reason="Promo discount email",
        )
    )

    cls, _ = classify(otp_email, llm_classifier=mock_llm, use_cache=False)
    assert cls.category == "auth"
    assert cls.sensitivity == "high"
    assert cls.source == "override"


def test_classification_caching():
    source = FixtureSource()
    e01 = source.get("e01")
    assert e01 is not None

    # First run caches result
    cls1, _ = classify(e01, use_cache=True)

    # Verify cached entry exists in SQLite
    content_hash = hashlib.sha256((e01.subject + e01.body_text).encode("utf-8")).hexdigest()
    cached = get_cached_classification(e01.id, content_hash, config.llm_model)
    assert cached is not None
    cached_cls, _ = cached
    assert cached_cls.category == "travel"

    # Second run returns from cache
    cls2, _ = classify(e01, use_cache=True)
    assert cls2.category == cls1.category
    assert cls2.source == cls1.source
