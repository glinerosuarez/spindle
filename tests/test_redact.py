from spindle.models import CustomRule
from spindle.redact import luhn_check, redact, scan


def test_plain_text_unchanged():
    text = "The quick brown fox jumps over the lazy dog."
    result, redactions = redact(text, level="strict")
    assert result == text
    assert len(redactions) == 0


def test_luhn_check():
    # Valid Visa test card
    assert luhn_check("4111 1111 1111 1111") is True
    assert luhn_check("4111-1111-1111-1111") is True
    assert luhn_check("4111111111111111") is True
    # Invalid card (last digit altered)
    assert luhn_check("4111 1111 1111 1112") is False
    # Too short / too long
    assert luhn_check("12345") is False


def test_card_redaction_and_luhn_failure():
    # Valid card should be redacted
    text_valid = "Payment with 4111 1111 1111 1111 card."
    res_valid, red_valid = redact(text_valid, level="light")
    assert "[REDACTED:card]" in res_valid
    assert any(r.type == "card" and r.count == 1 for r in red_valid)

    # Invalid card number should NOT be redacted as card
    text_invalid = "Random digits 4111 1111 1111 1112 here."
    res_invalid, red_invalid = redact(text_invalid, level="light")
    assert "[REDACTED:card]" not in res_invalid
    assert not any(r.type == "card" for r in red_invalid)


def test_every_redaction_type():
    # 1. auth_link
    t1 = "Click here: https://example.com/auth/reset?token=abc123xyz"
    r1, d1 = redact(t1, level="light")
    assert "[REDACTED:auth_link]" in r1

    # 2. otp
    t2 = "Your verification code is 849201 for login."
    r2, d2 = redact(t2, level="light")
    assert "[REDACTED:otp]" in r2

    t2_subj = "482913 is your Chase verification code"
    r2_s, _ = redact(t2_subj, level="light")
    assert r2_s.startswith("[REDACTED:otp]")

    # 3. api_key / password
    t3 = "api_key: sk-proj-1234567890abcdef"
    r3, d3 = redact(t3, level="light")
    assert "[REDACTED:api_key]" in r3

    t3_pw = "password: secretPassword123"
    r3_p, _ = redact(t3_pw, level="light")
    assert "[REDACTED:api_key]" in r3_p

    # 4. card
    t4 = "Charged to 4111111111111111"
    r4, d4 = redact(t4, level="light")
    assert "[REDACTED:card]" in r4

    # 5. ssn
    t5 = "SSN is 123-45-6789."
    r5, d5 = redact(t5, level="light")
    assert "[REDACTED:ssn]" in r5

    # 6. routing_number (standard, strict)
    t6 = "Bank routing number: 021000021."
    r6_light, _ = redact(t6, level="light")
    assert "021000021" in r6_light  # light does not redact routing
    r6_std, d6 = redact(t6, level="standard")
    assert "[REDACTED:routing_number]" in r6_std

    # 7. bank_account (standard, strict)
    t7 = "Checking account 482910394821 is active."
    r7_std, d7 = redact(t7, level="standard")
    assert "[REDACTED:bank_account]" in r7_std

    # 8. medical_record (standard, strict)
    t8 = "Patient MRN: MRN-902104."
    r8_std, d8 = redact(t8, level="standard")
    assert "[REDACTED:medical_record]" in r8_std

    # 9. insurance_id (standard, strict)
    t9 = "Subscriber Member ID: XEH892019481"
    r9_std, d9 = redact(t9, level="standard")
    assert "[REDACTED:insurance_id]" in r9_std

    # 10. medication (standard, strict)
    t10 = "Prescribed metformin 500 mg daily."
    r10_std, d10 = redact(t10, level="standard")
    assert "[REDACTED:medication]" in r10_std

    # 11. dob (standard, strict)
    t11 = "Patient DOB: 04/15/1985."
    r11_std, d11 = redact(t11, level="standard")
    assert "[REDACTED:dob]" in r11_std

    # 12. street_address (standard, strict)
    t12 = "Visit us at 250 Beach Street, Apt 4B, San Francisco."
    r12_std, d12 = redact(t12, level="standard")
    assert "[REDACTED:street_address]" in r12_std

    # 13. phone (standard, strict)
    t13 = "Call us at (415) 555-0198."
    r13_light, _ = redact(t13, level="light")
    assert "(415) 555-0198" in r13_light  # light keeps phone
    r13_std, d13 = redact(t13, level="standard")
    assert "[REDACTED:phone]" in r13_std

    # 14. email_address (strict only)
    t14 = "Contact support@northwind.io for help."
    r14_std, _ = redact(t14, level="standard")
    assert "support@northwind.io" in r14_std  # standard keeps email
    r14_strict, d14 = redact(t14, level="strict")
    assert "[REDACTED:email_address]" in r14_strict

    # 15. url (strict only)
    t15 = "Check documentation at https://northwind.io/docs"
    r15_std, _ = redact(t15, level="standard")
    assert "https://northwind.io/docs" in r15_std
    r15_strict, d15 = redact(t15, level="strict")
    assert "[REDACTED:url]" in r15_strict

    # 16. zip (strict only)
    t16 = "Located in CA 94133-1234."
    r16_std, _ = redact(t16, level="standard")
    assert "94133-1234" in r16_std
    r16_strict, d16 = redact(t16, level="strict")
    assert "[REDACTED:zip]" in r16_strict


def test_custom_rules():
    custom = [
        CustomRule(
            name="compensation",
            pattern=r"(?i)\$\s?\d{2,3}(?:,\d{3})+(?:\s?(?:/yr|per year|base|salary))?",
        )
    ]
    text = "We are offering $185,000 base for this role."
    res, redactions = redact(text, level="standard", custom_rules=custom)
    assert "[REDACTED:compensation]" in res
    assert any(r.type == "compensation" and r.count == 1 for r in redactions)


def test_scan_function():
    text = "Call (415) 555-0198 or email test@example.com for SSN 123-45-6789."
    redactions = scan(text)
    types = {r.type for r in redactions}
    assert "phone" in types
    assert "email_address" in types
    assert "ssn" in types
    # Ensure text is not mutated
    assert "123-45-6789" in text
