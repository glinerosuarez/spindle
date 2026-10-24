"""Smoke test for LLM classification on 3 fixture emails."""

import json
import sys
import time
from spindle.config import config
from spindle.llm import classify_email
from spindle.sources import FixtureSource


def main():
    print(f"Connecting to LLM at {config.llm_base_url} (model: {config.llm_model})...")
    source = FixtureSource()
    fixtures_to_test = ["e01", "e16", "e17"]

    for email_id in fixtures_to_test:
        email = source.get(email_id)
        if not email:
            print(f"Error: Email {email_id} not found in fixtures.")
            continue

        print(f"\n--- Testing [{email.id}] {email.subject} ---")
        t0 = time.time()
        result = classify_email(email)
        dt = time.time() - t0

        if result:
            print(f"Success in {dt:.2f}s:")
            print(json.dumps(result.model_dump(), indent=2))
        else:
            print(f"Failed or returned None after {dt:.2f}s.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
