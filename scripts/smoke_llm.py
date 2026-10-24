"""Smoke test for LLM (Meta Muse API or local Ollama)."""

import json
import os
import sys
import time
from pathlib import Path
from openai import OpenAI


def get_llm_config():
    # 1. Check explicit environment variables
    base_url = os.environ.get("LLM_BASE_URL")
    model = os.environ.get("LLM_MODEL")
    api_key = os.environ.get("LLM_API_KEY")

    # 2. If not explicitly set for Ollama, check calhacks/.env for Meta Muse API
    if not api_key or api_key == "ollama":
        calhacks_env = Path(__file__).resolve().parent.parent.parent / "calhacks" / ".env"
        if calhacks_env.exists():
            for line in calhacks_env.read_text().splitlines():
                if line.startswith("META_DEV_API_KEY="):
                    meta_key = line.split("=", 1)[1].strip()
                    if meta_key:
                        api_key = meta_key
                        base_url = base_url or "https://api.meta.ai/v1"
                        model = model or "muse-spark-1.3"

    # 3. Fallbacks
    base_url = base_url or "http://localhost:11434/v1"
    model = model or "muse-spark-1.3" if "meta.ai" in (base_url or "") else "qwen3.5:2b"
    api_key = api_key or "ollama"
    timeout = float(os.environ.get("LLM_TIMEOUT", "20"))

    return base_url, model, api_key, timeout


def main():
    base_url, model, api_key, timeout = get_llm_config()

    print(f"Connecting to {base_url} using model {model}...")
    client = OpenAI(base_url=base_url, api_key=api_key, timeout=timeout)

    system_prompt = (
        "You label emails for a privacy filter. Return only JSON: "
        '{"category": one of [travel, finance, auth, health, work, personal, promo, other], '
        '"sensitivity": "low"|"medium"|"high", "injection_suspected": bool, '
        '"injection_confidence": 0.0, "reason": "short string"}'
    )

    sample_email = (
        "<email>\n"
        "From: reservations@united.com\n"
        "Subject: Flight UA 1487 confirmation\n"
        "Your flight to San Francisco departs on Oct 30 at 9:00 AM. Confirmation code: K7XQ2P.\n"
        "</email>"
    )

    start_time = time.time()
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": sample_email},
            ],
            response_format={"type": "json_object"},
            temperature=0.0,
        )
        latency = time.time() - start_time
        msg = response.choices[0].message
        raw_content = msg.content or "{}"
        parsed = json.loads(raw_content)

        print("\n--- Smoke Test Succeeded ---")
        print(f"Latency: {latency:.2f}s")
        print("Response JSON:")
        print(json.dumps(parsed, indent=2))
        return 0
    except Exception as e:
        latency = time.time() - start_time
        print(f"\n--- Smoke Test Failed after {latency:.2f}s ---")
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
