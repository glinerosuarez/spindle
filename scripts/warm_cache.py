"""Warms the SQLite classification cache for all demo inbox fixtures."""

import time
from spindle.classifier import classify
from spindle.config import config
from spindle.injection import inspect
from spindle.sources import FixtureSource
from spindle.store import init_db


def main():
    print(f"=== Spindle Cache Warmer ===")
    print(f"LLM Base URL: {config.llm_base_url}")
    print(f"LLM Model:    {config.llm_model}")
    print(f"LLM Enabled:  {config.llm_enabled}")

    init_db()
    source = FixtureSource()
    emails = source.search("", limit=100)
    print(f"\nFound {len(emails)} fixture emails to classify and cache...\n")

    latencies = []
    t_start_total = time.time()

    print(f"{'ID':<5} | {'Category':<10} | {'Sens':<7} | {'Source':<10} | {'Latency':<8} | {'Quar':<5} | Subject")
    print("-" * 80)

    for email in emails:
        t0 = time.time()
        # use_cache=False for the initial run to force classification, then caches
        cls, llm_res = classify(email, use_cache=True)
        dt = time.time() - t0
        latencies.append(dt)

        inj = inspect(email, llm_res)
        quar_str = "YES" if inj.quarantine else "no"

        print(
            f"{email.id:<5} | {cls.category:<10} | {cls.sensitivity:<7} | "
            f"{cls.source:<10} | {dt:6.2f}s | {quar_str:<5} | {email.subject[:35]}"
        )

    total_time = time.time() - t_start_total
    avg_lat = sum(latencies) / len(latencies) if latencies else 0.0

    print("-" * 80)
    print(f"Warmed {len(emails)} fixtures in {total_time:.2f}s (avg {avg_lat:.2f}s/email).")
    print("Cache is ready. Demo will now execute with zero network delay.")


if __name__ == "__main__":
    main()
