"""Quick demo reset between judges that keeps the classification cache."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import spindle.policy
from spindle.config import config
from spindle.policy import load_policy
from spindle.sources import FixtureSource
from spindle.store import get_connection, init_db


def reset_demo() -> int:
    init_db()

    # 1. Reset policies to policies/default.yaml
    app_dir = Path(__file__).resolve().parent.parent
    default_yaml = app_dir / "policies" / "default.yaml"
    if default_yaml.exists():
        shutil.copyfile(default_yaml, config.policy_path)
        spindle.policy._LAST_GOOD_POLICY = None
        # Reload to ensure state is fresh
        load_policy(config.policy_path)

    # 2. Clear tables while preserving classification_cache
    conn = get_connection()
    with conn:
        audit_count = conn.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
        req_count = conn.execute("SELECT COUNT(*) FROM approval_requests").fetchone()[0]
        appr_count = conn.execute("SELECT COUNT(*) FROM approvals").fetchone()[0]
        outbox_count = conn.execute("SELECT COUNT(*) FROM outbox").fetchone()[0]

        conn.execute("DELETE FROM audit;")
        conn.execute("DELETE FROM approval_requests;")
        conn.execute("DELETE FROM approvals;")
        conn.execute("DELETE FROM outbox;")

        cache_count = conn.execute("SELECT COUNT(*) FROM classification_cache").fetchone()[0]

    conn.close()

    # 3. Check cached classifications count against fixtures
    fixtures = FixtureSource().list()
    fixture_count = len(fixtures)

    print("=== Spindle Demo Reset ===")
    print(f"Policies reset to default from: {default_yaml}")
    print(f"Cleared {audit_count} audit rows")
    print(f"Cleared {req_count} approval requests")
    print(f"Cleared {appr_count} approvals")
    print(f"Cleared {outbox_count} outbox entries")
    print(f"Preserved {cache_count} cached classifications (fixtures: {fixture_count})")

    if cache_count < fixture_count:
        print(
            f"ERROR: Cached classifications count ({cache_count}) is below fixture count ({fixture_count}). "
            f"Please run 'uv run python scripts/warm_cache.py' before the demo."
        )
        return 1

    print("Demo reset complete. Ready for next judge.")
    return 0


def main() -> None:
    code = reset_demo()
    sys.exit(code)


if __name__ == "__main__":
    main()
