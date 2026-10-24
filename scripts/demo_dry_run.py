"""End-to-end dry run script for Spindle 2-minute demo beats (§10 of PLAN.md).

Tests 3 consecutive clean runs from a fresh ~/.spindle.
"""

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

# Ensure spindle is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from spindle.config import config
from spindle.gateway import search, read
from spindle.store import get_connection, init_db, decide_approval_request
from spindle.policy import load_policy, save_policy
from spindle.policy_assistant import compute_policy_diff, Change
from spindle.models import PolicyFile, AgentPolicy


def run_single_demo_cycle(cycle_num: int):
    print(f"\n=======================================================")
    print(f"  STARTING DEMO RUN CYCLE #{cycle_num}")
    print(f"=======================================================\n")

    spindle_home = config.home
    # Clear directory contents without removing parent if it causes issues
    if spindle_home.exists():
        shutil.rmtree(spindle_home)
    spindle_home.mkdir(parents=True, exist_ok=True)

    # 1. Initialize DB and default policies
    app_dir = Path(__file__).resolve().parent.parent
    default_yaml = app_dir / "policies" / "default.yaml"
    if default_yaml.exists():
        shutil.copyfile(default_yaml, spindle_home / "policies.yaml")
    init_db()
    print("✓ Initialized fresh ~/.spindle directory and schema.")

    # 2. Warm cache
    res = subprocess.run(
        [sys.executable, "scripts/warm_cache.py"],
        cwd=str(Path(__file__).resolve().parent.parent),
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"warm_cache failed: {res.stderr}"
    print("✓ Cache warmed successfully.")

    # 3. Beat 1: "Before" - Unprotected Agent
    print("\n--- Beat 1: Unprotected Agent (Passthrough) ---")
    before_output = search("unprotected", query="", timeout=1.0)
    assert 'unfiltered passthrough access for agent "unprotected"' in before_output, "Missing passthrough header"
    assert "482913" in before_output, "OTP must be exposed in unprotected mode"
    print("✓ Unprotected agent received raw emails including OTP '482913'.")

    conn = get_connection()
    passthrough_audits = conn.execute(
        "SELECT * FROM audit WHERE agent = 'unprotected' AND action = 'passthrough'"
    ).fetchall()
    assert len(passthrough_audits) > 0, "No audit records for unprotected agent"
    print(f"✓ Dashboard recorded {len(passthrough_audits)} UNPROTECTED passthrough events with exposed chips.")
    conn.close()

    # 4. Beat 2: "After" - Work Agent
    print("\n--- Beat 2: Work Agent (Governed) ---")
    # Search with a 1.0s timeout to allow ask requests to register as pending
    after_output = search("work-agent", query="", timeout=1.0)
    assert "Withheld by policy:" in after_output, "Missing withheld section"
    assert "health (denied by user policy)" in after_output, "Health not withheld"
    assert "auth (denied by user policy)" in after_output, "Auth not withheld"
    assert "Quarantined:" in after_output, "Quarantine missing"
    assert "it-compliance@northwind-it.co" in after_output, "e15 injection not quarantined"
    assert "Pending approval:" in after_output, "Pending approval section missing"
    assert "482913" not in after_output, "OTP leaked into work agent output!"
    print("✓ Work agent protected: auth & health withheld, prompt injections quarantined, finance/personal pending.")

    conn = get_connection()
    pending = conn.execute("SELECT * FROM approval_requests WHERE status = 'pending'").fetchall()
    assert len(pending) > 0, "Expected at least 1 pending approval request"
    req_id = pending[0]["id"]
    print(f"✓ Created pending approval request #{req_id} for user approval queue.")
    conn.close()

    # 5. Beat 3: Approval
    print("\n--- Beat 3: Dashboard Approval ---")
    decide_approval_request(req_id, "approved")
    approved_read = read("work-agent", "e03")
    assert "[REDACTED:bank_account]" in approved_read, "Bank account was not redacted after approval"
    print("✓ Approved request released e03 to work agent with bank account safely redacted.")

    # Search now shows approved email
    approved_search = search("work-agent", query="")
    assert "Your October statement is ready   (approved by user)" in approved_search, "Approved search tag missing"
    print("✓ Subsequent search clearly marks approved items: '(approved by user)'.")

    # 6. Beat 4: Policy Assistant & Loosening Detection
    print("\n--- Beat 4: Policy Assistant Plain English Update ---")
    current_policies = load_policy()
    work_policy = current_policies.agents["work-agent"]

    # Test loosening detection: loosening finance to allow
    loosened_policies = PolicyFile(
        agents=dict(current_policies.agents),
    )
    loosened_work_policy = AgentPolicy(
        description=work_policy.description,
        passthrough=work_policy.passthrough,
        protection_level=work_policy.protection_level,
        access=dict(work_policy.access),
        custom_rules=list(work_policy.custom_rules),
        max_results=work_policy.max_results,
    )
    loosened_work_policy.access["finance"] = "allow"
    loosened_policies.agents["work-agent"] = loosened_work_policy

    changes = compute_policy_diff(current_policies, loosened_policies)
    loosening_changes = [c for c in changes if c.is_loosening]
    assert len(loosening_changes) > 0, "Loosening warning for finance not triggered"
    assert any("finance" in c.field for c in loosening_changes), "Finance loosening field missing"
    print(f"✓ Policy assistant correctly flagged loosening change: {[c.description for c in loosening_changes]}")

    print(f"\n✓✓ Cycle #{cycle_num} completed successfully with zero errors!")


def main():
    print("=================================================================")
    print(" SPINDLE END-TO-END DRY RUN VALIDATION (3 CONSECUTIVE RUNS)")
    print("=================================================================")
    
    t_start = time.time()
    for cycle in range(1, 4):
        run_single_demo_cycle(cycle)

    total_time = time.time() - t_start
    print("\n=================================================================")
    print(f" ALL 3 DEMO CYCLES PASSED PERFECTLY IN {total_time:.2f}s!")
    print("=================================================================\n")


if __name__ == "__main__":
    main()
