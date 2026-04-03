# main.py
# This is the entry point. It runs everything and saves the report.

import json
import os
from datetime import datetime, timezone
from auditor.mock_data import get_mock_users, get_mock_roles
from auditor.checks import check_mfa, check_old_access_keys, check_unused_users, check_wildcard_roles

def run_audit():
    # Step 1 — Get the data
    users = get_mock_users()
    roles = get_mock_roles()

    # Step 2 — Run every check
    findings = {
        "audit_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "mfa_violations": check_mfa(users),
        "old_access_keys": check_old_access_keys(users),
        "unused_users": check_unused_users(users),
        "wildcard_roles": check_wildcard_roles(roles)
    }

    # Step 3 — Print results to terminal
    print("\n=== IAM AUDIT RESULTS ===\n")
    for category, results in findings.items():
        if category == "audit_timestamp":
            print(f"Audit run at: {results}\n")
        else:
            print(f"[{category.upper()}]")
            if results:
                for item in results:
                    print(f"  - {item}")
            else:
                print("  No issues found")
            print()

    # Step 4 — Save report to output folder
    output_path = os.path.join("output", "audit_report.json")
    with open(output_path, "w") as f:
        json.dump(findings, f, indent=4, default=str)

    print(f"Report saved to {output_path}")

run_audit()