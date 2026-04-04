# main.py
# Entry point. Runs all checks and saves the report.

import json
import os
from datetime import datetime, timezone

# Toggle this to switch between mock data and real AWS data
USE_MOCK_DATA = True

if USE_MOCK_DATA:
    from auditor.mock_data import get_mock_users as get_users
    from auditor.mock_data import get_mock_roles as get_roles
else:
    from auditor.aws_data import get_aws_users as get_users
    from auditor.aws_data import get_aws_roles as get_roles

from auditor.checks import check_mfa, check_old_access_keys, check_unused_users, check_wildcard_roles

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}

def print_findings(category, results):
    if not results:
        print("  No issues found")
        return
    sorted_results = sorted(results, key=lambda x: SEVERITY_ORDER.get(x.get("Severity", "MEDIUM"), 2))
    for item in sorted_results:
        severity = item.get("Severity", "UNKNOWN")
        print(f"  [{severity}] {item}")

def run_audit():
    print("Fetching IAM data...")
    users = get_users()
    roles = get_roles()
    print(f"Found {len(users)} users and {len(roles)} roles.\n")

    findings = {
        "audit_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "mfa_violations": check_mfa(users),
        "old_access_keys": check_old_access_keys(users),
        "unused_users": check_unused_users(users),
        "wildcard_roles": check_wildcard_roles(roles)
    }

    print("=== IAM AUDIT RESULTS ===\n")
    for category, results in findings.items():
        if category == "audit_timestamp":
            print(f"Audit run at: {results}\n")
        else:
            print(f"[{category.upper()}]")
            print_findings(category, results)
            print()

    output_path = os.path.join("output", "audit_report.json")
    with open(output_path, "w") as f:
        json.dump(findings, f, indent=4, default=str)

    print(f"Report saved to {output_path}")

run_audit()