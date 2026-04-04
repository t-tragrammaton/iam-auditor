# main.py
# Entry point. Now uses IAMAuditor class instead of loose functions.

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

from auditor.engine import IAMAuditor
from auditor.report import generate_html_report

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
    # Step 1 — Get data
    try:
        print("Fetching IAM data...")
        raw_users = get_users()
        raw_roles = get_roles()
        print(f"Found {len(raw_users)} users and {len(raw_roles)} roles.\n")
    except Exception as e:
        print(f"[FATAL] Failed to fetch IAM data: {e}")
        print("Check your AWS credentials and permissions.")
        return

    # Step 2 — Run all checks using the auditor class
    auditor = IAMAuditor(raw_users, raw_roles)
    findings = auditor.run_all_checks()

    # Step 3 — Add timestamp
    findings["audit_timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Step 4 — Print results
    print("\n=== IAM AUDIT RESULTS ===\n")
    print(f"Total findings: {auditor.total_findings()}")
    print(f"Critical: {auditor.critical_count()}\n")

    for category, results in findings.items():
        if category == "audit_timestamp":
            print(f"Audit run at: {results}\n")
        else:
            print(f"[{category.upper()}]")
            print_findings(category, results)
            print()

    # Step 5 — Save JSON report
    try:
        output_path = os.path.join("output", "audit_report.json")
        with open(output_path, "w") as f:
            json.dump(findings, f, indent=4, default=str)
        print(f"Report saved to {output_path}")
    except Exception as e:
        print(f"[ERROR] Failed to save report: {e}")

    # Step 6 — Save HTML report
    try:
        html_path = os.path.join("output", "audit_report.html")
        generate_html_report(findings, html_path)
    except Exception as e:
        print(f"[ERROR] Failed to generate HTML report: {e}")

run_audit()