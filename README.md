# IAM Auditor

A Python script that audits AWS IAM configurations and flags security issues.

## What it checks
- Users with no MFA enabled
- Access keys older than 90 days
- Unused accounts (never logged in)
- Roles with wildcard * permissions

## Output
Generates a JSON report saved to the output/ folder.

## Structure
- auditor/mock_data.py — simulated AWS IAM data
- auditor/checks.py — security check functions
- main.py — entry point, runs all checks and saves report

## Phase 2 (complete)
Replacing mock data with live boto3 calls against a real AWS account.
