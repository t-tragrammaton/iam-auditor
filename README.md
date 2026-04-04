# IAM Auditor

A Python security tool that audits AWS IAM configurations and flags misconfigurations by severity.

## What it checks

| Check | Severity |
|---|---|
| Users with no MFA enabled | CRITICAL |
| Roles with wildcard `*` permissions | CRITICAL |
| Access keys older than 90 days | HIGH |
| Accounts that have never logged in | MEDIUM |

## Output

Prints findings to terminal sorted by severity and saves a full JSON report to `output/audit_report.json`.

## How to run it

**1. Clone the repo**
