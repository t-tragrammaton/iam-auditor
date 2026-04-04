\# IAM Auditor

A Python security tool that audits AWS IAM configurations and flags misconfigurations by severity.

\## What it checks

| Check | Severity |
|---|---|
| Users with no MFA enabled | CRITICAL |
| Roles with wildcard `*` permissions | CRITICAL |
| Access keys older than 90 days | HIGH |
| Accounts that have never logged in | MEDIUM |

\## Output

Prints findings to terminal sorted by severity and saves a full JSON report to `output/audit_report.json`.

\## How to run it

\**1. Clone the repo**

`git clone https://github.com/aljinns/iam-auditor.git`

`cd iam-auditor`

\**2. Create a virtual environment and install dependencies**

`python -m venv venv`

`venv\Scripts\activate`

`pip install -r requirements.txt`

\**3. Run with mock data (no AWS account needed)**

`python main.py`

\**4. Run against a live AWS account**

Set `USE_MOCK_DATA = False` in `main.py`, then configure AWS credentials and run `python main.py`

\## Project structure

- `auditor/mock_data.py` — Simulated IAM data for local testing
- `auditor/aws_data.py` — Live boto3 calls against real AWS account
- `auditor/checks.py` — Security check functions
- `output/` — JSON reports saved here
- `main.py` — Entry point
- `requirements.txt` — Dependencies

\## Status

- [x] Mock data mode
- [x] Real boto3 integration
- [ ] HTML report output
- [ ] Scheduled runs via Lambda
