# report.py
# Generates a clean HTML report from audit findings.
# Color coded by severity — red for critical, orange for high, yellow for medium.

import json
import os
from datetime import datetime, timezone

SEVERITY_COLORS = {
    "CRITICAL": "#ff4444",
    "HIGH": "#ff8800",
    "MEDIUM": "#ffcc00",
    "UNKNOWN": "#aaaaaa"
}

def generate_html_report(findings, output_path):
    timestamp = findings.get("audit_timestamp", "Unknown")

    # Count total findings by severity
    all_findings = []
    for key, items in findings.items():
        if key == "audit_timestamp":
            continue
        if isinstance(items, list):
            all_findings.extend(items)

    critical = sum(1 for f in all_findings if f.get("Severity") == "CRITICAL")
    high = sum(1 for f in all_findings if f.get("Severity") == "HIGH")
    medium = sum(1 for f in all_findings if f.get("Severity") == "MEDIUM")
    total = len(all_findings)

    # Build finding rows
    rows = ""
    categories = {
        "mfa_violations": "MFA Violations",
        "old_access_keys": "Old Access Keys",
        "unused_users": "Unused Users",
        "wildcard_roles": "Wildcard Roles"
    }

    for key, label in categories.items():
        items = findings.get(key, [])
        if not items:
            rows += f"""
            <tr>
                <td><strong>{label}</strong></td>
                <td>—</td>
                <td>—</td>
                <td style="color: #00cc44;"><strong>Clean</strong></td>
            </tr>
            """
            continue
        for item in items:
            severity = item.get("Severity", "UNKNOWN")
            color = SEVERITY_COLORS.get(severity, "#aaaaaa")
            name = item.get("UserName") or item.get("RoleName") or "Unknown"
            issue = item.get("Issue", "Unknown issue")
            rows += f"""
            <tr>
                <td><strong>{label}</strong></td>
                <td>{name}</td>
                <td>{issue}</td>
                <td style="color: {color};"><strong>{severity}</strong></td>
            </tr>
            """

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IAM Audit Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #0f0f0f;
            color: #e0e0e0;
            margin: 0;
            padding: 40px;
        }}
        h1 {{
            color: #ffffff;
            font-size: 28px;
            margin-bottom: 4px;
        }}
        .timestamp {{
            color: #888;
            font-size: 14px;
            margin-bottom: 40px;
        }}
        .summary {{
            display: flex;
            gap: 20px;
            margin-bottom: 40px;
        }}
        .card {{
            background: #1a1a1a;
            border-radius: 8px;
            padding: 20px 30px;
            min-width: 120px;
            text-align: center;
        }}
        .card .number {{
            font-size: 36px;
            font-weight: bold;
        }}
        .card .label {{
            font-size: 13px;
            color: #888;
            margin-top: 4px;
        }}
        .critical {{ color: #ff4444; }}
        .high {{ color: #ff8800; }}
        .medium {{ color: #ffcc00; }}
        .total {{ color: #ffffff; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #1a1a1a;
            border-radius: 8px;
            overflow: hidden;
        }}
        th {{
            background: #222;
            padding: 14px 16px;
            text-align: left;
            font-size: 13px;
            color: #888;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        td {{
            padding: 14px 16px;
            border-top: 1px solid #222;
            font-size: 14px;
        }}
        tr:hover td {{
            background: #222;
        }}
    </style>
</head>
<body>
    <h1>IAM Audit Report</h1>
    <div class="timestamp">Generated: {timestamp}</div>

    <div class="summary">
        <div class="card">
            <div class="number total">{total}</div>
            <div class="label">Total Findings</div>
        </div>
        <div class="card">
            <div class="number critical">{critical}</div>
            <div class="label">Critical</div>
        </div>
        <div class="card">
            <div class="number high">{high}</div>
            <div class="label">High</div>
        </div>
        <div class="card">
            <div class="number medium">{medium}</div>
            <div class="label">Medium</div>
        </div>
    </div>

    <table>
        <thead>
            <tr>
                <th>Category</th>
                <th>Resource</th>
                <th>Issue</th>
                <th>Severity</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
</body>
</html>
"""

    with open(output_path, "w") as f:
        f.write(html)

    print(f"HTML report saved to {output_path}")