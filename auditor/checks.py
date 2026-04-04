# checks.py
# Security check functions with severity levels.

from datetime import datetime, timezone, timedelta

def check_mfa(users):
    flagged = []
    for user in users:
        if user["MFAEnabled"] == False:
            flagged.append({
                "UserName": user["UserName"],
                "Issue": "MFA not enabled",
                "Severity": "CRITICAL"
            })
    return flagged

def check_old_access_keys(users):
    flagged = []
    ninety_days_ago = datetime.now(timezone.utc) - timedelta(days=90)
    for user in users:
        for key in user["AccessKeys"]:
            if key["CreateDate"] < ninety_days_ago:
                flagged.append({
                    "UserName": user["UserName"],
                    "AccessKeyId": key["AccessKeyId"],
                    "Issue": "Access key older than 90 days",
                    "Severity": "HIGH"
                })
    return flagged

def check_unused_users(users):
    flagged = []
    for user in users:
        if user["PasswordLastUsed"] is None:
            flagged.append({
                "UserName": user["UserName"],
                "Issue": "User has never logged in",
                "Severity": "MEDIUM"
            })
    return flagged

def check_wildcard_roles(roles):
    flagged = []
    for role in roles:
        for statement in role["PolicyDocument"]["Statement"]:
            if statement["Action"] == "*" and statement["Resource"] == "*":
                flagged.append({
                    "RoleName": role["RoleName"],
                    "Issue": "Role has wildcard * permissions",
                    "Severity": "CRITICAL"
                })
    return flagged