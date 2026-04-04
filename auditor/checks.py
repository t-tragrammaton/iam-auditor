# checks.py
# Security check functions with severity levels and error handling.
# If one user or role causes an error, we log it and keep scanning.

from datetime import datetime, timezone, timedelta

def check_mfa(users):
    flagged = []
    errors = []

    for user in users:
        try:
            if user["MFAEnabled"] == False:
                flagged.append({
                    "UserName": user["UserName"],
                    "Issue": "MFA not enabled",
                    "Severity": "CRITICAL"
                })
        except KeyError as e:
            errors.append({
                "UserName": user.get("UserName", "unknown"),
                "Error": f"Missing field: {e}"
            })

    if errors:
        print(f"  [WARNING] {len(errors)} error(s) in check_mfa: {errors}")

    return flagged


def check_old_access_keys(users):
    flagged = []
    errors = []
    ninety_days_ago = datetime.now(timezone.utc) - timedelta(days=90)

    for user in users:
        try:
            for key in user["AccessKeys"]:
                if key["CreateDate"] < ninety_days_ago:
                    flagged.append({
                        "UserName": user["UserName"],
                        "AccessKeyId": key["AccessKeyId"],
                        "Issue": "Access key older than 90 days",
                        "Severity": "HIGH"
                    })
        except KeyError as e:
            errors.append({
                "UserName": user.get("UserName", "unknown"),
                "Error": f"Missing field: {e}"
            })

    if errors:
        print(f"  [WARNING] {len(errors)} error(s) in check_old_access_keys: {errors}")

    return flagged


def check_unused_users(users):
    flagged = []
    errors = []

    for user in users:
        try:
            if user["PasswordLastUsed"] is None:
                flagged.append({
                    "UserName": user["UserName"],
                    "Issue": "User has never logged in",
                    "Severity": "MEDIUM"
                })
        except KeyError as e:
            errors.append({
                "UserName": user.get("UserName", "unknown"),
                "Error": f"Missing field: {e}"
            })

    if errors:
        print(f"  [WARNING] {len(errors)} error(s) in check_unused_users: {errors}")

    return flagged


def check_wildcard_roles(roles):
    flagged = []
    errors = []

    for role in roles:
        try:
            for statement in role["PolicyDocument"]["Statement"]:
                if statement["Action"] == "*" and statement["Resource"] == "*":
                    flagged.append({
                        "RoleName": role["RoleName"],
                        "Issue": "Role has wildcard * permissions",
                        "Severity": "CRITICAL"
                    })
        except KeyError as e:
            errors.append({
                "RoleName": role.get("RoleName", "unknown"),
                "Error": f"Missing field: {e}"
            })

    if errors:
        print(f"  [WARNING] {len(errors)} error(s) in check_wildcard_roles: {errors}")

    return flagged