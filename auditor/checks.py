# checks.py
# This file contains the security check functions.
# Each function takes the AWS data and looks for one specific problem.

from datetime import datetime, timezone, timedelta

def check_mfa(users):
    # Returns a list of users who do not have MFA enabled
    flagged = []

    for user in users:
        if user["MFAEnabled"] == False:
            flagged.append({
                "UserName": user["UserName"],
                "Issue": "MFA not enabled"
            })

    return flagged

def check_old_access_keys(users):
    # Returns a list of users whose access keys are older than 90 days
    flagged = []
    ninety_days_ago = datetime.now(timezone.utc) - timedelta(days=90)

    for user in users:
        for key in user["AccessKeys"]:
            if key["CreateDate"] < ninety_days_ago:
                flagged.append({
                    "UserName": user["UserName"],
                    "AccessKeyId": key["AccessKeyId"],
                    "Issue": "Access key older than 90 days"
                })

    return flagged

def check_unused_users(users):
    # Returns a list of users who have never logged in
    flagged = []

    for user in users:
        if user["PasswordLastUsed"] is None:
            flagged.append({
                "UserName": user["UserName"],
                "Issue": "User has never logged in"
            })

    return flagged

def check_wildcard_roles(roles):
    # Returns a list of roles that have wildcard * permissions
    flagged = []

    for role in roles:
        for statement in role["PolicyDocument"]["Statement"]:
            if statement["Action"] == "*" and statement["Resource"] == "*":
                flagged.append({
                    "RoleName": role["RoleName"],
                    "Issue": "Role has wildcard * permissions"
                })

    return flagged