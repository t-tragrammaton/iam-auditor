# models.py
# Data classes for IAM users and roles.
# These replace raw dictionaries with objects that know how to describe themselves.

from datetime import datetime, timezone, timedelta

class IAMUser:
    def __init__(self, data):
        self.username = data["UserName"]
        self.user_id = data["UserId"]
        self.mfa_enabled = data["MFAEnabled"]
        self.password_last_used = data["PasswordLastUsed"]
        self.access_keys = data["AccessKeys"]

    def has_mfa(self):
        return self.mfa_enabled

    def has_never_logged_in(self):
        return self.password_last_used is None

    def get_old_keys(self, days=90):
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        return [
            key for key in self.access_keys
            if key["CreateDate"] < cutoff
        ]

    def to_dict(self):
        return {
            "UserName": self.username,
            "UserId": self.user_id,
            "MFAEnabled": self.mfa_enabled,
            "PasswordLastUsed": str(self.password_last_used),
            "AccessKeyCount": len(self.access_keys)
        }


class IAMRole:
    def __init__(self, data):
        self.role_name = data["RoleName"]
        self.role_id = data["RoleId"]
        self.statements = data["PolicyDocument"]["Statement"]

    def has_wildcard_permissions(self):
        for statement in self.statements:
            if statement["Action"] == "*" and statement["Resource"] == "*":
                return True
        return False

    def to_dict(self):
        return {
            "RoleName": self.role_name,
            "RoleId": self.role_id,
            "StatementCount": len(self.statements)
        }