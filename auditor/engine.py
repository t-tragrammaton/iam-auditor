# engine.py
# IAMAuditor class that runs all security checks.
# Takes User and Role objects and returns structured findings.

from auditor.models import IAMUser, IAMRole

class IAMAuditor:
    def __init__(self, raw_users, raw_roles):
        # Convert raw dictionaries into proper objects
        self.users = [IAMUser(u) for u in raw_users]
        self.roles = [IAMRole(r) for r in raw_roles]
        self.findings = {
            "mfa_violations": [],
            "old_access_keys": [],
            "unused_users": [],
            "wildcard_roles": []
        }

    def check_mfa(self):
        for user in self.users:
            try:
                if not user.has_mfa():
                    self.findings["mfa_violations"].append({
                        "UserName": user.username,
                        "Issue": "MFA not enabled",
                        "Severity": "CRITICAL"
                    })
            except Exception as e:
                print(f"  [ERROR] MFA check failed for {user.username}: {e}")
        return self

    def check_old_access_keys(self):
        for user in self.users:
            try:
                old_keys = user.get_old_keys(days=90)
                for key in old_keys:
                    self.findings["old_access_keys"].append({
                        "UserName": user.username,
                        "AccessKeyId": key["AccessKeyId"],
                        "Issue": "Access key older than 90 days",
                        "Severity": "HIGH"
                    })
            except Exception as e:
                print(f"  [ERROR] Key check failed for {user.username}: {e}")
        return self

    def check_unused_users(self):
        for user in self.users:
            try:
                if user.has_never_logged_in():
                    self.findings["unused_users"].append({
                        "UserName": user.username,
                        "Issue": "User has never logged in",
                        "Severity": "MEDIUM"
                    })
            except Exception as e:
                print(f"  [ERROR] Unused user check failed for {user.username}: {e}")
        return self

    def check_wildcard_roles(self):
        for role in self.roles:
            try:
                if role.has_wildcard_permissions():
                    self.findings["wildcard_roles"].append({
                        "RoleName": role.role_name,
                        "Issue": "Role has wildcard * permissions",
                        "Severity": "CRITICAL"
                    })
            except Exception as e:
                print(f"  [ERROR] Wildcard check failed for {role.role_name}: {e}")
        return self

    def run_all_checks(self):
        print("Running security checks...")
        self.check_mfa()
        self.check_old_access_keys()
        self.check_unused_users()
        self.check_wildcard_roles()
        return self.findings

    def total_findings(self):
        return sum(len(v) for v in self.findings.values() if isinstance(v, list))

    def critical_count(self):
        count = 0
        for items in self.findings.values():
            if not isinstance(items, list):
                continue
            for item in items:
                if isinstance(item, dict) and item.get("Severity") == "CRITICAL":
                    count += 1
        return count