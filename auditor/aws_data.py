# aws_data.py
# This file replaces mock_data.py when we have real AWS credentials.
# It uses boto3 to pull live IAM data from your AWS account.

import boto3
from datetime import datetime, timezone

def get_aws_users():
    # Create a connection to AWS IAM
    iam = boto3.client("iam")

    users = []
    
    # Get all IAM users in the account
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            
            # Check if MFA is enabled for this user
            mfa_devices = iam.list_mfa_devices(UserName=user["UserName"])
            mfa_enabled = len(mfa_devices["MFADevices"]) > 0

            # Get access keys for this user
            keys_response = iam.list_access_keys(UserName=user["UserName"])
            access_keys = []
            for key in keys_response["AccessKeyMetadata"]:
                access_keys.append({
                    "AccessKeyId": key["AccessKeyId"],
                    "Status": key["Status"],
                    "CreateDate": key["CreateDate"]
                })

            users.append({
                "UserName": user["UserName"],
                "UserId": user["UserId"],
                "MFAEnabled": mfa_enabled,
                "PasswordLastUsed": user.get("PasswordLastUsed", None),
                "AccessKeys": access_keys
            })

    return users


def get_aws_roles():
    # Create a connection to AWS IAM
    iam = boto3.client("iam")

    roles = []

    # Get all IAM roles in the account
    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page["Roles"]:
            
            # Get the policies attached to this role
            attached = iam.list_attached_role_policies(RoleName=role["RoleName"])
            statements = []

            for policy in attached["AttachedPolicies"]:
                # Get the actual policy document
                policy_detail = iam.get_policy(PolicyArn=policy["PolicyArn"])
                version_id = policy_detail["Policy"]["DefaultVersionId"]
                policy_version = iam.get_policy_version(
                    PolicyArn=policy["PolicyArn"],
                    VersionId=version_id
                )
                document = policy_version["PolicyVersion"]["Document"]
                statements.extend(document["Statement"])

            roles.append({
                "RoleName": role["RoleName"],
                "RoleId": role["RoleId"],
                "PolicyDocument": {
                    "Statement": statements
                }
            })

    return roles