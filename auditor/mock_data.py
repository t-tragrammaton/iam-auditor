# mock_data.py
# This file pretends to be AWS. It gives us fake IAM data to test our checks.
# Later we replace this with real boto3 calls.

from datetime import datetime, timezone, timedelta

def get_mock_users():
    return [
        {
            "UserName": "alice",
            "UserId": "AIDA000000000000ALICE",
            "MFAEnabled": True,
            "PasswordLastUsed": datetime.now(timezone.utc) - timedelta(days=10),
            "AccessKeys": [
                {
                    "AccessKeyId": "AKIA000000000000AAA1",
                    "Status": "Active",
                    "CreateDate": datetime.now(timezone.utc) - timedelta(days=20)
                }
            ]
        },
        {
            "UserName": "bob",
            "UserId": "AIDA000000000000BOBBB",
            "MFAEnabled": False,
            "PasswordLastUsed": datetime.now(timezone.utc) - timedelta(days=100),
            "AccessKeys": [
                {
                    "AccessKeyId": "AKIA000000000000BBB1",
                    "Status": "Active",
                    "CreateDate": datetime.now(timezone.utc) - timedelta(days=95)
                }
            ]
        },
        {
            "UserName": "carol",
            "UserId": "AIDA000000000000CAROL",
            "MFAEnabled": False,
            "PasswordLastUsed": None,
            "AccessKeys": []
        }
    ]

def get_mock_roles():
    return [
        {
            "RoleName": "AdminRole",
            "RoleId": "AROA000000000000ADMIN",
            "PolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*"
                    }
                ]
            }
        },
        {
            "RoleName": "ReadOnlyRole",
            "RoleId": "AROA000000000000READS",
            "PolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::my-bucket/*"
                    }
                ]
            }
        }
    ]