"""Synthetic CloudTrail records. Account IDs and addresses are documentation values."""

ACCOUNT = "111122223333"


def record(name, *, user="alice", kind="IAMUser", **fields):
    event = {
        "eventVersion": "1.10",
        "eventID": f"evt-{name}",
        "eventName": name,
        "eventTime": "2026-10-31T12:00:00Z",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.10",
        "recipientAccountId": ACCOUNT,
        "userIdentity": {
            "type": kind,
            "userName": user,
            "arn": f"arn:aws:iam::{ACCOUNT}:user/{user}",
        },
    }
    event.update(fields)
    return event


def login(mfa="Yes", result="Success", **kwargs):
    return record(
        "ConsoleLogin",
        responseElements={"ConsoleLogin": result},
        additionalEventData={"MFAUsed": mfa},
        **kwargs,
    )


def ingress(cidr="0.0.0.0/0", port=22, protocol="tcp", **fields):
    permission = {
        "ipProtocol": protocol,
        "fromPort": port,
        "toPort": port,
        "ipRanges": {"items": [{"cidrIp": cidr}]},
    }
    return record(
        "AuthorizeSecurityGroupIngress",
        requestParameters={"groupId": "sg-1", "ipPermissions": {"items": [permission]}},
        **fields,
    )


def block_config(**values):
    return record(
        "PutBucketPublicAccessBlock",
        requestParameters={"bucketName": "b", "PublicAccessBlockConfiguration": values},
    )


ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
READ_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"

# rule id -> (attack events that must alert, benign events that must not)
CASES = {
    "root-console-login": (
        [login(kind="Root", user=None)],
        [
            login(),
            login(kind="Root", user=None, result="Failure"),
        ],
    ),
    "console-login-without-mfa": (
        [login(mfa="No")],
        [
            login(mfa="Yes"),
            login(mfa="No", result="Failure"),
            login(mfa="No", kind="AssumedRole"),
        ],
    ),
    "audit-logging-tampered": (
        [
            record("StopLogging"),
            record("DeleteTrail"),
            record("UpdateTrail"),
            record("PutEventSelectors"),
            record("StopLogging", errorCode="AccessDenied"),
        ],
        [record("StartLogging"), record("DescribeTrails")],
    ),
    "access-key-for-another-user": (
        [record("CreateAccessKey", requestParameters={"userName": "bob"})],
        [
            record("CreateAccessKey", requestParameters={"userName": "alice"}),
            record("CreateAccessKey", requestParameters={}),
            record(
                "CreateAccessKey",
                requestParameters={"userName": "bob"},
                errorCode="AccessDenied",
            ),
        ],
    ),
    "admin-policy-attached": (
        [
            record("AttachUserPolicy", requestParameters={"policyArn": ADMIN_ARN}),
            record("AttachRolePolicy", requestParameters={"policyArn": ADMIN_ARN}),
            record("AttachGroupPolicy", requestParameters={"policyArn": ADMIN_ARN}),
        ],
        [
            record("AttachUserPolicy", requestParameters={"policyArn": READ_ARN}),
            record(
                "AttachUserPolicy",
                requestParameters={"policyArn": ADMIN_ARN},
                errorCode="AccessDenied",
            ),
        ],
    ),
    "bucket-public-access-block-weakened": (
        [
            record("DeleteBucketPublicAccessBlock", requestParameters={"bucketName": "b"}),
            block_config(BlockPublicAcls=False, BlockPublicPolicy=True),
        ],
        [block_config(BlockPublicAcls=True, BlockPublicPolicy=True)],
    ),
    "ingress-opened-to-world": (
        [
            ingress(),
            ingress(port=3389),
            ingress(protocol="-1", port=None),
        ],
        [
            ingress(cidr="198.51.100.0/24"),
            ingress(port=443),
            ingress(errorCode="UnauthorizedOperation"),
        ],
    ),
    "threat-detection-disabled": (
        [
            record("DeleteDetector", requestParameters={"detectorId": "d"}),
            record("UpdateDetector", requestParameters={"detectorId": "d", "enable": False}),
        ],
        [record("UpdateDetector", requestParameters={"detectorId": "d", "enable": True})],
    ),
}
