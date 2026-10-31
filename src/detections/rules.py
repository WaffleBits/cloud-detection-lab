"""Detections for CloudTrail management events, written as tested code.

Each rule names the API calls it reads, so the EventBridge filter is generated
from this file and cannot drift away from it.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

Event = dict[str, Any]

ADMIN_POLICY_SUFFIX = ":policy/AdministratorAccess"
REMOTE_ACCESS_PORTS = (22, 3389)
OPEN_CIDRS = ("0.0.0.0/0", "::/0")


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    technique: str
    event_names: tuple[str, ...]
    matches: Callable[[Event], bool]


def succeeded(event: Event) -> bool:
    return "errorCode" not in event


def request(event: Event) -> dict[str, Any]:
    return event.get("requestParameters") or {}


def identity(event: Event) -> dict[str, Any]:
    return event.get("userIdentity") or {}


def console_login_succeeded(event: Event) -> bool:
    return (event.get("responseElements") or {}).get("ConsoleLogin") == "Success"


def root_console_login(event: Event) -> bool:
    return identity(event).get("type") == "Root" and console_login_succeeded(event)


def console_login_without_mfa(event: Event) -> bool:
    used_mfa = (event.get("additionalEventData") or {}).get("MFAUsed")
    return (
        identity(event).get("type") == "IAMUser"
        and console_login_succeeded(event)
        and used_mfa == "No"
    )


def audit_logging_tampered(event: Event) -> bool:
    # A denied attempt to stop logging is as interesting as a successful one.
    return True


def access_key_for_another_user(event: Event) -> bool:
    target = request(event).get("userName")
    return succeeded(event) and bool(target) and target != identity(event).get("userName")


def admin_policy_attached(event: Event) -> bool:
    arn = request(event).get("policyArn", "")
    return succeeded(event) and arn.endswith(ADMIN_POLICY_SUFFIX)


def bucket_public_access_block_weakened(event: Event) -> bool:
    if not succeeded(event):
        return False
    if event.get("eventName") == "DeleteBucketPublicAccessBlock":
        return True
    config = request(event).get("PublicAccessBlockConfiguration") or {}
    return any(value is False for value in config.values())


def ingress_opened_to_world(event: Event) -> bool:
    if not succeeded(event):
        return False
    permissions = (request(event).get("ipPermissions") or {}).get("items") or []
    return any(_exposes_remote_access(permission) for permission in permissions)


def _exposes_remote_access(permission: dict[str, Any]) -> bool:
    low = permission.get("fromPort")
    high = permission.get("toPort")
    if permission.get("ipProtocol") == "-1":
        covers_port = True
    elif low is None or high is None:
        return False
    else:
        covers_port = any(low <= port <= high for port in REMOTE_ACCESS_PORTS)

    v4 = [r.get("cidrIp") for r in (permission.get("ipRanges") or {}).get("items") or []]
    v6 = [r.get("cidrIpv6") for r in (permission.get("ipv6Ranges") or {}).get("items") or []]
    return covers_port and any(cidr in OPEN_CIDRS for cidr in v4 + v6)


def threat_detection_disabled(event: Event) -> bool:
    if not succeeded(event):
        return False
    if event.get("eventName") == "DeleteDetector":
        return True
    return request(event).get("enable") is False


RULES: tuple[Rule, ...] = (
    Rule(
        "root-console-login",
        "Root user signed in to the console",
        "critical",
        "T1078.004",
        ("ConsoleLogin",),
        root_console_login,
    ),
    Rule(
        "console-login-without-mfa",
        "IAM user signed in without MFA",
        "medium",
        "T1078.004",
        ("ConsoleLogin",),
        console_login_without_mfa,
    ),
    Rule(
        "audit-logging-tampered",
        "CloudTrail logging was stopped, changed or deleted",
        "critical",
        "T1562.008",
        ("StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"),
        audit_logging_tampered,
    ),
    Rule(
        "access-key-for-another-user",
        "Access key created for a different IAM user",
        "high",
        "T1098.001",
        ("CreateAccessKey",),
        access_key_for_another_user,
    ),
    Rule(
        "admin-policy-attached",
        "AdministratorAccess attached to a principal",
        "high",
        "T1098.003",
        ("AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"),
        admin_policy_attached,
    ),
    Rule(
        "bucket-public-access-block-weakened",
        "S3 public access block removed or weakened",
        "high",
        "T1562.007",
        ("DeleteBucketPublicAccessBlock", "PutBucketPublicAccessBlock"),
        bucket_public_access_block_weakened,
    ),
    Rule(
        "ingress-opened-to-world",
        "SSH or RDP opened to the internet",
        "high",
        "T1562.007",
        ("AuthorizeSecurityGroupIngress",),
        ingress_opened_to_world,
    ),
    Rule(
        "threat-detection-disabled",
        "GuardDuty detector deleted or disabled",
        "critical",
        "T1562.001",
        ("DeleteDetector", "UpdateDetector"),
        threat_detection_disabled,
    ),
)


def monitored_event_names(rules: Iterable[Rule] = RULES) -> list[str]:
    return sorted({name for rule in rules for name in rule.event_names})
