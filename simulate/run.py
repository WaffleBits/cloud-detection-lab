"""Trigger the detections with real API calls in your own lab account.

Prints the plan by default. With --execute it runs each step and always removes
what it created. It refuses to run against any account but the one you name.

    python simulate/run.py --account-id 123456789012 --trail lab-trail --execute
"""

from __future__ import annotations

import argparse
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

ADMIN_POLICY = "arn:aws:iam::aws:policy/AdministratorAccess"


@dataclass(frozen=True)
class Step:
    expected_alert: str
    description: str
    run: Callable[[Any, dict[str, Any]], None]
    undo: Callable[[Any, dict[str, Any]], None]


def create_key(session: Any, state: dict[str, Any]) -> None:
    iam = session.client("iam")
    iam.create_user(UserName=state["user"])
    state["key"] = iam.create_access_key(UserName=state["user"])["AccessKey"]["AccessKeyId"]


def delete_key(session: Any, state: dict[str, Any]) -> None:
    iam = session.client("iam")
    if "key" in state:
        iam.delete_access_key(UserName=state["user"], AccessKeyId=state["key"])
    iam.delete_user(UserName=state["user"])


def attach_admin(session: Any, state: dict[str, Any]) -> None:
    session.client("iam").attach_user_policy(UserName=state["user"], PolicyArn=ADMIN_POLICY)


def detach_admin(session: Any, state: dict[str, Any]) -> None:
    session.client("iam").detach_user_policy(UserName=state["user"], PolicyArn=ADMIN_POLICY)


def stop_trail(session: Any, state: dict[str, Any]) -> None:
    session.client("cloudtrail").stop_logging(Name=state["trail"])


def start_trail(session: Any, state: dict[str, Any]) -> None:
    session.client("cloudtrail").start_logging(Name=state["trail"])


def open_ssh(session: Any, state: dict[str, Any]) -> None:
    ec2 = session.client("ec2")
    group = ec2.create_security_group(
        GroupName=state["user"], Description="Detection lab simulation"
    )
    state["group"] = group["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=state["group"],
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )


def delete_group(session: Any, state: dict[str, Any]) -> None:
    if "group" in state:
        session.client("ec2").delete_security_group(GroupId=state["group"])


STEPS = (
    Step(
        "access-key-for-another-user",
        "Create a throwaway user and an access key for it",
        create_key,
        delete_key,
    ),
    Step(
        "admin-policy-attached",
        "Attach AdministratorAccess to the throwaway user",
        attach_admin,
        detach_admin,
    ),
    Step(
        "ingress-opened-to-world",
        "Open SSH to the internet on an empty security group",
        open_ssh,
        delete_group,
    ),
    Step(
        "audit-logging-tampered",
        "Stop the lab trail, then start it again",
        stop_trail,
        start_trail,
    ),
)


def assert_account(session: Any, expected: str) -> None:
    actual = session.client("sts").get_caller_identity()["Account"]
    if actual != expected:
        raise SystemExit(f"refusing to run: credentials are for account {actual}")


def execute(session: Any, state: dict[str, Any]) -> None:
    done: list[Step] = []
    try:
        for step in STEPS:
            done.append(step)
            print(f"run: {step.description} (expect {step.expected_alert})")
            step.run(session, state)
    finally:
        for step in reversed(done):
            print(f"undo: {step.description}")
            step.undo(session, state)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--trail", required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()

    if not args.execute:
        for step in STEPS:
            print(f"{step.expected_alert}: {step.description}")
        return

    import boto3

    session = boto3.Session()
    assert_account(session, args.account_id)
    execute(session, {"user": f"lab-sim-{secrets.token_hex(4)}", "trail": args.trail})


if __name__ == "__main__":
    main()
