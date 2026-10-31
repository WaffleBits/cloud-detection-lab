"""Turn CloudTrail events into alerts."""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any

from detections.rules import RULES, Event, Rule, identity

DENIED_CODES = ("AccessDenied", "UnauthorizedOperation", "Client.UnauthorizedOperation")
BURST_RULE = Rule(
    "denied-call-burst",
    "One principal hit repeated access denials",
    "medium",
    "T1526",
    (),
    lambda event: False,
)


@dataclass(frozen=True)
class Alert:
    rule_id: str
    title: str
    severity: str
    technique: str
    event_id: str
    event_name: str
    event_time: str
    actor: str
    source_ip: str
    account: str
    region: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def actor_of(event: Event) -> str:
    who = identity(event)
    return who.get("arn") or who.get("principalId") or "unknown"


def build_alert(rule: Rule, event: Event) -> Alert:
    return Alert(
        rule_id=rule.id,
        title=rule.title,
        severity=rule.severity,
        technique=rule.technique,
        event_id=event.get("eventID", ""),
        event_name=event.get("eventName", ""),
        event_time=event.get("eventTime", ""),
        actor=actor_of(event),
        source_ip=event.get("sourceIPAddress", ""),
        account=event.get("recipientAccountId", ""),
        region=event.get("awsRegion", ""),
    )


def evaluate(event: Event, rules: Iterable[Rule] = RULES) -> list[Alert]:
    name = event.get("eventName")
    return [
        build_alert(rule, event)
        for rule in rules
        if name in rule.event_names and rule.matches(event)
    ]


def denied_call_bursts(
    events: Iterable[Event], threshold: int = 20, window_minutes: int = 5
) -> list[Alert]:
    """Find principals with `threshold` denials inside a sliding window.

    This needs state across events, so it runs in the offline replay rather than
    in the stateless Lambda. Each principal alerts once per burst: a new alert
    needs the window to empty out first.
    """
    window = timedelta(minutes=window_minutes)
    recent: dict[str, deque[datetime]] = defaultdict(deque)
    alerting: set[str] = set()
    alerts = []

    denied = [event for event in events if event.get("errorCode") in DENIED_CODES]
    for event in sorted(denied, key=lambda e: e["eventTime"]):
        actor = actor_of(event)
        when = _parse_time(event["eventTime"])
        times = recent[actor]
        while times and when - times[0] > window:
            times.popleft()
        if not times:
            alerting.discard(actor)
        times.append(when)
        if len(times) >= threshold and actor not in alerting:
            alerting.add(actor)
            alerts.append(build_alert(BURST_RULE, event))
    return alerts


def _parse_time(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
