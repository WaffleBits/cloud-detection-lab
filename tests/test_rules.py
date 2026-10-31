import json
from pathlib import Path

import pytest
from events import CASES, record

from detections.engine import build_alert, evaluate
from detections.rules import RULES, monitored_event_names

ROOT = Path(__file__).resolve().parents[1]
ATTACKS = [(rule, event) for rule, (bad, _) in CASES.items() for event in bad]
BENIGN = [(rule, event) for rule, (_, good) in CASES.items() for event in good]


def fired(event):
    return {alert.rule_id for alert in evaluate(event)}


def test_every_rule_has_attack_and_benign_cases():
    assert {rule.id for rule in RULES} == set(CASES)
    assert all(bad and good for bad, good in CASES.values())


@pytest.mark.parametrize("rule_id,event", ATTACKS)
def test_attack_alerts(rule_id, event):
    assert rule_id in fired(event)


@pytest.mark.parametrize("rule_id,event", BENIGN)
def test_benign_does_not_alert(rule_id, event):
    assert rule_id not in fired(event)


def test_rule_only_reads_its_own_event_names():
    assert evaluate(record("GetCallerIdentity")) == []


def test_alert_carries_who_what_and_where():
    rule = next(r for r in RULES if r.id == "audit-logging-tampered")

    alert = build_alert(rule, record("StopLogging"))

    assert alert.actor.endswith(":user/alice")
    assert alert.source_ip == "203.0.113.10"
    assert alert.account == "111122223333"
    assert alert.technique == "T1562.008"


def test_terraform_filter_matches_the_rules():
    committed = json.loads((ROOT / "terraform" / "event_names.json").read_text())

    assert committed == monitored_event_names()
