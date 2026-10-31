import gzip
import json
from datetime import datetime, timedelta

from events import login, record

from detections.engine import denied_call_bursts
from detections.handler import handle
from detections.replay import replay

START = datetime(2026, 10, 31, 12, 0, 0)


def denied(seconds, user="mallory", code="AccessDenied"):
    when = START + timedelta(seconds=seconds)
    return record(
        "ListBuckets",
        user=user,
        errorCode=code,
        eventTime=when.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def test_burst_alerts_at_the_threshold():
    assert len(denied_call_bursts([denied(i) for i in range(20)])) == 1


def test_one_short_of_the_threshold_is_quiet():
    assert denied_call_bursts([denied(i) for i in range(19)]) == []


def test_denials_spread_past_the_window_are_quiet():
    assert denied_call_bursts([denied(i * 20) for i in range(30)]) == []


def test_one_burst_alerts_once():
    assert len(denied_call_bursts([denied(i) for i in range(100)])) == 1


def test_separate_bursts_alert_separately():
    first = [denied(i) for i in range(20)]
    second = [denied(1000 + i) for i in range(20)]

    assert len(denied_call_bursts(first + second)) == 2


def test_principals_are_counted_apart():
    events = [denied(i, user=f"user{i % 2}") for i in range(30)]

    assert denied_call_bursts(events) == []


def test_order_of_log_files_does_not_matter():
    assert len(denied_call_bursts([denied(i) for i in reversed(range(20))])) == 1


class FakeSns:
    def __init__(self):
        self.sent = []

    def publish(self, **message):
        self.sent.append(message)


def test_handler_publishes_alerts(monkeypatch):
    monkeypatch.setenv("ALERT_TOPIC_ARN", "arn:aws:sns:us-east-1:111122223333:alerts")
    sns = FakeSns()

    result = handle({"detail": record("StopLogging")}, sns=sns)

    assert result == {"alerts": 1}
    assert sns.sent[0]["Subject"].startswith("[critical]")
    assert json.loads(sns.sent[0]["Message"])["rule_id"] == "audit-logging-tampered"


def test_handler_stays_quiet_on_benign_events():
    sns = FakeSns()

    assert handle({"detail": login()}, sns=sns) == {"alerts": 0}
    assert sns.sent == []


def test_replay_reads_gzipped_logs(tmp_path):
    records = [record("StopLogging")] + [denied(i) for i in range(20)]
    with gzip.open(tmp_path / "log.json.gz", "wt", encoding="utf-8") as handle_:
        json.dump({"Records": records}, handle_)

    alerts = replay(tmp_path)

    assert {a.rule_id for a in alerts} == {"audit-logging-tampered", "denied-call-burst"}
