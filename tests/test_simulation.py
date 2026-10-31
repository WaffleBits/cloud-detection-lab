import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "simulate"))

import run as simulation

from detections.rules import RULES


class FakeClient:
    def __init__(self, log, fail_on):
        self.log = log
        self.fail_on = fail_on

    def __getattr__(self, name):
        def call(**kwargs):
            self.log.append(name)
            if name == self.fail_on:
                raise RuntimeError(name)
            return {
                "AccessKey": {"AccessKeyId": "AKIAEXAMPLE"},
                "GroupId": "sg-1",
                "Account": "111122223333",
            }

        return call


class FakeSession:
    def __init__(self, fail_on=None):
        self.log = []
        self.fail_on = fail_on

    def client(self, name):
        return FakeClient(self.log, self.fail_on)


def state():
    return {"user": "lab-sim-test", "trail": "lab-trail"}


def test_every_step_targets_a_real_rule():
    ids = {rule.id for rule in RULES}

    assert all(step.expected_alert in ids for step in simulation.STEPS)


def test_full_run_undoes_everything_in_reverse():
    session = FakeSession()

    simulation.execute(session, state())

    log = session.log
    assert log.index("start_logging") < log.index("delete_security_group")
    assert log.index("detach_user_policy") < log.index("delete_user")
    assert log[-1] == "delete_user"


def test_failure_midway_still_cleans_up():
    session = FakeSession(fail_on="authorize_security_group_ingress")

    with pytest.raises(RuntimeError):
        simulation.execute(session, state())

    assert "delete_security_group" in session.log
    assert "delete_user" in session.log
    assert "stop_logging" not in session.log


def test_refuses_the_wrong_account():
    with pytest.raises(SystemExit):
        simulation.assert_account(FakeSession(), "999999999999")


def test_accepts_the_named_account():
    simulation.assert_account(FakeSession(), "111122223333")
