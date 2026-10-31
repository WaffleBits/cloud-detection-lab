"""Lambda entry point: EventBridge delivers one CloudTrail record per call."""

from __future__ import annotations

import json
import os
from typing import Any

from detections.engine import evaluate


def handle(event: dict[str, Any], context: Any = None, sns: Any = None) -> dict[str, int]:
    alerts = evaluate(event.get("detail") or {})
    if not alerts:
        return {"alerts": 0}

    if sns is None:
        import boto3

        sns = boto3.client("sns")
    topic = os.environ["ALERT_TOPIC_ARN"]

    for alert in alerts:
        print(json.dumps({"alert": alert.to_dict()}))
        sns.publish(
            TopicArn=topic,
            Subject=f"[{alert.severity}] {alert.title}"[:100],
            Message=json.dumps(alert.to_dict(), indent=2),
        )
    return {"alerts": len(alerts)}
