"""Run every detection over CloudTrail log files, for hunting and backtesting.

    python -m detections.replay path/to/logs
"""

from __future__ import annotations

import argparse
import gzip
import json
from collections.abc import Iterator
from pathlib import Path

from detections.engine import Alert, denied_call_bursts, evaluate
from detections.rules import Event


def read_records(path: Path) -> Iterator[Event]:
    files = sorted(path.rglob("*.json*")) if path.is_dir() else [path]
    for file in files:
        opener = gzip.open if file.suffix == ".gz" else open
        with opener(file, "rt", encoding="utf-8") as handle:
            yield from json.load(handle)["Records"]


def replay(path: Path) -> list[Alert]:
    records = list(read_records(path))
    alerts = [alert for record in records for alert in evaluate(record)]
    return alerts + denied_call_bursts(records)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    for alert in replay(args.path):
        print(json.dumps(alert.to_dict()))


if __name__ == "__main__":
    main()
