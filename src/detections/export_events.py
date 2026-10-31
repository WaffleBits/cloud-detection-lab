"""Print the API calls the rules read, for the EventBridge filter.

    python -m detections.export_events > terraform/event_names.json
"""

import json

from detections.rules import monitored_event_names

if __name__ == "__main__":
    print(json.dumps(monitored_event_names(), indent=2))
