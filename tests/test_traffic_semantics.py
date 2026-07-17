from __future__ import annotations

from android_assessor.traffic import summarize_traffic_events


def test_empty_traffic_is_completed_no_data() -> None:
    assert summarize_traffic_events([]) == (0, 0, "completed_no_data")


def test_traffic_counts_only_attributed_request_flows() -> None:
    events = [
        {"event": "request", "attribution": "unattributed"},
        {"event": "request", "attribution": "target"},
        {"event": "response", "attribution": "target"},
    ]
    assert summarize_traffic_events(events) == (2, 1, "completed")
