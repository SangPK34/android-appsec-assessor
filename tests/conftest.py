from __future__ import annotations

import os

import pytest


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    del config
    if os.environ.get("ANDROID_INTEGRATION_TESTS") == "1":
        return
    blocked = pytest.mark.skip(
        reason="BLOCKED_NO_DEVICE: set ANDROID_INTEGRATION_TESTS=1 explicitly"
    )
    for item in items:
        if item.get_closest_marker("physical_android") is not None:
            item.add_marker(blocked)
