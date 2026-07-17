from __future__ import annotations

from typing import Any

from tests.conftest import pytest_collection_modifyitems


class FakeItem:
    def __init__(self, *, physical: bool) -> None:
        self.physical = physical
        self.markers: list[Any] = []

    def get_closest_marker(self, name: str) -> object | None:
        return object() if self.physical and name == "physical_android" else None

    def add_marker(self, marker: object) -> None:
        self.markers.append(marker)


def test_physical_android_tests_are_skipped_by_default(monkeypatch: Any) -> None:
    monkeypatch.delenv("ANDROID_INTEGRATION_TESTS", raising=False)
    physical = FakeItem(physical=True)
    regular = FakeItem(physical=False)

    pytest_collection_modifyitems(None, [physical, regular])  # type: ignore[arg-type]

    assert len(physical.markers) == 1
    assert regular.markers == []


def test_physical_android_tests_require_explicit_opt_in(monkeypatch: Any) -> None:
    monkeypatch.setenv("ANDROID_INTEGRATION_TESTS", "1")
    physical = FakeItem(physical=True)

    pytest_collection_modifyitems(None, [physical])  # type: ignore[arg-type]

    assert physical.markers == []
