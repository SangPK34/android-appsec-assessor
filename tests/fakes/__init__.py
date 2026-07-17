"""Hardware-independent Android test doubles."""

from .android import FakeAndroidBackend, FaultInjected
from .fixture_loader import FIXTURE_ROOT, load_fixture

__all__ = ["FIXTURE_ROOT", "FaultInjected", "FakeAndroidBackend", "load_fixture"]
