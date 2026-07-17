from __future__ import annotations

import os

import pytest

from android_assessor.host_process import WindowsProcessController


@pytest.mark.skipif(os.name != "nt", reason="Windows-native process identity test")
def test_captures_current_process_identity_without_terminating_it() -> None:
    identity = WindowsProcessController().capture(os.getpid())

    assert identity is not None
    assert identity.pid == os.getpid()
    assert identity.executable.lower().endswith("python.exe")
    assert identity.creation_filetime > 0
