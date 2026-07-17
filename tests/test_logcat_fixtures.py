from __future__ import annotations

from android_assessor.logcat import LogcatCollector
from android_assessor.redaction import redact_text

from .fakes.fixture_loader import load_fixture


def test_legacy_threadtime_fixture_is_filtered_to_target_pid() -> None:
    fixture = load_fixture("logcat/legacy.json")
    target_lines = "\n".join(fixture["lines"])
    mixed = (
        "07-17 09:59:59.000 20222 20222 I Background: unrelated\n"
        f"{target_lines}\n"
        "    at com.example.rootedlab.Example.run(Example.java:1)\n"
        "07-17 10:00:02.000 20222 20222 I Background: unrelated again\n"
    )

    filtered = LogcatCollector._filter_threadtime_for_pid(mixed, 10123)

    assert "RootedLab: fixture startup" in filtered
    assert "Example.run" in filtered
    assert "Background" not in filtered


def test_legacy_and_modern_logcat_fixtures_are_simulated_and_redacted() -> None:
    legacy = load_fixture("logcat/legacy.json")
    modern = load_fixture("logcat/modern.json")

    assert legacy["source"] == modern["source"] == "fixture"
    assert legacy["environment"] == modern["environment"] == "simulated"

    redacted = redact_text("\n".join([*legacy["lines"], *modern["lines"]]))
    assert "THESIS_CANARY_LOGCAT_TOKEN" not in redacted
    assert "fixture@example.invalid" not in redacted
    assert "<redacted>" in redacted
