from __future__ import annotations

from android_assessor.rule_catalog import ROOT_FOCUSED_TESTS, merge_root_coverage


def test_root_focused_catalog_has_eleven_unique_bounded_groups() -> None:
    identifiers = [item.test_id for item in ROOT_FOCUSED_TESTS]

    assert len(identifiers) == len(set(identifiers)) == 11
    assert all(item.available_with_root for item in ROOT_FOCUSED_TESTS)
    assert sum(not item.available_without_root for item in ROOT_FOCUSED_TESTS) == 3
    assert sum(item.requires_frida for item in ROOT_FOCUSED_TESTS) == 2
    assert all(item.physical_validation_status == "UNVERIFIED" for item in ROOT_FOCUSED_TESTS)


def test_catalog_merge_preserves_observed_status_without_faking_unrun_results() -> None:
    merged = merge_root_coverage(
        [
            {
                "test_id": "ASL-MVP-001",
                "finding_status": "pass",
                "physical_validation_status": "UNVERIFIED",
            }
        ]
    )
    by_id = {item["test_id"]: item for item in merged}

    assert by_id["ASL-MVP-001"]["finding_status"] == "pass"
    assert by_id["ASL-ROOT-STORAGE"]["finding_status"] == "skipped"
    assert all(item["physical_validation_status"] != "PASSED" for item in merged)


def test_unknown_future_test_is_appended_without_overwriting_catalog() -> None:
    extra = {
        "test_id": "ASL-FUTURE-FIXTURE",
        "available_without_root": False,
        "available_with_root": True,
        "requires_frida": True,
        "implementation_status": "IMPLEMENTED_UNVERIFIED",
        "physical_validation_status": "UNVERIFIED",
        "finding_status": "inconclusive",
    }

    merged = merge_root_coverage([extra])

    assert merged[-1] == extra
