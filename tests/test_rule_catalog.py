from __future__ import annotations

import ast
from pathlib import Path

import yaml

from android_assessor.rule_catalog import ROOT_FOCUSED_TESTS, merge_root_coverage
from android_assessor.validation_definitions import validation_for_rule


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


def test_machine_readable_coverage_registry_has_complete_unique_rows() -> None:
    registry_path = Path(__file__).parents[1] / "rules" / "coverage.yaml"
    payload = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    rows = payload["rules"]
    required = {
        "rule_id",
        "id_kind",
        "vulnerability_class",
        "masvs_mapping",
        "mastg_mapping",
        "static_support",
        "runtime_support",
        "root_required",
        "frida_required",
        "controlled_validation_available",
        "default_profile",
        "implementation_status",
        "detection_mode",
        "activation_required",
        "manual_interaction_required",
        "auto_confirm_possible",
        "runtime_sources",
    }

    assert payload["schema_version"] == 2
    assert set(payload["detection_modes"]) == {
        "static",
        "autonomous_runtime",
        "controlled_validation",
        "guided",
    }
    assert set(payload["id_kinds"]) == {
        "production_rule",
        "analyzer_result",
        "inventory_only",
        "planned",
    }
    assert rows
    assert len({row["rule_id"] for row in rows}) == len(rows)
    assert len({row["vulnerability_class"] for row in rows}) == len(rows)
    assert all(required <= row.keys() for row in rows)
    assert all(
        row["implementation_status"] in payload["statuses"] for row in rows
    )
    assert all(row["default_profile"] in {"quick", "full"} for row in rows)
    assert all(row["id_kind"] in payload["id_kinds"] for row in rows)
    assert all(row["detection_mode"] in payload["detection_modes"] for row in rows)
    assert all(isinstance(row["manual_interaction_required"], bool) for row in rows)
    assert all(isinstance(row["auto_confirm_possible"], bool) for row in rows)
    assert all(isinstance(row["runtime_sources"], list) for row in rows)


def test_coverage_registry_id_kinds_do_not_overstate_finding_support() -> None:
    registry_path = Path(__file__).parents[1] / "rules" / "coverage.yaml"
    rows = yaml.safe_load(registry_path.read_text(encoding="utf-8"))["rules"]
    allowed_statuses = {
        "production_rule": {"detected", "partially_detected", "observable_only"},
        "analyzer_result": {"partially_detected", "observable_only"},
        "inventory_only": {"observable_only"},
        "planned": {"observable_only", "not_supported"},
    }

    assert all(
        row["implementation_status"] in allowed_statuses[row["id_kind"]]
        for row in rows
    )
    assert all(
        row["rule_id"].startswith("ASL-INVENTORY-")
        for row in rows
        if row["id_kind"] == "inventory_only"
    )
    assert all(
        row["rule_id"].startswith("ASL-PLANNED-")
        for row in rows
        if row["id_kind"] == "planned"
    )


def test_coverage_registry_includes_every_crypto_analyzer_result_id() -> None:
    root = Path(__file__).parents[1]
    payload = yaml.safe_load(
        (root / "rules" / "coverage.yaml").read_text(encoding="utf-8")
    )
    production = yaml.safe_load(
        (root / "rules" / "mvp.yaml").read_text(encoding="utf-8")
    )["rules"]
    production_ids = {row["id"] for row in production}
    tree = ast.parse(
        (root / "android_assessor" / "crypto_analysis.py").read_text(
            encoding="utf-8"
        )
    )
    emitted_ids = {
        call.args[0].value
        for call in ast.walk(tree)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == "_result"
        and call.args
        and isinstance(call.args[0], ast.Constant)
        and isinstance(call.args[0].value, str)
    }
    rows_by_id = {row["rule_id"]: row for row in payload["rules"]}

    assert emitted_ids <= rows_by_id.keys()
    assert {
        rule_id
        for rule_id in emitted_ids
        if rule_id not in production_ids
    } == {
        rule_id
        for rule_id, row in rows_by_id.items()
        if row["id_kind"] == "analyzer_result"
    }


def test_partial_coverage_claims_match_current_production_boundaries() -> None:
    registry_path = Path(__file__).parents[1] / "rules" / "coverage.yaml"
    rows = yaml.safe_load(registry_path.read_text(encoding="utf-8"))["rules"]
    by_id = {row["rule_id"]: row for row in rows}

    for rule_id in {
        "ASL-MVP-001",
        "ASL-MANIFEST-ALLOW-BACKUP",
        "ASL-MVP-002",
        "ASL-MANIFEST-CUSTOM-PERMISSION",
        "ASL-MANIFEST-FILEPROVIDER-PATHS",
        "ASL-MANIFEST-DEEP-LINK-EXPOSURE",
        "ASL-STATIC-HARDCODED-SECRET",
    }:
        assert by_id[rule_id]["implementation_status"] == "partially_detected"
    assert by_id["ASL-MANIFEST-DEEP-LINK-EXPOSURE"]["runtime_support"] is False
    assert by_id["ASL-INVENTORY-ENDPOINTS"]["runtime_support"] is False
    assert by_id["ASL-RUNTIME-LOGGING"]["frida_required"] is True


def test_phase2_registry_does_not_overstate_static_or_auto_confirm_support() -> None:
    registry_path = Path(__file__).parents[1] / "rules" / "coverage.yaml"
    rows = yaml.safe_load(registry_path.read_text(encoding="utf-8"))["rules"]
    by_id = {row["rule_id"]: row for row in rows}

    for rule_id in {
        "ASL-MVP-005",
        "CRYPTO-SHORT-KEY",
        "CRYPTO-ZERO-IV",
        "CRYPTO-REUSED-IV",
    }:
        assert by_id[rule_id]["static_support"] is False
    for rule_id in {
        "WEBVIEW-JS-BRIDGE-REMOTE",
        "WEBVIEW-UNSAFE-SETTINGS",
        "CRYPTO-ECB",
        "CRYPTO-WEAK-ALGORITHM",
        "CRYPTO-WEAK-DIGEST",
        "CRYPTO-LOW-PBE-ITERATIONS",
        "CRYPTO-PREDICTABLE-RANDOM",
        "STORAGE-WORLD-READABLE",
        "STORAGE-WORLD-WRITABLE",
    }:
        assert by_id[rule_id]["static_support"] is True
    for rule_id in {
        "WEBVIEW-JS-BRIDGE-REMOTE",
        "WEBVIEW-UNSAFE-SETTINGS",
        "CRYPTO-WEAK-DIGEST",
        "CRYPTO-LOW-PBE-ITERATIONS",
    }:
        assert by_id[rule_id]["auto_confirm_possible"] is False
    assert by_id["ASL-INVENTORY-SECURITY-API"]["static_support"] is True
    assert by_id["ASL-INVENTORY-PENDING-INTENT"]["default_profile"] == "quick"


def test_inventory_and_unsupported_registry_rows_do_not_claim_findings() -> None:
    registry_path = Path(__file__).parents[1] / "rules" / "coverage.yaml"
    rows = yaml.safe_load(registry_path.read_text(encoding="utf-8"))["rules"]
    by_id = {row["rule_id"]: row for row in rows}

    assert by_id["ASL-INVENTORY-DYNAMIC-CODE"]["implementation_status"] == (
        "observable_only"
    )
    assert by_id["ASL-INVENTORY-DEPRECATED-API"]["implementation_status"] == (
        "observable_only"
    )
    assert by_id["ASL-PLANNED-PATH-TRAVERSAL"]["implementation_status"] == (
        "not_supported"
    )
    assert by_id["ASL-INVENTORY-PENDING-INTENT"]["implementation_status"] == (
        "observable_only"
    )
    assert by_id["ASL-INVENTORY-PENDING-INTENT"]["id_kind"] == "inventory_only"


def test_coverage_registry_matches_production_rule_and_validation_catalog() -> None:
    root = Path(__file__).parents[1]
    coverage = yaml.safe_load(
        (root / "rules" / "coverage.yaml").read_text(encoding="utf-8")
    )["rules"]
    production = yaml.safe_load(
        (root / "rules" / "mvp.yaml").read_text(encoding="utf-8")
    )["rules"]
    coverage_by_id = {row["rule_id"]: row for row in coverage}
    production_by_id = {row["id"]: row for row in production}
    production_ids = {row["id"] for row in production}

    assert production_ids <= coverage_by_id.keys()
    assert {
        row["rule_id"] for row in coverage if row["id_kind"] == "production_rule"
    } == production_ids
    for rule in production:
        assert coverage_by_id[rule["id"]]["root_required"] is bool(
            rule.get("root_required", False)
        )
        assert coverage_by_id[rule["id"]]["frida_required"] is bool(
            rule.get("frida_required", False)
        )
        definition = validation_for_rule(rule["id"])
        expected = bool(definition and definition.production_enabled)
        assert (
            coverage_by_id[rule["id"]]["controlled_validation_available"]
            is expected
        )
    assert production_by_id["STORAGE-SENSITIVE-CANARY"]["validation_type"] == (
        "evidence_correlation"
    )
    assert production_by_id["WEBVIEW-SSL-ERROR-PROCEED"]["frida_required"] is False
    assert production_by_id["WEBVIEW-SSL-ERROR-PROCEED"]["validation_type"] == (
        "evidence_correlation"
    )
