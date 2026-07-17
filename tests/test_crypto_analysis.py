from __future__ import annotations

from dataclasses import replace

import pytest

from android_assessor.crypto_analysis import (
    CryptoAnalyzer,
    CryptoOperation,
    CryptoPolicy,
    load_crypto_fixture,
    operations_from_frida_events,
)
from android_assessor.findings import FindingStatus
from android_assessor.frida_events import parse_frida_jsonl
from tests.fakes import FIXTURE_ROOT, load_fixture


def analyzed_fixture(name: str = "observations.json"):
    operations = load_crypto_fixture(load_fixture(f"crypto/{name}"))
    return operations, CryptoAnalyzer().analyze(operations)


def test_crypto_fixture_detects_weak_ecb_static_reused_short_key_and_canary() -> None:
    _operations, results = analyzed_fixture()
    by_id = {item.rule_id: item for item in results}

    assert by_id["CRYPTO-WEAK-ALGORITHM"].status is FindingStatus.CONFIRMED
    assert by_id["CRYPTO-ECB"].status is FindingStatus.CONFIRMED
    assert by_id["CRYPTO-SHORT-KEY"].details["observed_bits"] == [64]
    assert by_id["CRYPTO-STATIC-IV"].status is FindingStatus.CONFIRMED
    assert by_id["CRYPTO-REUSED-IV"].status is FindingStatus.CONFIRMED
    assert by_id["CRYPTO-STATIC-KEY"].status is FindingStatus.POTENTIAL
    assert by_id["CRYPTO-CANARY-BOUNDARY"].details == {"canary_match": True}
    assert (
        by_id["CRYPTO-TRANSFORMATION-INCOMPLETE"].status
        is FindingStatus.INCONCLUSIVE
    )
    assert all(not item.finding_eligible for item in results)
    assert all(item.physical_validation_status == "UNVERIFIED" for item in results)


def test_crypto_safe_fixture_passes_without_false_positive() -> None:
    _operations, results = analyzed_fixture("safe.json")

    assert len(results) == 1
    assert results[0].rule_id == "CRYPTO-POLICY"
    assert results[0].status is FindingStatus.PASS


def test_cipher_get_instance_aes_without_mode_is_inconclusive_not_safe_or_weak() -> None:
    operations = load_crypto_fixture(load_fixture("crypto/observations.json"))
    only_aes = tuple(item for item in operations if item.transformation == "AES")

    results = CryptoAnalyzer().analyze(only_aes)

    assert [item.rule_id for item in results] == [
        "CRYPTO-TRANSFORMATION-INCOMPLETE"
    ]
    assert results[0].status is FindingStatus.INCONCLUSIVE


def test_rsa_transformation_named_ecb_is_not_symmetric_ecb_finding() -> None:
    operation = CryptoOperation.from_mapping(
        {
            "operation_id": "rsa-1",
            "transformation": "RSA/ECB/PKCS1Padding",
            "purpose": "encrypt",
            "executed": True,
            "key_length_bits": 1024,
            "key_sha256": "a" * 64,
            "iv_sha256": None,
            "iv_source": "none",
            "key_origin": "generated",
            "canary_match": False,
        },
        source="fixture",
        environment="simulated",
    )

    results = CryptoAnalyzer().analyze((operation,))

    assert [item.rule_id for item in results] == ["CRYPTO-POLICY"]


def test_crypto_empty_runtime_coverage_is_inconclusive() -> None:
    results = CryptoAnalyzer().analyze(())

    assert results[0].rule_id == "CRYPTO-COVERAGE"
    assert results[0].status is FindingStatus.INCONCLUSIVE
    assert results[0].finding_eligible is False


@pytest.mark.parametrize("forbidden", ("key", "key_material", "iv", "plaintext", "ciphertext"))
def test_crypto_model_rejects_raw_secret_material(forbidden: str) -> None:
    value = {
        "operation_id": "fixture-1",
        "transformation": "AES/GCM/NoPadding",
        "purpose": "encrypt",
        "executed": True,
        "canary_match": False,
        forbidden: "DO_NOT_STORE_THIS",
    }

    with pytest.raises(ValueError, match="forbidden raw material"):
        CryptoOperation.from_mapping(
            value,
            source="fixture",
            environment="simulated",
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("key_sha256", "short"),
        ("iv_sha256", "z" * 64),
        ("key_length_bits", 0),
        ("transformation", "AES/GCM/NoPadding;id"),
        ("purpose", "sign"),
    ),
)
def test_crypto_model_rejects_invalid_normalized_metadata(
    field: str,
    value: object,
) -> None:
    payload = {
        "operation_id": "fixture-1",
        "transformation": "AES/GCM/NoPadding",
        "purpose": "encrypt",
        "executed": True,
        "key_length_bits": 256,
        "key_sha256": "a" * 64,
        "iv_sha256": "b" * 64,
        "iv_source": "random",
        "key_origin": "generated",
        "canary_match": False,
    }
    payload[field] = value

    with pytest.raises(ValueError):
        CryptoOperation.from_mapping(
            payload,
            source="fixture",
            environment="simulated",
        )


def test_crypto_output_contains_hashes_but_no_key_material() -> None:
    _operations, results = analyzed_fixture()
    rendered = str([item.to_dict() for item in results])

    assert "key_material" not in rendered
    assert "DO_NOT_STORE_THIS" not in rendered
    assert "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" in rendered


def test_crypto_policy_key_length_is_configurable() -> None:
    operations = load_crypto_fixture(load_fixture("crypto/safe.json"))

    results = CryptoAnalyzer(CryptoPolicy(minimum_symmetric_key_bits=512)).analyze(
        operations
    )

    assert results[0].rule_id == "CRYPTO-SHORT-KEY"


def test_crypto_analysis_rejects_mixed_fixture_and_physical_evidence() -> None:
    operations = load_crypto_fixture(load_fixture("crypto/safe.json"))
    physical = replace(operations[0], source="frida", environment="physical")

    with pytest.raises(ValueError, match="cannot mix"):
        CryptoAnalyzer().analyze((operations[0], physical))


def test_crypto_operations_are_extracted_from_redacted_frida_events() -> None:
    events = parse_frida_jsonl(
        (FIXTURE_ROOT / "frida" / "events.jsonl").read_text(encoding="utf-8"),
        expected_session_id="fixture-session",
        expected_package="com.example.rootedlab",
        source="fixture",
        environment="simulated",
    )

    extracted = operations_from_frida_events(
        events.events,
        source="fixture",
        environment="simulated",
    )

    assert extracted.errors == ()
    assert len(extracted.operations) == 1
    operation = extracted.operations[0]
    assert operation.transformation == "AES/GCM/NoPadding"
    assert operation.key_length_bits == 256
    assert operation.key_sha256 == "a" * 64
    assert operation.iv_sha256 == "b" * 64
    assert operation.canary_match is True
