from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from android_assessor.crypto_analysis import (
    CryptoAnalyzer,
    CryptoKeyOrigin,
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


def test_phase2_crypto_fixture_detects_zero_iv_reuse_and_low_pbe_iterations() -> None:
    operations, results = analyzed_fixture("phase2_positive.json")
    by_id = {item.rule_id: item for item in results}

    assert by_id["CRYPTO-ZERO-IV"].status is FindingStatus.CONFIRMED
    assert by_id["CRYPTO-ZERO-IV"].details == {
        "iv_lengths": [16],
        "deterministic_zero_iv": True,
    }
    assert "CRYPTO-STATIC-IV" not in by_id
    assert by_id["CRYPTO-REUSED-IV"].status is FindingStatus.CONFIRMED
    assert by_id["CRYPTO-REUSED-IV"].operation_ids == ("reuse-1", "reuse-2")
    assert by_id["CRYPTO-LOW-PBE-ITERATIONS"].status is FindingStatus.POTENTIAL
    assert by_id["CRYPTO-LOW-PBE-ITERATIONS"].details["observed_iterations"] == [
        1000
    ]
    assert by_id["CRYPTO-WEAK-DIGEST"].status is FindingStatus.POTENTIAL
    assert {item.operation_kind for item in operations} == {
        "cipher",
        "digest",
        "mac",
        "pbe",
    }


def test_phase2_safe_fixture_does_not_reuse_iv_across_different_keys() -> None:
    _operations, results = analyzed_fixture("phase2_negative.json")

    assert [item.rule_id for item in results] == ["CRYPTO-POLICY"]
    assert results[0].status is FindingStatus.PASS


def test_duplicate_crypto_event_does_not_confirm_iv_reuse() -> None:
    operations = load_crypto_fixture(load_fixture("crypto/phase2_positive.json"))
    operation = next(item for item in operations if item.operation_id == "reuse-1")

    results = CryptoAnalyzer().analyze((operation, operation))

    assert "CRYPTO-REUSED-IV" not in {item.rule_id for item in results}


def test_weak_digest_without_sensitive_context_is_potential_with_missing_evidence() -> None:
    _operations, results = analyzed_fixture("phase2_ambiguous.json")

    assert [item.rule_id for item in results] == ["CRYPTO-WEAK-DIGEST"]
    assert results[0].status is FindingStatus.POTENTIAL
    assert results[0].details["observed_algorithms"] == ["MD5"]
    assert results[0].details["missing_evidence"] == [
        "security-sensitive data or authentication context"
    ]


@pytest.mark.parametrize(
    ("transformation", "operation_kind", "purpose"),
    (
        ("MD5", "digest", "digest"),
        ("SHA-1", "digest", "digest"),
        ("HmacSHA1", "mac", "sign"),
    ),
)
def test_weak_digest_and_mac_operations_are_potential_without_context(
    transformation: str,
    operation_kind: str,
    purpose: str,
) -> None:
    operation = CryptoOperation.from_mapping(
        {
            "operation_id": f"weak-{operation_kind}",
            "operation_kind": operation_kind,
            "transformation": transformation,
            "purpose": purpose,
            "executed": True,
            "key_length_bits": None,
            "key_sha256": None,
            "iv_sha256": None,
            "iv_source": "none",
            "key_origin": "unknown",
            "canary_match": False,
        },
        source="fixture",
        environment="simulated",
    )

    results = CryptoAnalyzer().analyze((operation,))

    assert [item.rule_id for item in results] == ["CRYPTO-WEAK-DIGEST"]
    assert results[0].status is FindingStatus.POTENTIAL


def test_weak_random_must_be_correlated_to_runtime_key_or_iv_material() -> None:
    weak = CryptoOperation.from_mapping(
        {
            "operation_id": "weak-random-cipher",
            "operation_kind": "cipher",
            "transformation": "AES/CBC/PKCS5Padding",
            "purpose": "encrypt",
            "executed": True,
            "key_length_bits": 128,
            "key_sha256": "a" * 64,
            "iv_sha256": "b" * 64,
            "iv_source": "weak_random",
            "key_origin": "weak_random",
            "canary_match": False,
        },
        source="fixture",
        environment="simulated",
    )
    secure = replace(
        weak,
        operation_id="secure-random-cipher",
        iv_source="random",
        key_origin=CryptoKeyOrigin.GENERATED,
    )
    decrypt_only = replace(
        weak,
        operation_id="weak-random-decrypt-iv",
        purpose="decrypt",
        key_origin=CryptoKeyOrigin.GENERATED,
    )

    weak_results = {item.rule_id: item for item in CryptoAnalyzer().analyze((weak,))}
    secure_results = CryptoAnalyzer().analyze((secure,))
    decrypt_results = CryptoAnalyzer().analyze((decrypt_only,))

    assert weak_results["CRYPTO-PREDICTABLE-RANDOM"].status is FindingStatus.CONFIRMED
    assert weak_results["CRYPTO-PREDICTABLE-RANDOM"].details["uses"] == [
        "initialization_vector",
        "key_material",
    ]
    assert [item.rule_id for item in secure_results] == ["CRYPTO-POLICY"]
    assert secure_results[0].status is FindingStatus.PASS
    assert [item.rule_id for item in decrypt_results] == ["CRYPTO-POLICY"]


def test_phase2_flow_not_triggered_is_inconclusive() -> None:
    _operations, results = analyzed_fixture("phase2_flow_not_triggered.json")

    assert [item.rule_id for item in results] == ["CRYPTO-COVERAGE"]
    assert results[0].status is FindingStatus.INCONCLUSIVE


def test_legacy_crypto_fixture_uses_backward_compatible_metadata_defaults() -> None:
    operation = load_crypto_fixture(load_fixture("crypto/safe.json"))[0]

    assert operation.operation_kind == "cipher"
    assert operation.iv_length is None
    assert operation.iv_zero is None
    assert operation.salt_length is None
    assert operation.iteration_count is None
    assert operation.call_sequence == ()


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


def test_unexecuted_crypto_events_are_inconclusive_not_policy_pass() -> None:
    operation = replace(
        load_crypto_fixture(load_fixture("crypto/safe.json"))[0],
        executed=False,
    )

    results = CryptoAnalyzer().analyze((operation,))

    assert len(results) == 1
    assert results[0].rule_id == "CRYPTO-COVERAGE"
    assert results[0].status is FindingStatus.INCONCLUSIVE


def test_constant_iv_used_only_for_decryption_is_not_static_iv_confirmation() -> None:
    operation = replace(
        load_crypto_fixture(load_fixture("crypto/safe.json"))[0],
        purpose="decrypt",
        iv_source="constant",
    )

    results = CryptoAnalyzer().analyze((operation,))

    assert "CRYPTO-STATIC-IV" not in {item.rule_id for item in results}


@pytest.mark.parametrize(
    "forbidden",
    (
        "key",
        "key_material",
        "raw_key",
        "iv",
        "raw_iv",
        "plaintext",
        "raw_plaintext",
        "password",
        "raw_password",
        "ciphertext",
    ),
)
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
        ("purpose", "exchange"),
        ("operation_kind", "encryptor"),
        ("iv_length", -1),
        ("iv_zero", "false"),
        ("salt_length", -1),
        ("iteration_count", -1),
        ("call_sequence", ["cipher.init\nraw"]),
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


def test_crypto_redaction_fixture_is_rejected_before_analysis() -> None:
    payload = load_fixture("crypto/phase2_redaction_rejected.json")

    with pytest.raises(ValueError, match="forbidden raw material"):
        load_crypto_fixture(payload)


@pytest.mark.parametrize("transformation", ("DES", "3DES", "DESEDE", "RC4"))
def test_runtime_weak_ciphers_are_confirmed(transformation: str) -> None:
    operation = CryptoOperation.from_mapping(
        {
            "operation_id": f"weak-{transformation}",
            "operation_kind": "cipher",
            "transformation": transformation,
            "purpose": "encrypt",
            "executed": True,
            "key_length_bits": None,
            "key_sha256": None,
            "iv_sha256": None,
            "iv_source": "none",
            "key_origin": "unknown",
            "canary_match": False,
        },
        source="fixture",
        environment="simulated",
    )

    results = CryptoAnalyzer().analyze((operation,))

    assert results[0].rule_id == "CRYPTO-WEAK-ALGORITHM"
    assert results[0].status is FindingStatus.CONFIRMED


def test_crypto_policy_key_length_is_configurable() -> None:
    operations = load_crypto_fixture(load_fixture("crypto/safe.json"))

    results = CryptoAnalyzer(CryptoPolicy(minimum_symmetric_key_bits=512)).analyze(
        operations
    )

    assert results[0].rule_id == "CRYPTO-SHORT-KEY"


def test_crypto_policy_preserves_existing_positional_arguments() -> None:
    policy = CryptoPolicy(192, frozenset({"DES"}))

    assert policy.minimum_symmetric_key_bits == 192
    assert policy.weak_algorithms == frozenset({"DES"})
    assert policy.minimum_pbe_iterations == 100_000


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
    assert operation.operation_kind == "cipher"
    assert operation.call_sequence == ("cipher.do_final",)


@pytest.mark.parametrize(
    ("method", "payload", "expected_kind", "expected_purpose"),
    (
        (
            "cipher.do_final",
            {"transformation": "AES/GCM/NoPadding"},
            "cipher",
            "unknown",
        ),
        ("digest.digest", {"algorithm": "SHA-1"}, "digest", "digest"),
        ("mac.do_final", {"algorithm": "HmacSHA1"}, "mac", "sign"),
        (
            "pbe.key_spec",
            {
                "algorithm": "PBKDF2WithHmacSHA256",
                "salt_length": 16,
                "iteration_count": 1000,
            },
            "pbe",
            "derive",
        ),
    ),
)
def test_supported_crypto_events_are_normalized(
    method: str,
    payload: dict[str, object],
    expected_kind: str,
    expected_purpose: str,
) -> None:
    event = SimpleNamespace(
        category="crypto",
        method=method,
        arguments_redacted=(payload,),
        canary_match=False,
    )

    extracted = operations_from_frida_events(
        (event,),
        source="fixture",
        environment="simulated",
    )

    assert extracted.errors == ()
    assert len(extracted.operations) == 1
    operation = extracted.operations[0]
    assert operation.operation_kind == expected_kind
    assert operation.purpose == expected_purpose
    assert operation.call_sequence == (method,)


def test_crypto_event_extraction_rejects_raw_password() -> None:
    event = SimpleNamespace(
        category="crypto",
        method="pbe.key_spec",
        arguments_redacted=(
            {
                "algorithm": "PBKDF2WithHmacSHA256",
                "password": "must-not-survive-normalization",
                "iteration_count": 1000,
            },
        ),
        canary_match=False,
    )

    extracted = operations_from_frida_events(
        (event,),
        source="fixture",
        environment="simulated",
    )

    assert extracted.operations == ()
    assert extracted.errors == (
        "event 1: Crypto observation contains forbidden raw material fields.",
    )


def test_crypto_event_extraction_rejects_missing_algorithm_metadata() -> None:
    event = SimpleNamespace(
        category="crypto",
        method="digest.digest",
        arguments_redacted=({},),
        canary_match=False,
    )

    extracted = operations_from_frida_events(
        (event,),
        source="fixture",
        environment="simulated",
    )

    assert extracted.operations == ()
    assert extracted.errors == ("event 1: crypto transformation is missing",)
