"""Offline analysis of normalized, redacted runtime crypto observations."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any

from .findings import FindingStatus

_HASH = re.compile(r"^[a-f0-9]{64}$")
_TRANSFORMATION = re.compile(r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+){0,2}$")
_SYMMETRIC_ALGORITHMS = {
    "AES",
    "DES",
    "3DES",
    "DESEDE",
    "RC4",
    "BLOWFISH",
    "TWOFISH",
    "CAMELLIA",
}
_OPERATION_KINDS = {"cipher", "digest", "mac", "pbe", "random", "unknown"}
_WEAK_DIGEST_ALGORITHMS = {"MD5", "SHA1", "HMACSHA1"}
_PURPOSES = {
    "encrypt",
    "decrypt",
    "wrap",
    "unwrap",
    "digest",
    "sign",
    "verify",
    "derive",
    "unknown",
}


class CryptoKeyOrigin(StrEnum):
    UNKNOWN = "unknown"
    GENERATED = "generated"
    DERIVED = "derived"
    STATIC_RUNTIME = "static_runtime"
    WEAK_RANDOM = "weak_random"


@dataclass(frozen=True, slots=True)
class CryptoPolicy:
    minimum_symmetric_key_bits: int = 128
    weak_algorithms: frozenset[str] = frozenset({"DES", "3DES", "DESEDE", "RC4"})
    minimum_pbe_iterations: int = 100_000

    def __post_init__(self) -> None:
        if not 64 <= self.minimum_symmetric_key_bits <= 512:
            raise ValueError("Crypto minimum key length must be between 64 and 512 bits.")
        if not 1_000 <= self.minimum_pbe_iterations <= 10_000_000:
            raise ValueError("PBE minimum iterations must be between 1000 and 10000000.")


@dataclass(frozen=True, slots=True)
class CryptoOperation:
    operation_id: str
    transformation: str
    algorithm: str
    mode: str | None
    padding: str | None
    purpose: str
    executed: bool
    key_length_bits: int | None
    key_sha256: str | None
    iv_sha256: str | None
    iv_source: str
    key_origin: CryptoKeyOrigin
    canary_match: bool
    source: str
    environment: str
    operation_kind: str = "cipher"
    iv_length: int | None = None
    iv_zero: bool | None = None
    salt_length: int | None = None
    iteration_count: int | None = None
    call_sequence: tuple[str, ...] = ()

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
        *,
        source: str,
        environment: str,
    ) -> CryptoOperation:
        forbidden = {
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
        } & set(value)
        if forbidden:
            raise ValueError("Crypto observation contains forbidden raw material fields.")
        operation_id = str(value.get("operation_id", ""))
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", operation_id):
            raise ValueError("Crypto operation ID is invalid.")
        transformation = str(value.get("transformation", ""))
        if not _TRANSFORMATION.fullmatch(transformation):
            raise ValueError("Crypto transformation is invalid.")
        parts = transformation.upper().split("/")
        algorithm = parts[0]
        mode = parts[1] if len(parts) >= 2 else None
        padding = parts[2] if len(parts) >= 3 else None
        purpose = str(value.get("purpose", "unknown")).casefold()
        if purpose not in _PURPOSES:
            raise ValueError("Crypto purpose is invalid.")
        operation_kind = str(value.get("operation_kind", "cipher")).casefold()
        if operation_kind not in _OPERATION_KINDS:
            raise ValueError("Crypto operation kind is invalid.")
        executed = value.get("executed")
        canary_match = value.get("canary_match")
        if not isinstance(executed, bool) or not isinstance(canary_match, bool):
            raise ValueError("Crypto executed/canary fields must be boolean.")
        key_length = value.get("key_length_bits")
        if key_length is not None and (
            isinstance(key_length, bool)
            or not isinstance(key_length, int)
            or not 1 <= key_length <= 16384
        ):
            raise ValueError("Crypto key length is invalid.")
        key_hash = value.get("key_sha256")
        iv_hash = value.get("iv_sha256")
        for name, digest in (("key_sha256", key_hash), ("iv_sha256", iv_hash)):
            if digest is not None and (
                not isinstance(digest, str) or not _HASH.fullmatch(digest)
            ):
                raise ValueError(f"Crypto {name} is invalid.")
        iv_source = str(value.get("iv_source", "unknown"))
        if iv_source not in {
            "random",
            "weak_random",
            "constant",
            "derived",
            "unknown",
            "none",
        }:
            raise ValueError("Crypto IV source is invalid.")
        try:
            key_origin = CryptoKeyOrigin(str(value.get("key_origin", "unknown")))
        except ValueError as exc:
            raise ValueError("Crypto key origin is invalid.") from exc
        iv_length = cls._optional_non_negative_int(value, "iv_length", maximum=65_536)
        iv_zero = value.get("iv_zero")
        if iv_zero is not None and not isinstance(iv_zero, bool):
            raise ValueError("Crypto iv_zero is invalid.")
        salt_length = cls._optional_non_negative_int(
            value,
            "salt_length",
            maximum=65_536,
        )
        iteration_count = cls._optional_non_negative_int(
            value,
            "iteration_count",
            maximum=2_147_483_647,
        )
        call_sequence_value = value.get("call_sequence", ())
        if (
            not isinstance(call_sequence_value, (list, tuple))
            or len(call_sequence_value) > 64
            or any(
                not isinstance(item, str)
                or not 1 <= len(item) <= 160
                or any(character in item for character in "\r\n\x00")
                for item in call_sequence_value
            )
        ):
            raise ValueError("Crypto call sequence is invalid.")
        return cls(
            operation_id=operation_id,
            transformation=transformation,
            algorithm=algorithm,
            mode=mode,
            padding=padding,
            purpose=purpose,
            executed=executed,
            key_length_bits=key_length,
            key_sha256=key_hash,
            iv_sha256=iv_hash,
            iv_source=iv_source,
            key_origin=key_origin,
            canary_match=canary_match,
            source=source,
            environment=environment,
            operation_kind=operation_kind,
            iv_length=iv_length,
            iv_zero=iv_zero,
            salt_length=salt_length,
            iteration_count=iteration_count,
            call_sequence=tuple(call_sequence_value),
        )

    @staticmethod
    def _optional_non_negative_int(
        value: Mapping[str, Any],
        name: str,
        *,
        maximum: int,
    ) -> int | None:
        item = value.get(name)
        if item is not None and (
            isinstance(item, bool)
            or not isinstance(item, int)
            or not 0 <= item <= maximum
        ):
            raise ValueError(f"Crypto {name} is invalid.")
        return item


@dataclass(frozen=True, slots=True)
class CryptoRuleResult:
    rule_id: str
    title: str
    status: FindingStatus
    confidence: str
    validation_type: str
    operation_ids: tuple[str, ...]
    details: dict[str, Any]
    finding_eligible: bool
    physical_validation_status: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["status"] = self.status.value
        return payload


@dataclass(frozen=True, slots=True)
class CryptoExtractionResult:
    operations: tuple[CryptoOperation, ...]
    errors: tuple[str, ...]


class CryptoAnalyzer:
    def __init__(self, policy: CryptoPolicy | None = None) -> None:
        self.policy = policy or CryptoPolicy()

    def analyze(
        self,
        operations: Iterable[CryptoOperation],
    ) -> tuple[CryptoRuleResult, ...]:
        values = tuple(operations)
        for item in values:
            if (item.source == "fixture") != (item.environment == "simulated"):
                raise ValueError("Fixture crypto operations require simulated provenance.")
        if len({(item.source, item.environment) for item in values}) > 1:
            raise ValueError("Crypto analysis cannot mix fixture and physical evidence.")
        if not values:
            return (
                self._result(
                    "CRYPTO-COVERAGE",
                    "Crypto runtime coverage unavailable",
                    FindingStatus.INCONCLUSIVE,
                    (),
                    {"reason": "No normalized runtime crypto operation was observed."},
                    values,
                ),
            )
        executed = tuple(item for item in values if item.executed)
        if not executed:
            return (
                self._result(
                    "CRYPTO-COVERAGE",
                    "Crypto runtime execution unavailable",
                    FindingStatus.INCONCLUSIVE,
                    (),
                    {"reason": "Normalized events did not prove a completed crypto operation."},
                    values,
                ),
            )
        output: list[CryptoRuleResult] = []
        weak = tuple(
            item for item in executed if item.algorithm in self.policy.weak_algorithms
        )
        if weak:
            output.append(
                self._result(
                    "CRYPTO-WEAK-ALGORITHM",
                    "Weak runtime crypto algorithm",
                    FindingStatus.CONFIRMED,
                    weak,
                    {"algorithms": sorted({item.algorithm for item in weak})},
                    values,
                )
            )
        weak_digest = tuple(
            item
            for item in executed
            if item.operation_kind in {"digest", "mac"}
            and re.sub(r"[^A-Z0-9]", "", item.algorithm)
            in _WEAK_DIGEST_ALGORITHMS
        )
        if weak_digest:
            output.append(
                self._result(
                    "CRYPTO-WEAK-DIGEST",
                    "Weak digest or MAC observed at runtime",
                    FindingStatus.POTENTIAL,
                    weak_digest,
                    {
                        "observed_algorithms": sorted(
                            {item.algorithm for item in weak_digest}
                        ),
                        "missing_evidence": [
                            "security-sensitive data or authentication context"
                        ],
                    },
                    values,
                )
            )
        weak_random = tuple(
            item
            for item in executed
            if item.operation_kind == "cipher"
            and (
                (item.iv_source == "weak_random" and item.purpose == "encrypt")
                or item.key_origin is CryptoKeyOrigin.WEAK_RANDOM
            )
        )
        if weak_random:
            output.append(
                self._result(
                    "CRYPTO-PREDICTABLE-RANDOM",
                    "Weak random output used as runtime cryptographic material",
                    FindingStatus.CONFIRMED,
                    weak_random,
                    {
                        "uses": sorted(
                            {
                                use
                                for item in weak_random
                                for use in (
                                    "initialization_vector"
                                    if item.iv_source == "weak_random"
                                    and item.purpose == "encrypt"
                                    else None,
                                    "key_material"
                                    if item.key_origin is CryptoKeyOrigin.WEAK_RANDOM
                                    else None,
                                )
                                if use is not None
                            }
                        ),
                        "missing_evidence": [],
                    },
                    values,
                )
            )
        ecb = tuple(
            item
            for item in executed
            if item.algorithm in _SYMMETRIC_ALGORITHMS and item.mode == "ECB"
        )
        if ecb:
            output.append(
                self._result(
                    "CRYPTO-ECB",
                    "ECB mode observed at runtime",
                    FindingStatus.CONFIRMED,
                    ecb,
                    {"transformations": sorted({item.transformation for item in ecb})},
                    values,
                )
            )
        short = tuple(
            item
            for item in executed
            if item.algorithm in _SYMMETRIC_ALGORITHMS
            and item.key_length_bits is not None
            and item.key_length_bits < self.policy.minimum_symmetric_key_bits
        )
        if short:
            output.append(
                self._result(
                    "CRYPTO-SHORT-KEY",
                    "Runtime key length below policy",
                    FindingStatus.CONFIRMED,
                    short,
                    {
                        "minimum_bits": self.policy.minimum_symmetric_key_bits,
                        "observed_bits": sorted(
                            {item.key_length_bits for item in short if item.key_length_bits}
                        ),
                    },
                    values,
                )
            )
        static_iv = tuple(
            item
            for item in executed
            if item.purpose == "encrypt"
            and item.iv_source == "constant"
            and item.iv_zero is not True
        )
        if static_iv:
            output.append(
                self._result(
                    "CRYPTO-STATIC-IV",
                    "Static IV source observed",
                    FindingStatus.CONFIRMED,
                    static_iv,
                    {
                        "iv_hashes": sorted(
                            {item.iv_sha256 for item in static_iv if item.iv_sha256}
                        )
                    },
                    values,
                )
            )
        zero_iv = tuple(
            item
            for item in executed
            if item.operation_kind == "cipher"
            and item.purpose == "encrypt"
            and item.iv_zero is True
        )
        if zero_iv:
            output.append(
                self._result(
                    "CRYPTO-ZERO-IV",
                    "All-zero IV observed at runtime",
                    FindingStatus.CONFIRMED,
                    zero_iv,
                    {
                        "iv_lengths": sorted(
                            {item.iv_length for item in zero_iv if item.iv_length is not None}
                        ),
                        "deterministic_zero_iv": True,
                    },
                    values,
                )
            )
        iv_operations: dict[tuple[str, str], set[str]] = {}
        for item in executed:
            if (
                item.operation_kind != "cipher"
                or item.purpose != "encrypt"
                or item.key_sha256 is None
                or item.iv_sha256 is None
            ):
                continue
            iv_operations.setdefault((item.key_sha256, item.iv_sha256), set()).add(
                item.operation_id
            )
        reused_pairs = {
            pair for pair, operation_ids in iv_operations.items() if len(operation_ids) >= 2
        }
        reused_by_id = {
            item.operation_id: item
            for item in executed
            if item.operation_kind == "cipher"
            and item.purpose == "encrypt"
            and (item.key_sha256, item.iv_sha256) in reused_pairs
        }
        reused = tuple(reused_by_id.values())
        if reused:
            output.append(
                self._result(
                    "CRYPTO-REUSED-IV",
                    "IV reuse observed across encryption operations",
                    FindingStatus.CONFIRMED,
                    reused,
                    {
                        "reuse_identifiers": [
                            {
                                "key_sha256": key_hash,
                                "iv_sha256": iv_hash,
                                "operation_count": len(
                                    iv_operations[(key_hash, iv_hash)]
                                ),
                            }
                            for key_hash, iv_hash in sorted(reused_pairs)
                        ]
                    },
                    values,
                )
            )
        low_pbe = tuple(
            item
            for item in executed
            if item.operation_kind == "pbe"
            and item.iteration_count is not None
            and item.iteration_count < self.policy.minimum_pbe_iterations
        )
        if low_pbe:
            output.append(
                self._result(
                    "CRYPTO-LOW-PBE-ITERATIONS",
                    "PBE iteration count below policy",
                    FindingStatus.POTENTIAL,
                    low_pbe,
                    {
                        "minimum_iterations": self.policy.minimum_pbe_iterations,
                        "observed_iterations": sorted(
                            {
                                item.iteration_count
                                for item in low_pbe
                                if item.iteration_count is not None
                            }
                        ),
                        "missing_evidence": [
                            "security-sensitive password derivation context"
                        ],
                    },
                    values,
                )
            )
        static_key = tuple(
            item for item in executed if item.key_origin is CryptoKeyOrigin.STATIC_RUNTIME
        )
        if static_key:
            output.append(
                self._result(
                    "CRYPTO-STATIC-KEY",
                    "Potential static key material observed at runtime",
                    FindingStatus.POTENTIAL,
                    static_key,
                    {
                        "key_hashes": sorted(
                            {item.key_sha256 for item in static_key if item.key_sha256}
                        )
                    },
                    values,
                )
            )
        canary = tuple(item for item in executed if item.canary_match)
        if canary:
            output.append(
                self._result(
                    "CRYPTO-CANARY-BOUNDARY",
                    "Controlled plaintext canary observed at crypto boundary",
                    FindingStatus.CONFIRMED,
                    canary,
                    {"canary_match": True},
                    values,
                )
            )
        incomplete = tuple(
            item
            for item in values
            if item.executed
            and item.operation_kind == "cipher"
            and (item.mode is None or item.padding is None)
        )
        if incomplete:
            output.append(
                self._result(
                    "CRYPTO-TRANSFORMATION-INCOMPLETE",
                    "Crypto transformation lacks mode or padding context",
                    FindingStatus.INCONCLUSIVE,
                    incomplete,
                    {
                        "transformations": sorted(
                            {item.transformation for item in incomplete}
                        )
                    },
                    values,
                )
            )
        if not output:
            output.append(
                self._result(
                    "CRYPTO-POLICY",
                    "No configured crypto weakness observed",
                    FindingStatus.PASS,
                    executed,
                    {"executed_operation_count": len(executed)},
                    values,
                )
            )
        return tuple(output)

    @staticmethod
    def _result(
        rule_id: str,
        title: str,
        status: FindingStatus,
        matched: Iterable[CryptoOperation],
        details: dict[str, Any],
        all_operations: tuple[CryptoOperation, ...],
    ) -> CryptoRuleResult:
        matched_values = tuple(matched)
        simulated = not all_operations or all(
            item.source == "fixture" and item.environment == "simulated"
            for item in all_operations
        )
        return CryptoRuleResult(
            rule_id=rule_id,
            title=title,
            status=status,
            confidence="high" if status is FindingStatus.CONFIRMED else "medium",
            validation_type="instrumented_validation",
            operation_ids=tuple(item.operation_id for item in matched_values),
            details=details,
            finding_eligible=not simulated,
            physical_validation_status="UNVERIFIED",
        )


def load_crypto_fixture(payload: Mapping[str, Any]) -> tuple[CryptoOperation, ...]:
    if payload.get("source") != "fixture" or payload.get("environment") != "simulated":
        raise ValueError("Crypto fixture requires fixture/simulated provenance.")
    operations = payload.get("operations")
    if not isinstance(operations, list):
        raise ValueError("Crypto fixture operations must be a list.")
    if not all(isinstance(item, Mapping) for item in operations):
        raise ValueError("Every crypto fixture operation must be an object.")
    return tuple(
        CryptoOperation.from_mapping(
            item,
            source="fixture",
            environment="simulated",
        )
        for item in operations
    )


def operations_from_frida_events(
    events: Iterable[Any],
    *,
    source: str,
    environment: str,
) -> CryptoExtractionResult:
    operations: list[CryptoOperation] = []
    errors: list[str] = []
    supported_methods = {
        "cipher.do_final": ("cipher", "unknown"),
        "digest.digest": ("digest", "digest"),
        "mac.do_final": ("mac", "sign"),
        "pbe.key_spec": ("pbe", "derive"),
    }
    for index, event in enumerate(events, start=1):
        method = getattr(event, "method", None)
        if getattr(event, "category", None) != "crypto" or method not in supported_methods:
            continue
        arguments = getattr(event, "arguments_redacted", ())
        if not arguments or not isinstance(arguments[0], Mapping):
            errors.append(f"event {index}: crypto metadata is missing")
            continue
        payload = dict(arguments[0])
        operation_kind, purpose = supported_methods[method]
        transformation = payload.get("transformation") or payload.get("algorithm")
        if not isinstance(transformation, str) or not transformation.strip():
            errors.append(f"event {index}: crypto transformation is missing")
            continue
        payload.setdefault("operation_id", f"runtime-{index}-{method}")
        payload.setdefault("transformation", transformation)
        payload.setdefault("operation_kind", operation_kind)
        payload.setdefault("purpose", purpose)
        payload.setdefault("executed", True)
        payload.setdefault("iv_source", "unknown" if operation_kind == "cipher" else "none")
        payload.setdefault("key_origin", "unknown")
        payload.setdefault("call_sequence", [method])
        payload["canary_match"] = bool(getattr(event, "canary_match", False))
        for digest_name in ("key_sha256", "iv_sha256"):
            if payload.get(digest_name) == "<redacted>":
                payload[digest_name] = None
        try:
            operations.append(
                CryptoOperation.from_mapping(
                    payload,
                    source=source,
                    environment=environment,
                )
            )
        except ValueError as exc:
            errors.append(f"event {index}: {exc}")
    return CryptoExtractionResult(tuple(operations), tuple(errors))
