"""Offline analysis of normalized, redacted runtime crypto observations."""

from __future__ import annotations

import re
from collections import Counter
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


class CryptoKeyOrigin(StrEnum):
    UNKNOWN = "unknown"
    GENERATED = "generated"
    DERIVED = "derived"
    STATIC_RUNTIME = "static_runtime"


@dataclass(frozen=True, slots=True)
class CryptoPolicy:
    minimum_symmetric_key_bits: int = 128
    weak_algorithms: frozenset[str] = frozenset({"DES", "3DES", "DESEDE", "RC4"})

    def __post_init__(self) -> None:
        if not 64 <= self.minimum_symmetric_key_bits <= 512:
            raise ValueError("Crypto minimum key length must be between 64 and 512 bits.")


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

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
        *,
        source: str,
        environment: str,
    ) -> CryptoOperation:
        forbidden = {"key", "key_material", "iv", "plaintext", "ciphertext"} & set(value)
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
        if purpose not in {"encrypt", "decrypt", "wrap", "unwrap", "unknown"}:
            raise ValueError("Crypto purpose is invalid.")
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
        if iv_source not in {"random", "constant", "derived", "unknown", "none"}:
            raise ValueError("Crypto IV source is invalid.")
        try:
            key_origin = CryptoKeyOrigin(str(value.get("key_origin", "unknown")))
        except ValueError as exc:
            raise ValueError("Crypto key origin is invalid.") from exc
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
        )


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
        static_iv = tuple(item for item in executed if item.iv_source == "constant")
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
        iv_counts = Counter(
            item.iv_sha256
            for item in executed
            if item.purpose == "encrypt" and item.iv_sha256 is not None
        )
        reused_hashes = {digest for digest, count in iv_counts.items() if count > 1}
        reused = tuple(item for item in executed if item.iv_sha256 in reused_hashes)
        if reused:
            output.append(
                self._result(
                    "CRYPTO-REUSED-IV",
                    "IV reuse observed across encryption operations",
                    FindingStatus.CONFIRMED,
                    reused,
                    {"reuse_identifiers": sorted(reused_hashes)},
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
            if item.executed and (item.mode is None or item.padding is None)
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
            physical_validation_status="UNVERIFIED" if simulated else "UNVERIFIED",
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
    for index, event in enumerate(events, start=1):
        if getattr(event, "category", None) != "crypto" or getattr(
            event, "method", None
        ) != "cipher.do_final":
            continue
        arguments = getattr(event, "arguments_redacted", ())
        if not arguments or not isinstance(arguments[0], Mapping):
            errors.append(f"event {index}: crypto metadata is missing")
            continue
        payload = dict(arguments[0])
        payload["canary_match"] = bool(getattr(event, "canary_match", False))
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
