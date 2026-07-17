"""Feature-gated certificate-authority ownership and rollback planning."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from .backends import CertificateAuthorityBackend
from .errors import AndroidAssessorError, CleanupConflictError, CleanupError
from .redaction import redact_text
from .validation import validate_session_id

PHYSICAL_VALIDATION_STATUS = "UNVERIFIED_ON_PHYSICAL_DEVICE"
IMPLEMENTATION_STATUS = "IMPLEMENTED_UNVERIFIED"
_CERTIFICATE_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")


class CaStore(StrEnum):
    USER = "user"
    SYSTEM = "system"


class CaSnapshotState(StrEnum):
    CAPTURED_PRESENT = "CAPTURED_PRESENT"
    CAPTURED_ABSENT = "CAPTURED_ABSENT"
    CAPTURE_FAILED = "CAPTURE_FAILED"


class CaAppliedState(StrEnum):
    NOT_APPLIED = "NOT_APPLIED"
    PRE_EXISTING = "PRE_EXISTING"
    APPLIED = "APPLIED"
    REMOVED = "REMOVED"


class CaOwnershipState(StrEnum):
    NONE = "none"
    PRE_EXISTING = "pre_existing"
    FRAMEWORK_OWNED = "framework_owned"
    UNKNOWN = "unknown"


class CaCleanupDecision(StrEnum):
    REMOVE_OWNED = "REMOVE_OWNED"
    PRESERVE_PRE_EXISTING = "PRESERVE_PRE_EXISTING"
    ALREADY_ABSENT = "ALREADY_ABSENT"
    NO_ACTION = "NO_ACTION"
    CONFLICT = "CONFLICT"
    REFUSE_UNCAPTURED = "REFUSE_UNCAPTURED"


@dataclass(frozen=True, slots=True)
class CaSnapshot:
    state: CaSnapshotState
    fingerprint_sha256: str | None
    error: str | None
    captured_at: str


@dataclass(frozen=True, slots=True)
class CaOwnershipLedger:
    session_id: str
    store: CaStore
    certificate_id: str
    target_fingerprint_sha256: str
    snapshot: CaSnapshot
    applied_state: CaAppliedState = CaAppliedState.NOT_APPLIED
    ownership_state: CaOwnershipState = CaOwnershipState.NONE
    applied_fingerprint_sha256: str | None = None
    applied_at: str | None = None
    cleanup_error: str | None = None
    implementation_status: str = IMPLEMENTATION_STATUS
    physical_validation_status: str = PHYSICAL_VALIDATION_STATUS

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["store"] = self.store.value
        payload["snapshot"]["state"] = self.snapshot.state.value
        payload["applied_state"] = self.applied_state.value
        payload["ownership_state"] = self.ownership_state.value
        return payload


class CaApplyRollbackError(CleanupError):
    """An apply failed and owned state remains for stale-session recovery."""

    def __init__(self, message: str, recovery_ledger: CaOwnershipLedger) -> None:
        super().__init__(message)
        self.recovery_ledger = recovery_ledger


@dataclass(frozen=True, slots=True)
class CaCleanupPlan:
    decision: CaCleanupDecision
    current_fingerprint_sha256: str | None
    reason: str


def normalize_ca_fingerprint(value: str) -> str:
    normalized = value.replace(":", "").strip().casefold()
    if not _SHA256.fullmatch(normalized):
        raise ValueError("CA fingerprint must be a complete SHA-256 value.")
    return normalized


def validate_certificate_id(value: str) -> str:
    if not _CERTIFICATE_ID.fullmatch(value):
        raise ValueError("CA certificate ID is invalid.")
    return value


def _now() -> str:
    return datetime.now(UTC).isoformat()


class CaStateManager:
    """Plans ownership-safe CA changes; no production route enables this yet."""

    def __init__(self, backend: CertificateAuthorityBackend) -> None:
        self.backend = backend

    def snapshot(
        self,
        serial: str,
        *,
        session_id: str,
        store: CaStore,
        certificate_id: str,
        target_fingerprint_sha256: str,
    ) -> CaOwnershipLedger:
        selected_session = validate_session_id(session_id)
        selected_id = validate_certificate_id(certificate_id)
        target = normalize_ca_fingerprint(target_fingerprint_sha256)
        try:
            current = self.backend.read_ca_fingerprint(
                serial,
                store=store.value,
                certificate_id=selected_id,
            )
            normalized_current = (
                normalize_ca_fingerprint(current) if current is not None else None
            )
            state = (
                CaSnapshotState.CAPTURED_PRESENT
                if normalized_current is not None
                else CaSnapshotState.CAPTURED_ABSENT
            )
            error = None
        except (AndroidAssessorError, ValueError) as exc:
            normalized_current = None
            state = CaSnapshotState.CAPTURE_FAILED
            error = redact_text(str(exc))[:300] or type(exc).__name__
        return CaOwnershipLedger(
            session_id=selected_session,
            store=store,
            certificate_id=selected_id,
            target_fingerprint_sha256=target,
            snapshot=CaSnapshot(
                state=state,
                fingerprint_sha256=normalized_current,
                error=error,
                captured_at=_now(),
            ),
            ownership_state=(
                CaOwnershipState.UNKNOWN
                if state is CaSnapshotState.CAPTURE_FAILED
                else CaOwnershipState.NONE
            ),
        )

    def apply(self, serial: str, ledger: CaOwnershipLedger) -> CaOwnershipLedger:
        if ledger.snapshot.state is CaSnapshotState.CAPTURE_FAILED:
            raise CleanupError("Refusing CA mutation because the snapshot failed.")
        if ledger.applied_state is not CaAppliedState.NOT_APPLIED:
            return ledger
        previous = ledger.snapshot.fingerprint_sha256
        if previous is not None:
            if previous != ledger.target_fingerprint_sha256:
                raise CleanupConflictError(
                    "A different certificate already occupies the managed CA identity."
                )
            return replace(
                ledger,
                applied_state=CaAppliedState.PRE_EXISTING,
                ownership_state=CaOwnershipState.PRE_EXISTING,
                applied_fingerprint_sha256=previous,
            )
        recovery_ledger = replace(
            ledger,
            applied_state=CaAppliedState.APPLIED,
            ownership_state=CaOwnershipState.FRAMEWORK_OWNED,
            applied_fingerprint_sha256=ledger.target_fingerprint_sha256,
            applied_at=_now(),
        )
        try:
            self.backend.install_ca(
                serial,
                store=ledger.store.value,
                certificate_id=ledger.certificate_id,
                fingerprint_sha256=ledger.target_fingerprint_sha256,
            )
            current = self.backend.read_ca_fingerprint(
                serial,
                store=ledger.store.value,
                certificate_id=ledger.certificate_id,
            )
            if (
                current is None
                or normalize_ca_fingerprint(current)
                != ledger.target_fingerprint_sha256
            ):
                raise CleanupError("Installed CA fingerprint could not be verified.")
        except (AndroidAssessorError, ValueError) as exc:
            try:
                plan = self.plan_cleanup(serial, recovery_ledger)
                if plan.decision is CaCleanupDecision.REMOVE_OWNED:
                    self.cleanup(serial, recovery_ledger)
                elif plan.decision is not CaCleanupDecision.ALREADY_ABSENT:
                    raise CleanupConflictError(plan.reason)
            except (AndroidAssessorError, ValueError) as rollback_exc:
                raise CaApplyRollbackError(
                    "CA apply failed and rollback requires stale-session recovery.",
                    recovery_ledger,
                ) from rollback_exc
            raise CleanupError("CA apply failed and its owned mutation was rolled back.") from exc
        return recovery_ledger

    def plan_cleanup(self, serial: str, ledger: CaOwnershipLedger) -> CaCleanupPlan:
        if ledger.snapshot.state is CaSnapshotState.CAPTURE_FAILED:
            return CaCleanupPlan(
                CaCleanupDecision.REFUSE_UNCAPTURED,
                None,
                "Original CA state was not captured; no mutation is safe.",
            )
        if ledger.ownership_state is CaOwnershipState.PRE_EXISTING:
            return CaCleanupPlan(
                CaCleanupDecision.PRESERVE_PRE_EXISTING,
                ledger.snapshot.fingerprint_sha256,
                "The certificate existed before this session.",
            )
        if ledger.ownership_state is not CaOwnershipState.FRAMEWORK_OWNED:
            return CaCleanupPlan(
                CaCleanupDecision.NO_ACTION,
                None,
                "The session does not own a certificate mutation.",
            )
        try:
            current = self.backend.read_ca_fingerprint(
                serial,
                store=ledger.store.value,
                certificate_id=ledger.certificate_id,
            )
            normalized = normalize_ca_fingerprint(current) if current is not None else None
        except (AndroidAssessorError, ValueError) as exc:
            return CaCleanupPlan(
                CaCleanupDecision.CONFLICT,
                None,
                f"Current CA state could not be verified: {redact_text(str(exc))[:200]}",
            )
        if normalized is None:
            return CaCleanupPlan(
                CaCleanupDecision.ALREADY_ABSENT,
                None,
                "The framework-owned certificate is already absent.",
            )
        if normalized != ledger.applied_fingerprint_sha256:
            return CaCleanupPlan(
                CaCleanupDecision.CONFLICT,
                normalized,
                "The managed CA identity now has a different fingerprint.",
            )
        return CaCleanupPlan(
            CaCleanupDecision.REMOVE_OWNED,
            normalized,
            "The current certificate matches the session-owned fingerprint.",
        )

    def cleanup(self, serial: str, ledger: CaOwnershipLedger) -> CaOwnershipLedger:
        plan = self.plan_cleanup(serial, ledger)
        if plan.decision in {
            CaCleanupDecision.PRESERVE_PRE_EXISTING,
            CaCleanupDecision.ALREADY_ABSENT,
            CaCleanupDecision.NO_ACTION,
        }:
            return replace(
                ledger,
                applied_state=(
                    CaAppliedState.REMOVED
                    if plan.decision is CaCleanupDecision.ALREADY_ABSENT
                    else ledger.applied_state
                ),
                cleanup_error=None,
            )
        if plan.decision is CaCleanupDecision.REFUSE_UNCAPTURED:
            raise CleanupError(plan.reason)
        if plan.decision is CaCleanupDecision.CONFLICT:
            raise CleanupConflictError(plan.reason)
        removed = self.backend.remove_ca(
            serial,
            store=ledger.store.value,
            certificate_id=ledger.certificate_id,
            expected_fingerprint_sha256=ledger.target_fingerprint_sha256,
        )
        if not removed:
            raise CleanupConflictError("CA fingerprint changed before removal.")
        current = self.backend.read_ca_fingerprint(
            serial,
            store=ledger.store.value,
            certificate_id=ledger.certificate_id,
        )
        if current is not None:
            raise CleanupError("Framework-owned CA remains installed after cleanup.")
        return replace(
            ledger,
            applied_state=CaAppliedState.REMOVED,
            ownership_state=CaOwnershipState.NONE,
            cleanup_error=None,
        )
