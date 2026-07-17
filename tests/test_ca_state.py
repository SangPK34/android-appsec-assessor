from __future__ import annotations

import pytest

from android_assessor.ca_state import (
    IMPLEMENTATION_STATUS,
    PHYSICAL_VALIDATION_STATUS,
    CaAppliedState,
    CaApplyRollbackError,
    CaCleanupDecision,
    CaOwnershipState,
    CaSnapshotState,
    CaStateManager,
    CaStore,
    normalize_ca_fingerprint,
)
from android_assessor.errors import AdbError, CleanupConflictError, CleanupError
from tests.fakes import FakeAndroidBackend, load_fixture

SESSION_ID = "20260717-120000-abcdef"
SERIAL = "FIXTURE_SERIAL"


@pytest.fixture
def ca_fixture() -> dict[str, object]:
    return load_fixture("ca/states.json")


def _values(ca_fixture: dict[str, object]) -> tuple[str, str, str]:
    return (
        str(ca_fixture["certificate_id"]),
        str(ca_fixture["target_fingerprint_sha256"]),
        str(ca_fixture["replacement_fingerprint_sha256"]),
    )


def _snapshot(
    backend: FakeAndroidBackend,
    ca_fixture: dict[str, object],
    *,
    store: CaStore = CaStore.USER,
):
    certificate_id, target, _ = _values(ca_fixture)
    return CaStateManager(backend).snapshot(
        SERIAL,
        session_id=SESSION_ID,
        store=store,
        certificate_id=certificate_id,
        target_fingerprint_sha256=target,
    )


def test_ca_snapshot_failure_refuses_apply_and_cleanup(
    ca_fixture: dict[str, object],
) -> None:
    backend = FakeAndroidBackend(ca_snapshot_fails=True)
    manager = CaStateManager(backend)
    ledger = _snapshot(backend, ca_fixture)

    assert ledger.snapshot.state is CaSnapshotState.CAPTURE_FAILED
    assert ledger.ownership_state is CaOwnershipState.UNKNOWN
    with pytest.raises(CleanupError, match="snapshot failed"):
        manager.apply(SERIAL, ledger)
    with pytest.raises(CleanupError, match="not captured"):
        manager.cleanup(SERIAL, ledger)
    assert not any(name in {"install_ca", "remove_ca"} for name, _ in backend.operations)


def test_preexisting_ca_is_never_owned_or_removed(ca_fixture: dict[str, object]) -> None:
    certificate_id, target, _ = _values(ca_fixture)
    backend = FakeAndroidBackend(
        ca_certificates={(CaStore.USER.value, certificate_id): target}
    )
    manager = CaStateManager(backend)
    ledger = manager.apply(SERIAL, _snapshot(backend, ca_fixture))

    assert ledger.applied_state is CaAppliedState.PRE_EXISTING
    assert ledger.ownership_state is CaOwnershipState.PRE_EXISTING
    assert manager.plan_cleanup(SERIAL, ledger).decision is (
        CaCleanupDecision.PRESERVE_PRE_EXISTING
    )
    cleaned = manager.cleanup(SERIAL, ledger)
    assert cleaned.applied_state is CaAppliedState.PRE_EXISTING
    assert backend.ca_certificates[(CaStore.USER.value, certificate_id)] == target
    assert not any(name == "remove_ca" for name, _ in backend.operations)


def test_framework_owned_ca_cleanup_is_verified_and_idempotent(
    ca_fixture: dict[str, object],
) -> None:
    certificate_id, target, _ = _values(ca_fixture)
    backend = FakeAndroidBackend()
    manager = CaStateManager(backend)
    ledger = manager.apply(SERIAL, _snapshot(backend, ca_fixture))

    assert ledger.ownership_state is CaOwnershipState.FRAMEWORK_OWNED
    assert ledger.applied_fingerprint_sha256 == target
    assert manager.plan_cleanup(SERIAL, ledger).decision is CaCleanupDecision.REMOVE_OWNED

    cleaned = manager.cleanup(SERIAL, ledger)
    cleaned_again = manager.cleanup(SERIAL, cleaned)

    assert cleaned.applied_state is CaAppliedState.REMOVED
    assert cleaned_again == cleaned
    assert (CaStore.USER.value, certificate_id) not in backend.ca_certificates
    assert sum(name == "remove_ca" for name, _ in backend.operations) == 1


def test_external_ca_replacement_is_a_cleanup_conflict(
    ca_fixture: dict[str, object],
) -> None:
    certificate_id, _, replacement = _values(ca_fixture)
    backend = FakeAndroidBackend()
    manager = CaStateManager(backend)
    ledger = manager.apply(SERIAL, _snapshot(backend, ca_fixture))
    backend.ca_certificates[(CaStore.USER.value, certificate_id)] = replacement

    plan = manager.plan_cleanup(SERIAL, ledger)

    assert plan.decision is CaCleanupDecision.CONFLICT
    assert plan.current_fingerprint_sha256 == replacement
    with pytest.raises(CleanupConflictError, match="different fingerprint"):
        manager.cleanup(SERIAL, ledger)
    assert backend.ca_certificates[(CaStore.USER.value, certificate_id)] == replacement
    assert not any(name == "remove_ca" for name, _ in backend.operations)


def test_different_preexisting_ca_blocks_apply_without_overwrite(
    ca_fixture: dict[str, object],
) -> None:
    certificate_id, _, replacement = _values(ca_fixture)
    backend = FakeAndroidBackend(
        ca_certificates={(CaStore.SYSTEM.value, certificate_id): replacement}
    )
    manager = CaStateManager(backend)
    ledger = _snapshot(backend, ca_fixture, store=CaStore.SYSTEM)

    with pytest.raises(CleanupConflictError, match="different certificate"):
        manager.apply(SERIAL, ledger)
    assert backend.ca_certificates[(CaStore.SYSTEM.value, certificate_id)] == replacement
    assert not any(name == "install_ca" for name, _ in backend.operations)


def test_user_and_system_ca_stores_are_distinct(ca_fixture: dict[str, object]) -> None:
    certificate_id, target, replacement = _values(ca_fixture)
    backend = FakeAndroidBackend(
        ca_certificates={(CaStore.USER.value, certificate_id): replacement}
    )
    manager = CaStateManager(backend)
    system_ledger = manager.apply(
        SERIAL,
        _snapshot(backend, ca_fixture, store=CaStore.SYSTEM),
    )

    assert system_ledger.store is CaStore.SYSTEM
    assert backend.ca_certificates[(CaStore.USER.value, certificate_id)] == replacement
    assert backend.ca_certificates[(CaStore.SYSTEM.value, certificate_id)] == target


def test_cleanup_refuses_when_current_ca_state_cannot_be_verified(
    ca_fixture: dict[str, object],
) -> None:
    backend = FakeAndroidBackend()
    manager = CaStateManager(backend)
    ledger = manager.apply(SERIAL, _snapshot(backend, ca_fixture))
    backend.ca_snapshot_fails = True

    assert manager.plan_cleanup(SERIAL, ledger).decision is CaCleanupDecision.CONFLICT
    with pytest.raises(CleanupConflictError, match="could not be verified"):
        manager.cleanup(SERIAL, ledger)
    assert not any(name == "remove_ca" for name, _ in backend.operations)


def test_fault_after_ca_install_is_rolled_back_immediately(
    ca_fixture: dict[str, object],
) -> None:
    certificate_id, _, _ = _values(ca_fixture)
    backend = FakeAndroidBackend(fail_after_mutation=1)
    manager = CaStateManager(backend)

    with pytest.raises(CleanupError, match="owned mutation was rolled back"):
        manager.apply(SERIAL, _snapshot(backend, ca_fixture))

    assert (CaStore.USER.value, certificate_id) not in backend.ca_certificates
    assert [name for name, _ in backend.operations if name.endswith("_ca")] == [
        "read_ca",
        "install_ca",
        "read_ca",
        "read_ca",
        "remove_ca",
        "read_ca",
    ]


class RollbackBlockedBackend(FakeAndroidBackend):
    rollback_blocked: bool = True

    def remove_ca(
        self,
        serial: str,
        *,
        store: str,
        certificate_id: str,
        expected_fingerprint_sha256: str,
    ) -> bool:
        if self.rollback_blocked:
            raise AdbError("Injected CA rollback failure.")
        return super().remove_ca(
            serial,
            store=store,
            certificate_id=certificate_id,
            expected_fingerprint_sha256=expected_fingerprint_sha256,
        )


def test_failed_ca_rollback_exposes_recovery_ledger(
    ca_fixture: dict[str, object],
) -> None:
    certificate_id, target, _ = _values(ca_fixture)
    backend = RollbackBlockedBackend(fail_after_mutation=1)
    manager = CaStateManager(backend)

    with pytest.raises(CaApplyRollbackError) as captured:
        manager.apply(SERIAL, _snapshot(backend, ca_fixture))

    recovery = captured.value.recovery_ledger
    assert recovery.ownership_state is CaOwnershipState.FRAMEWORK_OWNED
    assert recovery.applied_fingerprint_sha256 == target
    assert backend.ca_certificates[(CaStore.USER.value, certificate_id)] == target

    backend.rollback_blocked = False
    cleaned = manager.cleanup(SERIAL, recovery)
    assert cleaned.applied_state is CaAppliedState.REMOVED


@pytest.mark.parametrize(
    "value",
    (
        "short",
        "g" * 64,
        "a" * 63,
        "a" * 65,
    ),
)
def test_ca_fingerprint_rejects_incomplete_or_non_sha256_values(value: str) -> None:
    with pytest.raises(ValueError, match="SHA-256"):
        normalize_ca_fingerprint(value)


def test_ca_fingerprint_accepts_colon_separated_uppercase() -> None:
    value = ":".join(["AA"] * 32)
    assert normalize_ca_fingerprint(value) == "a" * 64


def test_ca_ledger_cannot_claim_physical_validation(ca_fixture: dict[str, object]) -> None:
    ledger = _snapshot(FakeAndroidBackend(), ca_fixture)
    payload = ledger.to_dict()

    assert payload["implementation_status"] == IMPLEMENTATION_STATUS
    assert payload["physical_validation_status"] == PHYSICAL_VALIDATION_STATUS
    assert payload["snapshot"]["state"] == "CAPTURED_ABSENT"
    assert ca_fixture["source"] == "fixture"
    assert ca_fixture["environment"] == "simulated"
