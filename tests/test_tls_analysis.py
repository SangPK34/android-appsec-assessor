from __future__ import annotations

import json
from pathlib import Path
from shutil import copyfile

import pytest

from android_assessor.findings import FindingStatus
from android_assessor.paths import ProjectPaths
from android_assessor.rules import RuleEngine
from android_assessor.session import SessionRepository
from android_assessor.storage import write_json_atomic
from android_assessor.tls_analysis import (
    TlsBehaviorAnalyzer,
    TlsBehaviorState,
    TlsEvidence,
    load_tls_fixture,
)
from tests.fakes import load_fixture


@pytest.mark.parametrize(
    ("scenario", "state", "status"),
    (
        ("mitm_accepted", TlsBehaviorState.MITM_ACCEPTED, FindingStatus.CONFIRMED),
        ("mitm_rejected", TlsBehaviorState.MITM_REJECTED, FindingStatus.PASS),
        (
            "pinning_observed",
            TlsBehaviorState.PINNING_OBSERVED,
            FindingStatus.INCONCLUSIVE,
        ),
        (
            "trust_manager_observed",
            TlsBehaviorState.TRUST_MANAGER_OBSERVED,
            FindingStatus.INCONCLUSIVE,
        ),
        ("no_traffic", TlsBehaviorState.NO_TRAFFIC, FindingStatus.INCONCLUSIVE),
        ("network_error", TlsBehaviorState.NETWORK_ERROR, FindingStatus.INCONCLUSIVE),
        (
            "unattributed_traffic",
            TlsBehaviorState.UNATTRIBUTED_TRAFFIC,
            FindingStatus.INCONCLUSIVE,
        ),
        ("inconclusive", TlsBehaviorState.INCONCLUSIVE, FindingStatus.INCONCLUSIVE),
    ),
)
def test_tls_fixture_state_matrix(
    scenario: str,
    state: TlsBehaviorState,
    status: FindingStatus,
) -> None:
    evidence = load_tls_fixture(load_fixture("tls/states.json"), scenario)

    result = TlsBehaviorAnalyzer.analyze(evidence)

    assert result.state is state
    assert result.finding_status is status
    assert result.finding_eligible is False
    assert result.physical_validation_status == "UNVERIFIED"


def test_tls_validation_type_reflects_actual_instrumentation_dependency() -> None:
    traffic_only = TlsBehaviorAnalyzer.analyze(
        TlsEvidence(
            target_request_count=1,
            canary_request_count=1,
            canary_response_count=1,
            source="fixture",
            environment="simulated",
        )
    )
    instrumented = TlsBehaviorAnalyzer.analyze(
        TlsEvidence(
            target_request_count=1,
            canary_request_count=1,
            pinning_observed=True,
            source="fixture",
            environment="simulated",
        )
    )

    assert traffic_only.validation_type == "adb_assisted_validation"
    assert instrumented.validation_type == "instrumented_validation"


def test_target_https_response_without_canary_is_not_confirmed() -> None:
    result = TlsBehaviorAnalyzer.from_events(
        [
            {
                "event": "request",
                "flow_id": "target-1",
                "scheme": "https",
                "attribution": "target",
            },
            {
                "event": "response",
                "flow_id": "target-1",
                "attribution": "target",
            },
        ],
        [],
        source="fixture",
        environment="simulated",
    )

    assert result.state is TlsBehaviorState.INCONCLUSIVE
    assert result.finding_status is FindingStatus.INCONCLUSIVE


def test_unattributed_background_https_cannot_confirm_target() -> None:
    result = TlsBehaviorAnalyzer.from_events(
        [
            {
                "event": "request",
                "flow_id": "background",
                "scheme": "https",
                "attribution": "unattributed",
            },
            {
                "event": "response",
                "flow_id": "background",
                "attribution": "unattributed",
            },
        ],
        [],
        source="fixture",
        environment="simulated",
    )

    assert result.state is TlsBehaviorState.UNATTRIBUTED_TRAFFIC
    assert result.finding_status is FindingStatus.INCONCLUSIVE


def test_network_failure_is_not_interpreted_as_pinning() -> None:
    result = TlsBehaviorAnalyzer.from_events(
        [
            {
                "event": "network_error",
                "flow_id": "canary",
                "scheme": "https",
                "attribution": "validation_canary",
                "error_kind": "network",
            }
        ],
        [],
        source="fixture",
        environment="simulated",
    )

    assert result.state is TlsBehaviorState.NETWORK_ERROR
    assert result.finding_status is FindingStatus.INCONCLUSIVE


def test_trust_manager_call_without_outcome_is_inconclusive() -> None:
    result = TlsBehaviorAnalyzer.from_events(
        [
            {
                "event": "request",
                "flow_id": "target",
                "scheme": "https",
                "attribution": "target",
            }
        ],
        [
            {
                "category": "tls",
                "method": "javax.net.ssl.SSLContext.init",
                "hook_id": "trust.ssl_context_init.0",
            }
        ],
        source="fixture",
        environment="simulated",
    )

    assert result.state is TlsBehaviorState.INCONCLUSIVE
    assert result.finding_status is FindingStatus.INCONCLUSIVE


@pytest.mark.parametrize(
    ("method", "marker", "decision", "class_name"),
    (
        (
            "tls.check_server_trusted",
            "custom_trust_manager",
            "returned",
            "unknown",
        ),
        (
            "tls.check_server_trusted",
            "custom_trust_manager",
            "returned",
            "com.android.org.conscrypt.TrustManagerImpl",
        ),
        (
            "tls.hostname_verify",
            "custom_hostname_verifier",
            "accepted",
            "com.android.okhttp.internal.tls.OkHostnameVerifier",
        ),
        (
            "tls.hostname_verify",
            "custom_hostname_verifier",
            "accepted",
            "okhttp3.internal.tls.OkHostnameVerifier",
        ),
    ),
)
def test_unknown_or_platform_tls_class_is_not_classified_custom(
    method: str,
    marker: str,
    decision: str,
    class_name: str,
) -> None:
    result = TlsBehaviorAnalyzer.from_events(
        [
            {
                "event": "request",
                "flow_id": "target",
                "scheme": "https",
                "attribution": "target",
            }
        ],
        [
            {
                "category": "tls",
                "method": method,
                "arguments_redacted": [
                    {
                        marker: True,
                        "implementation_class_name": class_name,
                        "decision": decision,
                    }
                ],
            }
        ],
        source="fixture",
        environment="simulated",
    )

    assert result.state is not TlsBehaviorState.CUSTOM_TRUST_CONFIGURED
    assert result.finding_status is FindingStatus.INCONCLUSIVE
    assert result.evidence.custom_trust_manager_observed is False
    assert result.evidence.custom_hostname_verifier_observed is False


@pytest.mark.parametrize(
    ("method", "marker", "decision"),
    (
        ("tls.check_server_trusted", "custom_trust_manager", "threw"),
        ("tls.hostname_verify", "custom_hostname_verifier", "rejected"),
    ),
)
def test_custom_tls_component_that_only_rejects_is_not_potential(
    method: str,
    marker: str,
    decision: str,
) -> None:
    result = TlsBehaviorAnalyzer.from_events(
        [
            {
                "event": "request",
                "flow_id": "target",
                "scheme": "https",
                "attribution": "target",
            }
        ],
        [
            {
                "category": "tls",
                "method": method,
                "arguments_redacted": [
                    {
                        marker: True,
                        "implementation_class_name": "com.example.security.StrictVerifier",
                        "decision": decision,
                    }
                ],
            }
        ],
        source="fixture",
        environment="simulated",
    )

    assert result.state is TlsBehaviorState.CUSTOM_TRUST_CONFIGURED
    assert result.finding_status is FindingStatus.INCONCLUSIVE
    assert "rejected" in result.rationale


@pytest.mark.parametrize(
    ("method", "marker", "decision"),
    (
        ("tls.check_server_trusted", "custom_trust_manager", "returned"),
        ("tls.hostname_verify", "custom_hostname_verifier", "accepted"),
    ),
)
def test_custom_tls_acceptance_remains_potential_without_controlled_proof(
    method: str,
    marker: str,
    decision: str,
) -> None:
    result = TlsBehaviorAnalyzer.from_events(
        [
            {
                "event": "request",
                "flow_id": "target",
                "scheme": "https",
                "attribution": "target",
            }
        ],
        [
            {
                "category": "tls",
                "method": method,
                "arguments_redacted": [
                    {
                        marker: True,
                        "implementation_class_name": "com.example.security.CustomVerifier",
                        "decision": decision,
                    }
                ],
            }
        ],
        source="fixture",
        environment="simulated",
    )

    assert result.state is TlsBehaviorState.CUSTOM_TRUST_CONFIGURED
    assert result.finding_status is FindingStatus.POTENTIAL


@pytest.mark.parametrize(
    "kwargs",
    (
        {"target_request_count": 0, "canary_request_count": 1},
        {"target_request_count": 1, "canary_request_count": 0, "canary_response_count": 1},
        {"target_request_count": -1},
        {"source": "fixture", "environment": "physical"},
    ),
)
def test_tls_evidence_rejects_impossible_counts_or_provenance(
    kwargs: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        TlsEvidence(**kwargs)  # type: ignore[arg-type]


def prepared_rule_session(tmp_path: Path) -> tuple[ProjectPaths, SessionRepository, str]:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
    (paths.root / "rules").mkdir()
    copyfile(
        Path(__file__).resolve().parent.parent / "rules" / "core.yaml",
        paths.root / "rules" / "core.yaml",
    )
    repository = SessionRepository(paths)
    record = repository.initialize(serial="FIXTURE_SERIAL", package="com.example.app")
    session_paths = repository.paths_for(record.session_id)
    write_json_atomic(
        session_paths.app_json,
        {
            "package": record.package,
            "manifest": {
                "debuggable": False,
                "test_only": False,
                "uses_cleartext_traffic": False,
                "network_security_config": None,
                "components": [],
            },
        },
        root=paths.root,
    )
    return paths, repository, record.session_id


@pytest.mark.parametrize(
    ("attribution", "expected"),
    (
        ("target", FindingStatus.INCONCLUSIVE),
        ("validation_canary", FindingStatus.CONFIRMED),
    ),
)
def test_tls_rule_requires_validation_canary_for_confirmation(
    tmp_path: Path,
    attribution: str,
    expected: FindingStatus,
) -> None:
    paths, repository, session_id = prepared_rule_session(tmp_path)
    session_paths = repository.paths_for(session_id)
    event_path = session_paths.traffic_dir / "events.jsonl"
    events = [
        {
            "event": "request",
            "flow_id": "fixture-flow",
            "scheme": "https",
            "attribution": attribution,
        },
        {
            "event": "response",
            "flow_id": "fixture-flow",
            "attribution": attribution,
        },
    ]
    event_path.write_text(
        "".join(json.dumps(item) + "\n" for item in events),
        encoding="utf-8",
    )
    write_json_atomic(
        session_paths.traffic_dir / "state.json",
        {"events_path": "traffic/events.jsonl"},
        root=paths.root,
    )

    findings = {
        item.rule_id: item for item in RuleEngine(paths, repository).evaluate(session_id)
    }

    assert findings["ASL-NETWORK-TLS-TRUST"].status is expected
    assert findings["ASL-NETWORK-TLS-TRUST"].details["tls_behavior_state"] == (
        "MITM_ACCEPTED" if expected is FindingStatus.CONFIRMED else "INCONCLUSIVE"
    )
