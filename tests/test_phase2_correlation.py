from __future__ import annotations

import json
from pathlib import Path
from shutil import copyfile

from android_assessor.evidence import EvidenceRepository
from android_assessor.findings import FindingStatus
from android_assessor.frida_events import parse_frida_jsonl
from android_assessor.paths import ProjectPaths
from android_assessor.rules import RuleEngine
from android_assessor.session import SessionRepository
from android_assessor.storage import read_json_object, write_json_atomic, write_text_atomic

PACKAGE = "com.example.phase2lab"


def _prepared_session(
    tmp_path: Path,
    *,
    static_candidates: tuple[str, ...] = (),
) -> tuple[ProjectPaths, SessionRepository, str]:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
    (paths.root / "rules").mkdir()
    copyfile(
        Path(__file__).resolve().parent.parent / "rules" / "mvp.yaml",
        paths.root / "rules" / "mvp.yaml",
    )
    repository = SessionRepository(paths)
    record = repository.initialize(serial="FIXTURE_SERIAL", package=PACKAGE)
    session_paths = repository.paths_for(record.session_id)
    write_json_atomic(
        session_paths.app_json,
        {
            "package": PACKAGE,
            "manifest": {
                "debuggable": False,
                "test_only": False,
                "uses_cleartext_traffic": False,
                "network_security_config": None,
                "components": [],
            },
            "static_analysis": {
                "status": "completed",
                "security_api_candidates": [
                    {"inventory_id": candidate} for candidate in static_candidates
                ],
            },
        },
        root=paths.root,
    )
    return paths, repository, record.session_id


def _event(
    session_id: str,
    *,
    category: str,
    method: str,
    metadata: dict[str, object],
    index: int,
    canary: bool = False,
    package: str = PACKAGE,
) -> dict[str, object]:
    return {
        "timestamp": f"2026-07-18T10:00:{index:02d}+00:00",
        "session_id": session_id,
        "package": package,
        "pid": 4242,
        "thread_id": 7,
        "hook_id": f"phase2.fixture.{index}",
        "category": category,
        "method": method,
        "arguments_redacted": [metadata],
        "return_value_redacted": None,
        "canary_match": canary,
        "observer_version": "0.6.0",
    }


def _write_frida_events(
    paths: ProjectPaths,
    repository: SessionRepository,
    session_id: str,
    events: list[dict[str, object]],
) -> None:
    lifecycle = _event(
        session_id,
        category="lifecycle",
        method="observer_started",
        metadata={},
        index=0,
    )
    raw = "".join(json.dumps(item) + "\n" for item in [lifecycle, *events])
    parsed = parse_frida_jsonl(
        raw,
        expected_session_id=session_id,
        expected_package=PACKAGE,
        source="fixture",
        environment="simulated",
    )
    assert parsed.errors == ()
    session_paths = repository.paths_for(session_id)
    event_path = session_paths.redacted_dir / "frida" / "events.jsonl"
    write_text_atomic(event_path, parsed.to_jsonl(), root=paths.root)
    EvidenceRepository(paths, repository).register_file(
        session_id,
        event_path,
        evidence_type="frida_events",
        source="fixture",
        description="Attributed Phase 2 fixture events.",
        sensitive=True,
        redacted=True,
    )
    write_json_atomic(
        session_paths.frida_dir / "state.json",
        {"events_path": event_path.relative_to(session_paths.root).as_posix()},
        root=paths.root,
    )


def _findings(
    paths: ProjectPaths,
    repository: SessionRepository,
    session_id: str,
):
    return {
        item.rule_id: item
        for item in RuleEngine(paths, repository).evaluate(session_id)
    }


def _write_orchestrated_scan(
    paths: ProjectPaths,
    repository: SessionRepository,
    session_id: str,
    *,
    profile: str,
    frida_step: str,
    storage_step: str,
    capabilities: tuple[str, ...] = (),
    capability_errors: tuple[str, ...] = (),
) -> None:
    session_paths = repository.paths_for(session_id)
    write_json_atomic(
        session_paths.device_json,
        {
            "capabilities": {
                "capabilities": [
                    *(
                        {"name": name, "state": "available", "available": True}
                        for name in capabilities
                    ),
                    *(
                        {"name": name, "state": "error", "available": False}
                        for name in capability_errors
                    ),
                ]
            }
        },
        root=paths.root,
    )
    write_json_atomic(
        session_paths.scan_json,
        {
            "status": "running",
            "effective_profile": profile,
            "dynamic_steps": {
                "frida_observation": frida_step,
                "private_storage": storage_step,
                "rules": "running",
            },
        },
        root=paths.root,
    )


def test_webview_same_instance_correlation_is_potential_not_automatic_confirmation(
    tmp_path: Path,
) -> None:
    paths, repository, session_id = _prepared_session(tmp_path)
    _write_frida_events(
        paths,
        repository,
        session_id,
        [
            _event(
                session_id,
                category="webview",
                method="webview.setting",
                metadata={
                    "setting": "javascript_enabled",
                    "enabled": True,
                    "settings_id": "settings-1",
                    "webview_id": "webview-1",
                },
                index=1,
            ),
            _event(
                session_id,
                category="webview",
                method="webview.javascript_interface",
                metadata={
                    "webview_id": "webview-1",
                    "interface_name_sha256": "a" * 64,
                    "interface_name_length": 6,
                },
                index=2,
            ),
            _event(
                session_id,
                category="webview",
                method="webview.load_url",
                metadata={
                    "webview_id": "webview-1",
                    "url_scheme": "https",
                    "content_origin": "remote",
                    "is_remote": True,
                    "is_file": False,
                    "host_sha256": "b" * 64,
                    "length": 32,
                },
                index=3,
            ),
        ],
    )

    finding = _findings(paths, repository, session_id)["WEBVIEW-JS-BRIDGE-REMOTE"]

    assert finding.status is FindingStatus.POTENTIAL
    assert finding.details["observed_behavior"]["correlated_load_count"] == 1
    assert "attacker control" in finding.details["missing_evidence"][0]
    assert finding.frida_used is True
    assert finding.evidence_ids


def test_webview_load_only_and_cross_instance_configuration_are_not_findings(
    tmp_path: Path,
) -> None:
    paths, repository, session_id = _prepared_session(tmp_path)
    _write_frida_events(
        paths,
        repository,
        session_id,
        [
            _event(
                session_id,
                category="webview",
                method="webview.setting",
                metadata={
                    "setting": "javascript_enabled",
                    "enabled": True,
                    "settings_id": "settings-1",
                    "webview_id": "webview-1",
                },
                index=1,
            ),
            _event(
                session_id,
                category="webview",
                method="webview.javascript_interface",
                metadata={"webview_id": "webview-2"},
                index=2,
            ),
            _event(
                session_id,
                category="webview",
                method="webview.load_url",
                metadata={"webview_id": "webview-3", "is_remote": True},
                index=3,
            ),
        ],
    )

    findings = _findings(paths, repository, session_id)

    assert findings["WEBVIEW-JS-BRIDGE-REMOTE"].status is FindingStatus.INCONCLUSIVE
    assert findings["ASL-RUNTIME-WEBVIEW"].details["observation_status"] == "observed"


def test_webview_disabled_setting_or_removed_bridge_is_not_correlated(
    tmp_path: Path,
) -> None:
    paths, repository, session_id = _prepared_session(tmp_path)
    _write_frida_events(
        paths,
        repository,
        session_id,
        [
            _event(
                session_id,
                category="webview",
                method="webview.setting",
                metadata={
                    "setting": "javascript_enabled",
                    "enabled": True,
                    "webview_id": "webview-1",
                },
                index=1,
            ),
            _event(
                session_id,
                category="webview",
                method="webview.javascript_interface",
                metadata={
                    "webview_id": "webview-1",
                    "interface_name_sha256": "a" * 64,
                },
                index=2,
            ),
            _event(
                session_id,
                category="webview",
                method="webview.javascript_interface_removed",
                metadata={
                    "webview_id": "webview-1",
                    "interface_name_sha256": "a" * 64,
                },
                index=3,
            ),
            _event(
                session_id,
                category="webview",
                method="webview.setting",
                metadata={
                    "setting": "javascript_enabled",
                    "enabled": False,
                    "webview_id": "webview-1",
                },
                index=4,
            ),
            _event(
                session_id,
                category="webview",
                method="webview.load_url",
                metadata={"webview_id": "webview-1", "is_remote": True},
                index=5,
            ),
        ],
    )

    finding = _findings(paths, repository, session_id)["WEBVIEW-JS-BRIDGE-REMOTE"]

    assert finding.status is FindingStatus.INCONCLUSIVE
    assert finding.details["observed_behavior"]["correlated_load_count"] == 0


def test_webview_remote_content_is_correlated_with_later_runtime_configuration(
    tmp_path: Path,
) -> None:
    paths, repository, session_id = _prepared_session(tmp_path)
    _write_frida_events(
        paths,
        repository,
        session_id,
        [
            _event(
                session_id,
                category="webview",
                method="webview.load_url",
                metadata={"webview_id": "webview-1", "is_remote": True},
                index=1,
            ),
            _event(
                session_id,
                category="webview",
                method="webview.setting",
                metadata={
                    "setting": "javascript_enabled",
                    "enabled": True,
                    "webview_id": "webview-1",
                },
                index=2,
            ),
            _event(
                session_id,
                category="webview",
                method="webview.javascript_interface",
                metadata={
                    "webview_id": "webview-1",
                    "interface_name_sha256": "a" * 64,
                },
                index=3,
            ),
            _event(
                session_id,
                category="webview",
                method="webview.setting",
                metadata={
                    "setting": "mixed_content",
                    "mixed_content_mode": "always_allow",
                    "webview_id": "webview-1",
                },
                index=4,
            ),
        ],
    )

    findings = _findings(paths, repository, session_id)

    assert findings["WEBVIEW-JS-BRIDGE-REMOTE"].status is FindingStatus.POTENTIAL
    assert findings["WEBVIEW-UNSAFE-SETTINGS"].status is FindingStatus.POTENTIAL


def test_webview_file_access_setting_only_correlates_with_file_origin(
    tmp_path: Path,
) -> None:
    for index, (origin, expected) in enumerate(
        (
            ("remote", FindingStatus.INCONCLUSIVE),
            ("file", FindingStatus.POTENTIAL),
        ),
        start=1,
    ):
        paths, repository, session_id = _prepared_session(tmp_path / str(index))
        _write_frida_events(
            paths,
            repository,
            session_id,
            [
                _event(
                    session_id,
                    category="webview",
                    method="webview.setting",
                    metadata={
                        "setting": "file_url_access",
                        "enabled": True,
                        "webview_id": "webview-1",
                    },
                    index=1,
                ),
                _event(
                    session_id,
                    category="webview",
                    method="webview.load_url",
                    metadata={
                        "webview_id": "webview-1",
                        "content_origin": origin,
                        "is_remote": origin == "remote",
                        "is_file": origin == "file",
                    },
                    index=2,
                ),
            ],
        )

        finding = _findings(paths, repository, session_id)["WEBVIEW-UNSAFE-SETTINGS"]

        assert finding.status is expected



def test_webview_ssl_proceed_runtime_confirms_and_static_candidate_is_only_potential(
    tmp_path: Path,
) -> None:
    static_paths, static_repository, static_session = _prepared_session(
        tmp_path / "static",
        static_candidates=("WEBVIEW_SSL_ERROR_PROCEED",),
    )
    static_finding = _findings(
        static_paths,
        static_repository,
        static_session,
    )["WEBVIEW-SSL-ERROR-PROCEED"]
    assert static_finding.status is FindingStatus.POTENTIAL

    paths, repository, session_id = _prepared_session(tmp_path / "runtime")
    _write_frida_events(
        paths,
        repository,
        session_id,
        [
            _event(
                session_id,
                category="webview",
                method="webview.ssl_error_callback",
                metadata={"handler_id": "ssl-handler-1", "ssl_error_callback": True},
                index=1,
            ),
            _event(
                session_id,
                category="webview",
                method="webview.ssl_error_proceed",
                metadata={"handler_id": "ssl-handler-1", "decision": "proceed"},
                index=2,
            )
        ],
    )
    runtime_finding = _findings(paths, repository, session_id)[
        "WEBVIEW-SSL-ERROR-PROCEED"
    ]
    assert runtime_finding.status is FindingStatus.CONFIRMED


def test_webview_ssl_proceed_requires_the_same_callback_handler(tmp_path: Path) -> None:
    paths, repository, session_id = _prepared_session(tmp_path)
    _write_frida_events(
        paths,
        repository,
        session_id,
        [
            _event(
                session_id,
                category="webview",
                method="webview.ssl_error_callback",
                metadata={"handler_id": "ssl-handler-1"},
                index=1,
            ),
            _event(
                session_id,
                category="webview",
                method="webview.ssl_error_proceed",
                metadata={"handler_id": "ssl-handler-2", "decision": "proceed"},
                index=2,
            ),
        ],
    )

    finding = _findings(paths, repository, session_id)[
        "WEBVIEW-SSL-ERROR-PROCEED"
    ]

    assert finding.status is FindingStatus.INCONCLUSIVE
    assert finding.details["observed_behavior"]["matched_callback_proceed_count"] == 0
    assert finding.details["observed_behavior"]["unmatched_proceed_count"] == 1


def test_custom_trust_runtime_is_potential_and_generic_tls_call_is_inconclusive(
    tmp_path: Path,
) -> None:
    paths, repository, session_id = _prepared_session(tmp_path / "custom")
    _write_frida_events(
        paths,
        repository,
        session_id,
        [
            _event(
                session_id,
                category="tls",
                method="tls.ssl_context_init",
                metadata={
                    "ssl_context_id": "ssl-context-1",
                    "trust_manager_count": 1,
                    "custom_trust_manager": True,
                    "manager_class_hashes": ["c" * 64],
                },
                index=1,
            ),
            _event(
                session_id,
                category="tls",
                method="tls.check_server_trusted",
                metadata={
                    "implementation_class_sha256": "e" * 64,
                    "custom_trust_manager": True,
                    "decision": "returned",
                },
                index=2,
            ),
        ],
    )
    custom = _findings(paths, repository, session_id)["ASL-MVP-005"]
    assert custom.status is FindingStatus.POTENTIAL
    assert custom.details["custom_trust_manager_observed"] is True
    assert custom.details["trust_manager_accept_observed"] is True
    assert custom.details["missing_evidence"]

    safe_paths, safe_repository, safe_session = _prepared_session(tmp_path / "generic")
    _write_frida_events(
        safe_paths,
        safe_repository,
        safe_session,
        [
            _event(
                safe_session,
                category="tls",
                method="tls.ssl_context_init",
                metadata={
                    "ssl_context_id": "ssl-context-2",
                    "trust_manager_count": 1,
                    "custom_trust_manager": False,
                    "manager_class_hashes": ["d" * 64],
                },
                index=1,
            )
        ],
    )
    generic = _findings(safe_paths, safe_repository, safe_session)["ASL-MVP-005"]
    assert generic.status is FindingStatus.INCONCLUSIVE


def test_exact_canary_storage_sink_confirms_but_shape_or_wrong_package_does_not(
    tmp_path: Path,
) -> None:
    paths, repository, session_id = _prepared_session(tmp_path / "exact")
    _write_frida_events(
        paths,
        repository,
        session_id,
        [
            _event(
                session_id,
                category="storage",
                method="storage.sink",
                metadata={
                    "sink_type": "shared_preferences",
                    "persisted": True,
                    "editor_id": "pref-editor-1",
                },
                index=1,
                canary=True,
            )
        ],
    )
    findings = _findings(paths, repository, session_id)
    aggregate = findings["ASL-MVP-003"]
    exact = findings["STORAGE-SENSITIVE-CANARY"]
    assert aggregate.status is FindingStatus.INCONCLUSIVE
    assert exact.status is FindingStatus.CONFIRMED
    assert exact.details["observed_behavior"]["runtime_sinks"][0]["sink_type"] == (
        "shared_preferences"
    )

    rejected_paths, rejected_repository, rejected_session = _prepared_session(
        tmp_path / "wrong-package"
    )
    invalid = _event(
        rejected_session,
        category="storage",
        method="storage.sink",
        metadata={"sink_type": "shared_preferences", "persisted": True},
        index=1,
        canary=True,
        package="com.example.other",
    )
    parsed = parse_frida_jsonl(
        json.dumps(invalid),
        expected_session_id=rejected_session,
        expected_package=PACKAGE,
        source="fixture",
        environment="simulated",
    )
    assert parsed.events == ()
    assert "package attribution mismatch" in parsed.errors[0]
    rejected = _findings(
        rejected_paths,
        rejected_repository,
        rejected_session,
    )["ASL-MVP-003"]
    assert rejected.status is FindingStatus.INCONCLUSIVE


def test_exact_canary_sensitive_sinks_require_a_clear_external_boundary(
    tmp_path: Path,
) -> None:
    confirmed_paths, confirmed_repository, confirmed_session = _prepared_session(
        tmp_path / "confirmed"
    )
    _write_frida_events(
        confirmed_paths,
        confirmed_repository,
        confirmed_session,
        [
            _event(
                confirmed_session,
                category="sensitive_data",
                method="sensitive.sink",
                metadata={
                    "sink_type": "notification",
                    "target_scope": "system_ui",
                    "boundary_exposed": True,
                    "exposure_confidence": "clear",
                    "persisted": False,
                },
                index=1,
                canary=True,
            )
        ],
    )
    confirmed = _findings(
        confirmed_paths,
        confirmed_repository,
        confirmed_session,
    )["ASL-MVP-003"]
    assert confirmed.status is FindingStatus.CONFIRMED
    assert confirmed.details["exact_frida_sinks"][0]["sink_type"] == "notification"

    candidate_paths, candidate_repository, candidate_session = _prepared_session(
        tmp_path / "candidate"
    )
    _write_frida_events(
        candidate_paths,
        candidate_repository,
        candidate_session,
        [
            _event(
                candidate_session,
                category="sensitive_data",
                method="sensitive.sink",
                metadata={
                    "sink_type": "broadcast",
                    "delivery_kind": "sendBroadcast",
                    "target_scope": "implicit",
                    "boundary_exposed": True,
                    "exposure_confidence": "candidate",
                    "persisted": False,
                },
                index=1,
                canary=True,
            )
        ],
    )
    candidate = _findings(
        candidate_paths,
        candidate_repository,
        candidate_session,
    )["ASL-MVP-003"]
    assert candidate.status is FindingStatus.POTENTIAL
    assert candidate.details["exact_frida_sinks"] == []
    assert candidate.details["exact_frida_sink_candidates"][0]["sink_type"] == (
        "broadcast"
    )

    observed_paths, observed_repository, observed_session = _prepared_session(
        tmp_path / "observed"
    )
    _write_frida_events(
        observed_paths,
        observed_repository,
        observed_session,
        [
            _event(
                observed_session,
                category="sensitive_data",
                method="sensitive.sink",
                metadata={
                    "sink_type": "content_provider",
                    "target_scope": "unknown",
                    "boundary_exposed": False,
                    "exposure_confidence": "unknown",
                    "persisted": True,
                },
                index=1,
                canary=True,
            )
        ],
    )
    observed = _findings(
        observed_paths,
        observed_repository,
        observed_session,
    )["ASL-MVP-003"]
    assert observed.status is FindingStatus.INCONCLUSIVE
    assert observed.details["exact_frida_sink_observations"][0]["sink_type"] == (
        "content_provider"
    )


def test_exact_canary_file_sink_requires_package_scoped_storage(
    tmp_path: Path,
) -> None:
    cases = (
        ("other", False, FindingStatus.INCONCLUSIVE),
        ("external", False, FindingStatus.INCONCLUSIVE),
        ("internal", True, FindingStatus.CONFIRMED),
    )
    for index, (storage_area, package_scoped, expected) in enumerate(cases, start=1):
        paths, repository, session_id = _prepared_session(tmp_path / str(index))
        _write_frida_events(
            paths,
            repository,
            session_id,
            [
                _event(
                    session_id,
                    category="storage",
                    method="storage.sink",
                    metadata={
                        "sink_type": "file",
                        "storage_area": storage_area,
                        "package_scoped": package_scoped,
                        "persisted": True,
                        "path_sha256": "a" * 64,
                    },
                    index=1,
                    canary=True,
                )
            ],
        )

        finding = _findings(paths, repository, session_id)["STORAGE-SENSITIVE-CANARY"]

        assert finding.status is expected


def test_crypto_rule_coverage_is_per_flow_not_aggregate_policy_pass(
    tmp_path: Path,
) -> None:
    paths, repository, session_id = _prepared_session(tmp_path)
    _write_frida_events(
        paths,
        repository,
        session_id,
        [
            _event(
                session_id,
                category="crypto",
                method="digest.digest",
                metadata={
                    "operation_id": "digest-1",
                    "operation_kind": "digest",
                    "transformation": "MD5",
                    "purpose": "digest",
                    "executed": True,
                    "key_length_bits": None,
                    "key_sha256": None,
                    "iv_sha256": None,
                    "iv_source": "none",
                    "key_origin": "unknown",
                    "iv_length": None,
                    "iv_zero": None,
                    "salt_length": None,
                    "iteration_count": None,
                    "call_sequence": ["digest.get_instance", "digest.digest"],
                },
                index=1,
            )
        ],
    )

    findings = _findings(paths, repository, session_id)

    assert findings["CRYPTO-WEAK-DIGEST"].status is FindingStatus.POTENTIAL
    assert findings["CRYPTO-WEAK-DIGEST"].details["reason"]
    assert findings["CRYPTO-WEAK-DIGEST"].details["missing_evidence"] == [
        "security-sensitive data or authentication context"
    ]
    assert findings["CRYPTO-ECB"].status is FindingStatus.INCONCLUSIVE
    assert findings["CRYPTO-ECB"].details["observed_behavior"] == (
        "flow_not_triggered"
    )


def test_weak_random_crypto_correlation_is_consumed_by_rule_engine(
    tmp_path: Path,
) -> None:
    paths, repository, session_id = _prepared_session(tmp_path)
    _write_frida_events(
        paths,
        repository,
        session_id,
        [
            _event(
                session_id,
                category="crypto",
                method="cipher.do_final",
                metadata={
                    "operation_id": "weak-random-runtime",
                    "operation_kind": "cipher",
                    "transformation": "AES/CBC/PKCS5Padding",
                    "purpose": "encrypt",
                    "executed": True,
                    "key_length_bits": 128,
                    "key_sha256": "a" * 64,
                    "iv_sha256": "b" * 64,
                    "iv_length": 16,
                    "iv_zero": False,
                    "iv_source": "weak_random",
                    "key_origin": "weak_random",
                    "call_sequence": [
                        "random.next_bytes",
                        "cipher.init",
                        "cipher.do_final",
                    ],
                },
                index=1,
            )
        ],
    )

    finding = _findings(paths, repository, session_id)[
        "CRYPTO-PREDICTABLE-RANDOM"
    ]
    assert finding.status is FindingStatus.CONFIRMED
    assert finding.details["uses"] == ["initialization_vector", "key_material"]


def test_crypto_rules_do_not_pass_when_required_metadata_is_missing(
    tmp_path: Path,
) -> None:
    paths, repository, session_id = _prepared_session(tmp_path)

    def operation(operation_id: str) -> dict[str, object]:
        return {
            "operation_id": operation_id,
            "operation_kind": "cipher",
            "transformation": "AES",
            "purpose": "encrypt",
            "executed": True,
            "key_length_bits": None,
            "key_sha256": None,
            "iv_sha256": None,
            "iv_source": "unknown",
            "key_origin": "unknown",
            "iv_length": None,
            "iv_zero": None,
            "salt_length": None,
            "iteration_count": None,
            "call_sequence": ["cipher.do_final"],
        }

    pbe = {
        **operation("pbe-1"),
        "operation_kind": "pbe",
        "transformation": "PBE",
        "purpose": "derive",
        "call_sequence": ["pbe.key_spec"],
    }
    _write_frida_events(
        paths,
        repository,
        session_id,
        [
            _event(
                session_id,
                category="crypto",
                method="cipher.do_final",
                metadata=operation("cipher-1"),
                index=1,
            ),
            _event(
                session_id,
                category="crypto",
                method="cipher.do_final",
                metadata=operation("cipher-2"),
                index=2,
            ),
            _event(
                session_id,
                category="crypto",
                method="pbe.key_spec",
                metadata=pbe,
                index=3,
            ),
        ],
    )

    findings = _findings(paths, repository, session_id)

    for rule_id in (
        "CRYPTO-ECB",
        "CRYPTO-SHORT-KEY",
        "CRYPTO-ZERO-IV",
        "CRYPTO-REUSED-IV",
        "CRYPTO-LOW-PBE-ITERATIONS",
    ):
        assert findings[rule_id].status is FindingStatus.INCONCLUSIVE
        assert findings[rule_id].details["missing_evidence"]


def test_storage_security_rules_do_not_treat_root_readability_as_a_finding(
    tmp_path: Path,
) -> None:
    paths, repository, session_id = _prepared_session(tmp_path)
    session_paths = repository.paths_for(session_id)
    output = session_paths.redacted_dir / "storage" / "private-storage.json"
    write_json_atomic(
        output,
        {
            "root_mode": "adb_root",
            "observations": [
                {
                    "observation_id": "storage-root-readable",
                    "status": "post_compromise_observation",
                    "finding_eligible": False,
                    "artifact_paths": ["files/state.bin"],
                    "rationale": "Root readability alone is not an app weakness.",
                }
            ],
        },
        root=paths.root,
    )
    EvidenceRepository(paths, repository).register_file(
        session_id,
        output,
        evidence_type="private_storage_metadata",
        source="fixture",
        description="Bounded storage fixture.",
        sensitive=True,
        redacted=True,
    )

    findings = _findings(paths, repository, session_id)

    assert findings["STORAGE-WORLD-READABLE"].status is FindingStatus.PASS
    assert findings["STORAGE-WORLD-WRITABLE"].status is FindingStatus.PASS
    assert findings["STORAGE-SENSITIVE-CANARY"].status is FindingStatus.INCONCLUSIVE
    assert findings["ASL-RUNTIME-STORAGE"].details["observation_only"] is True


def test_incomplete_storage_inventory_cannot_produce_permission_passes(
    tmp_path: Path,
) -> None:
    paths, repository, session_id = _prepared_session(tmp_path)
    session_paths = repository.paths_for(session_id)
    output = session_paths.redacted_dir / "storage" / "private-storage.json"
    write_json_atomic(
        output,
        {
            "root_mode": "adb_root",
            "inventory_status": "partial",
            "inventory_limitations": ["aggregate_entry_limit"],
            "content_scan_status": "not_requested",
            "observations": [],
        },
        root=paths.root,
    )
    EvidenceRepository(paths, repository).register_file(
        session_id,
        output,
        evidence_type="private_storage_metadata",
        source="fixture",
        description="Truncated storage fixture.",
        sensitive=True,
        redacted=True,
    )

    findings = _findings(paths, repository, session_id)

    for rule_id in ("STORAGE-WORLD-READABLE", "STORAGE-WORLD-WRITABLE"):
        finding = findings[rule_id]
        assert finding.status is FindingStatus.INCONCLUSIVE
        assert finding.details["inventory_status"] == "partial"
        assert finding.details["missing_evidence"] == ["aggregate_entry_limit"]


def test_storage_canary_probe_failure_is_error_not_clean_no_match(
    tmp_path: Path,
) -> None:
    paths, repository, session_id = _prepared_session(tmp_path)
    session_paths = repository.paths_for(session_id)
    output = session_paths.redacted_dir / "storage" / "private-storage.json"
    write_json_atomic(
        output,
        {
            "root_mode": "adb_root",
            "inventory_status": "completed",
            "inventory_limitations": [],
            "content_scan_status": "error",
            "content_scan_limitations": ["probe_command_failed"],
            "observations": [],
        },
        root=paths.root,
    )
    EvidenceRepository(paths, repository).register_file(
        session_id,
        output,
        evidence_type="private_storage_metadata",
        source="fixture",
        description="Failed storage canary probe fixture.",
        sensitive=True,
        redacted=True,
    )

    finding = _findings(paths, repository, session_id)["STORAGE-SENSITIVE-CANARY"]

    assert finding.status is FindingStatus.ERROR
    assert finding.details["content_scan_status"] == "error"
    assert finding.details["missing_evidence"] == ["probe_command_failed"]


def test_phase2_metadata_parser_keeps_only_normalized_values() -> None:
    session_id = "20260718-100000-abcdef"
    event = _event(
        session_id,
        category="webview",
        method="webview.load_url",
        metadata={
            "webview_id": "webview-7",
            "url_scheme": "https",
            "content_origin": "remote",
            "host_sha256": "e" * 64,
            "is_remote": True,
            "raw_url": "https://lab.invalid/path?token=raw-secret",
            "interface_name": "raw-interface-name",
        },
        index=1,
    )

    parsed = parse_frida_jsonl(
        json.dumps(event),
        expected_session_id=session_id,
        expected_package=PACKAGE,
        source="fixture",
        environment="simulated",
    )
    rendered = parsed.to_jsonl()

    assert parsed.errors == ()
    assert "raw-secret" not in rendered
    assert "raw-interface-name" not in rendered
    assert "webview-7" in rendered
    assert "e" * 64 in rendered


def test_quick_profile_structurally_skips_capability_dependent_rules(
    tmp_path: Path,
) -> None:
    paths, repository, session_id = _prepared_session(
        tmp_path,
        static_candidates=("WEBVIEW_SSL_ERROR_PROCEED",),
    )
    _write_orchestrated_scan(
        paths,
        repository,
        session_id,
        profile="quick",
        frida_step="skipped",
        storage_step="skipped",
    )

    findings = _findings(paths, repository, session_id)

    assert findings["CRYPTO-ECB"].status is FindingStatus.SKIPPED
    assert (
        findings["CRYPTO-ECB"].details["error_category"]
        == "not_planned_for_profile"
    )
    assert findings["STORAGE-WORLD-READABLE"].status is FindingStatus.SKIPPED
    assert findings["STORAGE-WORLD-READABLE"].root_required is True
    # The static WebView SSL candidate remains evaluable without Frida.
    assert findings["WEBVIEW-SSL-ERROR-PROCEED"].status is FindingStatus.POTENTIAL
    assert findings["WEBVIEW-SSL-ERROR-PROCEED"].details["frida_required"] is False


def test_full_profile_skips_unavailable_capabilities_and_errors_failed_modules(
    tmp_path: Path,
) -> None:
    unavailable_paths, unavailable_repository, unavailable_session = _prepared_session(
        tmp_path / "unavailable"
    )
    _write_orchestrated_scan(
        unavailable_paths,
        unavailable_repository,
        unavailable_session,
        profile="full",
        frida_step="skipped",
        storage_step="skipped",
    )
    unavailable = _findings(
        unavailable_paths,
        unavailable_repository,
        unavailable_session,
    )

    assert unavailable["CRYPTO-ECB"].status is FindingStatus.SKIPPED
    assert (
        unavailable["CRYPTO-ECB"].details["error_category"]
        == "capability_unavailable"
    )
    assert unavailable["STORAGE-WORLD-WRITABLE"].status is FindingStatus.SKIPPED
    assert unavailable["STORAGE-SENSITIVE-CANARY"].status is FindingStatus.SKIPPED
    assert unavailable["WEBVIEW-SSL-ERROR-PROCEED"].status is FindingStatus.SKIPPED

    failed_paths, failed_repository, failed_session = _prepared_session(
        tmp_path / "failed"
    )
    _write_orchestrated_scan(
        failed_paths,
        failed_repository,
        failed_session,
        profile="full",
        frida_step="skipped",
        storage_step="skipped",
        capabilities=("ANDROID_ROOT", "FRIDA_CLIENT"),
    )
    failed = _findings(failed_paths, failed_repository, failed_session)

    assert failed["CRYPTO-ECB"].status is FindingStatus.ERROR
    assert (
        failed["CRYPTO-ECB"].details["error_category"]
        == "module_execution_failure"
    )
    assert failed["STORAGE-WORLD-WRITABLE"].status is FindingStatus.ERROR
    assert failed["STORAGE-WORLD-WRITABLE"].root_required is True
    assert failed["STORAGE-SENSITIVE-CANARY"].status is FindingStatus.ERROR
    assert failed["WEBVIEW-SSL-ERROR-PROCEED"].status is FindingStatus.ERROR

    probe_paths, probe_repository, probe_session = _prepared_session(
        tmp_path / "probe-error"
    )
    _write_orchestrated_scan(
        probe_paths,
        probe_repository,
        probe_session,
        profile="full",
        frida_step="skipped",
        storage_step="skipped",
        capability_errors=("ANDROID_ROOT", "FRIDA_CLIENT"),
    )
    probe_failed = _findings(probe_paths, probe_repository, probe_session)

    assert probe_failed["CRYPTO-ECB"].status is FindingStatus.ERROR
    assert probe_failed["CRYPTO-ECB"].details["error_category"] == (
        "capability_probe_failure"
    )
    assert probe_failed["STORAGE-WORLD-READABLE"].status is FindingStatus.ERROR
    assert probe_failed["STORAGE-SENSITIVE-CANARY"].status is FindingStatus.ERROR


def test_direct_rule_api_without_scan_metadata_keeps_evidence_driven_behavior(
    tmp_path: Path,
) -> None:
    paths, repository, session_id = _prepared_session(tmp_path)

    findings = _findings(paths, repository, session_id)

    assert findings["CRYPTO-ECB"].status is FindingStatus.INCONCLUSIVE
    assert findings["STORAGE-WORLD-READABLE"].status is FindingStatus.SKIPPED
    assert findings["STORAGE-WORLD-READABLE"].analysis_type != "capability_gate"
    assert findings["CRYPTO-ECB"].details["frida_required"] is True
    assert findings["STORAGE-WORLD-READABLE"].root_required is True


def test_rule_engine_accepts_pre_inventory_static_analysis_schema(tmp_path: Path) -> None:
    paths, repository, session_id = _prepared_session(tmp_path)
    app_path = repository.paths_for(session_id).app_json
    app = read_json_object(app_path, root=paths.root)
    app["static_analysis"] = {"schema_version": 1, "status": "completed"}
    write_json_atomic(app_path, app, root=paths.root)

    findings = _findings(paths, repository, session_id)

    assert findings["WEBVIEW-SSL-ERROR-PROCEED"].status is FindingStatus.INCONCLUSIVE
    assert findings["CRYPTO-ECB"].status is FindingStatus.INCONCLUSIVE


def test_predictable_random_rule_does_not_pass_partial_key_or_iv_coverage(
    tmp_path: Path,
) -> None:
    paths, repository, session_id = _prepared_session(tmp_path)

    def cipher_event(
        index: int,
        *,
        operation_id: str,
        iv_source: str,
        iv_sha256: str | None,
    ) -> dict[str, object]:
        return _event(
            session_id,
            category="crypto",
            method="cipher.do_final",
            metadata={
                "operation_id": operation_id,
                "operation_kind": "cipher",
                "transformation": "AES/CBC/PKCS5Padding",
                "purpose": "encrypt",
                "executed": True,
                "key_length_bits": 128,
                "key_sha256": "a" * 64,
                "iv_sha256": iv_sha256,
                "iv_length": 16 if iv_sha256 else None,
                "iv_zero": False if iv_sha256 else None,
                "iv_source": iv_source,
                "key_origin": "generated",
                "call_sequence": ["cipher.init", "cipher.do_final"],
            },
            index=index,
        )

    _write_frida_events(
        paths,
        repository,
        session_id,
        [
            cipher_event(
                1,
                operation_id="complete-secure-flow",
                iv_source="random",
                iv_sha256="b" * 64,
            ),
            cipher_event(
                2,
                operation_id="partial-flow",
                iv_source="unknown",
                iv_sha256=None,
            ),
        ],
    )

    finding = _findings(paths, repository, session_id)["CRYPTO-PREDICTABLE-RANDOM"]

    assert finding.status is FindingStatus.INCONCLUSIVE
    assert "every observed cipher operation" in finding.details["missing_evidence"][0]


def test_crypto_rule_does_not_pass_when_an_attributed_event_is_malformed(
    tmp_path: Path,
) -> None:
    paths, repository, session_id = _prepared_session(tmp_path)
    complete = {
        "operation_id": "complete-safe-flow",
        "operation_kind": "cipher",
        "transformation": "AES/GCM/NoPadding",
        "purpose": "encrypt",
        "executed": True,
        "key_length_bits": 256,
        "key_sha256": "a" * 64,
        "iv_sha256": "b" * 64,
        "iv_length": 12,
        "iv_zero": False,
        "iv_source": "random",
        "key_origin": "generated",
        "call_sequence": ["cipher.init", "cipher.do_final"],
    }
    malformed = {**complete, "operation_id": ""}
    _write_frida_events(
        paths,
        repository,
        session_id,
        [
            _event(
                session_id,
                category="crypto",
                method="cipher.do_final",
                metadata=complete,
                index=1,
            ),
            _event(
                session_id,
                category="crypto",
                method="cipher.do_final",
                metadata=malformed,
                index=2,
            ),
        ],
    )

    finding = _findings(paths, repository, session_id)["CRYPTO-ECB"]

    assert finding.status is FindingStatus.ERROR
    assert finding.details["error_category"] == "crypto_event_parse_failure"


def test_rule_engine_rejects_mixed_or_tampered_frida_evidence(
    tmp_path: Path,
) -> None:
    mixed_paths, mixed_repository, mixed_session = _prepared_session(
        tmp_path / "mixed"
    )
    _write_frida_events(mixed_paths, mixed_repository, mixed_session, [])
    mixed_session_paths = mixed_repository.paths_for(mixed_session)
    fixture_path = mixed_session_paths.redacted_dir / "frida" / "events.jsonl"
    runtime_path = mixed_session_paths.redacted_dir / "frida" / "runtime.jsonl"
    write_text_atomic(
        runtime_path,
        fixture_path.read_text(encoding="utf-8"),
        root=mixed_paths.root,
    )
    EvidenceRepository(mixed_paths, mixed_repository).register_file(
        mixed_session,
        runtime_path,
        evidence_type="frida_events",
        source="frida",
        description="Runtime provenance collision fixture.",
        sensitive=True,
        redacted=True,
    )

    mixed_finding = _findings(mixed_paths, mixed_repository, mixed_session)["CRYPTO-ECB"]

    assert mixed_finding.status is FindingStatus.ERROR
    assert mixed_finding.details["error_category"] == (
        "frida_evidence_validation_failure"
    )

    tampered_paths, tampered_repository, tampered_session = _prepared_session(
        tmp_path / "tampered"
    )
    _write_frida_events(tampered_paths, tampered_repository, tampered_session, [])
    tampered_path = (
        tampered_repository.paths_for(tampered_session).redacted_dir
        / "frida"
        / "events.jsonl"
    )
    write_text_atomic(
        tampered_path,
        tampered_path.read_text(encoding="utf-8") + "\n",
        root=tampered_paths.root,
    )

    tampered_finding = _findings(
        tampered_paths,
        tampered_repository,
        tampered_session,
    )["CRYPTO-ECB"]

    assert tampered_finding.status is FindingStatus.ERROR
    assert "integrity mismatch" in tampered_finding.details["evidence_errors"][0]


def test_orchestrated_scan_rejects_unregistered_frida_evidence(
    tmp_path: Path,
) -> None:
    paths, repository, session_id = _prepared_session(tmp_path)
    session_paths = repository.paths_for(session_id)
    events = [
        _event(
            session_id,
            category="lifecycle",
            method="observer_started",
            metadata={},
            index=0,
        ),
        _event(
            session_id,
            category="crypto",
            method="cipher.do_final",
            metadata={
                "operation_id": "unregistered-operation",
                "operation_kind": "cipher",
                "transformation": "AES/ECB/PKCS5Padding",
                "purpose": "encrypt",
                "executed": True,
                "canary_match": False,
                "iv_source": "none",
                "key_origin": "unknown",
            },
            index=1,
        ),
    ]
    event_path = session_paths.redacted_dir / "frida" / "unregistered.jsonl"
    write_text_atomic(
        event_path,
        "".join(json.dumps(item) + "\n" for item in events),
        root=paths.root,
    )
    write_json_atomic(
        session_paths.frida_dir / "state.json",
        {
            "events_path": event_path.relative_to(session_paths.root).as_posix(),
            "status": "stopped",
            "handshake_status": "VALID",
        },
        root=paths.root,
    )
    _write_orchestrated_scan(
        paths,
        repository,
        session_id,
        profile="full",
        frida_step="stopped",
        storage_step="skipped",
        capabilities=("ANDROID_ROOT", "FRIDA_CLIENT"),
    )

    finding = _findings(paths, repository, session_id)["CRYPTO-ECB"]

    assert finding.status is FindingStatus.ERROR
    assert finding.details["error_category"] == "frida_evidence_validation_failure"
    assert "not registered" in finding.details["evidence_errors"][0]


def test_exact_canary_webview_sink_requires_a_clear_remote_boundary(
    tmp_path: Path,
) -> None:
    cases = (
        ("webview.load_data", False, FindingStatus.INCONCLUSIVE),
        ("webview.load_data_with_base_url", True, FindingStatus.POTENTIAL),
        ("webview.load_url", True, FindingStatus.CONFIRMED),
    )
    for index, (method, is_remote, expected) in enumerate(cases, start=1):
        paths, repository, session_id = _prepared_session(tmp_path / str(index))
        _write_frida_events(
            paths,
            repository,
            session_id,
            [
                _event(
                    session_id,
                    category="webview",
                    method=method,
                    metadata={
                        "webview_id": f"webview-{index}",
                        "content_origin": "remote" if is_remote else "inline",
                        "is_remote": is_remote,
                    },
                    index=1,
                    canary=True,
                )
            ],
        )

        finding = _findings(paths, repository, session_id)["ASL-MVP-003"]

        assert finding.status is expected
