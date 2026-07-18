"""Profile-neutral rule evaluation over shared static and runtime evidence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import yaml

from .crypto_analysis import CryptoAnalyzer, operations_from_frida_events
from .errors import AndroidAssessorError, SessionError
from .evidence import EvidenceRepository, sha256_file
from .findings import FindingRecord, FindingRepository, FindingStatus
from .frida_events import FridaHandshakeStatus, parse_frida_jsonl
from .manifest_analysis import ManifestSecurityAnalyzer
from .paths import ProjectPaths
from .redaction import redact_text
from .root_detection import RootDetectionAnalyzer, root_events_from_frida
from .session import SessionRepository
from .storage import read_json_object, require_under_root
from .tls_analysis import TlsBehaviorAnalyzer
from .traffic import load_traffic_events


@dataclass(frozen=True, slots=True)
class RuleDefinition:
    rule_id: str
    evaluator: str
    title: str
    category: str
    description: str
    severity: str
    confidence: str
    remediation: str
    mappings: dict[str, str]
    validation_type: str
    validation_supported: bool
    validation_observable: str | None
    root_required: bool = False
    frida_required: bool = False
    observation_only: bool = False


def _optional_json(path: Path, root: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        return read_json_object(path, root=root)
    except SessionError:
        return None


def _frida_events(
    path: Path,
    *,
    expected_session_id: str,
    expected_package: str,
    source: str,
    environment: str,
) -> tuple[list[dict[str, Any]], list[str]]:
    if not path.is_file():
        return [], [f"Frida evidence file is missing: {path.name}"]
    try:
        parsed = parse_frida_jsonl(
            path.read_text(encoding="utf-8", errors="replace"),
            expected_session_id=expected_session_id,
            expected_package=expected_package,
            source=source,
            environment=environment,
        )
    except (AndroidAssessorError, OSError, ValueError) as exc:
        return [], [redact_text(str(exc))[:300]]
    errors = list(parsed.errors)
    if parsed.handshake_status is not FridaHandshakeStatus.VALID:
        errors.append(
            f"Frida observer handshake is {parsed.handshake_status.value.casefold()}."
        )
    if errors:
        return [], errors
    return [item.to_dict() for item in parsed.events], []


def _event_metadata(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        argument
        for event in events
        for argument in event.get("arguments_redacted", [])
        if isinstance(argument, dict)
    ]


def _static_api_ids(static_analysis: dict[str, Any] | None) -> set[str]:
    if not static_analysis:
        return set()
    candidates = static_analysis.get("security_api_candidates", [])
    if not isinstance(candidates, list):
        return set()
    return {
        str(item.get("inventory_id"))
        for item in candidates
        if isinstance(item, dict) and item.get("inventory_id")
    }


_SYMMETRIC_CIPHERS = {
    "AES",
    "DES",
    "3DES",
    "DESEDE",
    "RC4",
    "BLOWFISH",
    "TWOFISH",
    "CAMELLIA",
}


class RuleEngine:
    def __init__(
        self,
        paths: ProjectPaths,
        sessions: SessionRepository | None = None,
    ) -> None:
        self.paths = paths
        self.sessions = sessions or SessionRepository(paths)
        self.findings = FindingRepository(paths, self.sessions)
        self.evidence = EvidenceRepository(paths, self.sessions)
        self.definitions = self._load_definitions(paths.root / "rules" / "mvp.yaml")

    def _load_definitions(self, path: Path) -> tuple[RuleDefinition, ...]:
        self.paths.require_inside_root(path)
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise SessionError(f"Could not load rules: {exc}") from exc
        values = payload.get("rules") if isinstance(payload, dict) else None
        if not isinstance(values, list) or not values:
            raise SessionError("Rule file must contain at least one rule.")
        output: list[RuleDefinition] = []
        for value in values:
            if not isinstance(value, dict):
                raise SessionError("Rule entry is invalid.")
            validation_type = str(value.get("validation_type", "none"))
            output.append(
                RuleDefinition(
                    rule_id=str(value["id"]),
                    evaluator=str(value["evaluator"]),
                    title=str(value["title"]),
                    category=str(value["category"]),
                    description=str(value["description"]),
                    severity=str(value["severity"]),
                    confidence=str(value["confidence"]),
                    remediation=str(value["remediation"]),
                    mappings={
                        "masvs": str(value.get("masvs_mapping", "mapping_pending")),
                        "mastg": str(value.get("mastg_mapping", "mapping_pending")),
                        "cwe": str(value.get("cwe_mapping", "mapping_pending")),
                    },
                    validation_type=validation_type,
                    validation_supported=validation_type
                    in {"natural_validation", "adb_assisted_validation"},
                    validation_observable=(
                        str(value["validation_observable"])
                        if value.get("validation_observable")
                        else None
                    ),
                    root_required=bool(value.get("root_required", False)),
                    frida_required=bool(value.get("frida_required", False)),
                    observation_only=bool(value.get("observation_only", False)),
                )
            )
        return tuple(output)

    @staticmethod
    def _execution_gate(
        definition: RuleDefinition,
        context: dict[str, Any],
    ) -> tuple[FindingStatus, str, dict[str, Any], tuple[str, ...], bool, bool] | None:
        """Gate capability-dependent rules only for orchestrated scan profiles.

        Direct RuleEngine callers predate scan profiles and intentionally remain
        evidence-driven when scan metadata is absent.
        """
        scan = context.get("scan_state")
        if not isinstance(scan, dict):
            return None
        profile = str(scan.get("effective_profile") or scan.get("profile") or "")
        if profile not in {"quick", "full"}:
            return None
        steps = scan.get("dynamic_steps")
        steps = steps if isinstance(steps, dict) else {}

        requirements: list[tuple[str, str, bool, bool, bool]] = []
        if definition.root_required:
            requirements.append(
                (
                    "root",
                    "private_storage",
                    bool(context.get("root_available")),
                    context.get("private_storage") is not None,
                    bool(context.get("root_capability_error")),
                )
            )
        if definition.frida_required:
            frida_state = context.get("frida_state")
            frida_ready = bool(
                isinstance(frida_state, dict)
                and frida_state.get("handshake_status") == "VALID"
                and frida_state.get("status") in {"running", "stopped", "stop_failed"}
            )
            requirements.append(
                (
                    "frida",
                    "frida_observation",
                    bool(context.get("frida_available")),
                    frida_ready,
                    bool(context.get("frida_capability_error")),
                )
            )

        for capability, step_name, available, executed, probe_error in requirements:
            if executed:
                continue
            step_status = str(steps.get(step_name, "not_recorded"))
            if profile == "quick":
                status = FindingStatus.SKIPPED
                category = "not_planned_for_profile"
                reason = (
                    f"{capability} execution is not planned for the quick scan profile."
                )
            elif probe_error:
                status = FindingStatus.ERROR
                category = "capability_probe_failure"
                reason = f"Required {capability} capability probe failed."
            elif not available:
                status = FindingStatus.SKIPPED
                category = "capability_unavailable"
                reason = f"Required {capability} capability is unavailable."
            else:
                status = FindingStatus.ERROR
                category = "module_execution_failure"
                reason = (
                    f"Required {capability} module did not produce a usable execution "
                    "result."
                )
            return (
                status,
                "capability_gate",
                {
                    "reason": reason,
                    "error_category": category,
                    "method": "orchestrated_capability_gate",
                    "preconditions": [f"{capability}_capability_and_module_execution"],
                    "missing_evidence": [f"{step_name}_execution"],
                    "module": step_name,
                    "module_result": step_status,
                    "effective_profile": profile,
                    "root_required": definition.root_required,
                    "frida_required": definition.frida_required,
                },
                (),
                False,
                False,
            )
        return None

    @staticmethod
    def _alternative_execution_gate(
        context: dict[str, Any],
        requirements: tuple[tuple[str, str, bool, bool, bool], ...],
    ) -> tuple[FindingStatus, str, dict[str, Any], tuple[str, ...], bool, bool] | None:
        """Require at least one usable evidence path for an orchestrated Full scan."""
        scan = context.get("scan_state")
        if not isinstance(scan, dict):
            return None
        profile = str(scan.get("effective_profile") or scan.get("profile") or "")
        if profile != "full" or any(item[3] for item in requirements):
            return None
        steps = scan.get("dynamic_steps")
        steps = steps if isinstance(steps, dict) else {}
        available = [item for item in requirements if item[2]]
        probe_errors = [item for item in requirements if item[4]]
        if probe_errors and not available:
            status = FindingStatus.ERROR
            category = "capability_probe_failure"
            reason = "Every alternative evidence capability failed or was unavailable."
        elif not available:
            status = FindingStatus.SKIPPED
            category = "capability_unavailable"
            reason = "No alternative evidence capability is available for this rule."
        else:
            status = FindingStatus.ERROR
            category = "module_execution_failure"
            reason = "Available alternative modules produced no usable evidence result."
        return (
            status,
            "capability_gate",
            {
                "reason": reason,
                "error_category": category,
                "method": "orchestrated_alternative_capability_gate",
                "preconditions": ["at_least_one_alternative_evidence_path"],
                "missing_evidence": [item[1] for item in requirements],
                "alternative_capabilities": [item[0] for item in requirements],
                "module_results": {
                    item[1]: str(steps.get(item[1], "not_recorded"))
                    for item in requirements
                },
                "effective_profile": profile,
            },
            (),
            False,
            False,
        )

    @staticmethod
    def _is_launcher(component: dict[str, Any]) -> bool:
        for intent_filter in component.get("intent_filters", []):
            actions = intent_filter.get("actions", [])
            categories = intent_filter.get("categories", [])
            if (
                "android.intent.action.MAIN" in actions
                and "android.intent.category.LAUNCHER" in categories
            ):
                return True
        return False

    def _evaluate_rule(
        self,
        definition: RuleDefinition,
        context: dict[str, Any],
    ) -> tuple[FindingStatus, str, dict[str, Any], tuple[str, ...], bool, bool]:
        manifest = context["manifest"]
        evidence = context["evidence"]
        traffic = context["traffic_events"]
        logcat = context["logcat"]
        frida = context["frida_events"]
        static_analysis = context["static_analysis"]
        if definition.frida_required and context.get("frida_evidence_errors"):
            return (
                FindingStatus.ERROR,
                "instrumentation",
                {
                    "reason": "Attributed Frida evidence failed integrity or schema checks.",
                    "error_category": "frida_evidence_validation_failure",
                    "evidence_errors": list(context["frida_evidence_errors"]),
                    "method": "frida_evidence_attribution_gate",
                    "preconditions": [
                        "evidence hash matches the registered artifact",
                        "observer handshake, version, session, and package are valid",
                    ],
                    "missing_evidence": ["usable attributed Frida observer events"],
                },
                context["evidence"]("frida_events"),
                False,
                False,
            )
        attributed_traffic = [
            item
            for item in traffic
            if item.get("attribution") in {"target", "validation_canary"}
        ]
        if definition.evaluator == "app_debuggable":
            if manifest is None:
                return (
                    FindingStatus.SKIPPED,
                    "static",
                    {
                        "reason": "Normalized manifest evidence is unavailable.",
                        "method": "normalized_manifest_build_flags",
                        "preconditions": ["AndroidManifest.xml was parsed"],
                        "missing_evidence": ["debuggable and testOnly attributes"],
                    },
                    (),
                    False,
                    False,
                )
            values = {
                "debuggable": manifest.get("debuggable"),
                "test_only": manifest.get("test_only"),
            }
            status = (
                FindingStatus.CONFIRMED
                if any(value is True for value in values.values())
                else FindingStatus.PASS
                if all(value is False for value in values.values())
                else FindingStatus.INCONCLUSIVE
            )
            complete = all(isinstance(value, bool) for value in values.values())
            return (
                status,
                "static",
                {
                    **values,
                    "reason": (
                        "A debuggable or test-only build flag is enabled."
                        if status is FindingStatus.CONFIRMED
                        else "Both build flags are explicitly disabled."
                        if status is FindingStatus.PASS
                        else "One or more normalized build flags are unavailable."
                    ),
                    "method": "normalized_manifest_build_flags",
                    "preconditions": ["AndroidManifest.xml was parsed"],
                    "missing_evidence": (
                        [] if complete else ["explicit normalized build-flag values"]
                    ),
                },
                evidence("manifest_tree"),
                False,
                False,
            )

        if definition.evaluator == "manifest_policy":
            if manifest is None:
                return FindingStatus.SKIPPED, "static", {}, (), False, False
            source = (
                "emulator"
                if str(context["serial"]).startswith("emulator-")
                else "physical_device"
            )
            results = ManifestSecurityAnalyzer.analyze(
                manifest,
                source=source,
                environment=source,
            )
            selected = next(
                (item for item in results if item.test_id == definition.rule_id),
                None,
            )
            if selected is None:
                return (
                    FindingStatus.INCONCLUSIVE,
                    "static",
                    {"reason": "policy result unavailable"},
                    (),
                    False,
                    False,
                )
            details = {
                **selected.details,
                "rationale": selected.rationale,
                "reason": selected.rationale,
                "method": "normalized_manifest_policy",
                "preconditions": [
                    "the installed APK set was collected from the selected package",
                    "available AndroidManifest.xml files were parsed by the bounded "
                    "AAPT2 inspector",
                ],
                "missing_evidence": (
                    ["runtime reachability or security impact"]
                    if selected.finding_status is FindingStatus.POTENTIAL
                    else ["complete normalized manifest or referenced resource metadata"]
                    if selected.finding_status is FindingStatus.INCONCLUSIVE
                    else []
                ),
                "analysis_confidence": selected.confidence,
                "observation_only": definition.observation_only,
            }
            evidence_ids = evidence("manifest_tree")
            if definition.rule_id == "ASL-MANIFEST-FILEPROVIDER-PATHS":
                evidence_ids = tuple(
                    dict.fromkeys(
                        (
                            *evidence_ids,
                            *evidence("manifest_resource_xml"),
                            *evidence("manifest_resource_table"),
                        )
                    )
                )
            return (
                selected.finding_status,
                "static",
                details,
                evidence_ids,
                False,
                False,
            )

        if definition.evaluator == "static_secret_candidate":
            if static_analysis is None:
                return (
                    FindingStatus.SKIPPED,
                    "static",
                    {
                        "method": "bounded_apk_static_inventory",
                        "preconditions": ["static APK analysis completed"],
                        "missing_evidence": ["static APK inventory"],
                        "reason": "Static APK inventory is unavailable.",
                    },
                    (),
                    False,
                    False,
                )
            raw_candidates = static_analysis.get("secret_candidates", [])
            candidates = (
                [
                    item
                    for item in raw_candidates
                    if isinstance(item, dict)
                    and item.get("confidence") in {"high", "medium"}
                ]
                if isinstance(raw_candidates, list)
                else []
            )
            inventory_status = str(static_analysis.get("status", "partial"))
            if candidates:
                status = FindingStatus.POTENTIAL
                reason = (
                    "Contextual secret material is present in packaged application "
                    "content; runtime use and credential validity were not assumed."
                )
                missing = [
                    "runtime use or reachable trust boundary",
                    "credential validity and server-side scope",
                ]
            elif inventory_status == "completed":
                status = FindingStatus.PASS
                reason = "No contextual secret candidate matched the bounded inventory."
                missing = []
            else:
                status = FindingStatus.INCONCLUSIVE
                reason = "The bounded static inventory did not complete all planned input."
                missing = ["complete bounded APK input coverage"]
            return (
                status,
                "static",
                {
                    "method": "bounded_apk_static_inventory",
                    "preconditions": [
                        "APK artifacts were collected from the selected package",
                        "archive and DEX limits were enforced",
                    ],
                    "missing_evidence": missing,
                    "reason": reason,
                    "candidate_count": len(candidates),
                    "candidates": candidates,
                    "inventory_status": inventory_status,
                    "limitations": list(static_analysis.get("limitations", []))[:20],
                    "redaction": "Candidate values are represented only by length and SHA-256.",
                },
                evidence("static_apk_inventory"),
                False,
                False,
            )

        if definition.evaluator == "cleartext":
            observed = [
                item
                for item in attributed_traffic
                if item.get("event") == "request" and item.get("cleartext") is True
            ]
            configured = manifest.get("uses_cleartext_traffic") if manifest else None
            network_config = manifest.get("network_security_config") if manifest else None
            if observed:
                status = FindingStatus.CONFIRMED
                analysis = "dynamic"
            elif configured is True:
                status = FindingStatus.POTENTIAL
                analysis = "static"
            elif configured is False and not network_config:
                status = FindingStatus.PASS
                analysis = "static"
            elif manifest is None:
                status = FindingStatus.SKIPPED
                analysis = "static"
            else:
                status = FindingStatus.INCONCLUSIVE
                analysis = "static"
            details = {
                "uses_cleartext_traffic": configured,
                "network_security_config": network_config,
                "cleartext_request_count": len(observed),
                "unattributed_request_count": sum(
                    item.get("event") == "request"
                    and item.get("attribution", "unattributed") == "unattributed"
                    for item in traffic
                ),
                "reason": (
                    "A package-attributed cleartext request was observed."
                    if observed
                    else "The manifest explicitly permits cleartext traffic."
                    if configured is True
                    else "The manifest explicitly disables cleartext traffic."
                    if status is FindingStatus.PASS
                    else "Cleartext policy or runtime behavior could not be resolved."
                ),
                "method": "manifest_and_attributed_traffic_correlation",
                "preconditions": [
                    "AndroidManifest.xml was parsed",
                    "only package-attributed or exact-canary traffic supports runtime status",
                ],
                "missing_evidence": (
                    []
                    if status in {
                        FindingStatus.CONFIRMED,
                        FindingStatus.POTENTIAL,
                        FindingStatus.PASS,
                    }
                    else ["explicit manifest policy or attributed cleartext request"]
                ),
            }
            ids = evidence("traffic_events") if observed else evidence("manifest_tree")
            return status, analysis, details, ids, False, False

        if definition.evaluator == "sensitive_token":
            query_keys = sorted(
                {
                    str(key)
                    for item in attributed_traffic
                    for key in item.get("sensitive_query_keys", [])
                }
            )
            log_markers = list(logcat.get("sensitive_marker_types", [])) if logcat else []
            canary_flows = [
                item
                for item in attributed_traffic
                if item.get("event") == "request"
                and item.get("attribution") == "validation_canary"
            ]
            traffic_canary_sink_types = sorted(
                {
                    str(sink_type)
                    for item in canary_flows
                    for sink_type in item.get("canary_sink_types", [])
                    if isinstance(sink_type, str)
                }
            )
            log_canary = bool(logcat and logcat.get("canary_observed") is True)
            frida_sinks: list[dict[str, Any]] = []
            frida_candidate_sinks: list[dict[str, Any]] = []
            frida_sink_observations: list[dict[str, Any]] = []
            for item in frida:
                if item.get("canary_match") is not True:
                    continue
                metadata = _event_metadata([item])
                if (
                    item.get("category") == "sensitive_data"
                    and item.get("method") == "sensitive.sink"
                ):
                    for value in metadata:
                        sink = {
                            "sink_type": value.get("sink_type"),
                            "delivery_kind": value.get("delivery_kind"),
                            "target_scope": value.get("target_scope"),
                            "boundary_exposed": value.get("boundary_exposed") is True,
                            "exposure_confidence": value.get("exposure_confidence"),
                        }
                        frida_sink_observations.append(sink)
                        if sink["boundary_exposed"]:
                            if sink["exposure_confidence"] == "clear":
                                frida_sinks.append(sink)
                            else:
                                frida_candidate_sinks.append(sink)
                    continue
                if item.get("category") == "logging":
                    frida_sinks.append(
                        {"sink_type": "logcat", "method": item.get("method")}
                    )
                    continue
                if item.get("category") == "webview" and item.get("method") in {
                    "webview.load_url",
                    "webview.load_data",
                    "webview.load_data_with_base_url",
                }:
                    for value in metadata:
                        sink = {
                            "sink_type": "webview",
                            "method": item.get("method"),
                            "content_origin": value.get("content_origin"),
                            "boundary_exposed": bool(
                                item.get("method") == "webview.load_url"
                                and value.get("is_remote") is True
                            ),
                        }
                        frida_sink_observations.append(sink)
                        if sink["boundary_exposed"]:
                            frida_sinks.append(sink)
                        elif value.get("is_remote") is True:
                            frida_candidate_sinks.append(sink)
                    continue
                if item.get("category") != "storage" or item.get("method") != "storage.sink":
                    continue
                for value in metadata:
                    if value.get("persisted") is not True:
                        continue
                    sink_type = str(value.get("sink_type", "unknown"))
                    if sink_type == "clipboard":
                        frida_sinks.append(
                            {
                                "sink_type": sink_type,
                                "storage_area": value.get("storage_area"),
                                "method": item.get("method"),
                            }
                        )
            if canary_flows or log_canary or frida_sinks:
                status = FindingStatus.CONFIRMED
                reason = (
                    "The exact session canary reached a package-attributed runtime "
                    "or bounded storage sink."
                )
                missing_evidence: list[str] = []
            elif frida_candidate_sinks or query_keys or log_markers:
                status = FindingStatus.POTENTIAL
                reason = (
                    "A candidate exposed sink or sensitive-name heuristic was observed, "
                    "but the external trust boundary was not deterministic."
                )
                missing_evidence = [
                    "exact session canary crossing a deterministic external boundary"
                ]
            else:
                status = FindingStatus.INCONCLUSIVE
                reason = (
                    "No exact canary or attributed sensitive-sink evidence was observed "
                    "during the bounded capture window."
                )
                missing_evidence = [
                    "activated target flow carrying the exact session canary"
                ]
            ids = tuple(
                dict.fromkeys((*evidence("traffic_events"), *evidence("target_logcat")))
            )
            return (
                status,
                "dynamic",
                {
                    "query_keys": query_keys,
                    "log_marker_types": log_markers,
                    "exact_canary_flow_count": len(canary_flows),
                    "traffic_canary_sink_types": traffic_canary_sink_types,
                    "exact_log_canary_observed": log_canary,
                    "exact_frida_sinks": frida_sinks,
                    "exact_frida_sink_candidates": frida_candidate_sinks,
                    "exact_frida_sink_observations": frida_sink_observations,
                    "frida_evidence_errors": list(
                        context.get("frida_evidence_errors", [])
                    ),
                    "reason": reason,
                    "method": "exact_session_canary_sink_attribution",
                    "preconditions": [
                        "target traffic or target-process log capture was active",
                        "a session-scoped canary was used for controlled attribution",
                    ],
                    "missing_evidence": missing_evidence,
                },
                tuple(
                    dict.fromkeys(
                        (
                            *ids,
                            *evidence("frida_events"),
                        )
                    )
                ),
                False,
                False,
            )

        if definition.evaluator == "exported_component":
            if manifest is None:
                return FindingStatus.SKIPPED, "static", {}, (), False, False
            exposed = []
            application_permission = manifest.get("application_permission")
            for component in manifest.get("components", []):
                if component.get("effective_exported") is not True:
                    continue
                protected = any(
                    component.get(name)
                    for name in ("permission", "read_permission", "write_permission")
                ) or bool(application_permission)
                if not protected and not self._is_launcher(component):
                    exposed.append(
                        {
                            "component_type": component.get("component_type"),
                            "name": component.get("name"),
                        }
                    )
            status = FindingStatus.POTENTIAL if exposed else FindingStatus.PASS
            return (
                status,
                "static",
                {
                    "unprotected_exported_components": exposed,
                    "reason": (
                        "One or more exported non-launcher components lack an explicit "
                        "permission boundary."
                        if exposed
                        else "No unprotected exported non-launcher component was found."
                    ),
                    "method": "normalized_manifest_component_boundary",
                    "preconditions": [
                        "effective exported state and application/component permissions "
                        "were normalized"
                    ],
                    "missing_evidence": (
                        ["runtime reachability or security impact"] if exposed else []
                    ),
                },
                evidence("manifest_tree"),
                False,
                False,
            )

        if definition.evaluator == "tls_interception":
            tls = TlsBehaviorAnalyzer.from_events(traffic, frida)
            frida_tls = any(
                (
                    tls.evidence.trust_manager_observed,
                    tls.evidence.pinning_observed,
                    tls.evidence.custom_trust_manager_observed,
                    tls.evidence.custom_hostname_verifier_observed,
                    tls.evidence.webview_ssl_proceed_observed,
                )
            )
            static_tls_candidates = sorted(
                item
                for item in _static_api_ids(static_analysis)
                if item.startswith("TLS_")
            )
            ids = tuple(
                dict.fromkeys(
                    (
                        *evidence("traffic_events"),
                        *evidence("frida_events"),
                        *evidence("static_apk_inventory"),
                    )
                )
            )
            missing_evidence = []
            if tls.finding_status in {
                FindingStatus.INCONCLUSIVE,
                FindingStatus.POTENTIAL,
            }:
                missing_evidence.append(
                    "target-attributed deterministic certificate or hostname outcome"
                )
            return (
                tls.finding_status,
                "instrumentation" if frida_tls else "dynamic",
                {
                    "tls_behavior_state": tls.state.value,
                    "target_request_count": tls.evidence.target_request_count,
                    "canary_request_count": tls.evidence.canary_request_count,
                    "canary_response_count": tls.evidence.canary_response_count,
                    "unattributed_request_count": (
                        tls.evidence.unattributed_request_count
                    ),
                    "pinning_observed": tls.evidence.pinning_observed,
                    "trust_manager_observed": tls.evidence.trust_manager_observed,
                    "custom_trust_manager_observed": (
                        tls.evidence.custom_trust_manager_observed
                    ),
                    "custom_hostname_verifier_observed": (
                        tls.evidence.custom_hostname_verifier_observed
                    ),
                    "webview_ssl_proceed_observed": (
                        tls.evidence.webview_ssl_proceed_observed
                    ),
                    "trust_manager_accept_observed": (
                        tls.evidence.trust_manager_accept_observed
                    ),
                    "trust_manager_reject_observed": (
                        tls.evidence.trust_manager_reject_observed
                    ),
                    "hostname_verifier_accept_observed": (
                        tls.evidence.hostname_verifier_accept_observed
                    ),
                    "hostname_verifier_reject_observed": (
                        tls.evidence.hostname_verifier_reject_observed
                    ),
                    "static_candidates": static_tls_candidates,
                    "frida_evidence_errors": list(
                        context.get("frida_evidence_errors", [])
                    ),
                    "interpretation": tls.rationale,
                    "reason": tls.rationale,
                    "observed_behavior": tls.state.value,
                    "method": "attributed_tls_and_runtime_trust_correlation",
                    "preconditions": [
                        "traffic events are attributed to the target package or exact canary",
                        "Frida events pass session and package attribution checks",
                    ],
                    "missing_evidence": missing_evidence,
                },
                ids,
                bool(context["root_used"] and frida_tls),
                bool(frida_tls),
            )
        if definition.evaluator == "crypto_runtime":
            values = [SimpleNamespace(**item) for item in frida]
            extraction = operations_from_frida_events(
                values,
                source=str(context["frida_source"]),
                environment=str(context["frida_environment"]),
            )
            results = CryptoAnalyzer().analyze(extraction.operations)
            matched = next((item for item in results if item.rule_id == definition.rule_id), None)
            if matched is None and extraction.errors:
                return (
                    FindingStatus.ERROR,
                    "instrumentation",
                    {
                        "reason": "One or more attributed crypto events could not be normalized.",
                        "error_category": "crypto_event_parse_failure",
                        "extraction_errors": list(extraction.errors),
                        "missing_evidence": [
                            "complete normalized metadata for every observed crypto event"
                        ],
                        "method": "normalized_frida_crypto_correlation",
                        "preconditions": [
                            "observer events conform to the supported schema",
                            "events match the assessment session and package",
                        ],
                    },
                    evidence("frida_events"),
                    False,
                    bool(frida),
                )
            operation_kind = {
                "CRYPTO-WEAK-DIGEST": {"digest", "mac"},
                "CRYPTO-LOW-PBE-ITERATIONS": {"pbe"},
            }.get(definition.rule_id, {"cipher"})
            relevant = [
                item
                for item in extraction.operations
                if item.executed and item.operation_kind in operation_kind
            ]
            if matched is None:
                comparable = relevant
                missing = ["runtime execution of the relevant crypto operation"]
                if definition.rule_id == "CRYPTO-ECB":
                    comparable = [
                        item
                        for item in relevant
                        if item.algorithm in _SYMMETRIC_CIPHERS and item.mode is not None
                    ]
                    missing = ["runtime cipher mode metadata"]
                elif definition.rule_id == "CRYPTO-SHORT-KEY":
                    comparable = [
                        item
                        for item in relevant
                        if item.algorithm in _SYMMETRIC_CIPHERS
                        and item.key_length_bits is not None
                    ]
                    missing = ["runtime symmetric key-length metadata"]
                elif definition.rule_id == "CRYPTO-ZERO-IV":
                    comparable = [
                        item
                        for item in relevant
                        if item.purpose == "encrypt" and item.iv_zero is not None
                    ]
                    missing = ["runtime encryption IV zero/nonzero metadata"]
                elif definition.rule_id == "CRYPTO-REUSED-IV":
                    comparable = [
                        item
                        for item in relevant
                        if item.purpose == "encrypt"
                        and item.key_sha256 is not None
                        and item.iv_sha256 is not None
                    ]
                    missing = [
                        "at least two attributed encryption operations with "
                        "comparable key and IV fingerprints"
                    ]
                elif definition.rule_id == "CRYPTO-LOW-PBE-ITERATIONS":
                    comparable = [
                        item for item in relevant if item.iteration_count is not None
                    ]
                    missing = ["runtime PBE iteration-count metadata"]
                elif definition.rule_id == "CRYPTO-PREDICTABLE-RANDOM":
                    comparable = [
                        item
                        for item in relevant
                        if item.key_origin.value != "unknown"
                        and (
                            item.purpose != "encrypt"
                            or item.algorithm not in _SYMMETRIC_CIPHERS
                            or item.mode == "ECB"
                            or item.iv_source in {"random", "constant", "derived"}
                        )
                    ]
                    missing = [
                        "complete runtime attribution of key generation and encryption "
                        "IV source for every observed cipher operation"
                    ]
                enough_coverage = bool(comparable)
                if definition.rule_id == "CRYPTO-REUSED-IV":
                    enough_coverage = len(comparable) >= 2
                elif definition.rule_id == "CRYPTO-PREDICTABLE-RANDOM":
                    enough_coverage = bool(relevant) and len(comparable) == len(relevant)
                status = (
                    FindingStatus.PASS
                    if enough_coverage
                    else FindingStatus.INCONCLUSIVE
                )
                return (
                    status,
                    "instrumentation",
                    {
                        "observation_only": definition.observation_only,
                        "observed_algorithms": sorted(
                            {item.algorithm for item in relevant}
                        ),
                        "static_candidates": sorted(
                            item
                            for item in _static_api_ids(static_analysis)
                            if item.startswith("CRYPTO_")
                        ),
                        "extraction_errors": list(extraction.errors),
                        "missing_evidence": [] if enough_coverage else missing,
                        "reason": (
                            "Relevant attributed operations completed without matching "
                            "this crypto policy."
                            if enough_coverage
                            else "The required attributed crypto flow was not observed."
                        ),
                        "observed_behavior": "no_policy_match"
                        if enough_coverage
                        else "flow_not_triggered",
                        "method": "normalized_frida_crypto_correlation",
                        "preconditions": [
                            "observer handshake succeeded",
                            "events match the assessment session and package",
                        ],
                        "finding_eligible": context["frida_finding_eligible"],
                    },
                    evidence("frida_events"),
                    False,
                    bool(extraction.operations),
                )
            details = {
                **matched.details,
                "operation_ids": list(matched.operation_ids),
                "observation_only": definition.observation_only,
                "observed_behavior": matched.title,
                "reason": (
                    "Completed attributed crypto operations matched this policy."
                    if matched.status is FindingStatus.CONFIRMED
                    else "Attributed crypto operations matched a candidate weakness, "
                    "but the security-sensitive data context remains unresolved."
                ),
                "method": "normalized_frida_crypto_correlation",
                "preconditions": [
                    "observer handshake succeeded",
                    "events match the assessment session and package",
                    "the crypto operation completed at runtime",
                ],
                "missing_evidence": list(matched.details.get("missing_evidence", [])),
                "analysis_confidence": matched.confidence,
                "static_candidates": sorted(
                    item
                    for item in _static_api_ids(static_analysis)
                    if item.startswith("CRYPTO_")
                ),
                "extraction_errors": list(extraction.errors),
                "finding_eligible": matched.finding_eligible,
            }
            return (
                matched.status,
                "instrumentation",
                details,
                evidence("frida_events"),
                False,
                bool(extraction.operations),
            )

        if definition.evaluator == "webview_security":
            events = [item for item in frida if item.get("category") == "webview"]
            static_ids = _static_api_ids(static_analysis)
            if (
                definition.rule_id == "WEBVIEW-SSL-ERROR-PROCEED"
                and "WEBVIEW_SSL_ERROR_PROCEED" not in static_ids
            ):
                gated = self._alternative_execution_gate(
                    context,
                    (
                        (
                            "frida",
                            "frida_observation",
                            bool(context["frida_available"]),
                            bool(context["frida_execution_usable"]),
                            bool(context["frida_capability_error"]),
                        ),
                    ),
                )
                if gated is not None:
                    return gated
            state_by_webview: dict[str, dict[str, Any]] = {}
            remote_instances: set[str] = set()
            correlated_remote_instances: set[str] = set()
            unsafe_content_instances: set[str] = set()
            unsafe_setting_activations = 0
            debugging_enabled = False
            ssl_callbacks: set[str] = set()
            matched_ssl_proceeds: list[str] = []
            unmatched_ssl_proceeds: list[str] = []

            def correlate_active_content(webview_id: str) -> None:
                current = state_by_webview.get(webview_id, {})
                content_origin = current.get("content_origin")
                if content_origin == "remote" and current.get(
                    "javascript_enabled"
                ) is True and current.get(
                    "interfaces"
                ):
                    correlated_remote_instances.add(webview_id)
                unsafe_file_origin = content_origin == "file" and (
                    current.get("file_url_access") is True
                    or current.get("universal_file_url_access") is True
                )
                unsafe_remote_origin = (
                    content_origin == "remote"
                    and current.get("mixed_content") == "always_allow"
                )
                if unsafe_file_origin or unsafe_remote_origin:
                    unsafe_content_instances.add(webview_id)

            for event in events:
                method = str(event.get("method", ""))
                for metadata in _event_metadata([event]):
                    webview_id = str(metadata.get("webview_id") or "")
                    if method == "webview.setting" and webview_id:
                        current = state_by_webview.setdefault(
                            webview_id,
                            {"interfaces": set()},
                        )
                        setting = str(metadata.get("setting") or "")
                        if setting == "mixed_content":
                            current[setting] = metadata.get("mixed_content_mode")
                            unsafe_setting_activations += int(
                                metadata.get("mixed_content_mode") == "always_allow"
                            )
                        elif setting:
                            current[setting] = metadata.get("enabled") is True
                            unsafe_setting_activations += int(
                                setting
                                in {"file_url_access", "universal_file_url_access"}
                                and metadata.get("enabled") is True
                            )
                        correlate_active_content(webview_id)
                    elif method == "webview.javascript_interface" and webview_id:
                        interface_hash = str(
                            metadata.get("interface_name_sha256") or ""
                        )
                        if interface_hash:
                            state_by_webview.setdefault(
                                webview_id,
                                {"interfaces": set()},
                            )["interfaces"].add(interface_hash)
                            correlate_active_content(webview_id)
                    elif (
                        method == "webview.javascript_interface_removed"
                        and webview_id
                    ):
                        interface_hash = str(
                            metadata.get("interface_name_sha256") or ""
                        )
                        state_by_webview.setdefault(
                            webview_id,
                            {"interfaces": set()},
                        )["interfaces"].discard(interface_hash)
                    elif method in {
                        "webview.load_url",
                        "webview.load_data",
                        "webview.load_data_with_base_url",
                    } and webview_id:
                        current = state_by_webview.setdefault(
                            webview_id,
                            {"interfaces": set()},
                        )
                        content_origin = str(metadata.get("content_origin") or "")
                        if not content_origin:
                            content_origin = (
                                "remote"
                                if metadata.get("is_remote") is True
                                else "file"
                                if metadata.get("is_file") is True
                                else "other"
                            )
                        current["content_origin"] = content_origin
                        if current["content_origin"] == "remote":
                            remote_instances.add(webview_id)
                        correlate_active_content(webview_id)
                    elif method == "webview.debugging":
                        debugging_enabled = metadata.get("enabled") is True
                    elif method == "webview.ssl_error_callback":
                        handler_id = str(metadata.get("handler_id") or "")
                        if handler_id:
                            ssl_callbacks.add(handler_id)
                    elif method == "webview.ssl_error_proceed":
                        handler_id = str(metadata.get("handler_id") or "")
                        if handler_id and handler_id in ssl_callbacks:
                            matched_ssl_proceeds.append(handler_id)
                            ssl_callbacks.discard(handler_id)
                        else:
                            unmatched_ssl_proceeds.append(handler_id)
                    elif method == "webview.ssl_error_cancel":
                        ssl_callbacks.discard(str(metadata.get("handler_id") or ""))
            status = FindingStatus.INCONCLUSIVE
            observed_behavior: dict[str, Any] = {}
            missing: list[str] = []
            if definition.rule_id == "WEBVIEW-JS-BRIDGE-REMOTE":
                javascript = {
                    webview_id
                    for webview_id, values in state_by_webview.items()
                    if values.get("javascript_enabled") is True
                }
                interfaces = {
                    webview_id
                    for webview_id, values in state_by_webview.items()
                    if values.get("interfaces")
                }
                observed_behavior = {
                    "javascript_enabled_instances": len(javascript),
                    "javascript_interface_instances": len(interfaces),
                    "remote_content_instances": len(remote_instances),
                    "correlated_load_count": len(correlated_remote_instances),
                }
                if correlated_remote_instances:
                    status = FindingStatus.POTENTIAL
                    missing = [
                        "attacker control of loaded content or exposed bridge methods"
                    ]
                else:
                    missing = [
                        "JavaScript, bridge, and remote content on the same WebView instance"
                    ]
            elif definition.rule_id == "WEBVIEW-UNSAFE-SETTINGS":
                observed_behavior = {
                    "unsafe_setting_activation_count": unsafe_setting_activations,
                    "unsafe_correlated_content_count": len(unsafe_content_instances),
                    "debugging_enabled": debugging_enabled,
                }
                if unsafe_content_instances or debugging_enabled:
                    status = FindingStatus.POTENTIAL
                    missing = ["reachable untrusted content or sensitive production context"]
                elif unsafe_setting_activations:
                    missing = [
                        "remote content loaded while the unsafe setting remained enabled"
                    ]
                else:
                    missing = ["runtime activation of a security-relevant WebView setting"]
            elif definition.rule_id == "WEBVIEW-SSL-ERROR-PROCEED":
                static_candidate = "WEBVIEW_SSL_ERROR_PROCEED" in static_ids
                observed_behavior = {
                    "matched_callback_proceed_count": len(matched_ssl_proceeds),
                    "unmatched_proceed_count": len(unmatched_ssl_proceeds),
                    "static_proceed_candidate": static_candidate,
                }
                if matched_ssl_proceeds:
                    status = FindingStatus.CONFIRMED
                elif static_candidate:
                    status = FindingStatus.POTENTIAL
                    missing = [
                        "same-handler package-attributed SSL callback and proceed behavior"
                    ]
                elif unmatched_ssl_proceeds:
                    missing = ["matching SSL error callback handler attribution"]
                else:
                    missing = ["SSL error callback flow activation"]
            return (
                status,
                "instrumentation" if events else "static",
                {
                    "observed_behavior": observed_behavior,
                    "event_count": len(events),
                    "static_candidates": sorted(
                        item for item in static_ids if item.startswith("WEBVIEW_")
                    ),
                    "missing_evidence": missing,
                    "reason": (
                        "Runtime evidence matched the rule correlation."
                        if status in {FindingStatus.CONFIRMED, FindingStatus.POTENTIAL}
                        else "The required correlated WebView behavior was not observed."
                    ),
                    "method": "same_session_webview_runtime_correlation",
                    "preconditions": [
                        "Frida events match the assessment session and package",
                        "WebView object identifiers correlate configuration and content",
                    ],
                },
                tuple(
                    dict.fromkeys(
                        (*evidence("frida_events"), *evidence("static_apk_inventory"))
                    )
                ),
                False,
                bool(events),
            )

        if definition.evaluator == "runtime_observation":
            category = definition.rule_id.rsplit("-", 1)[-1].casefold()
            if category == "webview":
                observed = [item for item in frida if item.get("category") == "webview"]
            elif category == "logging":
                observed = [item for item in frida if item.get("category") == "logging"]
            elif category == "storage":
                observed = [item for item in frida if item.get("category") == "storage"]
            elif category == "root":
                observed = [item for item in frida if item.get("category") == "root_detection"]
            else:
                observed = []
            if category == "root":
                values = [SimpleNamespace(**item) for item in frida]
                source = (
                    "emulator"
                    if str(context["serial"]).startswith("emulator-")
                    else "physical_device"
                )
                root_events = root_events_from_frida(values, source=source, environment=source)
                result = RootDetectionAnalyzer.analyze(
                    root_events,
                    expected_root_present=bool(context["root_available"]),
                )
                details = {
                    **result.to_dict(),
                    "observation_only": True,
                    "observation_status": "observed" if root_events else "not_observed",
                    "reason": (
                        "Target-process root-detection behavior was observed."
                        if root_events
                        else "No attributed root-detection behavior was observed."
                    ),
                    "method": "attributed_frida_runtime_observation",
                    "preconditions": [
                        "Frida observer events match the assessment session and package"
                    ],
                    "missing_evidence": (
                        [] if root_events else ["activated root-detection application flow"]
                    ),
                }
                return (
                    FindingStatus.PASS if root_events else FindingStatus.INCONCLUSIVE,
                    "instrumentation",
                    details,
                    evidence("frida_events"),
                    False,
                    bool(frida),
                )
            status = FindingStatus.PASS if observed else FindingStatus.INCONCLUSIVE
            return (
                status,
                "instrumentation",
                {
                    "event_count": len(observed),
                    "observation_only": True,
                    "observation_status": "observed" if observed else "not_observed",
                    "reason": (
                        f"Attributed {category} runtime events were observed."
                        if observed
                        else f"No attributed {category} runtime event was observed."
                    ),
                    "method": "attributed_frida_runtime_observation",
                    "preconditions": [
                        "Frida observer events match the assessment session and package"
                    ],
                    "missing_evidence": (
                        [] if observed else [f"activated {category} application flow"]
                    ),
                },
                evidence("frida_events"),
                False,
                bool(observed),
            )

        if definition.evaluator == "storage_observation":
            storage = context["private_storage"]
            if not storage:
                return (
                    FindingStatus.SKIPPED,
                    "root_assisted",
                    {
                        "observation_only": True,
                        "observation_status": "skipped",
                        "reason": "Package-scoped private-storage evidence is unavailable.",
                        "method": "bounded_private_storage_observation",
                        "preconditions": ["root-assisted storage capability"],
                        "missing_evidence": ["private-storage inventory"],
                    },
                    (),
                    True,
                    False,
                )
            observations = storage.get("observations", [])
            eligible = [item for item in observations if item.get("finding_eligible")]
            status = FindingStatus.POTENTIAL if eligible else FindingStatus.PASS
            return (
                status,
                "root_assisted",
                {
                    "observation_count": len(observations),
                    "finding_eligible_count": len(eligible),
                    "observation_only": True,
                    "observation_status": "observed" if observations else "not_observed",
                    "root_mode": storage.get("root_mode"),
                    "reason": (
                        "Bounded package storage observations were collected."
                        if observations
                        else "The bounded inventory produced no storage observation."
                    ),
                    "method": "bounded_private_storage_observation",
                    "preconditions": [
                        "storage paths remain inside normalized package roots"
                    ],
                    "missing_evidence": (
                        [] if observations else ["bounded package storage metadata"]
                    ),
                },
                evidence("private_storage_metadata"),
                True,
                False,
            )

        if definition.evaluator == "storage_security":
            storage = context["private_storage"]
            if definition.rule_id == "STORAGE-SENSITIVE-CANARY":
                gated = self._alternative_execution_gate(
                    context,
                    (
                        (
                            "root",
                            "private_storage",
                            bool(context["root_available"]),
                            storage is not None,
                            bool(context["root_capability_error"]),
                        ),
                        (
                            "frida",
                            "frida_observation",
                            bool(context["frida_available"]),
                            bool(context["frida_execution_usable"]),
                            bool(context["frida_capability_error"]),
                        ),
                    ),
                )
                if gated is not None:
                    return gated
            if not storage and definition.rule_id != "STORAGE-SENSITIVE-CANARY":
                return (
                    FindingStatus.SKIPPED,
                    "root_assisted",
                    {
                        "reason": "Bounded private-storage evidence is unavailable.",
                        "method": "bounded_private_storage_correlation",
                        "preconditions": ["root-assisted storage capability"],
                        "missing_evidence": ["package-scoped private-storage inventory"],
                    },
                    (),
                    False,
                    False,
                )
            observations = [
                item
                for item in (storage.get("observations", []) if storage else [])
                if isinstance(item, dict)
            ]
            if definition.rule_id == "STORAGE-WORLD-READABLE":
                matched = next(
                    (
                        item
                        for item in observations
                        if item.get("observation_id") == "storage-world-readable"
                    ),
                    None,
                )
            elif definition.rule_id == "STORAGE-WORLD-WRITABLE":
                matched = next(
                    (
                        item
                        for item in observations
                        if item.get("observation_id") == "storage-world-writable"
                    ),
                    None,
                )
            else:
                matched_values = [
                    item
                    for item in observations
                    if str(item.get("observation_id", "")).startswith(
                        "storage-plaintext-"
                    )
                    and item.get("finding_eligible") is True
                ]
                runtime_observations = [
                    {
                        "sink_type": metadata.get("sink_type"),
                        "storage_area": metadata.get("storage_area"),
                        "package_scoped": metadata.get("package_scoped"),
                        "method": event.get("method"),
                    }
                    for event in frida
                    if event.get("category") == "storage"
                    and event.get("method") == "storage.sink"
                    and event.get("canary_match") is True
                    for metadata in _event_metadata([event])
                    if metadata.get("persisted") is True
                    and metadata.get("sink_type") in {"shared_preferences", "sqlite", "file"}
                ]
                runtime_matches = [
                    item
                    for item in runtime_observations
                    if item["sink_type"] in {"shared_preferences", "sqlite"}
                    or (
                        item["sink_type"] == "file"
                        and item["package_scoped"] is True
                        and item["storage_area"]
                        in {"internal", "cache", "external_app"}
                    )
                ]
                matched = (
                    {
                        "status": "confirmed",
                        "artifact_paths": [
                            path
                            for item in matched_values
                            for path in item.get("artifact_paths", [])
                        ],
                        "rationale": (
                            "The exact session canary matched bounded package storage."
                        ),
                        "finding_eligible": True,
                        "runtime_sinks": runtime_matches,
                    }
                    if matched_values or runtime_matches
                    else None
                )
            eligible = bool(matched and matched.get("finding_eligible") is True)
            inventory_status = str(
                storage.get("inventory_status", "completed")
                if storage
                else "unavailable"
            )
            inventory_limitations = [
                str(item)
                for item in (
                    storage.get("inventory_limitations", []) if storage else []
                )
            ]
            content_scan_status = str(
                storage.get("content_scan_status", "not_requested")
                if storage
                else "not_requested"
            )
            content_scan_limitations = [
                str(item)
                for item in (
                    storage.get("content_scan_limitations", []) if storage else []
                )
            ]
            if eligible and matched.get("status") == "confirmed":
                status = FindingStatus.CONFIRMED
            elif eligible and matched.get("status") == "potential":
                status = FindingStatus.POTENTIAL
            elif definition.rule_id == "STORAGE-SENSITIVE-CANARY":
                status = (
                    FindingStatus.ERROR
                    if content_scan_status == "error"
                    else FindingStatus.INCONCLUSIVE
                )
            elif inventory_status == "error":
                status = FindingStatus.ERROR
            elif inventory_status != "completed":
                status = FindingStatus.INCONCLUSIVE
            else:
                status = FindingStatus.PASS
            sensitive_canary_rule = definition.rule_id == "STORAGE-SENSITIVE-CANARY"
            if matched:
                reason = str(matched.get("rationale"))
                missing_evidence: list[str] = []
            elif sensitive_canary_rule and content_scan_status == "error":
                reason = "The storage canary probe failed before coverage completed."
                missing_evidence = content_scan_limitations
            elif sensitive_canary_rule:
                reason = (
                    "No exact session canary was attributed to a persisted storage sink."
                )
                missing_evidence = content_scan_limitations or [
                    "activated storage flow persisting the exact session canary"
                ]
            elif inventory_status != "completed":
                reason = "The bounded storage inventory did not complete."
                missing_evidence = inventory_limitations
            else:
                reason = "No matching storage weakness was observed in bounded evidence."
                missing_evidence = []
            return (
                status,
                "instrumentation"
                if sensitive_canary_rule and not storage
                else "root_assisted",
                {
                    "observed_behavior": matched or {},
                    "reason": reason,
                    "method": (
                        "exact_canary_storage_sink_correlation"
                        if sensitive_canary_rule
                        else "bounded_private_storage_correlation"
                    ),
                    "preconditions": [
                        "storage paths remain inside the selected package roots",
                        "content matching is bounded and exact-canary attributed",
                    ],
                    "missing_evidence": missing_evidence,
                    "root_mode": storage.get("root_mode") if storage else None,
                    "inventory_status": inventory_status,
                    "inventory_limitations": inventory_limitations,
                    "content_scan_status": content_scan_status,
                    "content_scan_limitations": content_scan_limitations,
                    "runtime_sink_observations": (
                        runtime_observations if sensitive_canary_rule else []
                    ),
                },
                tuple(
                    dict.fromkeys(
                        (
                            *evidence("private_storage_metadata"),
                            *(
                                evidence("frida_events")
                                if sensitive_canary_rule
                                else ()
                            ),
                        )
                    )
                ),
                bool(storage),
                bool(sensitive_canary_rule and frida),
            )

        raise SessionError(f"Unknown rule evaluator: {definition.evaluator}")

    def evaluate(self, session_id: str) -> list[FindingRecord]:
        with self.sessions.state_lock(session_id):
            return self._evaluate_locked(session_id)

    def _evaluate_locked(self, session_id: str) -> list[FindingRecord]:
        paths = self.sessions.paths_for(session_id)
        session_record = self.sessions.load(session_id)
        app = read_json_object(paths.app_json, root=self.paths.root)
        manifest = app.get("manifest") if isinstance(app.get("manifest"), dict) else None
        static_analysis = (
            app.get("static_analysis")
            if isinstance(app.get("static_analysis"), dict)
            else None
        )
        if manifest is not None:
            manifest = dict(manifest)
            metadata = app.get("metadata") if isinstance(app.get("metadata"), dict) else {}
            flags = {
                str(item).casefold()
                for item in metadata.get("flags", [])
                if isinstance(item, str)
            }
            # Package-manager metadata is the authoritative fallback when an
            # AAPT2 tree omits a defaulted application attribute.
            if manifest.get("debuggable") is None:
                manifest["debuggable"] = "debuggable" in flags
            if manifest.get("test_only") is None:
                manifest["test_only"] = "test_only" in flags
            if manifest.get("allow_backup") is None and flags:
                manifest["allow_backup"] = "allow_backup" in flags
        traffic_state = _optional_json(paths.traffic_dir / "state.json", self.paths.root)
        traffic_path = (
            require_under_root(
                paths.root / str(traffic_state.get("events_path")),
                paths.root,
            )
            if traffic_state
            else None
        )
        traffic_events = load_traffic_events(traffic_path) if traffic_path else []
        logcat = _optional_json(paths.logcat_dir / "state.json", self.paths.root)
        frida_state = _optional_json(paths.frida_dir / "state.json", self.paths.root)
        frida_path = (
            require_under_root(
                paths.root / str(frida_state.get("events_path")),
                paths.root,
            )
            if frida_state
            else None
        )
        private_storage = _optional_json(
            paths.redacted_dir / "storage" / "private-storage.json", self.paths.root
        )
        scan_state = _optional_json(paths.scan_json, self.paths.root)
        device_state = _optional_json(paths.device_json, self.paths.root) or {}
        capability_values = device_state.get("capabilities", {}).get("capabilities", [])
        available_capabilities = {
            str(item.get("name"))
            for item in capability_values
            if isinstance(item, dict) and item.get("available") is True
        } if isinstance(capability_values, list) else set()
        capability_states = {
            str(item.get("name")): str(item.get("state", "unknown"))
            for item in capability_values
            if isinstance(item, dict) and item.get("name")
        } if isinstance(capability_values, list) else {}
        root_capability = "ANDROID_ROOT" in available_capabilities
        frida_capability = "FRIDA_CLIENT" in available_capabilities and (
            "FRIDA_SERVER" in available_capabilities or root_capability
        )
        root_capability_error = capability_states.get("ANDROID_ROOT") == "error"
        frida_capability_error = (
            capability_states.get("FRIDA_CLIENT") == "error"
            or (
                not root_capability
                and capability_states.get("FRIDA_SERVER") == "error"
            )
        )
        evidence_values = self.evidence.list(session_id)
        device_environment = (
            "emulator"
            if session_record.serial.startswith("emulator-")
            else "physical_device"
        )
        frida_candidates: dict[Path, tuple[str, str | None]] = {}
        if frida_path is not None:
            frida_candidates[frida_path] = ("frida", None)
        for item in evidence_values:
            if item.get("evidence_type") != "frida_events":
                continue
            candidate = require_under_root(
                paths.root / str(item.get("relative_path", "")),
                paths.root,
            )
            frida_candidates[candidate] = (
                str(item.get("source") or "unknown"),
                str(item.get("sha256")) if item.get("sha256") else None,
            )
        frida_evidence_sources = {
            source for source, _expected_hash in frida_candidates.values()
        }
        source_classes = {
            "fixture" if source == "fixture" else "runtime"
            for source in frida_evidence_sources
        }
        frida_errors: list[str] = []
        frida_events: list[dict[str, Any]] = []
        if scan_state is not None:
            for candidate, (_source, expected_hash) in frida_candidates.items():
                if expected_hash is None:
                    frida_errors.append(
                        f"Orchestrated Frida evidence is not registered: {candidate.name}"
                    )
        if len(source_classes) > 1:
            frida_errors.append("Mixed fixture and runtime Frida evidence is rejected.")
        elif not frida_errors:
            for candidate, (source, expected_hash) in frida_candidates.items():
                if expected_hash is not None and (
                    not candidate.is_file() or sha256_file(candidate) != expected_hash
                ):
                    frida_errors.append(
                        f"Frida evidence integrity mismatch: {candidate.name}"
                    )
                    continue
                environment = "simulated" if source == "fixture" else device_environment
                parsed_events, parse_errors = _frida_events(
                    candidate,
                    expected_session_id=session_id,
                    expected_package=session_record.package,
                    source=source,
                    environment=environment,
                )
                frida_events.extend(parsed_events)
                frida_errors.extend(parse_errors)
        if frida_errors:
            frida_events = []
        frida_is_fixture = bool(frida_evidence_sources) and frida_evidence_sources == {
            "fixture"
        }
        if scan_state is not None and frida_is_fixture:
            frida_errors.append(
                "Fixture Frida evidence is not eligible for an orchestrated scan."
            )
            frida_events = []
        frida_evidence_usable = bool(frida_candidates) and not frida_errors
        frida_execution_usable = bool(
            frida_state
            and frida_state.get("handshake_status") == "VALID"
            and frida_state.get("status") in {"running", "stopped", "stop_failed"}
            and frida_evidence_usable
        )

        def evidence_ids(evidence_type: str) -> tuple[str, ...]:
            return tuple(
                str(item["evidence_id"])
                for item in evidence_values
                if item.get("evidence_type") == evidence_type
            )

        context = {
            "manifest": manifest,
            "static_analysis": static_analysis,
            "traffic_events": traffic_events,
            "logcat": logcat,
            "frida_events": frida_events,
            "frida_state": frida_state,
            "frida_source": "fixture" if frida_is_fixture else "frida_observer",
            "frida_environment": (
                "simulated" if frida_is_fixture else device_environment
            ),
            "frida_finding_eligible": not frida_is_fixture,
            "frida_evidence_errors": frida_errors,
            "frida_evidence_usable": frida_evidence_usable,
            "evidence": evidence_ids,
            "root_used": bool(
                frida_state and frida_state.get("server_started_by_framework") is True
            ) or bool(private_storage),
            "root_available": root_capability or bool(
                private_storage
                and private_storage.get("root_mode")
                not in {None, "none", "non_root"}
            ),
            "root_capability_error": root_capability_error,
            "frida_available": frida_capability,
            "frida_capability_error": frida_capability_error,
            "frida_execution_usable": frida_execution_usable,
            "private_storage": private_storage,
            "scan_state": scan_state,
            "serial": session_record.serial,
        }
        now = datetime.now(UTC).isoformat()
        previous_findings = {
            item.rule_id: item for item in self.findings.list(session_id)
        }
        findings: list[FindingRecord] = []
        for definition in self.definitions:
            try:
                gated = self._execution_gate(definition, context)
                if gated is not None:
                    status, analysis, details, ids, root_used, frida_used = gated
                else:
                    status, analysis, details, ids, root_used, frida_used = (
                        self._evaluate_rule(
                            definition,
                            context,
                        )
                    )
            except (AndroidAssessorError, OSError, ValueError) as exc:
                status = FindingStatus.ERROR
                analysis = "unknown"
                details = {"error": redact_text(str(exc))[:500]}
                ids = ()
                root_used = False
                frida_used = False
            previous = previous_findings.get(definition.rule_id)
            if definition.validation_observable:
                details = {
                    **details,
                    "validation_observable": definition.validation_observable,
                }
            details = {
                **details,
                "root_required": definition.root_required,
                "frida_required": definition.frida_required,
            }
            if definition.validation_type != "none":
                details = {
                    **details,
                    "validation_type": definition.validation_type,
                }
            validation = previous.validation if previous else None
            if validation and validation.status is FindingStatus.CONFIRMED:
                status = FindingStatus.CONFIRMED
                ids = tuple(dict.fromkeys((*ids, *validation.evidence_ids)))
            findings.append(
                FindingRecord(
                    finding_id=f"finding-{definition.rule_id.lower()}",
                    rule_id=definition.rule_id,
                    title=definition.title,
                    category=definition.category,
                    description=definition.description,
                    severity=definition.severity,
                    confidence=definition.confidence,
                    status=status,
                    analysis_type=analysis,
                    root_required=definition.root_required,
                    root_used=root_used,
                    frida_used=frida_used,
                    validation_supported=definition.validation_supported,
                    validation=validation,
                    evidence_ids=ids,
                    remediation=definition.remediation,
                    mappings=definition.mappings,
                    details=details,
                    created_at=previous.created_at if previous else now,
                    updated_at=now,
                )
            )
        self.findings.save(session_id, findings)
        self.sessions.append_event(
            session_id,
            "rules_evaluated",
            {"rule_count": len(findings)},
        )
        return findings
