"""Profile-neutral rule evaluation over shared static and runtime evidence."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import yaml

from .crypto_analysis import CryptoAnalyzer, operations_from_frida_events
from .errors import AndroidAssessorError, SessionError
from .evidence import EvidenceRepository
from .findings import FindingRecord, FindingRepository, FindingStatus
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
    observation_only: bool = False


def _optional_json(path: Path, root: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        return read_json_object(path, root=root)
    except SessionError:
        return None


def _frida_events(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    events: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            candidate = line[line.find("{") :] if "{" in line else ""
            if not candidate:
                continue
            try:
                value = json.loads(candidate)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                events.append(value)
    except OSError:
        return []
    return events


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
                    observation_only=bool(value.get("observation_only", False)),
                )
            )
        return tuple(output)

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
        attributed_traffic = [
            item
            for item in traffic
            if item.get("attribution") in {"target", "validation_canary"}
        ]
        if definition.evaluator == "app_debuggable":
            if manifest is None:
                return FindingStatus.SKIPPED, "static", {}, (), False, False
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
            return status, "static", values, evidence("manifest_tree"), False, False

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
            log_canary = bool(logcat and logcat.get("canary_observed") is True)
            if canary_flows or log_canary:
                status = FindingStatus.CONFIRMED
                reason = (
                    "The exact session canary reached an attributed URL or "
                    "target-process log sink."
                )
                missing_evidence: list[str] = []
            elif query_keys or log_markers:
                status = FindingStatus.POTENTIAL
                reason = (
                    "A sensitive-name heuristic was observed, but no exact session "
                    "canary established data attribution."
                )
                missing_evidence = [
                    "exact session canary in an attributed target sink"
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
                    "exact_log_canary_observed": log_canary,
                    "reason": reason,
                    "method": "exact_session_canary_sink_attribution",
                    "preconditions": [
                        "target traffic or target-process log capture was active",
                        "a session-scoped canary was used for controlled attribution",
                    ],
                    "missing_evidence": missing_evidence,
                },
                ids,
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
                {"unprotected_exported_components": exposed},
                evidence("manifest_tree"),
                False,
                False,
            )

        if definition.evaluator == "tls_interception":
            tls = TlsBehaviorAnalyzer.from_events(traffic, frida)
            frida_tls = tls.evidence.trust_manager_observed or tls.evidence.pinning_observed
            ids = tuple(
                dict.fromkeys((*evidence("traffic_events"), *evidence("frida_events")))
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
                    "interpretation": tls.rationale,
                },
                ids,
                bool(context["root_used"] and frida_tls),
                bool(frida_tls),
            )
        if definition.evaluator == "crypto_runtime":
            values = [SimpleNamespace(**item) for item in frida]
            source = (
                "emulator"
                if str(context["serial"]).startswith("emulator-")
                else "physical_device"
            )
            extraction = operations_from_frida_events(
                values,
                source=source,
                environment=source,
            )
            results = CryptoAnalyzer().analyze(extraction.operations)
            matched = next((item for item in results if item.rule_id == definition.rule_id), None)
            if matched is None:
                matched = next((item for item in results if item.rule_id == "CRYPTO-POLICY"), None)
            if matched is None:
                return (
                    FindingStatus.INCONCLUSIVE,
                    "instrumentation",
                    {
                        "observation_only": definition.observation_only,
                        "observed_algorithms": sorted(
                            {
                                str(item.get("algorithm", ""))
                                for item in frida
                                if item.get("category") == "crypto"
                            }
                        ),
                        "missing_evidence": ["matching configured crypto operation"],
                        "reason": (
                            "No configured weak-algorithm operation matched runtime evidence."
                        ),
                    },
                    evidence("frida_events"),
                    False,
                    bool(frida),
                )
            details = {
                **matched.details,
                "operation_ids": list(matched.operation_ids),
                "observation_only": definition.observation_only,
            }
            return (
                matched.status,
                "instrumentation",
                details,
                evidence("frida_events"),
                False,
                bool(frida),
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
                    {"observation_only": True, "observation_status": "skipped"},
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
                },
                evidence("private_storage_metadata"),
                True,
                False,
            )

        raise SessionError(f"Unknown rule evaluator: {definition.evaluator}")

    def evaluate(self, session_id: str) -> list[FindingRecord]:
        with self.sessions.state_lock(session_id):
            return self._evaluate_locked(session_id)

    def _evaluate_locked(self, session_id: str) -> list[FindingRecord]:
        paths = self.sessions.paths_for(session_id)
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
        device_state = _optional_json(paths.device_json, self.paths.root) or {}
        capability_values = device_state.get("capabilities", {}).get("capabilities", [])
        root_capability = any(
            isinstance(item, dict)
            and item.get("name") == "ANDROID_ROOT"
            and item.get("available") is True
            for item in capability_values
        ) if isinstance(capability_values, list) else False
        evidence_values = self.evidence.list(session_id)
        frida_paths: list[Path] = []
        if frida_path is not None:
            frida_paths.append(frida_path)
        for item in evidence_values:
            if item.get("evidence_type") != "frida_events":
                continue
            candidate = require_under_root(
                paths.root / str(item.get("relative_path", "")),
                paths.root,
            )
            if candidate not in frida_paths:
                frida_paths.append(candidate)
        frida_events = [
            event
            for candidate in frida_paths
            for event in _frida_events(candidate)
        ]

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
            "evidence": evidence_ids,
            "root_used": bool(
                frida_state and frida_state.get("server_started_by_framework") is True
            ) or bool(private_storage),
            "root_available": root_capability or bool(
                private_storage
                and private_storage.get("root_mode")
                not in {None, "none", "non_root"}
            ),
            "private_storage": private_storage,
            "serial": self.sessions.load(session_id).serial,
        }
        now = datetime.now(UTC).isoformat()
        previous_findings = {
            item.rule_id: item for item in self.findings.list(session_id)
        }
        findings: list[FindingRecord] = []
        for definition in self.definitions:
            try:
                status, analysis, details, ids, root_used, frida_used = self._evaluate_rule(
                    definition,
                    context,
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
                    root_required=False,
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
