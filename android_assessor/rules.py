"""Five-rule MVP evaluator over app, traffic, logcat, and Frida evidence."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from .errors import AndroidAssessorError, SessionError
from .evidence import EvidenceRepository
from .findings import FindingRecord, FindingRepository, FindingStatus
from .paths import ProjectPaths
from .redaction import redact_text
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
            raise SessionError(f"Could not load MVP rules: {exc}") from exc
        values = payload.get("rules") if isinstance(payload, dict) else None
        if not isinstance(values, list) or len(values) != 5:
            raise SessionError("MVP rule file must contain exactly five rules.")
        output: list[RuleDefinition] = []
        for value in values:
            if not isinstance(value, dict):
                raise SessionError("MVP rule entry is invalid.")
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
            if query_keys or log_markers:
                status = FindingStatus.CONFIRMED
            elif attributed_traffic or (
                logcat and logcat.get("status") == "completed"
            ):
                status = FindingStatus.PASS
            else:
                status = FindingStatus.INCONCLUSIVE
            ids = tuple(
                dict.fromkeys((*evidence("traffic_events"), *evidence("target_logcat")))
            )
            return (
                status,
                "dynamic",
                {"query_keys": query_keys, "log_marker_types": log_markers},
                ids,
                False,
                False,
            )

        if definition.evaluator == "exported_component":
            if manifest is None:
                return FindingStatus.SKIPPED, "static", {}, (), False, False
            exposed = []
            for component in manifest.get("components", []):
                if component.get("effective_exported") is not True:
                    continue
                protected = any(
                    component.get(name)
                    for name in ("permission", "read_permission", "write_permission")
                )
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
        raise SessionError(f"Unknown MVP rule evaluator: {definition.evaluator}")

    def evaluate(self, session_id: str) -> list[FindingRecord]:
        with self.sessions.state_lock(session_id):
            return self._evaluate_locked(session_id)

    def _evaluate_locked(self, session_id: str) -> list[FindingRecord]:
        paths = self.sessions.paths_for(session_id)
        app = read_json_object(paths.app_json, root=self.paths.root)
        manifest = app.get("manifest") if isinstance(app.get("manifest"), dict) else None
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
        frida_events = _frida_events(frida_path) if frida_path else []
        evidence_values = self.evidence.list(session_id)

        def evidence_ids(evidence_type: str) -> tuple[str, ...]:
            return tuple(
                str(item["evidence_id"])
                for item in evidence_values
                if item.get("evidence_type") == evidence_type
            )

        context = {
            "manifest": manifest,
            "traffic_events": traffic_events,
            "logcat": logcat,
            "frida_events": frida_events,
            "evidence": evidence_ids,
            "root_used": bool(
                frida_state and frida_state.get("server_started_by_framework") is True
            ),
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
            "mvp_rules_evaluated",
            {"rule_count": len(findings)},
        )
        return findings
