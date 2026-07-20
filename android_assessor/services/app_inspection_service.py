"""Orchestrate reproducible package/APK/manifest inspection sessions."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..adb import mask_serial
from ..apk import (
    DEFAULT_MAX_APK_FILE_BYTES,
    DEFAULT_MAX_APK_FILES,
    DEFAULT_MAX_TOTAL_APK_BYTES,
    ApkArtifact,
    ApkPuller,
    PackageInspector,
    PackageMetadata,
    merge_badging,
)
from ..app_context import AppContext
from ..environment import find_tool_spec, resolve_binary
from ..errors import AndroidAssessorError, ApkInspectionError
from ..evidence import EvidenceRepository
from ..manifest import (
    Aapt2Inspector,
    AaptInspection,
    parse_aapt_resource_xml_paths,
    redact_aapt_xmltree,
)
from ..redaction import redact_text
from ..scope import load_scope
from ..session import SessionRecord, SessionRepository, SessionStatus
from ..signature import ApkSignatureInspector
from ..static_apk_analysis import StaticApkInput, analyze_apks
from ..storage import write_json_atomic, write_text_atomic
from ..validation import validate_package_name
from .session_service import SessionService

_MANIFEST_COLLECTION_FIELDS = (
    "permissions",
    "custom_permissions",
    "components",
    "deep_links",
    "file_provider_paths",
)
_MANIFEST_BOOLEAN_FIELDS = (
    "debuggable",
    "test_only",
    "uses_cleartext_traffic",
    "allow_backup",
    "application_enabled",
)
_COMPONENT_BOOLEAN_FIELDS = (
    "exported",
    "effective_exported",
    "enabled",
    "grant_uri_permissions",
    "direct_boot_aware",
    "stop_with_task",
    "isolated_process",
    "multiprocess",
)


def _merge_manifest_payloads(
    values: list[tuple[str, dict[str, Any]]],
    limitations: list[str],
) -> dict[str, Any]:
    """Merge base/split normalized manifests without claiming omitted coverage."""

    if not values:
        raise ApkInspectionError("No APK manifest was available for normalization.")
    base_source, base = values[0]
    merged = dict(base)
    merged["manifest_sources"] = [source for source, _payload in values]
    merged["manifest_limitations"] = list(dict.fromkeys(limitations))
    merged["manifest_complete"] = not limitations
    for field_name in _MANIFEST_BOOLEAN_FIELDS:
        observed = [
            (source, payload.get(field_name))
            for source, payload in values
            if isinstance(payload.get(field_name), bool)
        ]
        if not observed:
            merged[field_name] = None
            continue
        merged[field_name] = observed[0][1]
        if any(value != observed[0][1] for _source, value in observed[1:]):
            merged[field_name] = None
            conflicting_source = next(
                source
                for source, value in observed[1:]
                if value != observed[0][1]
            )
            limitations.append(
                f"{conflicting_source}:conflicting_manifest_boolean:{field_name}"
            )
    for field_name in _MANIFEST_COLLECTION_FIELDS:
        rows: list[dict[str, Any]] = []
        exact: set[str] = set()
        component_identities: dict[tuple[str, str], str] = {}
        component_rows: dict[tuple[str, str], list[dict[str, Any]]] = {}
        component_boolean_values: dict[
            tuple[str, str], dict[str, set[bool]]
        ] = {}
        custom_permission_identities: dict[str, str] = {}
        for source, payload in values:
            raw_rows = payload.get(field_name, [])
            if not isinstance(raw_rows, list):
                limitations.append(f"{source}:{field_name}_not_a_list")
                continue
            for raw_row in raw_rows:
                if not isinstance(raw_row, dict):
                    limitations.append(f"{source}:{field_name}_entry_invalid")
                    continue
                identity = json.dumps(raw_row, sort_keys=True, separators=(",", ":"))
                if identity in exact:
                    continue
                exact.add(identity)
                row = {**raw_row, "source_apk": source}
                if field_name == "components":
                    component_key = (
                        str(raw_row.get("component_type", "")),
                        str(raw_row.get("name", "")),
                    )
                    previous = component_identities.get(component_key)
                    boolean_values = component_boolean_values.setdefault(
                        component_key,
                        {},
                    )
                    conflicting_boolean_fields: list[str] = []
                    for boolean_field in _COMPONENT_BOOLEAN_FIELDS:
                        current_value = raw_row.get(boolean_field)
                        if not isinstance(current_value, bool):
                            continue
                        observed_values = boolean_values.setdefault(boolean_field, set())
                        observed_values.add(current_value)
                        if len(observed_values) > 1:
                            conflicting_boolean_fields.append(boolean_field)
                    if previous is not None and previous != identity:
                        limitations.append(
                            f"{source}:conflicting_component:{component_key[0]}"
                        )
                        previous_rows = component_rows.get(component_key, [])
                        for boolean_field in conflicting_boolean_fields:
                            row[boolean_field] = None
                            for previous_row in previous_rows:
                                previous_row[boolean_field] = None
                            if boolean_field in {"exported", "effective_exported"}:
                                row["exported_source"] = "conflicting_split_values"
                                for previous_row in previous_rows:
                                    previous_row["exported_source"] = (
                                        "conflicting_split_values"
                                    )
                    component_identities[component_key] = identity
                    component_rows.setdefault(component_key, []).append(row)
                elif field_name == "custom_permissions":
                    permission_name = str(raw_row.get("name", ""))
                    previous = custom_permission_identities.get(permission_name)
                    if permission_name and previous is not None and previous != identity:
                        limitations.append(
                            f"{source}:conflicting_custom_permission:{permission_name}"
                        )
                    if permission_name:
                        custom_permission_identities[permission_name] = identity
                rows.append(row)
        merged[field_name] = rows
    merged["manifest_limitations"] = list(dict.fromkeys(limitations))
    merged["manifest_complete"] = not limitations
    merged["primary_manifest_source"] = base_source
    merged["deep_links_truncated"] = any(
        payload.get("deep_links_truncated") is True for _source, payload in values
    )
    return merged


@dataclass(frozen=True, slots=True)
class AppInspectionResult:
    session_id: str
    package: str
    serial_masked: str
    generated_at: str
    status: str
    metadata: PackageMetadata
    apks: tuple[ApkArtifact, ...]
    badging: dict[str, Any] | None
    manifest: dict[str, Any] | None
    signature: dict[str, Any] | None
    steps: dict[str, str]
    limitations: tuple[str, ...]
    errors: tuple[str, ...]
    evidence: tuple[dict[str, Any], ...]
    static_analysis: dict[str, Any] | None = None
    phase_timings: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "session_id": self.session_id,
            "package": self.package,
            "serial": self.serial_masked,
            "serial_masked": self.serial_masked,
            "generated_at": self.generated_at,
            "inspection_status": self.status,
            "metadata": self.metadata.to_dict(),
            "apks": [artifact.to_dict() for artifact in self.apks],
            "badging": self.badging,
            "manifest": self.manifest,
            "signature": self.signature,
            "steps": dict(self.steps),
            "limitations": list(self.limitations),
            "errors": list(self.errors),
            "evidence": list(self.evidence),
            "static_analysis": self.static_analysis,
            "phase_timings": dict(self.phase_timings),
        }


class AppInspectionService:
    def __init__(
        self,
        context: AppContext,
        repository: SessionRepository | None = None,
    ) -> None:
        self.context = context
        self.paths = context.paths
        self.repository = repository or SessionRepository(self.paths)
        self.evidence = EvidenceRepository(self.paths, self.repository)

    def _create_session(self, package: str, serial: str | None) -> SessionRecord:
        discovery_adb = self.context.adb_client()
        selected = self.context.device_selector(discovery_adb).resolve(serial)
        load_scope(self.paths).require_inspection(selected.serial, package)
        PackageInspector(discovery_adb).inspect(selected.serial, package)
        return SessionService(self.context, self.repository).create(
            package=package,
            serial=selected.serial,
        )

    def _register_text_evidence(
        self,
        record: SessionRecord,
        path: Path,
        *,
        evidence_type: str,
        source: str,
        description: str,
        sensitive: bool,
        redacted: bool = False,
    ) -> None:
        self.evidence.register_file(
            record.session_id,
            path,
            evidence_type=evidence_type,
            source=source,
            description=description,
            sensitive=sensitive,
            redacted=redacted,
        )

    def _register_aapt_evidence(
        self,
        record: SessionRecord,
        inspection: AaptInspection,
        *,
        source_id: str,
    ) -> None:
        session_paths = self.repository.paths_for(record.session_id)
        relative_dir = inspection.xmltree_path.parent.relative_to(
            session_paths.raw_dir
        )
        redacted_dir = session_paths.redacted_dir / relative_dir
        redacted_dir.mkdir(parents=True, exist_ok=True)
        redacted_badging = redacted_dir / inspection.badging_path.name
        redacted_xmltree = redacted_dir / inspection.xmltree_path.name
        write_text_atomic(
            redacted_badging,
            redact_text(
                inspection.badging_path.read_text(
                    encoding="utf-8",
                    errors="replace",
                )
            ),
            root=self.paths.root,
        )
        write_text_atomic(
            redacted_xmltree,
            redact_aapt_xmltree(
                inspection.xmltree_path.read_text(
                    encoding="utf-8",
                    errors="replace",
                )
            ),
            root=self.paths.root,
        )
        self._register_text_evidence(
            record,
            inspection.badging_path,
            evidence_type="apk_badging_raw",
            source="aapt2_dump_badging",
            description=f"Raw AAPT2 badging output for {source_id}.",
            sensitive=True,
            redacted=False,
        )
        self._register_text_evidence(
            record,
            redacted_badging,
            evidence_type="apk_badging",
            source="aapt2_dump_badging",
            description=f"Redacted AAPT2 badging output for {source_id}.",
            sensitive=True,
            redacted=True,
        )
        self._register_text_evidence(
            record,
            inspection.xmltree_path,
            evidence_type="manifest_tree_raw",
            source="aapt2_dump_xmltree",
            description=f"Raw AAPT2 AndroidManifest.xml tree for {source_id}.",
            sensitive=True,
            redacted=False,
        )
        self._register_text_evidence(
            record,
            redacted_xmltree,
            evidence_type="manifest_tree",
            source="aapt2_dump_xmltree",
            description=f"Redacted AAPT2 AndroidManifest.xml tree for {source_id}.",
            sensitive=True,
            redacted=True,
        )
        resource_dir = redacted_dir / "resources"
        for raw_resource in inspection.resource_xmltree_paths:
            resource_dir.mkdir(parents=True, exist_ok=True)
            redacted_resource = resource_dir / raw_resource.name
            write_text_atomic(
                redacted_resource,
                redact_aapt_xmltree(
                    raw_resource.read_text(encoding="utf-8", errors="replace")
                ),
                root=self.paths.root,
            )
            self._register_text_evidence(
                record,
                raw_resource,
                evidence_type="manifest_resource_xml_raw",
                source="aapt2_dump_xmltree",
                description=f"Raw FileProvider path resource for {source_id}.",
                sensitive=True,
                redacted=False,
            )
            self._register_text_evidence(
                record,
                redacted_resource,
                evidence_type="manifest_resource_xml",
                source="aapt2_dump_xmltree",
                description=f"Redacted FileProvider path resource for {source_id}.",
                sensitive=True,
                redacted=True,
            )
        if inspection.resource_table_path is None:
            return
        resource_dir.mkdir(parents=True, exist_ok=True)
        raw_table = inspection.resource_table_path.read_text(
            encoding="utf-8",
            errors="replace",
        )
        resource_map = parse_aapt_resource_xml_paths(raw_table)
        redacted_table = resource_dir / inspection.resource_table_path.name
        safe_lines = [
            f"{identifier} {path}"
            for identifier, paths in sorted(resource_map.items())
            if identifier.startswith("0x")
            for path in paths
        ]
        write_text_atomic(
            redacted_table,
            "\n".join(safe_lines) + ("\n" if safe_lines else ""),
            root=self.paths.root,
        )
        self._register_text_evidence(
            record,
            inspection.resource_table_path,
            evidence_type="manifest_resource_table_raw",
            source="aapt2_dump_resources",
            description=f"Raw AAPT2 resource table used for {source_id} XML resolution.",
            sensitive=True,
            redacted=False,
        )
        self._register_text_evidence(
            record,
            redacted_table,
            evidence_type="manifest_resource_table",
            source="aapt2_resource_reference_map",
            description=f"Redacted XML resource-reference map for {source_id}.",
            sensitive=False,
            redacted=True,
        )

    def inspect(
        self,
        *,
        package: str,
        serial: str | None = None,
    ) -> AppInspectionResult:
        target = validate_package_name(package)
        scope = load_scope(self.paths)
        record = self._create_session(target, serial)
        session_paths = self.repository.paths_for(record.session_id)
        errors: list[str] = []
        limitations: list[str] = []
        phase_timings: dict[str, float] = {}
        phase_started = time.perf_counter()
        steps = {
            "package_metadata": "pending",
            "apk_pull": "pending",
            "aapt2_manifest": "pending",
            "static_apk_analysis": "pending",
            "apksigner": "pending",
        }
        try:
            adb = self.context.adb_client(command_log=session_paths.commands_jsonl)
            collected = PackageInspector(adb).collect(record.serial, target)
            metadata = collected.metadata
            raw_paths = session_paths.root / "raw" / "pm-path.txt"
            raw_dumpsys = session_paths.root / "raw" / "package-dumpsys.txt"
            write_text_atomic(raw_paths, collected.pm_paths_output, root=self.paths.root)
            write_text_atomic(raw_dumpsys, collected.dumpsys_output, root=self.paths.root)
            self._register_text_evidence(
                record,
                raw_paths,
                evidence_type="package_paths",
                source="adb_pm_path",
                description="Raw Package Manager APK path output.",
                sensitive=True,
            )
            self._register_text_evidence(
                record,
                raw_dumpsys,
                evidence_type="package_metadata",
                source="adb_dumpsys_package",
                description="Raw dumpsys package metadata output.",
                sensitive=True,
            )
            steps["package_metadata"] = "completed"
            phase_timings["device_inspection"] = round(
                (time.perf_counter() - phase_started) * 1000,
                2,
            )

            phase_started = time.perf_counter()
            max_evidence_bytes = scope.limits.max_evidence_size_mb * 1024 * 1024
            max_apk_file_bytes = min(
                DEFAULT_MAX_APK_FILE_BYTES,
                max_evidence_bytes,
            )
            artifacts = ApkPuller(self.paths, adb).pull(
                record.serial,
                metadata.apk_paths,
                session_root=session_paths.root,
                destination_dir=session_paths.apk_dir,
                max_files=DEFAULT_MAX_APK_FILES,
                max_file_bytes=max_apk_file_bytes,
                max_total_bytes=min(
                    DEFAULT_MAX_TOTAL_APK_BYTES,
                    max_apk_file_bytes * DEFAULT_MAX_APK_FILES,
                ),
                stat_timeout=scope.limits.command_timeout_seconds,
            )
            for artifact in artifacts:
                self.evidence.register_file(
                    record.session_id,
                    session_paths.root / artifact.relative_path,
                    evidence_type="apk",
                    source="adb_pull",
                    description=f"{artifact.role.title()} APK collected from the lab device.",
                    sensitive=True,
                    redacted=False,
                )
            steps["apk_pull"] = "completed"
            phase_timings["apk_acquisition"] = round(
                (time.perf_counter() - phase_started) * 1000,
                2,
            )
            base_artifact = next(
                (artifact for artifact in artifacts if artifact.role == "base"),
                artifacts[0],
            )
            base_apk = session_paths.root / base_artifact.relative_path

            badging: dict[str, Any] | None = None
            manifest: dict[str, Any] | None = None
            resource_strings: dict[str, tuple[str, ...]] = {}
            static_input_limitations: list[str] = []
            aapt_inspector: Aapt2Inspector | None = None
            aapt2 = resolve_binary(
                find_tool_spec("aapt2"),
                self.paths,
                self.context.config,
            )
            if aapt2 is None:
                steps["aapt2_manifest"] = "skipped"
                limitations.append("aapt2 is unavailable; manifest inspection was skipped.")
            else:
                phase_started = time.perf_counter()
                aapt_inspector = Aapt2Inspector(
                    aapt2.path,
                    command_log=session_paths.commands_jsonl,
                )
                normalized_manifests: list[tuple[str, dict[str, Any]]] = []
                manifest_limitations: list[str] = []
                base_result: AaptInspection | None = None
                effective_target_sdk = metadata.target_sdk
                ordered_artifacts = sorted(
                    enumerate(artifacts),
                    key=lambda item: (item[1].role != "base", item[0]),
                )
                for index, artifact in ordered_artifacts:
                    source_id = f"{artifact.role}:{index}"
                    output_dir = session_paths.raw_dir / "manifest"
                    if artifact.role != "base":
                        output_dir = output_dir / f"split-{index:03d}"
                    try:
                        inspected = aapt_inspector.inspect(
                            session_paths.root / artifact.relative_path,
                            output_dir=output_dir,
                            project_root=self.paths.root,
                            target_sdk=effective_target_sdk,
                        )
                        self._register_aapt_evidence(
                            record,
                            inspected,
                            source_id=source_id,
                        )
                        if inspected.manifest.package not in {None, target}:
                            manifest_limitations.append(
                                f"{source_id}:manifest_package_mismatch"
                            )
                            continue
                        normalized_manifests.append(
                            (source_id, inspected.manifest.to_dict())
                        )
                        if artifact.role == "base" and base_result is None:
                            base_result = inspected
                            if effective_target_sdk is None:
                                effective_target_sdk = inspected.badging.target_sdk
                    except (AndroidAssessorError, OSError, ValueError) as exc:
                        manifest_limitations.append(
                            f"{source_id}:manifest_inspection_failed"
                        )
                        limitations.append(
                            f"Manifest inspection failed for {source_id}: "
                            f"{redact_text(str(exc))[:300]}"
                        )
                if base_result is None:
                    steps["aapt2_manifest"] = "error"
                    errors.append("The base APK manifest could not be inspected.")
                else:
                    metadata = merge_badging(metadata, base_result.badging)
                    badging = base_result.badging.to_dict()
                    file_provider_limitations: list[str] = []
                    if len(artifacts) > 1 and any(
                        payload.get("file_provider_paths")
                        for _source, payload in normalized_manifests
                    ):
                        file_provider_limitations.append(
                            "split_resource_variants_not_correlated"
                        )
                    manifest = _merge_manifest_payloads(
                        normalized_manifests,
                        manifest_limitations,
                    )
                    manifest["file_provider_limitations"] = file_provider_limitations
                    if manifest_limitations or file_provider_limitations:
                        limitations.append(
                            "Manifest coverage is partial: "
                            + ", ".join(
                                (*manifest_limitations, *file_provider_limitations)[:5]
                            )
                        )
                    steps["aapt2_manifest"] = (
                        "partial"
                        if manifest_limitations or file_provider_limitations
                        else "completed"
                    )
                phase_timings["manifest"] = round(
                    (time.perf_counter() - phase_started) * 1000,
                    2,
                )

            if aapt_inspector is None:
                static_input_limitations.append("resource_strings:aapt2_unavailable")
            else:
                string_failures: list[str] = []
                for index, artifact in enumerate(artifacts):
                    source_id = f"{artifact.role}:{index}"
                    try:
                        resource_strings[artifact.relative_path] = (
                            aapt_inspector.dump_strings(
                                session_paths.root / artifact.relative_path,
                                project_root=self.paths.root,
                            )
                        )
                    except (AndroidAssessorError, OSError, ValueError):
                        limitation = f"{source_id}:resource_strings_unavailable"
                        static_input_limitations.append(limitation)
                        string_failures.append(source_id)
                if string_failures:
                    limitations.append(
                        "AAPT2 resource-string inventory was unavailable for: "
                        + ", ".join(string_failures[:5])
                    )

            static_analysis: dict[str, Any] | None = None
            phase_started = time.perf_counter()
            try:
                static_result = analyze_apks(
                    tuple(
                        StaticApkInput(
                            path=session_paths.root / artifact.relative_path,
                            source_id=f"{artifact.role}:{index}",
                            resource_strings=resource_strings.get(
                                artifact.relative_path,
                                (),
                            ),
                            application_id=target,
                        )
                        for index, artifact in enumerate(artifacts)
                    )
                )
                if static_input_limitations:
                    static_result = replace(
                        static_result,
                        status="partial",
                        limitations=tuple(
                            dict.fromkeys(
                                (*static_result.limitations, *static_input_limitations)
                            )
                        ),
                    )
                static_analysis = static_result.to_dict()
                static_output = (
                    session_paths.redacted_dir
                    / "static"
                    / "static-apk-analysis.json"
                )
                write_json_atomic(
                    static_output,
                    static_analysis,
                    root=self.paths.root,
                )
                self.evidence.register_file(
                    record.session_id,
                    static_output,
                    evidence_type="static_apk_inventory",
                    source="bounded_apk_static_analysis",
                    description=(
                        "Redacted bounded inventory of APK, DEX, resource, asset, "
                        "endpoint, and API metadata."
                    ),
                    sensitive=True,
                    redacted=True,
                )
                steps["static_apk_analysis"] = static_result.status
                if static_result.limitations:
                    limitations.append(
                        "Static APK analysis completed with bounded limitations: "
                        + ", ".join(static_result.limitations[:5])
                    )
            except (OSError, ValueError) as exc:
                steps["static_apk_analysis"] = "error"
                errors.append(
                    f"Static APK analysis failed: {redact_text(str(exc))[:400]}"
                )
            phase_timings["static_apk_analysis"] = round(
                (time.perf_counter() - phase_started) * 1000,
                2,
            )

            signature: dict[str, Any] | None = None
            java = resolve_binary(
                find_tool_spec("java"),
                self.paths,
                self.context.config,
            )
            apksigner_jar = self.paths.tools_dir / "build-tools" / "lib" / "apksigner.jar"
            if java is None or not apksigner_jar.is_file():
                steps["apksigner"] = "skipped"
                limitations.append(
                    "Java or apksigner.jar is unavailable; signature inspection was skipped."
                )
            else:
                phase_started = time.perf_counter()
                try:
                    signature_result = ApkSignatureInspector(
                        java.path,
                        apksigner_jar,
                        command_log=session_paths.commands_jsonl,
                    ).inspect(
                        base_apk,
                        output_path=(
                            session_paths.redacted_dir / "signature" / "signature.txt"
                        ),
                        project_root=self.paths.root,
                    )
                    signature = signature_result.to_dict(root=session_paths.root)
                    if signature_result.output_path is not None:
                        self._register_text_evidence(
                            record,
                            signature_result.output_path,
                            evidence_type="apk_signature",
                            source="apksigner_verify",
                            description="Redacted apksigner verification and certificate output.",
                            sensitive=False,
                            redacted=True,
                        )
                    steps["apksigner"] = (
                        "completed" if signature_result.verified else "error"
                    )
                    if signature_result.error:
                        errors.append(signature_result.error)
                    phase_timings["signature"] = round(
                        (time.perf_counter() - phase_started) * 1000,
                        2,
                    )
                except (AndroidAssessorError, OSError, ValueError) as exc:
                    steps["apksigner"] = "error"
                    errors.append(redact_text(str(exc))[:500])

            status = (
                "completed"
                if all(value == "completed" for value in steps.values())
                else "partial"
            )
            result = AppInspectionResult(
                session_id=record.session_id,
                package=target,
                serial_masked=mask_serial(record.serial),
                generated_at=datetime.now(UTC).isoformat(),
                status=status,
                metadata=metadata,
                apks=artifacts,
                badging=badging,
                manifest=manifest,
                signature=signature,
                steps=steps,
                limitations=tuple(limitations),
                errors=tuple(errors),
                evidence=tuple(self.evidence.list(record.session_id)),
                static_analysis=static_analysis,
                phase_timings=phase_timings,
            )
            write_json_atomic(
                session_paths.app_json,
                result.to_dict(),
                root=self.paths.root,
            )
            self.repository.append_event(
                record.session_id,
                "app_inspection_completed",
                {
                    "status": status,
                    "apk_count": len(artifacts),
                    "component_count": len(manifest.get("components", []))
                    if manifest
                    else 0,
                    "errors": errors,
                },
            )
            return result
        except (AndroidAssessorError, OSError, ValueError) as exc:
            error = redact_text(str(exc))[:500]
            try:
                write_json_atomic(
                    session_paths.app_json,
                    {
                        "schema_version": 1,
                        "session_id": record.session_id,
                        "package": target,
                        "inspection_status": "error",
                        "error": error,
                        "steps": steps,
                    },
                    root=self.paths.root,
                )
                self.repository.set_status(
                    record.session_id,
                    SessionStatus.ERROR,
                    cleanup_success=False,
                    last_error=error,
                )
            except (AndroidAssessorError, OSError, ValueError):
                pass
            raise
