"""Orchestrate reproducible package/APK/manifest inspection sessions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..adb import mask_serial
from ..apk import ApkArtifact, ApkPuller, PackageInspector, PackageMetadata, merge_badging
from ..app_context import AppContext
from ..environment import find_tool_spec, resolve_binary
from ..errors import AndroidAssessorError, ApkInspectionError
from ..evidence import EvidenceRepository
from ..manifest import Aapt2Inspector
from ..redaction import redact_text
from ..scope import load_scope
from ..session import SessionRecord, SessionRepository, SessionStatus
from ..signature import ApkSignatureInspector
from ..storage import write_json_atomic, write_text_atomic
from ..validation import validate_package_name
from .session_service import SessionService


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

    def inspect(
        self,
        *,
        package: str,
        serial: str | None = None,
    ) -> AppInspectionResult:
        target = validate_package_name(package)
        record = self._create_session(target, serial)
        session_paths = self.repository.paths_for(record.session_id)
        errors: list[str] = []
        limitations: list[str] = []
        steps = {
            "package_metadata": "pending",
            "apk_pull": "pending",
            "aapt2_manifest": "pending",
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

            artifacts = ApkPuller(self.paths, adb).pull(
                record.serial,
                metadata.apk_paths,
                session_root=session_paths.root,
                destination_dir=session_paths.apk_dir,
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
            base_artifact = next(
                (artifact for artifact in artifacts if artifact.role == "base"),
                artifacts[0],
            )
            base_apk = session_paths.root / base_artifact.relative_path

            badging: dict[str, Any] | None = None
            manifest: dict[str, Any] | None = None
            aapt2 = resolve_binary(
                find_tool_spec("aapt2"),
                self.paths,
                self.context.config,
            )
            if aapt2 is None:
                steps["aapt2_manifest"] = "skipped"
                limitations.append("aapt2 is unavailable; manifest inspection was skipped.")
            else:
                try:
                    aapt_result = Aapt2Inspector(
                        aapt2.path,
                        command_log=session_paths.commands_jsonl,
                    ).inspect(
                        base_apk,
                        output_dir=session_paths.raw_dir / "manifest",
                        project_root=self.paths.root,
                        target_sdk=metadata.target_sdk,
                    )
                    metadata = merge_badging(metadata, aapt_result.badging)
                    if (
                        aapt_result.manifest.package
                        and aapt_result.manifest.package != target
                    ):
                        raise ApkInspectionError(
                            "Manifest package does not match the selected package."
                        )
                    badging = aapt_result.badging.to_dict()
                    manifest = aapt_result.manifest.to_dict()
                    redacted_manifest_dir = session_paths.redacted_dir / "manifest"
                    redacted_manifest_dir.mkdir(parents=True, exist_ok=True)
                    redacted_badging = redacted_manifest_dir / "badging.txt"
                    redacted_xmltree = redacted_manifest_dir / "manifest-xmltree.txt"
                    write_text_atomic(
                        redacted_badging,
                        redact_text(
                            aapt_result.badging_path.read_text(
                                encoding="utf-8",
                                errors="replace",
                            )
                        ),
                        root=self.paths.root,
                    )
                    write_text_atomic(
                        redacted_xmltree,
                        redact_text(
                            aapt_result.xmltree_path.read_text(
                                encoding="utf-8",
                                errors="replace",
                            )
                        ),
                        root=self.paths.root,
                    )
                    self._register_text_evidence(
                        record,
                        aapt_result.badging_path,
                        evidence_type="apk_badging_raw",
                        source="aapt2_dump_badging",
                        description="Raw AAPT2 badging output for the base APK.",
                        sensitive=True,
                        redacted=False,
                    )
                    self._register_text_evidence(
                        record,
                        redacted_badging,
                        evidence_type="apk_badging",
                        source="aapt2_dump_badging",
                        description="Redacted AAPT2 badging output for the base APK.",
                        sensitive=True,
                        redacted=True,
                    )
                    self._register_text_evidence(
                        record,
                        aapt_result.xmltree_path,
                        evidence_type="manifest_tree_raw",
                        source="aapt2_dump_xmltree",
                        description="Raw AAPT2 AndroidManifest.xml tree output.",
                        sensitive=True,
                        redacted=False,
                    )
                    self._register_text_evidence(
                        record,
                        redacted_xmltree,
                        evidence_type="manifest_tree",
                        source="aapt2_dump_xmltree",
                        description="Redacted AAPT2 AndroidManifest.xml tree output.",
                        sensitive=True,
                        redacted=True,
                    )
                    steps["aapt2_manifest"] = "completed"
                except (AndroidAssessorError, OSError, ValueError) as exc:
                    steps["aapt2_manifest"] = "error"
                    errors.append(redact_text(str(exc))[:500])

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
