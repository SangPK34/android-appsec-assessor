"""Three bounded canary validations for findings produced by the MVP rules."""

from __future__ import annotations

import json
import re
import time
from datetime import UTC, datetime
from urllib.parse import urlencode, urlunsplit

from ..app_context import AppContext
from ..device_lock import DeviceLock
from ..errors import AndroidAssessorError, SessionError
from ..evidence import EvidenceRepository
from ..findings import (
    FindingRecord,
    FindingRepository,
    FindingStatus,
    ValidationRecord,
)
from ..logcat import LogcatCollector
from ..private_storage import AdbPrivateStorageBackend, PrivateStorageService
from ..redaction import redact_text
from ..report import ReportService
from ..rules import RuleEngine
from ..scope import load_scope
from ..session import SessionRepository
from ..storage import read_json_object, require_under_root, write_text_atomic
from ..traffic import TrafficCaptureService, load_traffic_events
from ..validation import generate_session_canary
from ..validation_definitions import validation_for_rule

_HOST_PATTERN = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
_PATH_PATTERN = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$")
_BROADCAST_ACTION_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,255}$")


class ValidationService:
    def __init__(
        self,
        context: AppContext,
        repository: SessionRepository | None = None,
    ) -> None:
        self.context = context
        self.paths = context.paths
        self.repository = repository or SessionRepository(self.paths)
        self.findings = FindingRepository(self.paths, self.repository)
        self.evidence = EvidenceRepository(self.paths, self.repository)

    @staticmethod
    def _canary() -> str:
        return generate_session_canary()

    def _app(self, session_id: str) -> dict[str, object]:
        paths = self.repository.paths_for(session_id)
        return read_json_object(paths.app_json, root=self.paths.root)

    @staticmethod
    def _exported_activity(finding: FindingRecord) -> str | None:
        values = finding.details.get("unprotected_exported_components", [])
        if not isinstance(values, list):
            return None
        for item in values:
            if (
                isinstance(item, dict)
                and item.get("component_type") in {"activity", "activity-alias"}
                and isinstance(item.get("name"), str)
            ):
                return str(item["name"])
        return None

    def _deep_link(self, app: dict[str, object]) -> tuple[str, str] | None:
        manifest = app.get("manifest")
        if not isinstance(manifest, dict):
            return None
        links = manifest.get("deep_links", [])
        if not isinstance(links, list):
            return None
        for link in links:
            if not isinstance(link, dict) or link.get("scheme") != "http":
                continue
            component = link.get("component")
            host = link.get("host")
            if not isinstance(component, str) or not isinstance(host, str):
                continue
            if not _HOST_PATTERN.fullmatch(host) or host.startswith("."):
                continue
            path = next(
                (
                    value
                    for key in ("path", "path_prefix")
                    if isinstance((value := link.get(key)), str)
                    and _PATH_PATTERN.fullmatch(value)
                ),
                "/",
            )
            return component, urlunsplit(("http", host, path, "", ""))
        return None

    def _activity_evidence(
        self,
        session_id: str,
        rule_id: str,
        text: str,
        *,
        source: str = "adb_am_start",
    ) -> str:
        paths = self.repository.paths_for(session_id)
        target = (
            paths.redacted_dir
            / "validation"
            / f"validation-{rule_id.lower()}.txt"
        )
        write_text_atomic(target, redact_text(text), root=self.paths.root)
        record = self.evidence.register_file(
            session_id,
            target,
            evidence_type="controlled_validation",
            source=source,
            description=f"Bounded controlled-validation output for {rule_id}.",
            sensitive=True,
            redacted=True,
            related_findings=(f"finding-{rule_id.lower()}",),
        )
        return record.evidence_id

    @staticmethod
    def _descriptor_to_component(value: object) -> str | None:
        if not isinstance(value, str) or not value.startswith("L") or not value.endswith(";"):
            return None
        component = value[1:-1].replace("/", ".")
        return component if "." in component else None

    @staticmethod
    def _storage_receiver_candidate(
        app: dict[str, object],
        finding: FindingRecord,
    ) -> tuple[str, str] | None:
        manifest = app.get("manifest")
        if not isinstance(manifest, dict):
            return None
        components = manifest.get("components", [])
        if not isinstance(components, list):
            return None
        receivers: dict[str, dict[str, object]] = {}
        for item in components:
            if (
                isinstance(item, dict)
                and item.get("component_type") == "receiver"
                and item.get("effective_exported") is True
                and item.get("permission") in {None, ""}
                and isinstance(item.get("name"), str)
            ):
                receivers[str(item["name"])] = item
        candidates = finding.details.get("static_behavior_candidates", [])
        if not isinstance(candidates, list):
            return None
        for candidate in candidates:
            if (
                not isinstance(candidate, dict)
                or candidate.get("rule_id") != finding.rule_id
                or candidate.get("caller_method_name") != "onReceive"
            ):
                continue
            component = ValidationService._descriptor_to_component(
                candidate.get("caller_class_descriptor")
            )
            receiver = receivers.get(component or "")
            if receiver is None:
                continue
            filters = receiver.get("intent_filters", [])
            if not isinstance(filters, list):
                continue
            for intent_filter in filters:
                if not isinstance(intent_filter, dict):
                    continue
                actions = intent_filter.get("actions", [])
                if not isinstance(actions, list):
                    continue
                for action in actions:
                    if isinstance(action, str) and _BROADCAST_ACTION_PATTERN.fullmatch(
                        action
                    ):
                        return component or "", action
        return None

    def _validate_cleartext(
        self,
        session_id: str,
        finding: FindingRecord,
        canary: str,
    ) -> ValidationRecord:
        record = self.repository.load(session_id)
        deep_link = self._deep_link(self._app(session_id))
        if deep_link is None:
            return ValidationRecord(
                status=FindingStatus.SKIPPED,
                validation_type="adb_assisted_validation",
                validated_at=datetime.now(UTC).isoformat(),
                canary=canary,
                summary="No allowlisted HTTP deep link was available for a cleartext canary.",
            )
        component, base_uri = deep_link
        load_scope(self.paths).require_url(base_uri)
        separator = "&" if "?" in base_uri else "?"
        uri = f"{base_uri}{separator}{urlencode({'thesis_canary': canary})}"
        traffic = TrafficCaptureService(self.context, self.repository)
        state = traffic.load_state(session_id)
        started_here = not state or state.status != "running"
        if started_here:
            traffic.start(session_id, launch_app=False, canary=canary)
        try:
            paths = self.repository.paths_for(session_id)
            with DeviceLock(
                self.paths,
                record.serial,
                operation="validate_cleartext_canary",
                session_id=session_id,
            ):
                result = self.context.adb_client(
                    command_log=paths.commands_jsonl
                ).start_activity(
                    record.serial,
                    record.package,
                    component,
                    canary=canary,
                    data_uri=uri,
                )
            if result.timed_out or result.exit_code != 0:
                return ValidationRecord(
                    status=FindingStatus.INCONCLUSIVE,
                    validation_type="adb_assisted_validation",
                    validated_at=datetime.now(UTC).isoformat(),
                    canary=canary,
                    summary="The allowlisted deep-link launch did not complete.",
                )
            time.sleep(3)
        finally:
            if started_here:
                traffic.stop(session_id)
        latest = traffic.load_state(session_id)
        events = (
            load_traffic_events(
                require_under_root(
                    self.repository.paths_for(session_id).root / latest.events_path,
                    self.repository.paths_for(session_id).root,
                )
            )
            if latest
            else []
        )
        observed = any(
            item.get("attribution") == "validation_canary"
            or canary in str(item.get("url", ""))
            for item in events
        )
        evidence_ids = tuple(
            str(item["evidence_id"])
            for item in self.evidence.list(session_id)
            if item.get("evidence_type") == "traffic_events"
        )
        return ValidationRecord(
            status=FindingStatus.CONFIRMED if observed else FindingStatus.INCONCLUSIVE,
            validation_type="adb_assisted_validation",
            validated_at=datetime.now(UTC).isoformat(),
            canary=canary,
            summary=(
                "The canary was observed in cleartext proxy metadata."
                if observed
                else "The app accepted the intent, but no cleartext canary request was observed."
            ),
            evidence_ids=evidence_ids,
        )

    def _validate_sensitive_log(
        self,
        session_id: str,
        finding: FindingRecord,
        canary: str,
    ) -> ValidationRecord:
        component = self._exported_activity(finding)
        if component is None:
            exported = self.findings.get(session_id, "finding-asl-mvp-004")
            component = self._exported_activity(exported)
        if component is None:
            return ValidationRecord(
                status=FindingStatus.SKIPPED,
                validation_type="adb_assisted_validation",
                validated_at=datetime.now(UTC).isoformat(),
                canary=canary,
                summary="No unprotected exported activity was available for canary delivery.",
            )
        record = self.repository.load(session_id)
        paths = self.repository.paths_for(session_id)
        with DeviceLock(
            self.paths,
            record.serial,
            operation="validate_sensitive_logging",
            session_id=session_id,
        ):
            result = self.context.adb_client(
                command_log=paths.commands_jsonl
            ).start_activity(
                record.serial,
                record.package,
                component,
                canary=canary,
            )
        if result.timed_out or result.exit_code != 0:
            return ValidationRecord(
                status=FindingStatus.INCONCLUSIVE,
                validation_type="adb_assisted_validation",
                validated_at=datetime.now(UTC).isoformat(),
                canary=canary,
                summary="The canary activity launch did not complete.",
            )
        time.sleep(1)
        state = LogcatCollector(self.context, self.repository).collect(
            session_id,
            canary=canary,
        )
        return ValidationRecord(
            status=(
                FindingStatus.CONFIRMED
                if state.canary_observed
                else FindingStatus.INCONCLUSIVE
            ),
            validation_type="adb_assisted_validation",
            validated_at=datetime.now(UTC).isoformat(),
            canary=canary,
            summary=(
                "The controlled canary appeared in target-process logcat."
                if state.canary_observed
                else "The activity launched, but the controlled canary was not logged."
            ),
            evidence_ids=(state.evidence_id,) if state.evidence_id else (),
        )

    def _validate_exported_activity(
        self,
        session_id: str,
        finding: FindingRecord,
        canary: str,
    ) -> ValidationRecord:
        component = self._exported_activity(finding)
        if component is None:
            return ValidationRecord(
                status=FindingStatus.SKIPPED,
                validation_type="adb_assisted_validation",
                validated_at=datetime.now(UTC).isoformat(),
                canary=canary,
                summary="No unprotected exported activity was identified.",
            )
        record = self.repository.load(session_id)
        paths = self.repository.paths_for(session_id)
        with DeviceLock(
            self.paths,
            record.serial,
            operation="validate_exported_activity",
            session_id=session_id,
        ):
            result = self.context.adb_client(
                command_log=paths.commands_jsonl
            ).start_activity(
                record.serial,
                record.package,
                component,
                canary=canary,
            )
        output = f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}\n"
        evidence_id = self._activity_evidence(
            session_id,
            finding.rule_id,
            output,
        )
        blocked = "SecurityException" in output or "Error:" in output
        launched = (
            not result.timed_out
            and result.exit_code == 0
            and not blocked
            and ("Status: ok" in output or "Complete" in output)
        )
        logcat_evidence_id: str | None = None
        canary_observed = False
        if launched:
            time.sleep(1)
            logcat = LogcatCollector(self.context, self.repository).collect(
                session_id,
                canary=canary,
            )
            canary_observed = logcat.canary_observed
            logcat_evidence_id = logcat.evidence_id
        evidence_ids = tuple(
            item
            for item in (evidence_id, logcat_evidence_id)
            if item is not None
        )
        status = (
            FindingStatus.CONFIRMED
            if canary_observed
            else FindingStatus.POTENTIAL
            if launched
            else FindingStatus.INCONCLUSIVE
        )
        return ValidationRecord(
            status=status,
            validation_type="adb_assisted_validation",
            validated_at=datetime.now(UTC).isoformat(),
            canary=canary,
            summary=(
                "The exported activity produced target-process evidence containing the canary."
                if canary_observed
                else "The activity launched, but no defined canary impact was observed."
                if launched
                else "The explicit activity launch was blocked or did not complete."
            ),
            evidence_ids=evidence_ids,
        )

    def _validate_world_readable_storage(
        self,
        session_id: str,
        finding: FindingRecord,
        canary: str,
    ) -> ValidationRecord:
        target = self._storage_receiver_candidate(self._app(session_id), finding)
        if target is None:
            return ValidationRecord(
                status=FindingStatus.SKIPPED,
                validation_type="root_assisted_validation",
                validated_at=datetime.now(UTC).isoformat(),
                canary=canary,
                summary=(
                    "No exported receiver action was correlated to a static "
                    "world-readable storage call-site."
                ),
            )
        component, action = target
        record = self.repository.load(session_id)
        paths = self.repository.paths_for(session_id)
        with DeviceLock(
            self.paths,
            record.serial,
            operation="validate_world_readable_storage_receiver",
            session_id=session_id,
        ):
            result = self.context.adb_client(
                command_log=paths.commands_jsonl
            ).shell(
                record.serial,
                (
                    "am",
                    "broadcast",
                    "-n",
                    f"{record.package}/{component}",
                    "-a",
                    action,
                    "--es",
                    "thesis_canary",
                    canary,
                ),
                timeout=30,
                check=False,
                operation="broadcasting to an allowlisted receiver for validation",
            )
        output = f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}\n"
        broadcast_evidence_id = self._activity_evidence(
            session_id,
            finding.rule_id,
            output,
            source="adb_am_broadcast",
        )
        broadcast_completed = (
            not result.timed_out
            and result.exit_code == 0
            and "Broadcast completed" in output
        )
        if not broadcast_completed:
            return ValidationRecord(
                status=FindingStatus.INCONCLUSIVE,
                validation_type="root_assisted_validation",
                validated_at=datetime.now(UTC).isoformat(),
                canary=canary,
                summary="The receiver broadcast was blocked or did not complete.",
                evidence_ids=(broadcast_evidence_id,),
            )
        try:
            load_scope(self.paths).require_device_package(
                record.serial,
                record.package,
                action="root_storage_read",
            )
            backend = AdbPrivateStorageBackend(
                self.context.adb_client(command_log=paths.commands_jsonl)
            )
            if record.serial.startswith("emulator-"):
                backend.environment_type = "emulator"
            storage = PrivateStorageService(self.repository, backend).collect(
                session_id,
                session_canary=canary,
            )
        except (AndroidAssessorError, OSError, ValueError) as exc:
            return ValidationRecord(
                status=FindingStatus.INCONCLUSIVE,
                validation_type="root_assisted_validation",
                validated_at=datetime.now(UTC).isoformat(),
                canary=canary,
                summary=(
                    "The receiver broadcast completed, but private-storage "
                    f"validation did not complete: {redact_text(str(exc))[:200]}"
                ),
                evidence_ids=(broadcast_evidence_id,),
            )
        storage_evidence_ids = tuple(
            str(item["evidence_id"])
            for item in self.evidence.list(session_id)
            if item.get("evidence_type") == "private_storage_metadata"
        )
        evidence_ids = tuple(
            dict.fromkeys((broadcast_evidence_id, *storage_evidence_ids))
        )
        matched = next(
            (
                item
                for item in storage.observations
                if item.observation_id == "storage-world-readable"
            ),
            None,
        )
        if matched and matched.finding_eligible:
            status = FindingStatus.CONFIRMED
            summary = (
                "The receiver broadcast completed and private-storage metadata "
                "showed a world-readable package artifact."
            )
        elif (
            storage.inventory_status == "completed"
            and not storage.inventory_limitations
        ):
            status = FindingStatus.PASS
            summary = (
                "The receiver broadcast completed and bounded private-storage "
                "metadata rejected a world-readable artifact outcome."
            )
        else:
            status = FindingStatus.INCONCLUSIVE
            summary = (
                "The receiver broadcast completed, but private-storage inventory "
                "coverage was incomplete."
            )
        return ValidationRecord(
            status=status,
            validation_type="root_assisted_validation",
            validated_at=datetime.now(UTC).isoformat(),
            canary=canary,
            summary=summary,
            evidence_ids=evidence_ids,
        )

    def validate(self, session_id: str, finding_id: str) -> FindingRecord:
        record = self.repository.load(session_id)
        scope = load_scope(self.paths)
        scope.require_device_package(
            record.serial,
            record.package,
            action="controlled_validation",
        )
        self.repository.require_modifying_session_slot(record.serial, record.session_id)
        with DeviceLock(
            self.paths,
            record.serial,
            operation="controlled_validation",
            session_id=record.session_id,
            timeout=0,
        ):
            self.repository.require_modifying_session_slot(
                record.serial,
                record.session_id,
            )
            return self._validate_locked(
                session_id,
                finding_id,
                max_requests=scope.limits.max_validation_requests,
            )

    def _reserve_validation_attempt(self, session_id: str, max_requests: int) -> None:
        events_path = self.repository.paths_for(session_id).events_jsonl
        attempts = 0
        try:
            for line in events_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError("event is not an object")
                attempts += value.get("event") == "validation_attempt_started"
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise SessionError("Validation attempt ledger could not be verified.") from exc
        if attempts >= max_requests:
            raise SessionError("Session validation request limit has been reached.")
        self.repository.append_event(
            session_id,
            "validation_attempt_started",
            {"attempt": attempts + 1, "limit": max_requests},
        )

    def _validate_locked(
        self,
        session_id: str,
        finding_id: str,
        *,
        max_requests: int,
    ) -> FindingRecord:
        finding = self.findings.get(session_id, finding_id)
        if not finding.validation_supported:
            raise SessionError("This finding does not support controlled validation.")
        definition = validation_for_rule(finding.rule_id)
        if definition is None or not definition.production_enabled:
            raise SessionError("This controlled validation is not enabled in production.")
        self._reserve_validation_attempt(session_id, max_requests)
        canary = self._canary()
        if finding.rule_id == "ASL-MVP-002":
            validation = self._validate_cleartext(session_id, finding, canary)
        elif finding.rule_id == "ASL-MVP-003":
            validation = self._validate_sensitive_log(session_id, finding, canary)
        elif finding.rule_id == "ASL-MVP-004":
            validation = self._validate_exported_activity(session_id, finding, canary)
        elif finding.rule_id == "STORAGE-WORLD-READABLE":
            validation = self._validate_world_readable_storage(
                session_id,
                finding,
                canary,
            )
        else:
            raise SessionError("No production validator is registered for this finding.")
        self.findings.set_validation(session_id, finding_id, validation)
        self.repository.append_event(
            session_id,
            "finding_validated",
            {
                "finding_id": finding_id,
                "status": validation.status.value,
                "validation_type": validation.validation_type,
            },
        )
        # Controlled actions may add traffic, logcat, or other evidence consumed
        # by rules beyond the finding that initiated validation. Re-evaluate the
        # shared evidence once so those correlations are not left stale.
        RuleEngine(self.paths, self.repository).evaluate(session_id)
        updated = self.findings.get(session_id, finding_id)
        ReportService(self.paths, self.repository).generate(session_id)
        return updated
