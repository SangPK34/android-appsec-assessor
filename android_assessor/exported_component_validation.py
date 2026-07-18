"""Bounded, attribution-first validation for exported Android IPC routes.

The manifest is only a candidate source.  This module deliberately keeps the
route outcome separate from :class:`FindingStatus`: a command can complete
without proving that an exported boundary had a security-relevant impact.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from .app_context import AppContext
from .errors import AndroidAssessorError, ScopeError
from .evidence import EvidenceRepository
from .redaction import redact_text
from .scope import ScopeConfig
from .session import SessionRepository
from .storage import read_json_object, write_json_atomic
from .validation import generate_session_canary, validate_component_name

_ACTION_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,255}$")
_AUTHORITY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
_ACTIVITY_PATTERN = re.compile(
    r"(?:mResumedActivity|topResumedActivity)[:=].*?\s"
    r"([A-Za-z0-9_.]+)/([A-Za-z0-9_.$]+)"
)
_PID_PATTERN = re.compile(r"\b([1-9][0-9]{0,8})\b")
_ROW_PATTERN = re.compile(r"(?mi)^\s*row:\s*\d+\s+(?P<fields>.*)$")
_FIELD_PATTERN = re.compile(r"(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)\s*=")
_DENIAL_MARKERS = (
    "permission denial",
    "securityexception",
    "requires permission",
    "permission denied",
)
_UNKNOWN_COMPONENT_MARKERS = (
    "error type 3",
    "does not exist",
    "unable to resolve intent",
    "no activity found",
)
_UNKNOWN_URI_MARKERS = (
    "unknown uri",
    "unsupportedoperationexception",
    "illegalargumentexception",
    "no content provider",
    "no provider found",
)
_SENSITIVE_FIELD_MARKERS = (
    "password",
    "passwd",
    "secret",
    "token",
    "credential",
    "apikey",
    "api_key",
    "authorization",
    "session",
    "cookie",
    "private",
    "account",
    "email",
    "phone",
)


class IpcRouteOutcome(StrEnum):
    CONFIRMED = "confirmed"
    REJECTED = "rejected_for_tested_route"
    INCONCLUSIVE = "inconclusive"
    NOT_EXERCISED = "not_exercised"
    OUT_OF_SCOPE = "out_of_scope"


@dataclass(frozen=True, slots=True)
class IpcCandidate:
    component_type: str
    component: str
    permission_boundary: str
    permission: str | None = None
    action: str | None = None
    authority: str | None = None
    enabled: bool | None = None
    intent_filter_count: int = 0
    source: str = "normalized_manifest"

    @property
    def route_key(self) -> str:
        payload = {
            "type": self.component_type,
            "component": self.component,
            "permission": self.permission,
            "action": self.action,
            "authority": self.authority,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["candidate_key"] = self.route_key
        return value


@dataclass(slots=True)
class IpcRouteResult:
    candidate: IpcCandidate
    outcome: IpcRouteOutcome
    reason: str
    attempted: bool
    command_completed: bool = False
    command_exit_code: int | None = None
    timed_out: bool = False
    output_limited: bool = False
    canary_fingerprint: str | None = None
    observable_impact: bool = False
    target_package: str | None = None
    target_activity: str | None = None
    target_pid: int | None = None
    evidence_id: str | None = None
    cleanup_status: str = "not_required"
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["candidate"] = self.candidate.to_dict()
        value["outcome"] = self.outcome.value
        return value


@dataclass(frozen=True, slots=True)
class IpcValidationResult:
    session_id: str
    package: str
    routes: tuple[IpcRouteResult, ...]
    evidence_id: str | None
    artifact_path: str
    quota: dict[str, int]
    cleanup_status: str

    @property
    def executed(self) -> bool:
        return any(route.attempted for route in self.routes)

    def to_dict(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for route in self.routes:
            counts[route.outcome.value] = counts.get(route.outcome.value, 0) + 1
        return {
            "schema_version": 1,
            "session_id": self.session_id,
            "package": self.package,
            "routes": [route.to_dict() for route in self.routes],
            "counts": counts,
            "evidence_id": self.evidence_id,
            "artifact_path": self.artifact_path,
            "quota": dict(self.quota),
            "cleanup_status": self.cleanup_status,
        }


def _permission_boundary(
    manifest: dict[str, Any],
    component: dict[str, Any],
    *,
    read: bool = False,
) -> tuple[str, str | None]:
    if read:
        permission = component.get("read_permission") or component.get("permission")
    else:
        permission = component.get("permission")
    if not isinstance(permission, str) or not permission:
        inherited = manifest.get("application_permission")
        permission = inherited if isinstance(inherited, str) and inherited else None
    if permission is None:
        return "missing", None
    custom = manifest.get("custom_permissions", [])
    if isinstance(custom, list):
        for item in custom:
            if not isinstance(item, dict) or item.get("name") != permission:
                continue
            protection = str(item.get("protection_level") or "").casefold()
            if any(marker in protection for marker in ("signature", "privileged")):
                return "strong", permission
            if protection in {"normal", "dangerous", "unknown", ""}:
                return "weak", permission
    if permission.startswith("android.permission."):
        return "external_unknown", permission
    return "unknown", permission


def _launcher(component: dict[str, Any]) -> bool:
    filters = component.get("intent_filters", [])
    if not isinstance(filters, list):
        return False
    for item in filters:
        if not isinstance(item, dict):
            continue
        actions = item.get("actions", [])
        categories = item.get("categories", [])
        if (
            isinstance(actions, list)
            and "android.intent.action.MAIN" in actions
            and isinstance(categories, list)
            and "android.intent.category.LAUNCHER" in categories
        ):
            return True
    return False


def build_ipc_candidates(manifest: dict[str, Any]) -> tuple[IpcCandidate, ...]:
    """Build deterministic routes from normalized manifest data only."""

    components = manifest.get("components", [])
    if not isinstance(components, list):
        return ()
    candidates: list[IpcCandidate] = []
    for item in components:
        if not isinstance(item, dict) or item.get("effective_exported") is not True:
            continue
        kind = str(item.get("component_type") or "").casefold()
        name = item.get("name")
        if not isinstance(name, str):
            continue
        if kind in {"activity", "activity-alias"}:
            if kind == "activity-alias" or _launcher(item):
                continue
            boundary, permission = _permission_boundary(manifest, item)
            filters = item.get("intent_filters", [])
            candidates.append(
                IpcCandidate(
                    component_type="activity",
                    component=name,
                    permission_boundary=boundary,
                    permission=permission,
                    enabled=item.get("enabled"),
                    intent_filter_count=len(filters) if isinstance(filters, list) else 0,
                )
            )
        elif kind == "receiver":
            boundary, permission = _permission_boundary(manifest, item)
            filters = item.get("intent_filters", [])
            actions: list[str] = []
            if isinstance(filters, list):
                for intent_filter in filters:
                    if not isinstance(intent_filter, dict):
                        continue
                    values = intent_filter.get("actions", [])
                    if isinstance(values, list):
                        actions.extend(
                            value
                            for value in values
                            if isinstance(value, str) and _ACTION_PATTERN.fullmatch(value)
                        )
            unique_actions = tuple(dict.fromkeys(actions))
            if unique_actions:
                for action in unique_actions:
                    candidates.append(
                        IpcCandidate(
                            component_type="receiver",
                            component=name,
                            permission_boundary=boundary,
                            permission=permission,
                            action=action,
                            enabled=item.get("enabled"),
                            intent_filter_count=len(filters) if isinstance(filters, list) else 0,
                        )
                    )
            else:
                candidates.append(
                    IpcCandidate(
                        component_type="receiver",
                        component=name,
                        permission_boundary=boundary,
                        permission=permission,
                        enabled=item.get("enabled"),
                    )
                )
        elif kind == "provider":
            boundary, permission = _permission_boundary(manifest, item, read=True)
            raw_authorities = item.get("authorities")
            authorities = (
                tuple(
                    value.strip()
                    for value in str(raw_authorities).split(";")
                    if _AUTHORITY_PATTERN.fullmatch(value.strip())
                )
                if isinstance(raw_authorities, str)
                else ()
            )
            if authorities:
                for authority in dict.fromkeys(authorities):
                    candidates.append(
                        IpcCandidate(
                            component_type="provider",
                            component=name,
                            permission_boundary=boundary,
                            permission=permission,
                            authority=authority,
                            enabled=item.get("enabled"),
                        )
                    )
            else:
                candidates.append(
                    IpcCandidate(
                        component_type="provider",
                        component=name,
                        permission_boundary=boundary,
                        permission=permission,
                        enabled=item.get("enabled"),
                    )
                )
    return tuple(candidates)


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _marker(value: str, markers: tuple[str, ...]) -> bool:
    lowered = value.casefold()
    return any(item in lowered for item in markers)


def _safe_receiver_action(action: str) -> bool:
    """Allow only actions that declare a bounded probe-like contract."""

    tail = action.rsplit(".", 1)[-1].casefold()
    return any(marker in tail for marker in ("probe", "ping", "query", "test", "check"))


def _pid(value: str) -> int | None:
    match = _PID_PATTERN.search(value)
    return int(match.group(1)) if match else None


def _activity(value: str) -> tuple[str | None, str | None]:
    match = _ACTIVITY_PATTERN.search(value)
    if match is None:
        return None, None
    package, component = match.groups()
    if component.startswith("."):
        component = package + component
    return package, component


def _sensitive_fields(rows: list[str]) -> tuple[str, ...]:
    keys: set[str] = set()
    for row in rows:
        for match in _FIELD_PATTERN.finditer(row):
            key = match.group("key").casefold()
            if any(marker in key for marker in _SENSITIVE_FIELD_MARKERS):
                keys.add(key)
    return tuple(sorted(keys))


class ExportedComponentValidationService:
    """Execute a small, independent IPC budget inside an authorized session."""

    DEFAULT_TOTAL_QUOTA = 12
    DEFAULT_TYPE_QUOTAS = {"activity": 5, "receiver": 3, "provider": 3}
    DEFAULT_TIMEOUT = 8
    MAX_OUTPUT = 64 * 1024

    def __init__(
        self,
        context: AppContext,
        repository: SessionRepository | None = None,
        *,
        total_quota: int = DEFAULT_TOTAL_QUOTA,
        type_quotas: dict[str, int] | None = None,
        timeout_seconds: int = DEFAULT_TIMEOUT,
    ) -> None:
        if not 1 <= total_quota <= 100:
            raise ValueError("IPC total quota must be between 1 and 100.")
        if not 1 <= timeout_seconds <= 60:
            raise ValueError("IPC timeout must be between 1 and 60 seconds.")
        self.context = context
        self.paths = context.paths
        self.repository = repository or SessionRepository(self.paths)
        self.evidence = EvidenceRepository(self.paths, self.repository)
        self.total_quota = total_quota
        self.type_quotas = dict(type_quotas or self.DEFAULT_TYPE_QUOTAS)
        self.timeout_seconds = timeout_seconds

    def _shell(self, adb: Any, serial: str, arguments: tuple[str, ...], *, canary: str) -> Any:
        kwargs = {
            "timeout": self.timeout_seconds,
            "check": False,
            "operation": "running bounded exported-component validation",
            "sensitive_values": (canary,),
        }
        method = getattr(adb, "shell_bounded", None)
        if callable(method):
            return method(
                serial,
                arguments,
                max_stdout_bytes=self.MAX_OUTPUT,
                max_stderr_bytes=16 * 1024,
                **kwargs,
            )
        try:
            return adb.shell(serial, arguments, **kwargs)
        except TypeError:
            kwargs.pop("sensitive_values", None)
            return adb.shell(serial, arguments, **kwargs)

    def _state(
        self,
        adb: Any,
        serial: str,
        package: str,
    ) -> tuple[str | None, str | None, int | None]:
        try:
            current = self._shell(
                adb,
                serial,
                ("dumpsys", "activity", "activities"),
                canary="THESIS_CANARY_00000000T000000Z_000000000000",
            )
            target_package, target_activity = _activity(
                f"{current.stdout}\n{current.stderr}"
            )
            process = self._shell(
                adb,
                serial,
                ("pidof", package),
                canary="THESIS_CANARY_00000000T000000Z_000000000000",
            )
            return target_package, target_activity, _pid(process.stdout)
        except (AndroidAssessorError, OSError, ValueError):
            return None, None, None

    def _observe_canary(
        self,
        adb: Any,
        serial: str,
        package: str,
        canary: str,
        pid: int | None,
    ) -> bool:
        if pid is None:
            return False
        try:
            result = self._shell(
                adb,
                serial,
                ("logcat", "--pid", str(pid), "-d", "-t", "300"),
                canary=canary,
            )
        except (AndroidAssessorError, OSError, ValueError):
            return False
        del package
        return canary in f"{result.stdout}\n{result.stderr}"

    @staticmethod
    def _base_route(candidate: IpcCandidate, canary: str) -> IpcRouteResult:
        return IpcRouteResult(
            candidate=candidate,
            outcome=IpcRouteOutcome.INCONCLUSIVE,
            reason="route was not classified",
            attempted=True,
            canary_fingerprint=_fingerprint(canary),
        )

    def _activity_route(
        self,
        adb: Any,
        record: Any,
        candidate: IpcCandidate,
        canary: str,
    ) -> IpcRouteResult:
        route = self._base_route(candidate, canary)
        before_package, before_activity, _ = self._state(adb, record.serial, record.package)
        try:
            validate_component_name(candidate.component)
            result = adb.start_activity(
                record.serial,
                record.package,
                candidate.component,
                canary=canary,
            )
        except (AndroidAssessorError, OSError, ValueError, AttributeError) as exc:
            route.reason = f"activity dispatch failed: {redact_text(str(exc))[:180]}"
            return route
        output = f"{result.stdout}\n{result.stderr}"
        route.command_completed = not result.timed_out and result.exit_code == 0
        route.command_exit_code = result.exit_code
        route.timed_out = bool(result.timed_out)
        route.output_limited = bool(getattr(result, "output_limit_exceeded", False))
        if route.timed_out:
            route.reason = "activity dispatch timed out; completion is unknown"
            return route
        if route.output_limited:
            route.reason = "activity dispatch output exceeded the bounded limit"
            return route
        if _marker(output, _DENIAL_MARKERS):
            route.outcome = IpcRouteOutcome.REJECTED
            route.reason = "effective activity permission blocked the tested route"
            return route
        if not route.command_completed or _marker(output, _UNKNOWN_COMPONENT_MARKERS):
            route.reason = "activity route was not resolved or did not complete"
            return route
        after_package, after_activity, after_pid = self._state(
            adb, record.serial, record.package
        )
        route.target_package = after_package
        route.target_activity = after_activity
        route.target_pid = after_pid
        if after_package not in {None, record.package}:
            route.outcome = IpcRouteOutcome.OUT_OF_SCOPE
            route.reason = "activity launch moved the foreground window outside target package"
            return route
        canary_observed = self._observe_canary(
            adb, record.serial, record.package, canary, after_pid
        )
        reached = after_package == record.package and after_activity == candidate.component
        if candidate.permission_boundary not in {"missing", "weak"}:
            route.outcome = IpcRouteOutcome.REJECTED
            route.reason = "tested activity has an effective permission boundary"
        elif reached and after_pid is not None and before_activity != candidate.component:
            route.outcome = IpcRouteOutcome.CONFIRMED
            route.observable_impact = True
            route.details = {
                "observable_kind": (
                    "target_pid_canary" if canary_observed else "foreground_transition"
                ),
                "foreground_transition": True,
            }
            route.reason = (
                "external launch reached the target activity and produced a target-PID "
                "foreground transition"
            )
        elif reached:
            route.reason = "command succeeded but no target-PID observable impact was recorded"
        else:
            route.reason = (
                "command succeeded without an exact resumed target activity or "
                "observable impact"
            )
        if after_package == record.package and after_activity == candidate.component:
            try:
                cleanup = self._shell(
                    adb,
                    record.serial,
                    ("input", "keyevent", "KEYCODE_BACK"),
                    canary=canary,
                )
                route.cleanup_status = (
                    "completed" if not cleanup.timed_out and cleanup.exit_code == 0 else "error"
                )
            except (AndroidAssessorError, OSError, ValueError):
                route.cleanup_status = "error"
            if route.cleanup_status != "completed" and route.outcome is IpcRouteOutcome.CONFIRMED:
                route.outcome = IpcRouteOutcome.INCONCLUSIVE
                route.reason = "activity impact observed but cleanup could not be verified"
        return route

    def _receiver_route(
        self,
        adb: Any,
        record: Any,
        candidate: IpcCandidate,
        canary: str,
    ) -> IpcRouteResult:
        route = self._base_route(candidate, canary)
        if candidate.action is None:
            route.attempted = False
            route.outcome = IpcRouteOutcome.NOT_EXERCISED
            route.reason = "receiver has no safe manifest-declared action"
            return route
        if not _safe_receiver_action(candidate.action):
            route.attempted = False
            route.outcome = IpcRouteOutcome.NOT_EXERCISED
            route.reason = (
                "receiver action does not declare a bounded probe-like contract; "
                "mutation was refused"
            )
            return route
        try:
            result = self._shell(
                adb,
                record.serial,
                (
                    "am",
                    "broadcast",
                    "-n",
                    f"{record.package}/{candidate.component}",
                    "-a",
                    candidate.action,
                    "--es",
                    "thesis_canary",
                    canary,
                ),
                canary=canary,
            )
        except (AndroidAssessorError, OSError, ValueError) as exc:
            route.reason = f"receiver dispatch failed: {redact_text(str(exc))[:180]}"
            return route
        output = f"{result.stdout}\n{result.stderr}"
        route.command_completed = not result.timed_out and result.exit_code == 0
        route.command_exit_code = result.exit_code
        route.timed_out = bool(result.timed_out)
        route.output_limited = bool(getattr(result, "output_limit_exceeded", False))
        if route.timed_out:
            route.reason = "receiver dispatch timed out; the action was not replayed"
            return route
        if route.output_limited:
            route.reason = "receiver dispatch output exceeded the bounded limit"
            return route
        if _marker(output, _DENIAL_MARKERS):
            route.outcome = IpcRouteOutcome.REJECTED
            route.reason = "effective receiver permission blocked the tested route"
            return route
        if not route.command_completed or "broadcast completed" not in output.casefold():
            route.reason = "broadcast did not complete"
            return route
        _, _, pid = self._state(adb, record.serial, record.package)
        route.target_pid = pid
        observed = self._observe_canary(adb, record.serial, record.package, canary, pid)
        if candidate.permission_boundary not in {"missing", "weak"}:
            route.outcome = IpcRouteOutcome.REJECTED
            route.reason = "tested receiver has an effective permission boundary"
        elif observed:
            route.outcome = IpcRouteOutcome.CONFIRMED
            route.observable_impact = True
            route.reason = "broadcast reached target process and emitted target-PID canary evidence"
        else:
            route.reason = "broadcast completed without target-attributed observable impact"
        return route

    def _provider_route(
        self,
        adb: Any,
        record: Any,
        candidate: IpcCandidate,
        canary: str,
    ) -> IpcRouteResult:
        route = self._base_route(candidate, canary)
        if candidate.authority is None:
            route.attempted = False
            route.outcome = IpcRouteOutcome.NOT_EXERCISED
            route.reason = "provider has no manifest-declared authority"
            return route
        identity = self._shell(
            adb,
            record.serial,
            ("id", "-u"),
            canary=canary,
        )
        prefix: tuple[str, ...] = ()
        if identity.timed_out or identity.exit_code != 0:
            route.reason = "external caller identity could not be established"
            return route
        uid = _pid(identity.stdout)
        if uid != 2000:
            su_identity = self._shell(
                adb,
                record.serial,
                ("su", "2000", "id", "-u"),
                canary=canary,
            )
            if (
                su_identity.timed_out
                or su_identity.exit_code != 0
                or _pid(su_identity.stdout) != 2000
            ):
                route.reason = "provider route was not exercised as an unprivileged external caller"
                return route
            prefix = ("su", "2000")
        uri = f"content://{candidate.authority}/"
        try:
            result = self._shell(
                adb,
                record.serial,
                (*prefix, "content", "query", "--uri", uri),
                canary=canary,
            )
        except (AndroidAssessorError, OSError, ValueError) as exc:
            route.reason = f"provider query failed: {redact_text(str(exc))[:180]}"
            return route
        output = f"{result.stdout}\n{result.stderr}"
        route.command_completed = not result.timed_out and result.exit_code == 0
        route.command_exit_code = result.exit_code
        route.timed_out = bool(result.timed_out)
        route.output_limited = bool(getattr(result, "output_limit_exceeded", False))
        if route.timed_out:
            route.reason = "provider query timed out"
            return route
        if route.output_limited:
            route.reason = "provider query output exceeded the bounded limit"
            return route
        if _marker(output, _DENIAL_MARKERS):
            route.outcome = IpcRouteOutcome.REJECTED
            route.reason = "provider permission blocked the tested authority route"
            return route
        if _marker(output, _UNKNOWN_URI_MARKERS):
            route.reason = "manifest authority was not queryable at the bounded root URI"
            return route
        rows = _ROW_PATTERN.findall(output)
        if not rows and "no result found" in output.casefold():
            route.outcome = IpcRouteOutcome.REJECTED
            route.reason = "bounded authority query returned zero rows"
            route.details = {"uri": uri, "row_count": 0}
            return route
        sensitive_fields = _sensitive_fields(list(rows))
        canary_match = canary in output
        route.details = {
            "uri": uri,
            "row_count": len(rows),
            "sensitive_field_categories": list(sensitive_fields),
            "canary_match": canary_match,
        }
        if rows and candidate.permission_boundary in {"missing", "weak"} and (
            sensitive_fields or canary_match
        ):
            route.outcome = IpcRouteOutcome.CONFIRMED
            route.observable_impact = True
            route.reason = (
                "external query returned sensitive provider data/metadata on an "
                "unprotected route"
            )
        elif rows:
            route.reason = "provider returned rows without evidence that the data should be public"
        else:
            route.reason = "provider response did not expose a classified row or metadata result"
        return route

    def run(
        self,
        session_id: str,
        *,
        adb: Any,
        scope: ScopeConfig,
    ) -> IpcValidationResult:
        record = self.repository.load(session_id)
        app = read_json_object(
            self.repository.paths_for(session_id).app_json,
            root=self.paths.root,
        )
        manifest = app.get("manifest")
        manifest = manifest if isinstance(manifest, dict) else {}
        candidates = build_ipc_candidates(manifest)
        routes: list[IpcRouteResult] = []
        artifact_path = (
            self.repository.paths_for(session_id).redacted_dir
            / "ipc"
            / "exported-components.json"
        )
        try:
            scope.require_device_package(
                record.serial,
                record.package,
                action="controlled_validation",
            )
        except ScopeError as exc:
            for candidate in candidates:
                routes.append(
                    IpcRouteResult(
                        candidate=candidate,
                        outcome=IpcRouteOutcome.OUT_OF_SCOPE,
                        reason="IPC validation denied by session scope",
                        attempted=False,
                    )
                )
            payload = {
                "schema_version": 1,
                "session_id": session_id,
                "package": record.package,
                "routes": [item.to_dict() for item in routes],
                "limitation": redact_text(str(exc))[:300],
            }
            write_json_atomic(artifact_path, payload, root=self.paths.root)
            evidence = self.evidence.register_file(
                session_id,
                artifact_path,
                evidence_type="ipc_component_validation",
                source="scope_gate",
                description="Redacted exported-component IPC validation result.",
                sensitive=True,
                redacted=True,
            )
            for route in routes:
                route.evidence_id = evidence.evidence_id
            return IpcValidationResult(
                session_id=session_id,
                package=record.package,
                routes=tuple(routes),
                evidence_id=evidence.evidence_id,
                artifact_path=artifact_path.relative_to(self.repository.paths_for(session_id).root).as_posix(),
                quota={"total": 0, "used": 0, "remaining": self.total_quota},
                cleanup_status="not_required",
            )

        used_total = 0
        used_by_type = {key: 0 for key in self.type_quotas}
        started = time.monotonic()
        for candidate in candidates:
            if used_total >= self.total_quota:
                routes.append(
                    IpcRouteResult(
                        candidate=candidate,
                        outcome=IpcRouteOutcome.NOT_EXERCISED,
                        reason="IPC route quota exhausted before dispatch",
                        attempted=False,
                    )
                )
                continue
            if used_by_type.get(candidate.component_type, 0) >= self.type_quotas.get(
                candidate.component_type, 0
            ):
                routes.append(
                    IpcRouteResult(
                        candidate=candidate,
                        outcome=IpcRouteOutcome.NOT_EXERCISED,
                        reason=f"{candidate.component_type} IPC quota exhausted before dispatch",
                        attempted=False,
                    )
                )
                continue
            if time.monotonic() - started >= self.timeout_seconds * 4:
                routes.append(
                    IpcRouteResult(
                        candidate=candidate,
                        outcome=IpcRouteOutcome.NOT_EXERCISED,
                        reason="IPC validation deadline exhausted before dispatch",
                        attempted=False,
                    )
                )
                continue
            canary = generate_session_canary()
            used_total += 1
            used_by_type[candidate.component_type] = (
                used_by_type.get(candidate.component_type, 0) + 1
            )
            if candidate.enabled is False:
                routes.append(
                    IpcRouteResult(
                        candidate=candidate,
                        outcome=IpcRouteOutcome.NOT_EXERCISED,
                        reason="component is disabled in normalized manifest",
                        attempted=False,
                        canary_fingerprint=_fingerprint(canary),
                    )
                )
                continue
            try:
                if candidate.component_type == "activity":
                    route = self._activity_route(adb, record, candidate, canary)
                elif candidate.component_type == "receiver":
                    route = self._receiver_route(adb, record, candidate, canary)
                else:
                    route = self._provider_route(adb, record, candidate, canary)
            except (AndroidAssessorError, OSError, ValueError) as exc:
                route = self._base_route(candidate, canary)
                route.reason = f"bounded IPC validation failed: {redact_text(str(exc))[:180]}"
            routes.append(route)

        payload = {
            "schema_version": 1,
            "session_id": session_id,
            "package": record.package,
            "generated_at": datetime.now(UTC).isoformat(),
            "routes": [item.to_dict() for item in routes],
            "quota": {
                "total": self.total_quota,
                "used": used_total,
                "remaining": max(0, self.total_quota - used_total),
                "by_type": dict(used_by_type),
            },
            "cleanup_status": "completed",
        }
        write_json_atomic(artifact_path, payload, root=self.paths.root)
        evidence = self.evidence.register_file(
            session_id,
            artifact_path,
            evidence_type="ipc_component_validation",
            source="adb_ipc",
            description="Redacted exported-component IPC validation result.",
            sensitive=True,
            redacted=True,
        )
        for route in routes:
            route.evidence_id = evidence.evidence_id
        return IpcValidationResult(
            session_id=session_id,
            package=record.package,
            routes=tuple(routes),
            evidence_id=evidence.evidence_id,
            artifact_path=artifact_path.relative_to(self.repository.paths_for(session_id).root).as_posix(),
            quota={
                "total": self.total_quota,
                "used": used_total,
                "remaining": max(0, self.total_quota - used_total),
            },
            cleanup_status="completed",
        )
