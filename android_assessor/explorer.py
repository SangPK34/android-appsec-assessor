"""Bounded, package-scoped Android UI exploration using existing ADB primitives."""

from __future__ import annotations

import hashlib
import heapq
import json
import random
import re
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol
from urllib.parse import quote, urlencode, urlunsplit
from xml.etree import ElementTree

from .adb import AdbClient
from .errors import AdbError, AdbTimeoutError, AndroidAssessorError
from .evidence import EvidenceRepository
from .redaction import redact_text
from .scope import ScopeConfig
from .session import SessionRepository
from .storage import read_json_object, write_json_atomic, write_text_atomic
from .validation import (
    validate_component_name,
    validate_managed_remote_path,
    validate_package_name,
    validate_session_canary,
    validate_session_id,
)

_BOUNDS_PATTERN = re.compile(r"^\[(\d+),(\d+)]\[(\d+),(\d+)]$")
_ACTIVITY_PATTERNS = (
    re.compile(r"mResumedActivity:.*?\s([A-Za-z0-9_.]+)/(\.?[A-Za-z0-9_.$]+)"),
    re.compile(r"topResumedActivity=.*?\s([A-Za-z0-9_.]+)/(\.?[A-Za-z0-9_.$]+)"),
)
_VOLATILE_PATTERN = re.compile(r"(?:ASL|THESIS)_\S+|\b\d{2,}\b", re.IGNORECASE)
_SAFE_TEXT_PATTERN = re.compile(r"^[A-Za-z0-9@._:/+\-=$%,!#^~?]{1,160}$")
_SHELL_EXPANSION_PATTERN = re.compile(r"\$(?:[A-Za-z_{(])")
_DANGEROUS_LABELS = (
    "delete",
    "remove",
    "purchase",
    "pay",
    "transfer",
    "send money",
    "factory reset",
    "uninstall",
    "logout all",
    "submit order",
    "register",
    "sign up",
    "create account",
    "change password",
    "reset password",
    "update password",
    "deposit",
    "withdraw",
    "send sms",
    "text message",
    "place call",
    "call",
    "dial",
)
_CONTROLLED_CANARY_ACTIONS = (
    "login",
    "sign in",
    "authenticate",
    "connect",
    "request",
    "search",
    "lookup",
    "check",
)
_DENY_PERMISSION_LABELS = ("deny", "don't allow", "cancel", "no thanks", "not now")
_ALLOW_PERMISSION_LABELS = ("allow", "while using", "only this time")
_REVIEW_CONTINUE_LABELS = ("continue", "next", "done", "finish")
_REVIEW_CONTINUE_RESOURCE_MARKERS = (
    "continue_button",
    "next_button",
    "done_button",
    "finish_button",
)
_SYSTEM_ACK_LABELS = ("ok", "got it", "continue")
_SYSTEM_ACK_RESOURCE_MARKERS = ("android:id/button1", "android:id/ok")
_PERMISSION_CONTROLLER_PACKAGES = frozenset(
    {
        "com.android.packageinstaller",
        "com.android.permissioncontroller",
        "com.google.android.permissioncontroller",
    }
)
_SYSTEM_DIALOG_PACKAGES = frozenset({"android", "com.android.systemui"})
_REVIEW_ACTIVITY_MARKER = "reviewpermissionsactivity"
_LEGACY_ACK_ACTIVITY_MARKERS = ("deprecatedtargetsdkversiondialog",)
_UIAUTOMATION_TRANSIENT_ERRORS = ("already registered",)
_KEYWORD_CATEGORIES = {
    "crypto": (
        "encrypt",
        "decrypt",
        "crypto",
        "cipher",
        "hash",
        "digest",
        "random",
        "md5",
        "sha",
        "aes",
    ),
    "webview": ("web", "url", "browser", "html"),
    "storage": ("save", "database", "sqlite", "preference", "storage", "file"),
    "logging": ("login", "sign in", "token", "log", "username", "password"),
    "root_detection": ("root", "superuser", "magisk", "su "),
    "network": (
        "network",
        "http",
        "tls",
        "ssl",
        "certificate",
        "connect",
        "request",
    ),
}


class _ExplorerDeadlineReached(Exception):
    pass


class _ExplorerPackageBoundary(AndroidAssessorError):
    """The scoped application is no longer the resumed package."""

    def __init__(self, package: str | None, activity: str | None) -> None:
        self.package = package
        self.activity = activity
        observed = "/".join(part for part in (package, activity) if part) or "unknown"
        super().__init__(
            "Explorer left the scoped package boundary "
            f"(observed {observed})."
        )


@dataclass(frozen=True, slots=True)
class ExplorerConfig:
    max_runtime_seconds: int = 45
    plateau_seconds: int = 8
    max_states: int = 40
    max_actions: int = 100
    max_depth: int = 8
    per_action_timeout_seconds: int = 3
    max_observation_retries: int = 1
    max_action_failures: int = 3
    seed: int = 1337
    monkey_events: int = 0
    controlled_canary_delivery: bool = False

    def __post_init__(self) -> None:
        bounds = {
            "max_runtime_seconds": (self.max_runtime_seconds, 1, 300),
            "plateau_seconds": (self.plateau_seconds, 1, 60),
            "max_states": (self.max_states, 1, 200),
            "max_actions": (self.max_actions, 1, 1000),
            "max_depth": (self.max_depth, 1, 30),
            "per_action_timeout_seconds": (self.per_action_timeout_seconds, 1, 30),
            "max_observation_retries": (self.max_observation_retries, 0, 3),
            "max_action_failures": (self.max_action_failures, 1, 20),
            "monkey_events": (self.monkey_events, 0, 50),
        }
        for name, (value, minimum, maximum) in bounds.items():
            if isinstance(value, bool) or not minimum <= value <= maximum:
                raise ValueError(f"{name} must be between {minimum} and {maximum}.")
        if not isinstance(self.controlled_canary_delivery, bool):
            raise ValueError("controlled_canary_delivery must be a boolean.")


@dataclass(frozen=True, slots=True)
class UiNode:
    class_name: str
    package: str
    resource_id: str
    text: str
    content_description: str
    hint: str
    bounds: tuple[int, int, int, int]
    clickable: bool
    long_clickable: bool
    editable: bool
    scrollable: bool
    password: bool
    input_type: str
    enabled: bool = True
    visible: bool = True
    checked: bool = False

    @property
    def label(self) -> str:
        return " ".join(
            value
            for value in (self.text, self.content_description, self.hint, self.resource_id)
            if value
        ).strip()

    @property
    def center(self) -> tuple[int, int]:
        left, top, right, bottom = self.bounds
        return ((left + right) // 2, (top + bottom) // 2)


@dataclass(frozen=True, slots=True)
class UiState:
    package: str
    activity: str
    fingerprint: str
    nodes: tuple[UiNode, ...]


@dataclass(order=True, frozen=True, slots=True)
class ExplorerAction:
    sort_key: tuple[int, float, str]
    kind: str = field(compare=False)
    identity: str = field(compare=False)
    x: int | None = field(default=None, compare=False)
    y: int | None = field(default=None, compare=False)
    label: str = field(default="", compare=False)
    input_kind: str | None = field(default=None, compare=False)
    resource_id: str = field(default="", compare=False)


@dataclass(frozen=True, slots=True)
class RuntimeFeedback:
    categories: frozenset[str] = frozenset()
    methods: frozenset[str] = frozenset()
    traffic_hosts: frozenset[str] = frozenset()
    event_count: int = 0


@dataclass(frozen=True, slots=True)
class ExplorerResult:
    session_id: str
    status: str
    termination_reason: str
    duration_ms: float
    states_visited: int
    activities_visited: tuple[str, ...]
    actions_executed: int
    input_actions: int
    scroll_actions: int
    backtracks: int
    process_restarts: int
    crashes: int
    runtime_categories: tuple[str, ...]
    runtime_methods: int
    runtime_events: int
    activity_attempts: tuple[dict[str, Any], ...]
    deep_link_attempts: tuple[dict[str, Any], ...]
    actions_attempted: int = 0
    actions_succeeded: int = 0
    form_retries: int = 0
    duplicate_actions_avoided: int = 0
    safety_skips: int = 0
    adb_command_count: int = 0
    ui_dump_count: int = 0
    adb_operation_ms: float = 0.0
    idle_ms: float = 0.0
    exploring_ms: float = 0.0
    runtime_wait_ms: float = 0.0
    controlled_canary_inputs: int = 0
    controlled_canary_deliveries: int = 0
    actions_failed: int = 0
    observation_retries: int = 0
    state_refreshes: int = 0
    controlled_canary_attempts: int = 0
    controlled_canary_failures: int = 0
    controlled_canary_budget_skips: int = 0
    cleanup_status: str = "completed"
    cleanup_failure_reason: str | None = None
    trace_path: str | None = None
    summary_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["activities_visited"] = list(self.activities_visited)
        value["runtime_categories"] = list(self.runtime_categories)
        value["activity_attempts"] = list(self.activity_attempts)
        value["deep_link_attempts"] = list(self.deep_link_attempts)
        return value


class ExplorerBackend(Protocol):
    def set_runtime_budget(self, seconds: int) -> None: ...
    def launch(self) -> None: ...
    def dump_ui(self) -> str: ...
    def current_activity(self) -> tuple[str | None, str | None]: ...
    def process_id(self) -> int | None: ...
    def tap(self, x: int, y: int, *, long: bool = False) -> None: ...
    def input_text(self, x: int, y: int, value: str) -> None: ...
    def swipe(self, x1: int, y1: int, x2: int, y2: int) -> None: ...
    def back(self) -> None: ...
    def start_activity(self, component: str) -> str: ...
    def start_deep_link(self, uri: str) -> str: ...
    def monkey(self, event_count: int, seed: int) -> None: ...
    def dismiss_external_dialog(self) -> bool: ...
    def hide_keyboard(self) -> None: ...
    def cleanup(self) -> None: ...
    def performance_metrics(self) -> Mapping[str, int | float]: ...


def _truth(value: str | None) -> bool:
    return str(value).casefold() == "true"


def _normalize_label(value: str) -> str:
    normalized = " ".join(value.split()).casefold()
    return _VOLATILE_PATTERN.sub("<value>", normalized)[:160]


def _identifier_tokens(value: str) -> tuple[str, ...]:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value)
    return tuple(token for token in re.split(r"[^a-zA-Z0-9]+", value.casefold()) if token)


def _is_input_placeholder(
    text: str,
    *,
    resource_id: str,
    hint: str,
    content_description: str,
) -> bool:
    """Recognize UIAutomator's hint-as-text representation for empty fields.

    UIAutomator commonly exposes an empty EditText's hint through its ``text``
    attribute (for example ``text="Username"``).  Treating that value as
    entered data suppresses safe generated input and prevents generic form
    exploration.  Only generic labels or values echoed by a node's own
    metadata are considered placeholders; arbitrary prefilled values remain
    untouched.
    """
    normalized = _normalize_label(text)
    if not normalized:
        return False
    metadata = {
        _normalize_label(value)
        for value in (resource_id, hint, content_description)
        if value
    }
    if normalized in metadata:
        return True
    prompt_tokens = list(_identifier_tokens(text))
    while prompt_tokens and prompt_tokens[0] in {"enter", "input", "please", "type", "your"}:
        prompt_tokens.pop(0)
    resource_tokens = list(
        _identifier_tokens(resource_id.rsplit("/", 1)[-1].rsplit(":", 1)[-1])
    )
    while resource_tokens and resource_tokens[-1] in {
        "edit",
        "edittext",
        "field",
        "input",
        "text",
        "view",
    }:
        resource_tokens.pop()
    if prompt_tokens and resource_tokens[-len(prompt_tokens) :] == prompt_tokens:
        return True
    compact_prompt = "".join(prompt_tokens)
    return len(prompt_tokens) > 1 and any(
        compact_prompt == token for token in resource_tokens
    )


def _is_transient_ui_automation_error(error: BaseException) -> bool:
    message = str(error).casefold()
    return any(marker in message for marker in _UIAUTOMATION_TRANSIENT_ERRORS)


def _failure_reason(error: BaseException) -> str:
    """Return a stable redacted failure class for traces and reports."""
    if isinstance(error, AdbTimeoutError):
        return "adb_timeout"
    if isinstance(error, AdbError):
        return "adb_error"
    if isinstance(error, OSError):
        return "os_error"
    return "invalid_observation"


def _trace_label(value: str) -> str:
    """Retain only generic semantics, never arbitrary UI text, in redacted evidence."""
    normalized = _normalize_label(redact_text(value))
    semantics = sorted(_semantic_categories(normalized))
    navigation = [
        term for term in ("more options", "menu", "navigation") if term in normalized
    ]
    dangerous = [
        term
        for term in _DANGEROUS_LABELS
        if re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", normalized)
    ]
    values = semantics + navigation + [f"blocked:{term}" for term in dangerous]
    return ",".join(dict.fromkeys(values)) or "<ui-control>"


def _parse_bounds(value: str) -> tuple[int, int, int, int] | None:
    match = _BOUNDS_PATTERN.fullmatch(value)
    if match is None:
        return None
    bounds = tuple(int(item) for item in match.groups())
    left, top, right, bottom = bounds
    if right <= left or bottom <= top:
        return None
    return left, top, right, bottom


def parse_ui_hierarchy(
    xml: str,
    *,
    expected_package: str,
    activity: str,
) -> UiState:
    """Parse a bounded UIAutomator hierarchy without retaining entered values."""
    if len(xml.encode("utf-8", errors="ignore")) > 2_000_000:
        raise ValueError("UI hierarchy exceeds the 2 MB analysis bound.")
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError as exc:
        raise ValueError("UIAutomator returned malformed XML.") from exc
    nodes: list[UiNode] = []
    normalized: list[tuple[Any, ...]] = []
    parent_by_child = {child: parent for parent in root.iter() for child in list(parent)}
    for element in list(root.iter("node"))[:1000]:
        attributes = element.attrib
        bounds = _parse_bounds(attributes.get("bounds", ""))
        if bounds is None:
            continue
        package = attributes.get("package", "")
        if package != expected_package:
            continue
        class_name = attributes.get("class", "")
        resource_id = attributes.get("resource-id", "")
        password = _truth(attributes.get("password"))
        editable = class_name.endswith("EditText") or (
            _truth(attributes.get("focusable"))
            and any(
                word in (resource_id + attributes.get("hint", "")).casefold()
                for word in ("input", "edit", "username", "password", "email", "url")
            )
        )
        raw_text = attributes.get("text", "")
        placeholder = editable and _is_input_placeholder(
            raw_text,
            resource_id=resource_id,
            hint=attributes.get("hint", ""),
            content_description=attributes.get("content-desc", ""),
        )
        inferred_hint = attributes.get("hint", "")
        if placeholder and not inferred_hint:
            inferred_hint = raw_text
        if password:
            text = "" if placeholder or not raw_text else "<password>"
        else:
            text = "" if placeholder else raw_text
        ancestor = parent_by_child.get(element)
        in_selectable_collection = False
        while ancestor is not None:
            ancestor_class = ancestor.attrib.get("class", "")
            if ancestor_class.endswith(("ListView", "RecyclerView", "GridView")):
                in_selectable_collection = True
                break
            ancestor = parent_by_child.get(ancestor)
        inferred_collection_click = bool(
            in_selectable_collection
            and class_name.endswith("TextView")
            and (attributes.get("text") or attributes.get("content-desc"))
        )
        node = UiNode(
            class_name=class_name,
            package=package,
            resource_id=resource_id,
            text=text,
            content_description=attributes.get("content-desc", ""),
            hint=inferred_hint,
            bounds=bounds,
            clickable=_truth(attributes.get("clickable")) or inferred_collection_click,
            long_clickable=_truth(attributes.get("long-clickable")),
            editable=editable,
            scrollable=_truth(attributes.get("scrollable")),
            password=password,
            input_type=attributes.get("input-type", ""),
            enabled=str(attributes.get("enabled", "true")).casefold() != "false",
            visible=str(attributes.get("visible-to-user", "true")).casefold() != "false",
            checked=_truth(attributes.get("checked")),
        )
        nodes.append(node)
        normalized.append(
            (
                class_name,
                resource_id,
                "<input>" if editable else _normalize_label(text),
                _normalize_label(node.content_description),
                bounds,
                node.clickable,
                node.scrollable,
                node.enabled,
                node.visible,
                node.checked,
            )
        )
    digest = hashlib.sha256(
        json.dumps(
            [expected_package, activity, sorted(normalized, key=repr)],
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return UiState(expected_package, activity, digest, tuple(nodes))


def is_safe_action_label(label: str) -> bool:
    normalized = _normalize_label(label)
    return not any(
        re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", normalized)
        for term in _DANGEROUS_LABELS
    )


def classify_input(node: UiNode, *, allow_local_url: bool) -> tuple[str, str]:
    label = node.label.casefold()
    input_type = node.input_type.casefold()
    if node.password or "password" in label:
        return "password", "123456"
    if "email" in label or "textemailaddress" in input_type:
        return "email", "user@example.test"
    if any(value in label or value in input_type for value in ("number", "phone", "pin", "otp")):
        return "number", "123456"
    if any(value in label or value in input_type for value in ("url", "uri", "host", "web")):
        return ("url", "https://10.0.2.2/") if allow_local_url else ("text", "test")
    if any(value in label for value in ("user", "login", "account")):
        return "username", "user@example.test"
    if any(value in label for value in ("token", "canary", "log")):
        return "canary", "ASL_SESSION_CANARY"
    return "text", "test"


def is_input_candidate(node: UiNode) -> bool:
    """Avoid overwriting obvious result/output widgets exposed as editable views."""
    if (
        not node.editable
        or not node.enabled
        or not node.visible
        or bool(node.text.strip())
    ):
        return False
    marker = " ".join((node.resource_id, node.label)).casefold()
    return not any(
        token in marker
        for token in (
            "result",
            "output",
            "digest",
            "hash_result",
            "ciphertext_result",
            "response",
            "status",
        )
    )


def _action_priority(label: str, feedback: RuntimeFeedback) -> int:
    normalized = _normalize_label(label)
    score = 50
    for category, words in _KEYWORD_CATEGORIES.items():
        if category not in feedback.categories and any(word in normalized for word in words):
            score += 100
    if any(word in normalized for word in ("more options", "menu", "navigation")):
        score += 60
    if any(word in normalized for word in ("sign in", "login", "submit", "run", "start")):
        score += 15
    return score


def _semantic_categories(label: str) -> set[str]:
    normalized = _normalize_label(label)
    return {
        category
        for category, words in _KEYWORD_CATEGORIES.items()
        if any(word in normalized for word in words)
    }


def _could_trigger_network(label: str) -> bool:
    normalized = _normalize_label(label)
    return bool(
        _semantic_categories(normalized) & {"network", "webview"}
        or any(
            word in normalized
            for word in ("login", "sign in", "submit", "connect", "request")
        )
    )


def _is_controlled_canary_action(label: str) -> bool:
    normalized = _normalize_label(label)
    return any(term in normalized for term in _CONTROLLED_CANARY_ACTIONS)


def _node_identity(node: UiNode, activity: str) -> str:
    label = " ".join((node.content_description, node.hint)).strip() if node.editable else node.label
    geometry = "" if node.editable and node.resource_id else str(node.bounds)
    activity_key = "" if node.editable and node.resource_id else activity
    source = (
        f"{activity_key}|{node.class_name}|{node.resource_id}|{_normalize_label(label)}|{geometry}"
    )
    return hashlib.sha256(source.encode()).hexdigest()[:20]


def build_actions(
    state: UiState,
    *,
    feedback: RuntimeFeedback,
    allow_local_url: bool,
    network_guard_active: bool = False,
    controlled_canary_delivery: bool = False,
    rng: random.Random,
    skipped: list[dict[str, str]] | None = None,
) -> list[ExplorerAction]:
    actions: list[ExplorerAction] = []
    for node in state.nodes:
        if node.package and node.package != state.package:
            continue
        x, y = node.center
        label = node.label
        identity = _node_identity(node, state.activity)
        jitter = rng.random()
        if node.editable and node.enabled and node.visible and node.text.strip():
            if skipped is not None:
                skipped.append(
                    {
                        "reason": "preexisting_input_preserved",
                        "label": _trace_label(label),
                        "resource_id": node.resource_id,
                    }
                )
        if is_input_candidate(node):
            input_kind, _ = classify_input(node, allow_local_url=allow_local_url)
            # Keep credential/form fields eligible even when an earlier
            # runtime event already populated the same semantic category.
            # Otherwise a generic resource id such as ``login_username``
            # overlaps the logging category and prevents safe input generation.
            category_overlap = _semantic_categories(label) & feedback.categories
            if not category_overlap or input_kind in {
                "username",
                "password",
                "email",
                "number",
                "url",
                "canary",
            }:
                heapq.heappush(
                    actions,
                    ExplorerAction(
                        (-80, jitter, identity),
                        "input",
                        identity,
                        x,
                        y,
                        label,
                        input_kind,
                        node.resource_id,
                    ),
                )
        if node.clickable and not node.editable and not node.enabled:
            if skipped is not None:
                skipped.append(
                    {
                        "reason": "disabled_control",
                        "label": _trace_label(label),
                        "resource_id": node.resource_id,
                    }
                )
        elif node.clickable and not node.editable and not node.visible:
            if skipped is not None:
                skipped.append(
                    {
                        "reason": "hidden_control",
                        "label": _trace_label(label),
                        "resource_id": node.resource_id,
                    }
                )
        elif node.clickable and not node.editable and not is_safe_action_label(label):
            if skipped is not None:
                skipped.append(
                    {
                        "reason": "safety_denylist",
                        "label": _trace_label(label),
                        "resource_id": node.resource_id,
                    }
                )
        elif (
            node.clickable
            and not node.editable
            and _could_trigger_network(label)
            and not network_guard_active
        ):
            if skipped is not None:
                skipped.append(
                    {
                        "reason": "network_guard_required",
                        "label": _trace_label(label),
                        "resource_id": node.resource_id,
                    }
                )
        elif node.clickable and not node.editable:
            priority = _action_priority(label, feedback)
            if controlled_canary_delivery and _is_controlled_canary_action(label):
                priority += 200
            heapq.heappush(
                actions,
                ExplorerAction(
                    (-priority, jitter, identity),
                    "tap",
                    identity,
                    x,
                    y,
                    label,
                    resource_id=node.resource_id,
                ),
            )
        if (
            node.long_clickable
            and not node.editable
            and node.enabled
            and node.visible
            and is_safe_action_label(label)
        ):
            heapq.heappush(
                actions,
                ExplorerAction(
                    (-20, jitter, "long-" + identity),
                    "long_tap",
                    "long-" + identity,
                    x,
                    y,
                    label,
                    resource_id=node.resource_id,
                ),
            )
    return actions


class AdbExplorerBackend:
    """Production explorer backend restricted to one validated package and temp root."""

    def __init__(
        self,
        adb: AdbClient,
        *,
        serial: str,
        package: str,
        session_id: str,
        per_action_timeout: int,
    ) -> None:
        self.adb = adb
        self.serial = serial
        self.package = validate_package_name(package)
        safe_session = validate_session_id(session_id)
        self.remote_dir = validate_managed_remote_path(
            f"/data/local/tmp/android-security-lab/{safe_session}/explorer"
        )
        self.remote_xml = validate_managed_remote_path(f"{self.remote_dir}/window.xml")
        self.timeout = per_action_timeout
        self._adb_command_count = 0
        self._ui_dump_count = 0
        self._adb_operation_ms = 0.0
        self._deadline: float | None = None
        self._logical_deadlines: list[float] = []
        self._monotonic = time.monotonic
        self._workspace_ready = False
        self._cleanup_failure_reason: str | None = None

    def set_runtime_budget(self, seconds: int) -> None:
        self._deadline = self._monotonic() + seconds

    @contextmanager
    def logical_operation(self, timeout_seconds: float) -> Iterator[None]:
        """Share one deadline across every ADB command in a logical operation."""
        self._logical_deadlines.append(self._monotonic() + timeout_seconds)
        try:
            yield
        finally:
            self._logical_deadlines.pop()

    def _bounded_timeout(self, requested: int | float) -> float:
        now = self._monotonic()
        remaining_values = [float(requested)]
        if self._deadline is not None:
            runtime_remaining = self._deadline - now
            if runtime_remaining <= 0:
                raise _ExplorerDeadlineReached
            remaining_values.append(runtime_remaining)
        if self._logical_deadlines:
            logical_remaining = min(self._logical_deadlines) - now
            if logical_remaining <= 0:
                raise AdbTimeoutError(
                    "Explorer logical operation exceeded its bounded timeout."
                )
            remaining_values.append(logical_remaining)
        return min(remaining_values)

    def _record_adb_start(self) -> float:
        self._adb_command_count += 1
        return self._monotonic()

    def _record_adb_end(self, started: float) -> None:
        self._adb_operation_ms += (self._monotonic() - started) * 1000

    def _shell(
        self,
        arguments: Sequence[str],
        operation: str,
        *,
        timeout: int | float | None = None,
        sensitive_values: Sequence[str] = (),
    ) -> str:
        started = self._record_adb_start()
        try:
            result = self.adb.shell(
                self.serial,
                tuple(arguments),
                timeout=self._bounded_timeout(timeout or self.timeout),
                check=True,
                operation=operation,
                sensitive_values=sensitive_values,
            )
        finally:
            self._record_adb_end(started)
        return result.stdout

    def launch(self) -> None:
        self._shell(
            (
                "monkey",
                "-p",
                self.package,
                "-c",
                "android.intent.category.LAUNCHER",
                "1",
            ),
            "launching the scoped application",
        )

    def dump_ui(self) -> str:
        with self.logical_operation(self.timeout):
            return self._dump_ui_bounded()

    def _dump_ui_bounded(self) -> str:
        self._ui_dump_count += 1
        if not self._workspace_ready:
            self._shell(("mkdir", "-p", "--", self.remote_dir), "creating explorer workspace")
            self._workspace_ready = True
        for attempt in range(2):
            try:
                self._shell(
                    ("uiautomator", "dump", "--compressed", self.remote_xml),
                    "capturing bounded UI hierarchy",
                    timeout=self.timeout,
                )
                return self._shell(
                    ("cat", "--", self.remote_xml),
                    "reading UI hierarchy",
                    timeout=self.timeout,
                )
            except AdbError as exc:
                if attempt or not _is_transient_ui_automation_error(exc):
                    raise
                time.sleep(0.05)
        raise AdbError("UI hierarchy capture failed after transient retry.")

    def current_activity(self) -> tuple[str | None, str | None]:
        output = self._shell(
            ("dumpsys", "activity", "activities"),
            "reading the resumed Android activity",
            timeout=self.timeout,
        )
        for pattern in _ACTIVITY_PATTERNS:
            if match := pattern.search(output):
                package, activity = match.groups()
                if activity.startswith("."):
                    activity = package + activity
                return package, activity
        return None, None

    def process_id(self) -> int | None:
        started = self._record_adb_start()
        try:
            result = self.adb.shell(
                self.serial,
                ("pidof", self.package),
                timeout=self._bounded_timeout(self.timeout),
                check=False,
                operation="checking explorer target process",
            )
        finally:
            self._record_adb_end(started)
        if result.timed_out:
            raise AdbTimeoutError("ADB timed out while checking explorer target process.")
        if result.exit_code not in {0, 1}:
            raise AdbError("ADB failed while checking explorer target process.")
        return next((int(item) for item in result.stdout.split() if item.isdecimal()), None)

    def tap(self, x: int, y: int, *, long: bool = False) -> None:
        if long:
            self._shell(
                ("input", "swipe", str(x), str(y), str(x), str(y), "700"),
                "long-clicking UI control",
            )
        else:
            self._shell(("input", "tap", str(x), str(y)), "clicking UI control")

    def input_text(self, x: int, y: int, value: str) -> None:
        if not _SAFE_TEXT_PATTERN.fullmatch(value) or _SHELL_EXPANSION_PATTERN.search(value):
            raise AdbError("Generated explorer input contains unsupported characters.")
        with self.logical_operation(self.timeout):
            self.tap(x, y)
            self._shell(
                ("input", "text", value),
                "entering generated lab input",
                sensitive_values=(value,),
            )

    def swipe(self, x1: int, y1: int, x2: int, y2: int) -> None:
        self._shell(
            ("input", "swipe", str(x1), str(y1), str(x2), str(y2), "300"),
            "scrolling the application UI",
        )

    def back(self) -> None:
        self._shell(("input", "keyevent", "KEYCODE_BACK"), "backtracking application UI")

    def start_activity(self, component: str) -> str:
        target = validate_component_name(component)
        output = self._shell(
            ("am", "start", "-W", "-n", f"{self.package}/{target}"),
            "opening an exported application activity",
            timeout=self.timeout,
        )
        return output

    def start_deep_link(self, uri: str) -> str:
        output = self._shell(
            (
                "am",
                "start",
                "-W",
                "-a",
                "android.intent.action.VIEW",
                "-d",
                uri,
                "-p",
                self.package,
            ),
            "opening an allowlisted application deep link",
            timeout=self.timeout,
            sensitive_values=(uri,),
        )
        return output

    def monkey(self, event_count: int, seed: int) -> None:
        self._shell(
            (
                "monkey",
                "-p",
                self.package,
                "-s",
                str(seed),
                "--throttle",
                "100",
                "--pct-syskeys",
                "0",
                "--pct-appswitch",
                "0",
                "--pct-anyevent",
                "0",
                str(event_count),
            ),
            "running bounded package-only monkey fallback",
            timeout=max(self.timeout, event_count + 5),
        )

    def dismiss_external_dialog(self) -> bool:
        package, activity = self.current_activity()
        if package in {None, self.package}:
            return False
        activity_key = (activity or "").casefold()
        is_permission_controller = package in _PERMISSION_CONTROLLER_PACKAGES
        is_system_ack = (
            package in _SYSTEM_DIALOG_PACKAGES
            and any(marker in activity_key for marker in _LEGACY_ACK_ACTIVITY_MARKERS)
        )
        if not is_permission_controller and not is_system_ack:
            return False
        try:
            xml = self.dump_ui()
            state = parse_ui_hierarchy(
                xml,
                expected_package=package,
                activity=activity or "external_dialog",
            )
        except (AndroidAssessorError, OSError, ValueError):
            return False
        is_review = is_permission_controller and _REVIEW_ACTIVITY_MARKER in activity_key
        permission_switch_seen = False
        checked_permission_switch_seen = False
        if is_review:
            # Legacy permission review starts compatible runtime permissions as
            # checked.  Turn every permission switch off before acknowledging
            # the screen so the default remains deny; never tap an allow control.
            for node in state.nodes:
                class_key = node.class_name.casefold()
                resource_key = node.resource_id.casefold()
                is_switch = (
                    class_key.endswith(("switch", "checkbox", "togglebutton"))
                    or any(
                        marker in resource_key
                        for marker in (
                            "permission_switch",
                            "permission_toggle",
                            "grant_switch",
                            "grant_toggle",
                        )
                    )
                )
                if not is_switch:
                    continue
                permission_switch_seen = True
                if node.checked:
                    checked_permission_switch_seen = True
                    if node.clickable and node.enabled and node.visible:
                        self.tap(*node.center)
                        return True
            if checked_permission_switch_seen:
                return False
        for node in state.nodes:
            label = _normalize_label(node.label)
            resource_key = node.resource_id.casefold()
            resource_tail = resource_key.rsplit("/", 1)[-1]
            semantic_labels = {
                _normalize_label(value)
                for value in (node.text, node.content_description, node.hint)
                if value
            }
            if not node.clickable or not node.enabled or not node.visible:
                continue
            if any(term in label for term in _DENY_PERMISSION_LABELS):
                x, y = node.center
                self.tap(x, y)
                return True
            if any(term in label for term in _ALLOW_PERMISSION_LABELS):
                continue
            review_continue = (
                is_review
                and permission_switch_seen
                and not checked_permission_switch_seen
                and (
                    any(term in semantic_labels for term in _REVIEW_CONTINUE_LABELS)
                    or resource_tail in _REVIEW_CONTINUE_RESOURCE_MARKERS
                )
            )
            if review_continue:
                self.tap(*node.center)
                return True
            system_ack = is_system_ack and (
                any(term in semantic_labels for term in _SYSTEM_ACK_LABELS)
                or resource_key in _SYSTEM_ACK_RESOURCE_MARKERS
            )
            if system_ack:
                self.tap(*node.center)
                return True
        return False

    def hide_keyboard(self) -> None:
        self._shell(
            ("input", "keyevent", "KEYCODE_BACK"),
            "hiding the application keyboard",
        )

    def cleanup(self) -> None:
        self._cleanup_failure_reason = None
        started = self._record_adb_start()
        try:
            result = self.adb.shell(
                self.serial,
                ("rm", "-rf", "--", self.remote_dir),
                timeout=10,
                check=False,
                operation="removing managed explorer workspace",
            )
        finally:
            self._record_adb_end(started)
        if bool(getattr(result, "timed_out", False)):
            self._cleanup_failure_reason = "adb_timeout"
            return
        if int(getattr(result, "exit_code", 0)) != 0:
            self._cleanup_failure_reason = "adb_error"
            return
        self._workspace_ready = False

    @property
    def cleanup_failure_reason(self) -> str | None:
        return self._cleanup_failure_reason

    def performance_metrics(self) -> Mapping[str, int | float]:
        return {
            "adb_command_count": self._adb_command_count,
            "ui_dump_count": self._ui_dump_count,
            "adb_operation_ms": round(self._adb_operation_ms, 2),
        }


class AndroidExplorer:
    def __init__(
        self,
        backend: ExplorerBackend,
        *,
        package: str,
        session_id: str,
        manifest: Mapping[str, Any],
        scope: ScopeConfig,
        config: ExplorerConfig,
        feedback: Callable[[], RuntimeFeedback] | None = None,
        stop_requested: Callable[[], bool] | None = None,
        network_guard_active: bool = False,
        session_canary: str | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.backend = backend
        self.package = validate_package_name(package)
        self.session_id = validate_session_id(session_id)
        self.manifest = manifest
        self.scope = scope
        self.config = config
        self.network_guard_active = network_guard_active
        self.session_canary = (
            validate_session_canary(session_canary)
            if session_canary is not None
            else None
        )
        self.feedback = feedback or (lambda: RuntimeFeedback())
        self.stop_requested = stop_requested or (lambda: False)
        self.clock = clock
        self.sleeper = sleeper
        self.rng = random.Random(config.seed)
        self.trace: list[dict[str, Any]] = []
        self._ui_dump_count = 0
        self._observation_retries = 0
        self._safety_skip_keys: set[tuple[str, str]] = set()

    def _trace(self, event: str, **details: Any) -> None:
        self.trace.append(
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "event": event,
                **details,
            }
        )

    def _capture(self) -> UiState:
        if self.clock() >= getattr(self, "_hard_deadline", float("inf")):
            raise _ExplorerDeadlineReached
        package, activity = self.backend.current_activity()
        if self.clock() >= getattr(self, "_hard_deadline", float("inf")):
            raise _ExplorerDeadlineReached
        if package != self.package or not activity:
            key = (str(package), str(activity))
            if key not in self._safety_skip_keys:
                self._safety_skip_keys.add(key)
                self._trace(
                    "action_skipped",
                    reason="package_boundary",
                    observed_package_class=(
                        "permission_controller"
                        if package in _PERMISSION_CONTROLLER_PACKAGES
                        else "outside_scope"
                    ),
                )
            raise _ExplorerPackageBoundary(package, activity)
        self._ui_dump_count += 1
        xml = self.backend.dump_ui()
        if self.clock() >= getattr(self, "_hard_deadline", float("inf")):
            raise _ExplorerDeadlineReached
        return parse_ui_hierarchy(
            xml,
            expected_package=self.package,
            activity=activity,
        )

    @contextmanager
    def _operation_budget(self) -> Iterator[None]:
        logical_operation = getattr(self.backend, "logical_operation", None)
        if callable(logical_operation):
            with logical_operation(self.config.per_action_timeout_seconds):
                yield
            return
        yield

    def _wait_for_ui(self, previous: str | None = None) -> UiState:
        with self._operation_budget():
            return self._wait_for_ui_until(previous)

    def _wait_for_ui_until(self, previous: str | None = None) -> UiState:
        deadline = min(
            getattr(self, "_hard_deadline", float("inf")),
            self.clock() + self.config.per_action_timeout_seconds,
        )
        last: UiState | None = None
        last_error: AndroidAssessorError | OSError | ValueError | None = None
        failed_observations = 0
        stable_count = 0
        while self.clock() < deadline:
            try:
                current = self._capture()
                stable_count = (
                    stable_count + 1
                    if last is not None and last.fingerprint == current.fingerprint
                    else 1
                )
                last = current
                if previous is None or current.fingerprint != previous:
                    return current
                if stable_count >= 2:
                    return current
            except _ExplorerPackageBoundary:
                try:
                    if self.backend.dismiss_external_dialog():
                        self.sleeper(0.15)
                        continue
                except (AndroidAssessorError, OSError, ValueError):
                    pass
                raise
            except (AndroidAssessorError, OSError, ValueError) as exc:
                last_error = exc
                if failed_observations >= self.config.max_observation_retries:
                    raise
                failed_observations += 1
                self._observation_retries += 1
                self._trace(
                    "observation_retry",
                    reason=_failure_reason(exc),
                    attempt=failed_observations,
                )
                try:
                    self.backend.dismiss_external_dialog()
                except (AndroidAssessorError, OSError, ValueError):
                    pass
            self.sleeper(0.15)
        if last is not None:
            return last
        if self.clock() >= getattr(self, "_hard_deadline", float("inf")):
            raise _ExplorerDeadlineReached
        if last_error is not None:
            raise last_error
        return self._capture()

    @staticmethod
    def _feedback_changed(before: RuntimeFeedback, after: RuntimeFeedback) -> bool:
        return bool(
            after.categories - before.categories
            or after.methods - before.methods
            or after.traffic_hosts - before.traffic_hosts
        )

    @staticmethod
    def _is_semantic_action(action: ExplorerAction) -> bool:
        normalized = _normalize_label(action.label)
        return any(word in normalized for words in _KEYWORD_CATEGORIES.values() for word in words)

    def _nearby_inputs(
        self,
        state: UiState,
        action: ExplorerAction,
        executed: set[tuple[str, str]],
        *,
        include_executed: bool = False,
        limit: int = 2,
    ) -> list[UiNode]:
        """Select a minimal generic input set by UI proximity, never app identity."""
        action_x, action_y = action.x or 0, action.y or 0
        candidates: list[UiNode] = []
        for node in state.nodes:
            if node.package and node.package != state.package:
                continue
            identity = (state.fingerprint, _node_identity(node, state.activity))
            if identity in executed:
                if not include_executed or not (
                    node.editable and node.enabled and node.visible
                ):
                    continue
            elif not is_input_candidate(node):
                continue
            candidates.append(node)
        candidates.sort(
            key=lambda node: (
                abs(node.center[1] - action_y) + abs(node.center[0] - action_x),
                node.resource_id,
                node.bounds,
            )
        )
        return candidates[:limit]

    def _input_kind(self, node: UiNode) -> tuple[str, str]:
        return classify_input(
            node,
            allow_local_url="10.0.2.2" in self.scope.api_hosts,
        )

    def _controlled_form_inputs(
        self,
        state: UiState,
        action: ExplorerAction,
        executed: set[tuple[str, str]],
    ) -> tuple[UiNode | None, UiNode | None]:
        nearby = self._nearby_inputs(
            state,
            action,
            executed,
            include_executed=True,
            limit=4,
        )
        carrier = next(
            (
                node
                for node in nearby
                if self._input_kind(node)[0]
                in {"username", "email", "text", "canary", "url"}
            ),
            None,
        )
        supporting = next(
            (
                node
                for node in nearby
                if node is not carrier
                and self._input_kind(node)[0] in {"password", "number"}
            ),
            None,
        )
        return carrier, supporting

    def _is_controlled_form_action(
        self,
        state: UiState,
        action: ExplorerAction,
        carrier: UiNode | None,
        supporting: UiNode | None,
    ) -> bool:
        if carrier is None:
            return False
        if _is_controlled_canary_action(action.label):
            return True
        if supporting is None or action.kind != "tap" or action.y is None:
            return False
        action_node = next(
            (
                node
                for node in state.nodes
                if _node_identity(node, state.activity) == action.identity
            ),
            None,
        )
        button_like = action_node is not None and (
            "button" in action_node.class_name.casefold()
            or bool(
                {"action", "btn", "button", "submit"}
                & set(_identifier_tokens(action_node.resource_id))
            )
        )
        return bool(
            button_like
            and self._input_kind(carrier)[0]
            in {"username", "email", "text", "canary"}
            and self._input_kind(supporting)[0] == "password"
            and action.y >= max(carrier.bounds[3], supporting.bounds[3])
        )

    def _has_controlled_form_action(
        self,
        state: UiState,
        executed: set[tuple[str, str]],
    ) -> bool:
        for node in state.nodes:
            identity = _node_identity(node, state.activity)
            if (
                (state.fingerprint, identity) in executed
                or (node.package and node.package != state.package)
                or not node.clickable
                or node.editable
                or not node.enabled
                or not node.visible
                or not is_safe_action_label(node.label)
                or (_could_trigger_network(node.label) and not self.network_guard_active)
            ):
                continue
            action = ExplorerAction(
                (0, 0.0, identity),
                "tap",
                identity,
                *node.center,
                node.label,
                resource_id=node.resource_id,
            )
            carrier, supporting = self._controlled_form_inputs(
                state,
                action,
                executed,
            )
            if self._is_controlled_form_action(
                state,
                action,
                carrier,
                supporting,
            ):
                return True
        return False

    def _generated_input(
        self,
        node: UiNode,
        *,
        prefer_canary: bool = False,
    ) -> tuple[str, str]:
        input_kind, value = self._input_kind(node)
        if (
            self.session_canary is not None
            and self.config.controlled_canary_delivery
            and prefer_canary
        ):
            if input_kind in {"username", "text", "canary"}:
                value = self.session_canary
            elif input_kind == "email":
                value = f"{self.session_canary}@example.test"
            elif input_kind == "url":
                value = f"https://10.0.2.2/{self.session_canary}"
        elif input_kind == "canary":
            value = f"ASL_{self.session_id[-6:]}"
        return input_kind, value

    def _activity_attempts(
        self,
        current_activity: str,
    ) -> tuple[list[dict[str, Any]], list[tuple[str, int]]]:
        attempts: list[dict[str, Any]] = []
        targets: list[tuple[str, int]] = []
        for item in self.manifest.get("components", []):
            if not isinstance(item, Mapping) or item.get("component_type") != "activity":
                continue
            component = item.get("name")
            if not isinstance(component, str):
                continue
            if item.get("effective_exported") is not True:
                attempts.append({"component": component, "status": "not_exported"})
                continue
            if item.get("enabled") is False:
                attempts.append(
                    {"component": component, "status": "blocked", "reason": "disabled"}
                )
                continue
            if component != self.package and not component.startswith(self.package + "."):
                attempts.append(
                    {"component": component, "status": "blocked", "reason": "package_mismatch"}
                )
                continue
            if component == current_activity:
                attempts.append(
                    {"component": component, "status": "opened", "source": "launch"}
                )
                continue
            index = len(attempts)
            attempts.append({"component": component, "status": "attempted"})
            targets.append((component, index))
        return attempts, targets

    def _deep_link_attempts(
        self,
    ) -> tuple[list[dict[str, Any]], list[tuple[str, int]]]:
        attempts: list[dict[str, Any]] = []
        targets: list[tuple[str, int]] = []
        for item in self.manifest.get("deep_links", []):
            if not isinstance(item, Mapping):
                continue
            scheme = str(item.get("scheme") or "").casefold()
            host = str(item.get("host") or "").casefold()
            component = item.get("component")
            if scheme not in {"http", "https"} or host not in self.scope.api_hosts:
                attempts.append(
                    {"component": component, "status": "blocked", "reason": "host_not_allowlisted"}
                )
                continue
            raw_path = str(item.get("path") or item.get("path_prefix") or "/")
            path = quote(raw_path, safe="/-._~")
            raw_port = item.get("port")
            port = str(raw_port) if raw_port is not None else ""
            if port and (not port.isdecimal() or not 1 <= int(port) <= 65535):
                attempts.append(
                    {"component": component, "status": "blocked", "reason": "invalid_port"}
                )
                continue
            authority = f"{host}:{port}" if port else host
            canary_marker = (
                self.session_canary
                if self.config.controlled_canary_delivery
                and self.session_canary is not None
                else "canary"
            )
            query = urlencode(
                {"asl": canary_marker},
                safe="",
            )
            uri = urlunsplit(
                (scheme, authority, path if path.startswith("/") else "/" + path, query, "")
            )
            try:
                self.scope.require_url(uri)
            except AndroidAssessorError:
                attempts.append(
                    {"component": component, "status": "blocked", "reason": "scope_denied"}
                )
                continue
            index = len(attempts)
            attempts.append({"component": component, "status": "attempted", "host": host})
            targets.append((uri, index))
        return attempts, targets

    def run(self) -> ExplorerResult:
        started = self.clock()
        deadline = started + self.config.max_runtime_seconds
        self._hard_deadline = deadline
        set_runtime_budget = getattr(self.backend, "set_runtime_budget", None)
        if callable(set_runtime_budget):
            set_runtime_budget(self.config.max_runtime_seconds)
        visited: dict[str, UiState] = {}
        activities: set[str] = set()
        executed: set[tuple[str, str]] = set()
        executed_navigation: set[tuple[str, str]] = set()
        discovered_actions: set[tuple[str, str]] = set()
        retried_actions: set[tuple[str, str]] = set()
        traced_skips: set[tuple[str, str, str]] = set()
        scrolled: set[str] = set()
        history: list[str] = []
        actions_attempted = actions_executed = 0
        input_actions = scroll_actions = backtracks = 0
        controlled_canary_inputs = controlled_canary_deliveries = 0
        controlled_canary_attempts = controlled_canary_failures = 0
        controlled_canary_budget_skips = 0
        action_failures = state_refreshes = 0
        actions_succeeded = duplicate_actions_avoided = form_retries = 0
        process_restarts = crashes = 0
        idle_seconds = idle_plateau_seconds = runtime_wait_seconds = 0.0
        monkey_used = False
        keyboard_open = False
        termination = "completed"
        partial_result = False
        previous_pid: int | None = None
        feedback = RuntimeFeedback()
        activity_attempts: list[dict[str, Any]] = []
        deep_link_attempts: list[dict[str, Any]] = []
        pending_navigation: list[tuple[str, str, int]] = []
        controlled_form_pending = False
        cleanup_failure_reason: str | None = None

        def reset_idle() -> None:
            nonlocal idle_plateau_seconds
            idle_plateau_seconds = 0.0

        def record_action_failure(
            kind: str,
            error: AdbError | OSError,
            *,
            source: str | None = None,
        ) -> None:
            nonlocal action_failures, partial_result
            nonlocal controlled_canary_failures
            is_controlled_canary = bool(
                source and source.startswith("controlled_canary")
            )
            action_failures += 1
            partial_result = True
            if is_controlled_canary:
                controlled_canary_failures += 1
            self._trace(
                "action_failed",
                kind=kind,
                source=source,
                reason=_failure_reason(error),
                outcome="unknown",
                replayed=False,
            )

        def perform_action(
            kind: str,
            operation: Callable[[], None],
            *,
            source: str | None = None,
        ) -> bool:
            nonlocal actions_attempted, actions_executed
            nonlocal controlled_canary_attempts
            actions_attempted += 1
            if source == "controlled_canary":
                controlled_canary_attempts += 1
            try:
                with self._operation_budget():
                    operation()
            except (AdbError, OSError) as exc:
                record_action_failure(kind, exc, source=source)
                return False
            actions_executed += 1
            return True

        def enter_input(node: UiNode, state: UiState, *, source: str) -> bool:
            nonlocal actions_succeeded, input_actions, keyboard_open
            nonlocal controlled_canary_inputs
            input_kind, value = self._generated_input(
                node,
                prefer_canary=source == "controlled_canary",
            )
            if not perform_action(
                "input",
                lambda: self.backend.input_text(*node.center, value),
                source=source,
            ):
                return False
            identity = _node_identity(node, state.activity)
            executed.add((state.fingerprint, identity))
            actions_succeeded += 1
            input_actions += 1
            if source == "controlled_canary":
                controlled_canary_inputs += 1
            keyboard_open = True
            self._trace(
                "action",
                kind="input",
                source=source,
                input_kind=input_kind,
                resource_id=node.resource_id,
                state=state.fingerprint,
            )
            return True

        def block_pending_navigation(reason: str) -> None:
            for kind, _target, index in pending_navigation:
                attempts = activity_attempts if kind == "activity" else deep_link_attempts
                attempts[index]["status"] = "blocked"
                attempts[index]["reason"] = reason
            pending_navigation.clear()

        def recover_action_failure() -> UiState | None:
            nonlocal termination, state_refreshes, partial_result
            if action_failures >= self.config.max_action_failures:
                termination = "action_failure_limit"
                block_pending_navigation(termination)
                self._trace(
                    "exploration_stopped",
                    reason=termination,
                    actions_failed=action_failures,
                )
                return None
            try:
                refreshed = self._wait_for_ui()
            except (_ExplorerDeadlineReached, _ExplorerPackageBoundary):
                raise
            except (AndroidAssessorError, OSError, ValueError) as exc:
                partial_result = True
                termination = "action_recovery_failed"
                block_pending_navigation(termination)
                self._trace(
                    "exploration_stopped",
                    reason=termination,
                    observation_reason=_failure_reason(exc),
                )
                return None
            state_refreshes += 1
            self._trace(
                "state_refreshed",
                reason="action_failure",
                state=refreshed.fingerprint,
            )
            return refreshed

        def observe_after_action(previous: str | None = None) -> UiState | None:
            nonlocal termination, partial_result, crashes, process_restarts
            nonlocal previous_pid
            try:
                return self._wait_for_ui(previous)
            except _ExplorerDeadlineReached:
                raise
            except _ExplorerPackageBoundary:
                try:
                    with self._operation_budget():
                        process_alive = self.backend.process_id() is not None
                except (AdbError, OSError) as exc:
                    partial_result = True
                    termination = "process_state_unavailable"
                    block_pending_navigation(termination)
                    self._trace(
                        "exploration_stopped",
                        reason=termination,
                        observation_reason=_failure_reason(exc),
                    )
                    return None
                if process_alive:
                    raise
                try:
                    crashes += 1
                    with self._operation_budget():
                        self.backend.launch()
                        process_restarts += 1
                        previous_pid = self.backend.process_id()
                    return self._wait_for_ui()
                except _ExplorerDeadlineReached:
                    raise
                except (AndroidAssessorError, OSError, ValueError) as exc:
                    partial_result = True
                    termination = "state_refresh_failed"
                    block_pending_navigation(termination)
                    self._trace(
                        "exploration_stopped",
                        reason=termination,
                        observation_reason=_failure_reason(exc),
                    )
                    return None
            except (AndroidAssessorError, OSError, ValueError) as exc:
                partial_result = True
                termination = "state_refresh_failed"
                block_pending_navigation(termination)
                self._trace(
                    "exploration_stopped",
                    reason=termination,
                    observation_reason=_failure_reason(exc),
                )
                return None

        try:
            if not self.network_guard_active:
                self._trace(
                    "action_skipped",
                    reason="network_guard_required",
                )
                raise AdbError(
                    "Autonomous exploration requires an active scoped traffic guard."
                )
            with self._operation_budget():
                previous_pid = self.backend.process_id()
                if previous_pid is None:
                    self.backend.launch()
            feedback = self.feedback()
            current = self._wait_for_ui()
            activity_attempts, activity_targets = self._activity_attempts(current.activity)
            deep_link_attempts, deep_link_targets = self._deep_link_attempts()
            pending_navigation.extend(
                ("activity", target, index) for target, index in activity_targets
            )
            pending_navigation.extend(
                ("deep_link", target, index) for target, index in deep_link_targets
            )
            controlled_form_pending = bool(
                self.config.controlled_canary_delivery
                and self.session_canary is not None
                and self._has_controlled_form_action(current, executed)
            )
            while True:
                now = self.clock()
                if self.stop_requested():
                    termination = "stop_requested"
                    block_pending_navigation("stop_requested")
                    break
                if now >= deadline:
                    termination = "max_runtime"
                    block_pending_navigation("hard_limit")
                    break
                if deadline - now <= self.config.per_action_timeout_seconds:
                    termination = "max_runtime"
                    block_pending_navigation("insufficient_action_budget")
                    break
                if actions_attempted >= self.config.max_actions:
                    termination = "max_actions"
                    block_pending_navigation("max_actions")
                    break
                if len(visited) >= self.config.max_states and current.fingerprint not in visited:
                    termination = "max_states"
                    block_pending_navigation("max_states")
                    break

                new_state = current.fingerprint not in visited
                if new_state:
                    visited[current.fingerprint] = current
                    activities.add(current.activity)
                    reset_idle()
                    self._trace(
                        "state_discovered",
                        state=current.fingerprint,
                        activity=current.activity,
                        actionable_nodes=sum(
                            1 for node in current.nodes if node.clickable or node.editable
                        ),
                    )
                latest_feedback = self.feedback()
                if (
                    latest_feedback.categories - feedback.categories
                    or latest_feedback.methods - feedback.methods
                    or latest_feedback.traffic_hosts - feedback.traffic_hosts
                ):
                    reset_idle()
                    self._trace(
                        "runtime_yield",
                        categories=sorted(latest_feedback.categories),
                        method_count=len(latest_feedback.methods),
                        traffic_host_count=len(latest_feedback.traffic_hosts),
                    )
                feedback = latest_feedback
                if pending_navigation and not history and not controlled_form_pending:
                    reset_idle()
                    kind, target, index = pending_navigation.pop(0)
                    attempts = activity_attempts if kind == "activity" else deep_link_attempts
                    previous = current.fingerprint
                    navigation_action_failed = False
                    controlled_navigation = bool(
                        kind == "deep_link"
                        and self.config.controlled_canary_delivery
                        and self.session_canary is not None
                    )
                    actions_attempted += 1
                    if controlled_navigation:
                        controlled_canary_attempts += 1
                    try:
                        with self._operation_budget():
                            output = (
                                self.backend.start_activity(target)
                                if kind == "activity"
                                else self.backend.start_deep_link(target)
                            )
                        status = "permission_denied" if "Permission Denial" in output else "opened"
                    except AndroidAssessorError as exc:
                        if "permission" in str(exc).casefold():
                            status = "permission_denied"
                        elif isinstance(exc, AdbError):
                            status = "outcome_unknown"
                            record_action_failure(
                                kind,
                                exc,
                                source=(
                                    "controlled_canary_deep_link"
                                    if controlled_navigation
                                    else None
                                ),
                            )
                            navigation_action_failed = True
                            attempts[index]["reason"] = _failure_reason(exc)
                        else:
                            status = "blocked"
                            attempts[index]["reason"] = "policy_rejected"
                    except OSError as exc:
                        status = "outcome_unknown"
                        record_action_failure(
                            kind,
                            exc,
                            source=(
                                "controlled_canary_deep_link"
                                if controlled_navigation
                                else None
                            ),
                        )
                        navigation_action_failed = True
                        attempts[index]["reason"] = _failure_reason(exc)
                    if not navigation_action_failed:
                        actions_executed += 1
                    if status == "opened":
                        candidate = observe_after_action(previous)
                        if candidate is None:
                            status = "outcome_unknown"
                            attempts[index]["reason"] = termination
                            attempts[index]["status"] = status
                            self._trace(
                                "targeted_navigation",
                                kind=kind,
                                component=attempts[index].get("component"),
                                host=attempts[index].get("host"),
                                status=status,
                                reason=attempts[index].get("reason"),
                            )
                            break
                        if kind == "activity" and candidate.activity != target:
                            status = "blocked"
                            attempts[index]["reason"] = "activity_not_resumed"
                        else:
                            actions_succeeded += 1
                            if candidate.fingerprint != previous:
                                history.append(previous)
                            current = candidate
                    elif navigation_action_failed:
                        refreshed = recover_action_failure()
                        if refreshed is None:
                            attempts[index]["status"] = status
                            self._trace(
                                "targeted_navigation",
                                kind=kind,
                                component=attempts[index].get("component"),
                                host=attempts[index].get("host"),
                                status=status,
                                reason=attempts[index].get("reason"),
                            )
                            break
                        expected_activity = (
                            target
                            if kind == "activity"
                            else attempts[index].get("component")
                        )
                        current = refreshed
                        if expected_activity and current.activity == expected_activity:
                            status = "opened"
                            attempts[index]["reason"] = (
                                "completion_observed_after_action_error"
                            )
                            actions_succeeded += 1
                            if current.fingerprint != previous:
                                history.append(previous)
                    if controlled_navigation and status == "opened":
                        controlled_canary_deliveries += 1
                        self._trace(
                            "controlled_canary_delivery",
                            state=previous,
                            action="deep_link",
                            input_kind="deep_link_query",
                            supporting_input=False,
                            observation="completed",
                        )
                    attempts[index]["status"] = status
                    self._trace(
                        "targeted_navigation",
                        kind=kind,
                        component=attempts[index].get("component"),
                        host=attempts[index].get("host"),
                        status=status,
                        reason=attempts[index].get("reason"),
                    )
                    continue
                skipped_actions: list[dict[str, str]] = []
                queue = build_actions(
                    current,
                    feedback=feedback,
                    allow_local_url="10.0.2.2" in self.scope.api_hosts,
                    network_guard_active=self.network_guard_active,
                    controlled_canary_delivery=(
                        self.config.controlled_canary_delivery
                    ),
                    rng=self.rng,
                    skipped=skipped_actions,
                )
                for skip in skipped_actions:
                    key = (
                        current.fingerprint,
                        skip.get("reason", "policy"),
                        skip.get("resource_id", "") or skip.get("label", ""),
                    )
                    if key in traced_skips:
                        continue
                    traced_skips.add(key)
                    self._trace("action_skipped", state=current.fingerprint, **skip)
                newly_discovered = {
                    (current.fingerprint, candidate.identity)
                    for candidate in queue
                    if (current.fingerprint, candidate.identity) not in discovered_actions
                }
                if newly_discovered:
                    discovered_actions.update(newly_discovered)
                    reset_idle()
                    self._trace(
                        "actions_discovered",
                        state=current.fingerprint,
                        count=len(newly_discovered),
                    )
                action = None
                while queue:
                    candidate = heapq.heappop(queue)
                    if len(history) >= self.config.max_depth and candidate.kind not in {"input"}:
                        continue
                    activity_label = re.sub(
                        r"activity$",
                        "",
                        current.activity.rsplit(".", 1)[-1],
                        flags=re.IGNORECASE,
                    ).casefold()
                    display_label = _normalize_label(candidate.label).split(" ", 1)[0]
                    if (
                        candidate.resource_id.casefold().endswith("id/title")
                        and display_label == activity_label
                    ):
                        duplicate_actions_avoided += 1
                        continue
                    is_navigation = any(
                        word in _normalize_label(candidate.label)
                        for word in ("more options", "menu", "navigation")
                    )
                    if (
                        is_navigation
                        and (
                            current.fingerprint,
                            _normalize_label(candidate.label),
                        )
                        in executed_navigation
                    ):
                        duplicate_actions_avoided += 1
                        continue
                    if (current.fingerprint, candidate.identity) not in executed:
                        action = candidate
                        break
                    duplicate_actions_avoided += 1
                if action is not None:
                    reset_idle()
                    if keyboard_open and action.kind != "input":
                        keyboard_open = False
                        if not perform_action(
                            "hide_keyboard",
                            self.backend.hide_keyboard,
                        ):
                            refreshed = recover_action_failure()
                            if refreshed is None:
                                break
                            current = refreshed
                            continue
                        actions_succeeded += 1
                        self._trace("action", kind="hide_keyboard")
                        observed = observe_after_action(current.fingerprint)
                        if observed is None:
                            break
                        current = observed
                        continue
                    executed.add((current.fingerprint, action.identity))
                    if any(
                        word in _normalize_label(action.label)
                        for word in ("more options", "menu", "navigation")
                    ):
                        executed_navigation.add(
                            (current.fingerprint, _normalize_label(action.label))
                        )
                    previous = current.fingerprint
                    controlled_delivery: tuple[str, bool] | None = None
                    if action.kind == "input":
                        node = next(
                            node
                            for node in current.nodes
                            if _node_identity(node, current.activity) == action.identity
                        )
                        if not enter_input(node, current, source="traversal"):
                            refreshed = recover_action_failure()
                            if refreshed is None:
                                break
                            current = refreshed
                        continue
                    else:
                        controlled_form: tuple[UiNode | None, UiNode | None] | None = None
                        if self.config.controlled_canary_delivery:
                            carrier, supporting = self._controlled_form_inputs(
                                current,
                                action,
                                executed,
                            )
                            if self._is_controlled_form_action(
                                current,
                                action,
                                carrier,
                                supporting,
                            ):
                                controlled_form = (carrier, supporting)
                        if (
                            self.session_canary is not None
                            and controlled_form is not None
                        ):
                            carrier, supporting = controlled_form
                            required_actions = 3 + (supporting is not None)
                            remaining_actions = (
                                self.config.max_actions - actions_attempted
                            )
                            controlled_form_pending = False
                            if carrier is not None and remaining_actions >= required_actions:
                                if not enter_input(
                                    carrier,
                                    current,
                                    source="controlled_canary",
                                ):
                                    refreshed = recover_action_failure()
                                    if refreshed is None:
                                        break
                                    current = refreshed
                                    continue
                                if (
                                    supporting is not None
                                    and self.config.max_actions - actions_attempted >= 3
                                ):
                                    if not enter_input(
                                        supporting,
                                        current,
                                        source="controlled_canary_support",
                                    ):
                                        refreshed = recover_action_failure()
                                        if refreshed is None:
                                            break
                                        current = refreshed
                                        continue
                                if (
                                    keyboard_open
                                    and self.config.max_actions - actions_attempted >= 2
                                ):
                                    keyboard_open = False
                                    if not perform_action(
                                        "hide_keyboard",
                                        self.backend.hide_keyboard,
                                        source="controlled_canary_support",
                                    ):
                                        refreshed = recover_action_failure()
                                        if refreshed is None:
                                            break
                                        current = refreshed
                                        continue
                                    actions_succeeded += 1
                                controlled_delivery = (
                                    self._input_kind(carrier)[0],
                                    supporting is not None,
                                )
                            elif carrier is not None:
                                controlled_canary_budget_skips += 1
                                self._trace(
                                    "action_skipped",
                                    reason="controlled_canary_action_budget",
                                    required_actions=required_actions,
                                    remaining_actions=remaining_actions,
                                )
                        feedback_before = feedback
                        if not perform_action(
                            action.kind,
                            lambda action=action: self.backend.tap(
                                action.x or 0,
                                action.y or 0,
                                long=action.kind == "long_tap",
                            ),
                            source=(
                                "controlled_canary_submit"
                                if controlled_delivery is not None
                                else None
                            ),
                        ):
                            refreshed = recover_action_failure()
                            if refreshed is None:
                                break
                            current = refreshed
                            continue
                        self._trace(
                            "action",
                            kind=action.kind,
                            label=_trace_label(action.label),
                            state=previous,
                        )
                    candidate = observe_after_action(previous)
                    if candidate is None:
                        if controlled_delivery is not None:
                            controlled_canary_failures += 1
                        break
                    if controlled_delivery is not None:
                        controlled_canary_deliveries += 1
                        input_kind, supporting_input = controlled_delivery
                        self._trace(
                            "controlled_canary_delivery",
                            state=previous,
                            action=_trace_label(action.label),
                            input_kind=input_kind,
                            supporting_input=supporting_input,
                            observation="completed",
                        )
                    feedback_after = self.feedback()
                    action_changed_state = candidate.fingerprint != previous
                    action_yielded = self._feedback_changed(feedback_before, feedback_after)
                    if action_changed_state or action_yielded:
                        actions_succeeded += 1
                        reset_idle()
                    retry_key = (previous, action.identity)
                    nearby_inputs = (
                        self._nearby_inputs(current, action, executed)
                        if not action_changed_state
                        and not action_yielded
                        and self._is_semantic_action(action)
                        and retry_key not in retried_actions
                        else []
                    )
                    if nearby_inputs and actions_attempted < self.config.max_actions:
                        retried_actions.add(retry_key)
                        form_retries += 1
                        self._trace(
                            "form_retry",
                            state=previous,
                            action=_trace_label(action.label),
                            input_count=len(nearby_inputs),
                        )
                        retry_input_failed = False
                        for node in nearby_inputs:
                            if actions_attempted >= self.config.max_actions:
                                break
                            if not enter_input(node, current, source="form_retry"):
                                refreshed = recover_action_failure()
                                if refreshed is not None:
                                    current = refreshed
                                retry_input_failed = True
                                break
                        if retry_input_failed:
                            if refreshed is None:
                                break
                            continue
                        if keyboard_open and actions_attempted < self.config.max_actions:
                            keyboard_open = False
                            if not perform_action(
                                "hide_keyboard",
                                self.backend.hide_keyboard,
                                source="form_retry",
                            ):
                                refreshed = recover_action_failure()
                                if refreshed is None:
                                    break
                                current = refreshed
                                continue
                            actions_succeeded += 1
                        if actions_attempted < self.config.max_actions:
                            before_retry = self.feedback()
                            if not perform_action(
                                action.kind,
                                lambda action=action: self.backend.tap(
                                    action.x or 0,
                                    action.y or 0,
                                    long=action.kind == "long_tap",
                                ),
                                source="form_retry",
                            ):
                                refreshed = recover_action_failure()
                                if refreshed is None:
                                    break
                                current = refreshed
                                continue
                            retried_state = observe_after_action(previous)
                            if retried_state is None:
                                break
                            after_retry = self.feedback()
                            if (
                                retried_state.fingerprint != previous
                                or self._feedback_changed(before_retry, after_retry)
                            ):
                                actions_succeeded += 1
                                reset_idle()
                            candidate = retried_state
                            feedback_after = after_retry
                    feedback = feedback_after
                    if candidate.fingerprint != previous:
                        history.append(previous)
                    current = candidate
                    continue

                if current.fingerprint not in scrolled:
                    reset_idle()
                    scrolled.add(current.fingerprint)
                    scrollable = next((node for node in current.nodes if node.scrollable), None)
                    if scrollable is not None:
                        left, top, right, bottom = scrollable.bounds
                        x = (left + right) // 2
                        swipe_succeeded = perform_action(
                            "scroll",
                            lambda x=x, bottom=bottom, top=top: self.backend.swipe(
                                x,
                                bottom - 40,
                                x,
                                top + 40,
                            ),
                        )
                    else:
                        swipe_succeeded = perform_action(
                            "scroll",
                            lambda: self.backend.swipe(540, 1450, 540, 450),
                        )
                    if not swipe_succeeded:
                        refreshed = recover_action_failure()
                        if refreshed is None:
                            break
                        current = refreshed
                        continue
                    scroll_actions += 1
                    self._trace("action", kind="scroll", state=current.fingerprint)
                    candidate = observe_after_action(current.fingerprint)
                    if candidate is None:
                        break
                    if candidate.fingerprint != current.fingerprint:
                        actions_succeeded += 1
                    current = candidate
                    continue

                if history:
                    reset_idle()
                    previous = current.fingerprint
                    history.pop()
                    if not perform_action("back", self.backend.back):
                        refreshed = recover_action_failure()
                        if refreshed is None:
                            break
                        current = refreshed
                        continue
                    backtracks += 1
                    self._trace("action", kind="back")
                    candidate = observe_after_action()
                    if candidate is None:
                        break
                    if candidate.fingerprint != previous:
                        actions_succeeded += 1
                    current = candidate
                    continue

                if not monkey_used and self.config.monkey_events:
                    monkey_used = True
                    skip_key = (
                        current.fingerprint,
                        "unsafe_random_fallback_disabled",
                        "monkey",
                    )
                    traced_skips.add(skip_key)
                    self._trace(
                        "action_skipped",
                        state=current.fingerprint,
                        reason="unsafe_random_fallback_disabled",
                    )

                sleep_for = min(0.2, max(0.0, deadline - now))
                idle_started = self.clock()
                self.sleeper(sleep_for)
                idle_elapsed = max(0.0, self.clock() - idle_started)
                idle_seconds += idle_elapsed
                idle_plateau_seconds += idle_elapsed
                runtime_wait_seconds += idle_elapsed
                post_idle_feedback = self.feedback()
                if self._feedback_changed(feedback, post_idle_feedback):
                    feedback = post_idle_feedback
                    reset_idle()
                    self._trace(
                        "runtime_yield",
                        categories=sorted(feedback.categories),
                        method_count=len(feedback.methods),
                        traffic_host_count=len(feedback.traffic_hosts),
                    )
                    continue
                if (
                    actions_attempted > 0
                    and idle_plateau_seconds >= self.config.plateau_seconds
                ):
                    termination = "coverage_plateau"
                    break

                try:
                    with self._operation_budget():
                        pid = self.backend.process_id()
                except (AdbError, OSError) as exc:
                    partial_result = True
                    termination = "process_state_unavailable"
                    block_pending_navigation(termination)
                    self._trace(
                        "exploration_stopped",
                        reason=termination,
                        observation_reason=_failure_reason(exc),
                    )
                    break
                if pid is None:
                    reset_idle()
                    crashes += 1
                    try:
                        with self._operation_budget():
                            self.backend.launch()
                    except (AdbError, OSError) as exc:
                        partial_result = True
                        termination = "process_restart_failed"
                        block_pending_navigation(termination)
                        self._trace(
                            "exploration_stopped",
                            reason=termination,
                            observation_reason=_failure_reason(exc),
                        )
                        break
                    process_restarts += 1
                    observed = observe_after_action()
                    if observed is None:
                        break
                    current = observed
                elif previous_pid is not None and pid != previous_pid:
                    reset_idle()
                    process_restarts += 1
                previous_pid = pid
        except _ExplorerDeadlineReached:
            termination = "max_runtime"
            block_pending_navigation("hard_limit")
        except _ExplorerPackageBoundary as exc:
            partial_result = True
            termination = "package_boundary"
            block_pending_navigation("package_boundary")
            self._trace(
                "exploration_stopped",
                reason=termination,
                observed_package=exc.package,
                observed_activity=exc.activity,
            )
        finally:
            try:
                self.backend.cleanup()
            except (AdbError, OSError) as exc:
                cleanup_failure_reason = _failure_reason(exc)
        backend_cleanup_failure = getattr(
            self.backend,
            "cleanup_failure_reason",
            None,
        )
        if isinstance(backend_cleanup_failure, str):
            cleanup_failure_reason = backend_cleanup_failure
        if cleanup_failure_reason is not None:
            partial_result = True
            self._trace(
                "cleanup_failed",
                reason=cleanup_failure_reason,
            )
        final_feedback = self.feedback()
        if self._feedback_changed(feedback, final_feedback):
            self._trace(
                "runtime_flush",
                categories=sorted(final_feedback.categories),
                method_count=len(final_feedback.methods),
                event_count=final_feedback.event_count,
            )
        feedback = final_feedback
        duration_ms = round((self.clock() - started) * 1000, 2)
        metrics_method = getattr(self.backend, "performance_metrics", None)
        if not callable(metrics_method):
            metrics_method = getattr(self.backend, "metrics", None)
        backend_metrics = metrics_method() if callable(metrics_method) else {}
        active_ms = max(0.0, duration_ms - idle_seconds * 1000)
        return ExplorerResult(
            session_id=self.session_id,
            status="partial" if partial_result else "completed",
            termination_reason=termination,
            duration_ms=duration_ms,
            states_visited=len(visited),
            activities_visited=tuple(sorted(activities)),
            actions_executed=actions_executed,
            input_actions=input_actions,
            scroll_actions=scroll_actions,
            backtracks=backtracks,
            process_restarts=process_restarts,
            crashes=crashes,
            runtime_categories=tuple(sorted(feedback.categories)),
            runtime_methods=len(feedback.methods),
            runtime_events=feedback.event_count,
            activity_attempts=tuple(activity_attempts),
            deep_link_attempts=tuple(deep_link_attempts),
            actions_attempted=actions_attempted,
            actions_succeeded=actions_succeeded,
            form_retries=form_retries,
            duplicate_actions_avoided=duplicate_actions_avoided,
            safety_skips=len(traced_skips) + len(self._safety_skip_keys),
            adb_command_count=int(backend_metrics.get("adb_command_count", 0)),
            ui_dump_count=max(
                self._ui_dump_count,
                int(backend_metrics.get("ui_dump_count", 0)),
            ),
            adb_operation_ms=float(backend_metrics.get("adb_operation_ms", 0.0)),
            idle_ms=round(idle_seconds * 1000, 2),
            exploring_ms=round(active_ms, 2),
            runtime_wait_ms=round(runtime_wait_seconds * 1000, 2),
            controlled_canary_inputs=controlled_canary_inputs,
            controlled_canary_deliveries=controlled_canary_deliveries,
            actions_failed=action_failures,
            observation_retries=self._observation_retries,
            state_refreshes=state_refreshes,
            controlled_canary_attempts=controlled_canary_attempts,
            controlled_canary_failures=controlled_canary_failures,
            controlled_canary_budget_skips=controlled_canary_budget_skips,
            cleanup_status=(
                "failed" if cleanup_failure_reason is not None else "completed"
            ),
            cleanup_failure_reason=cleanup_failure_reason,
        )


class ExplorerService:
    """Run the explorer and register only redacted interaction metadata."""

    def __init__(self, paths: Any, repository: SessionRepository) -> None:
        self.paths = paths
        self.repository = repository
        self.evidence = EvidenceRepository(paths, repository)

    def run(
        self,
        session_id: str,
        *,
        adb: AdbClient,
        scope: ScopeConfig,
        config: ExplorerConfig,
        feedback: Callable[[], RuntimeFeedback],
        stop_requested: Callable[[], bool],
        network_guard_active: bool = False,
        session_canary: str | None = None,
    ) -> ExplorerResult:
        record = self.repository.load(session_id)
        scope.require_device_package(
            record.serial,
            record.package,
            action="inspect",
        )
        scope.require_device_package(
            record.serial,
            record.package,
            action="autonomous_exploration",
        )
        if config.controlled_canary_delivery:
            scope.require_device_package(
                record.serial,
                record.package,
                action="controlled_validation",
            )
            if session_canary is None:
                raise ValueError(
                    "Controlled canary delivery requires an exact session canary."
                )
        session_paths = self.repository.paths_for(record.session_id)
        app = read_json_object(session_paths.app_json, root=self.paths.root)
        manifest = app.get("manifest") if isinstance(app.get("manifest"), dict) else {}
        backend = AdbExplorerBackend(
            adb,
            serial=record.serial,
            package=record.package,
            session_id=record.session_id,
            per_action_timeout=config.per_action_timeout_seconds,
        )
        explorer = AndroidExplorer(
            backend,
            package=record.package,
            session_id=record.session_id,
            manifest=manifest,
            scope=scope,
            config=config,
            feedback=feedback,
            stop_requested=stop_requested,
            network_guard_active=network_guard_active,
            session_canary=session_canary,
        )
        result = explorer.run()
        output_dir = session_paths.redacted_dir / "explorer"
        trace_path = output_dir / "interaction-trace.jsonl"
        summary_path = output_dir / "summary.json"
        write_text_atomic(
            trace_path,
            "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in explorer.trace),
            root=self.paths.root,
        )
        payload = result.to_dict()
        payload["trace_path"] = trace_path.relative_to(session_paths.root).as_posix()
        payload["summary_path"] = summary_path.relative_to(session_paths.root).as_posix()
        write_json_atomic(summary_path, payload, root=self.paths.root)
        self.evidence.register_file(
            record.session_id,
            trace_path,
            evidence_type="autonomous_interaction_trace",
            source="adb_uiautomator",
            description="Redacted bounded package-scoped UI interaction trace.",
            sensitive=False,
            redacted=True,
        )
        self.evidence.register_file(
            record.session_id,
            summary_path,
            evidence_type="autonomous_exploration_summary",
            source="adb_uiautomator",
            description="Autonomous exploration coverage and termination summary.",
            sensitive=False,
            redacted=True,
        )
        self.repository.append_event(
            record.session_id,
            (
                "autonomous_exploration_partial"
                if result.status == "partial"
                else "autonomous_exploration_completed"
            ),
            {
                "status": result.status,
                "states_visited": result.states_visited,
                "actions_executed": result.actions_executed,
                "actions_failed": result.actions_failed,
                "termination_reason": result.termination_reason,
                "runtime_categories": list(result.runtime_categories),
            },
        )
        return ExplorerResult(
            **{
                **result.to_dict(),
                "activities_visited": tuple(result.activities_visited),
                "runtime_categories": tuple(result.runtime_categories),
                "activity_attempts": tuple(result.activity_attempts),
                "deep_link_attempts": tuple(result.deep_link_attempts),
                "trace_path": payload["trace_path"],
                "summary_path": payload["summary_path"],
            }
        )


class RuntimeFeedbackCollector:
    """Incrementally read bounded live observer metadata for one assessment session."""

    MAX_STREAM_BYTES = 10_000_000

    def __init__(self, session_paths: Any) -> None:
        self.session_paths = session_paths
        self.categories: set[str] = set()
        self.methods: set[str] = set()
        self.hosts: set[str] = set()
        self.event_count = 0
        self._positions: dict[str, int] = {}
        self._buffers: dict[str, str] = {}

    def _event_path(self, state_path: Any, *keys: str) -> Any | None:
        if not state_path.is_file():
            return None
        try:
            state = json.loads(state_path.read_text(encoding="utf-8-sig"))
            relative = next(
                (state.get(key) for key in keys if isinstance(state.get(key), str)),
                None,
            )
            if not relative:
                return None
            root = self.session_paths.root.resolve()
            path = (root / relative).resolve()
            return path if path.is_relative_to(root) else None
        except (OSError, ValueError, TypeError):
            return None

    def _new_lines(self, path: Any | None) -> list[str]:
        if path is None or not path.is_file():
            return []
        key = str(path)
        try:
            size = path.stat().st_size
            if size > self.MAX_STREAM_BYTES:
                return []
            offset = self._positions.get(key, 0)
            if size < offset:
                offset = 0
                self._buffers[key] = ""
            with path.open("rb") as stream:
                stream.seek(offset)
                chunk = stream.read(self.MAX_STREAM_BYTES - offset)
            self._positions[key] = offset + len(chunk)
            if not chunk:
                return []
            text = self._buffers.get(key, "") + chunk.decode("utf-8", errors="replace")
            complete = text.endswith(("\n", "\r"))
            lines = text.splitlines()
            self._buffers[key] = "" if complete or not lines else lines.pop()
            return lines
        except OSError:
            return []

    def poll(self) -> RuntimeFeedback:
        frida_path = self._event_path(
            self.session_paths.frida_dir / "state.json",
            "raw_events_path",
            "events_path",
        )
        for line in self._new_lines(frida_path):
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if not isinstance(event, dict) or event.get("type") == "observer_started":
                continue
            category = event.get("category")
            method = event.get("method")
            if isinstance(category, str):
                self.categories.add(category)
            if isinstance(method, str):
                self.methods.add(method)
            self.event_count += 1

        traffic_path = self._event_path(
            self.session_paths.traffic_dir / "state.json",
            "events_path",
        )
        for line in self._new_lines(traffic_path):
            try:
                event = json.loads(line)
            except ValueError:
                continue
            host = event.get("host") if isinstance(event, dict) else None
            if isinstance(host, str):
                self.hosts.add(host.casefold())

        return RuntimeFeedback(
            frozenset(self.categories),
            frozenset(self.methods),
            frozenset(self.hosts),
            self.event_count,
        )


def collect_runtime_feedback(session_paths: Any) -> RuntimeFeedback:
    """Compatibility helper for one bounded live observer snapshot."""
    return RuntimeFeedbackCollector(session_paths).poll()
