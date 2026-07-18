from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from android_assessor.errors import AdbError, ScopeError
from android_assessor.explorer import (
    AdbExplorerBackend,
    AndroidExplorer,
    ExplorerConfig,
    ExplorerResult,
    ExplorerService,
    RuntimeFeedback,
    RuntimeFeedbackCollector,
    UiNode,
    build_actions,
    classify_input,
    is_input_candidate,
    is_safe_action_label,
    parse_ui_hierarchy,
)
from android_assessor.paths import ProjectPaths
from android_assessor.scope import ScopeConfig
from android_assessor.session import SessionRepository


def _xml(*nodes: str) -> str:
    return "<?xml version='1.0'?><hierarchy>" + "".join(nodes) + "</hierarchy>"


def _node(
    *,
    text: str,
    resource: str,
    bounds: str = "[10,10][300,100]",
    class_name: str = "android.widget.Button",
    clickable: bool = True,
    editable: bool = False,
    scrollable: bool = False,
    password: bool = False,
    enabled: bool = True,
    visible: bool = True,
    checked: bool = False,
    hint: str = "",
    input_type: str = "",
    package: str = "com.example.app",
) -> str:
    return (
        f'<node text="{text}" resource-id="{resource}" class="{class_name}" '
        f'package="{package}" content-desc="" hint="{hint}" bounds="{bounds}" '
        f'clickable="{str(clickable).lower()}" long-clickable="false" '
        f'focusable="{str(editable).lower()}" scrollable="{str(scrollable).lower()}" '
        f'password="{str(password).lower()}" enabled="{str(enabled).lower()}" '
        f'visible-to-user="{str(visible).lower()}" checked="{str(checked).lower()}" '
        f'input-type="{input_type}" />'
    )


MAIN_XML = _xml(
    _node(
        text="old@example.test",
        resource="com.example.app:id/username",
        class_name="android.widget.EditText",
        clickable=True,
        editable=True,
    ),
    _node(text="Encryption", resource="com.example.app:id/encryption", bounds="[10,120][300,210]"),
    _node(text="Delete account", resource="com.example.app:id/delete", bounds="[10,220][300,310]"),
)
CRYPTO_XML = _xml(
    _node(text="AES encrypt", resource="com.example.app:id/aes"),
    _node(text="WebView", resource="com.example.app:id/web", bounds="[10,120][300,210]"),
)
WEB_XML = _xml(_node(text="Loaded page", resource="com.example.app:id/page", clickable=False))


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += max(seconds, 0.05)


class FakeBackend:
    def __init__(self) -> None:
        self.state = "main"
        self.stack: list[str] = []
        self.pid: int | None = 123
        self.categories: set[str] = set()
        self.methods: set[str] = set()
        self.inputs: list[str] = []
        self.started_activities: list[str] = []
        self.deep_links: list[str] = []
        self.cleanup_called = False
        self.launches = 0
        self.crash_on_encrypt = False
        self.tap_history: list[tuple[str, int, int]] = []
        self.adb_command_count = 0
        self.ui_dump_count = 0
        self.adb_operation_ms = 0.0
        self.monkey_calls = 0

    def _command(self) -> None:
        self.adb_command_count += 1

    def launch(self) -> None:
        self._command()
        self.launches += 1
        self.pid = 123 + self.launches
        self.state = "main"

    def dump_ui(self) -> str:
        self._command()
        self.ui_dump_count += 1
        if self.pid is None:
            raise ValueError("process exited")
        return {"main": MAIN_XML, "crypto": CRYPTO_XML, "web": WEB_XML}[self.state]

    def current_activity(self) -> tuple[str | None, str | None]:
        self._command()
        if self.pid is None:
            return None, None
        return "com.example.app", f"com.example.app.{self.state.title()}Activity"

    def process_id(self) -> int | None:
        self._command()
        return self.pid

    def tap(self, x: int, y: int, *, long: bool = False) -> None:
        self._command()
        del long
        self.tap_history.append((self.state, x, y))
        if self.state == "main" and y >= 120:
            if self.crash_on_encrypt:
                self.pid = None
                self.crash_on_encrypt = False
                return
            self.stack.append("main")
            self.state = "crypto"
        elif self.state == "crypto" and y < 120:
            self.categories.add("crypto")
            self.methods.add("cipher.do_final")
        elif self.state == "crypto":
            self.stack.append("crypto")
            self.state = "web"
            self.categories.add("webview")
            self.methods.add("webview.load_url")

    def input_text(self, x: int, y: int, value: str) -> None:
        self._command()
        del x, y
        self.inputs.append(value)

    def swipe(self, x1: int, y1: int, x2: int, y2: int) -> None:
        self._command()
        del x1, y1, x2, y2

    def back(self) -> None:
        self._command()
        if self.stack:
            self.state = self.stack.pop()

    def start_activity(self, component: str) -> str:
        self._command()
        self.started_activities.append(component)
        return "Status: ok"

    def start_deep_link(self, uri: str) -> str:
        self._command()
        self.deep_links.append(uri)
        return "Status: ok"

    def monkey(self, event_count: int, seed: int) -> None:
        self._command()
        self.monkey_calls += 1
        del event_count, seed

    def dismiss_external_dialog(self) -> bool:
        self._command()
        return False

    def hide_keyboard(self) -> None:
        self._command()

    def cleanup(self) -> None:
        self._command()
        self.cleanup_called = True

    def metrics(self) -> dict[str, float | int]:
        return {
            "adb_command_count": self.adb_command_count,
            "ui_dump_count": self.ui_dump_count,
            "adb_operation_ms": self.adb_operation_ms,
        }


FORM_XML = _xml(
    _node(
        text="",
        resource="org.lab.form:id/message",
        bounds="[10,20][500,110]",
        class_name="android.widget.EditText",
        editable=True,
        hint="Message",
        package="org.lab.form",
    ),
    _node(
        text="",
        resource="org.lab.form:id/hash_result",
        bounds="[10,120][500,210]",
        class_name="android.widget.EditText",
        editable=True,
        enabled=False,
        hint="Result",
        package="org.lab.form",
    ),
    _node(
        text="Hash value",
        resource="org.lab.form:id/hash",
        bounds="[10,230][500,320]",
        package="org.lab.form",
    ),
)


class FormRetryBackend(FakeBackend):
    def __init__(self) -> None:
        super().__init__()
        self.pid = 321
        self.button_taps = 0
        self.has_input = False

    def launch(self) -> None:
        self._command()
        self.launches += 1
        self.pid = 321 + self.launches

    def dump_ui(self) -> str:
        self._command()
        self.ui_dump_count += 1
        return FORM_XML

    def current_activity(self) -> tuple[str | None, str | None]:
        self._command()
        return "org.lab.form", "org.lab.form.FormActivity"

    def tap(self, x: int, y: int, *, long: bool = False) -> None:
        self._command()
        del x, long
        self.tap_history.append(("form", 0, y))
        if y >= 230:
            self.button_taps += 1
            if self.has_input:
                self.categories.add("crypto")
                self.methods.add("message_digest.get_instance")

    def input_text(self, x: int, y: int, value: str) -> None:
        self._command()
        del x, y
        self.inputs.append(value)
        self.has_input = True


TERMINAL_XML = _xml(
    _node(
        text="Status",
        resource="org.lab.viewer:id/status",
        clickable=False,
        package="org.lab.viewer",
    )
)


class SlowTerminalBackend(FakeBackend):
    def __init__(self) -> None:
        super().__init__()
        self.pid = 456
        self.clock: FakeClock | None = None

    def _advance(self, seconds: float) -> None:
        if self.clock is not None:
            self.clock.value += seconds

    def dump_ui(self) -> str:
        self._command()
        self.ui_dump_count += 1
        self._advance(1.2)
        return TERMINAL_XML

    def current_activity(self) -> tuple[str | None, str | None]:
        self._command()
        self._advance(0.4)
        return "org.lab.viewer", "org.lab.viewer.StatusActivity"

    def swipe(self, x1: int, y1: int, x2: int, y2: int) -> None:
        self._command()
        del x1, y1, x2, y2
        self._advance(1.2)


SCROLL_XML = _xml(
    _node(
        text="",
        resource="org.lab.catalog:id/list",
        bounds="[0,0][600,900]",
        class_name="android.widget.ScrollView",
        clickable=False,
        scrollable=True,
        package="org.lab.catalog",
    )
)
SCROLLED_XML = _xml(
    _node(
        text="Open browser",
        resource="org.lab.catalog:id/browser",
        bounds="[10,700][500,800]",
        package="org.lab.catalog",
    )
)


class ScrollBackend(FakeBackend):
    def __init__(self) -> None:
        super().__init__()
        self.pid = 654
        self.scrolled = False

    def dump_ui(self) -> str:
        self._command()
        self.ui_dump_count += 1
        return SCROLLED_XML if self.scrolled else SCROLL_XML

    def current_activity(self) -> tuple[str | None, str | None]:
        self._command()
        return "org.lab.catalog", "org.lab.catalog.CatalogActivity"

    def swipe(self, x1: int, y1: int, x2: int, y2: int) -> None:
        self._command()
        del x1, y1, x2, y2
        self.scrolled = True

    def tap(self, x: int, y: int, *, long: bool = False) -> None:
        self._command()
        del x, y, long
        self.categories.add("webview")
        self.methods.add("webview.load_url")


REPEATED_FIRST_XML = _xml(
    _node(
        text="Step one",
        resource="org.lab.repeat:id/status",
        clickable=False,
        package="org.lab.repeat",
    ),
    _node(
        text="Hash",
        resource="org.lab.repeat:id/run",
        bounds="[10,120][300,210]",
        package="org.lab.repeat",
    ),
)
REPEATED_SECOND_XML = REPEATED_FIRST_XML.replace("Step one", "Step two")


class RepeatedControlBackend(FakeBackend):
    def __init__(self) -> None:
        super().__init__()
        self.pid = 777
        self.state = "first"
        self.run_taps = 0

    def dump_ui(self) -> str:
        self._command()
        self.ui_dump_count += 1
        return REPEATED_FIRST_XML if self.state == "first" else REPEATED_SECOND_XML

    def current_activity(self) -> tuple[str | None, str | None]:
        self._command()
        return "org.lab.repeat", "org.lab.repeat.FormActivity"

    def tap(self, x: int, y: int, *, long: bool = False) -> None:
        self._command()
        del x, y, long
        self.run_taps += 1
        if self.state == "first":
            self.state = "second"
        else:
            self.categories.add("crypto")
            self.methods.add("message_digest.get_instance")


def _scope(
    *,
    package: str = "com.example.app",
    hosts: frozenset[str] = frozenset({"10.0.2.2"}),
) -> ScopeConfig:
    return ScopeConfig(
        devices=frozenset({"FAKE_SERIAL"}),
        packages=frozenset({package}),
        api_hosts=hosts,
        allowed_actions=frozenset({"inspect", "autonomous_exploration"}),
    )


def _run(
    backend: FakeBackend,
    *,
    package: str = "com.example.app",
    manifest: dict[str, object] | None = None,
    config: ExplorerConfig | None = None,
    network_guard_active: bool = True,
    session_canary: str | None = None,
) -> tuple[object, FakeClock, AndroidExplorer]:
    clock = FakeClock()
    if isinstance(backend, SlowTerminalBackend):
        backend.clock = clock
    explorer = AndroidExplorer(
        backend,
        package=package,
        session_id="20260717-210000-abcdef",
        manifest=manifest or {},
        scope=_scope(package=package),
        config=config
        or ExplorerConfig(
            max_runtime_seconds=10,
            plateau_seconds=1,
            max_states=10,
            max_actions=20,
            per_action_timeout_seconds=1,
            monkey_events=0,
        ),
        feedback=lambda: RuntimeFeedback(
            frozenset(backend.categories),
            frozenset(backend.methods),
            frozenset(),
            len(backend.methods),
        ),
        network_guard_active=network_guard_active,
        session_canary=session_canary,
        clock=clock,
        sleeper=clock.sleep,
    )
    return explorer.run(), clock, explorer


def test_explorer_refuses_all_active_traversal_without_network_guard() -> None:
    backend = FakeBackend()

    with pytest.raises(AdbError, match="traffic guard"):
        _run(backend, network_guard_active=False)

    assert backend.tap_history == []
    assert backend.cleanup_called is True


def test_ui_xml_parsing_and_fingerprint_hide_editable_values() -> None:
    first = parse_ui_hierarchy(
        MAIN_XML,
        expected_package="com.example.app",
        activity="com.example.app.MainActivity",
    )
    second = parse_ui_hierarchy(
        MAIN_XML.replace("old@example.test", "ASL_DIFFERENT_CANARY"),
        expected_package="com.example.app",
        activity="com.example.app.MainActivity",
    )
    assert first.fingerprint == second.fingerprint
    assert first.nodes[0].editable is True
    assert first.nodes[0].text == "old@example.test"


def test_action_generation_is_safe_deduplicable_and_feedback_prioritized() -> None:
    state = parse_ui_hierarchy(
        MAIN_XML,
        expected_package="com.example.app",
        activity="com.example.app.MainActivity",
    )
    first_skips: list[dict[str, str]] = []
    first = build_actions(
        state,
        feedback=RuntimeFeedback(),
        allow_local_url=True,
        rng=__import__("random").Random(7),
        skipped=first_skips,
    )
    second = build_actions(
        state,
        feedback=RuntimeFeedback(),
        allow_local_url=True,
        rng=__import__("random").Random(7),
    )
    assert [item.identity for item in first] == [item.identity for item in second]
    assert len({item.identity for item in first}) == len(first)
    assert all("delete" not in item.label.casefold() for item in first)
    assert any(
        item["reason"] == "safety_denylist" and "delete" in item["label"]
        for item in first_skips
    )
    assert any(item["reason"] == "preexisting_input_preserved" for item in first_skips)
    assert is_safe_action_label("AES encrypt") is True
    assert is_safe_action_label("Delete account") is False


def test_network_actions_require_active_allowlist_guard() -> None:
    state = parse_ui_hierarchy(
        _xml(
            _node(
                text="Open browser",
                resource="com.example.app:id/browser",
            )
        ),
        expected_package="com.example.app",
        activity="com.example.app.MainActivity",
    )
    skipped: list[dict[str, str]] = []
    blocked = build_actions(
        state,
        feedback=RuntimeFeedback(),
        allow_local_url=True,
        network_guard_active=False,
        rng=__import__("random").Random(1),
        skipped=skipped,
    )
    allowed = build_actions(
        state,
        feedback=RuntimeFeedback(),
        allow_local_url=True,
        network_guard_active=True,
        rng=__import__("random").Random(1),
    )

    assert blocked == []
    assert [item["reason"] for item in skipped] == ["network_guard_required"]
    assert len(allowed) == 1


def test_missing_evidence_semantic_action_precedes_navigation() -> None:
    state = parse_ui_hierarchy(
        _xml(
            _node(text="About", resource="com.example.app:id/about"),
            _node(
                text="More options",
                resource="com.example.app:id/menu",
                bounds="[10,120][300,210]",
            ),
            _node(
                text="Encrypt data",
                resource="com.example.app:id/encrypt",
                bounds="[10,220][300,310]",
            ),
        ),
        expected_package="com.example.app",
        activity="com.example.app.MainActivity",
    )
    actions = build_actions(
        state,
        feedback=RuntimeFeedback(),
        allow_local_url=True,
        network_guard_active=True,
        rng=__import__("random").Random(1),
    )

    assert [action.resource_id for action in sorted(actions)] == [
        "com.example.app:id/encrypt",
        "com.example.app:id/menu",
        "com.example.app:id/about",
    ]


def test_collection_text_rows_are_actionable_when_uiautomator_omits_clickable() -> None:
    xml = _xml(
        '<node text="" resource-id="" class="android.widget.ListView" '
        'package="com.example.app" bounds="[0,0][400,800]" clickable="false" '
        'long-clickable="false" focusable="true" scrollable="false" password="false">'
        + _node(
            text="Encryption",
            resource="id/title",
            class_name="android.widget.TextView",
            clickable=False,
        )
        + "</node>"
    )
    state = parse_ui_hierarchy(
        xml,
        expected_package="com.example.app",
        activity="com.example.app.MainActivity",
    )
    assert next(node for node in state.nodes if node.text == "Encryption").clickable is True


def test_input_generation_uses_only_lab_values() -> None:
    base = UiNode(
        class_name="android.widget.EditText",
        package="com.example.app",
        resource_id="id/email",
        text="",
        content_description="",
        hint="",
        bounds=(0, 0, 100, 100),
        clickable=True,
        long_clickable=False,
        editable=True,
        scrollable=False,
        password=False,
        input_type="textEmailAddress",
    )
    assert classify_input(base, allow_local_url=True) == ("email", "user@example.test")
    password = replace(base, resource_id="id/password", password=True)
    assert classify_input(password, allow_local_url=True) == ("password", "123456")
    url = replace(base, resource_id="id/url", input_type="textUri")
    assert classify_input(url, allow_local_url=True) == ("url", "https://10.0.2.2/")
    assert classify_input(url, allow_local_url=False) == ("text", "test")
    assert is_input_candidate(replace(base, resource_id="id/hashing_result")) is False
    assert is_input_candidate(replace(base, resource_id="id/plaintext_encryption")) is True


def test_adb_input_dispatch_never_attempts_unverified_destructive_clear() -> None:
    commands: list[tuple[str, ...]] = []

    class Adb:
        def shell(self, _serial: str, arguments: tuple[str, ...], **_kwargs: object) -> object:
            commands.append(arguments)
            return SimpleNamespace(stdout="")

    backend = AdbExplorerBackend(
        Adb(),  # type: ignore[arg-type]
        serial="FAKE_SERIAL",
        package="com.example.app",
        session_id="20260717-210000-abcdef",
        per_action_timeout=2,
    )
    backend.input_text(10, 20, "test")
    assert ("input", "text", "test") in commands
    assert not any(
        "KEYCODE_DEL" in command or "KEYCODE_MOVE_END" in command
        for command in commands
    )


def test_adb_deep_link_dispatch_uses_argument_vector_without_remote_shell() -> None:
    commands: list[tuple[str, ...]] = []

    class Adb:
        def shell(self, _serial: str, arguments: tuple[str, ...], **_kwargs: object) -> object:
            commands.append(arguments)
            return SimpleNamespace(stdout="Status: ok")

    backend = AdbExplorerBackend(
        Adb(),  # type: ignore[arg-type]
        serial="FAKE_SERIAL",
        package="com.example.app",
        session_id="20260717-210000-abcdef",
        per_action_timeout=2,
    )
    uri = "https://10.0.2.2/lab?asl=canary"
    backend.start_deep_link(uri)

    assert commands == [
        (
            "am",
            "start",
            "-W",
            "-a",
            "android.intent.action.VIEW",
            "-d",
            uri,
            "-p",
            "com.example.app",
        )
    ]


def test_external_dialog_dismissal_is_limited_to_permission_controller(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Adb:
        def shell(self, *_args: object, **_kwargs: object) -> object:
            return SimpleNamespace(stdout="")

    backend = AdbExplorerBackend(
        Adb(),  # type: ignore[arg-type]
        serial="FAKE_SERIAL",
        package="com.example.app",
        session_id="20260717-210000-abcdef",
        per_action_timeout=2,
    )
    interactions: list[str] = []
    monkeypatch.setattr(
        backend,
        "current_activity",
        lambda: ("org.foreign.app", "org.foreign.app.DialogActivity"),
    )
    monkeypatch.setattr(backend, "dump_ui", lambda: interactions.append("dump") or "")
    monkeypatch.setattr(
        backend,
        "tap",
        lambda *_args, **_kwargs: interactions.append("tap"),
    )
    monkeypatch.setattr(backend, "back", lambda: interactions.append("back"))

    assert backend.dismiss_external_dialog() is False
    assert interactions == []

    permission_package = "com.android.permissioncontroller"
    permission_xml = _xml(
        _node(
            text="Deny",
            resource=f"{permission_package}:id/permission_deny_button",
            package=permission_package,
        )
    )
    monkeypatch.setattr(
        backend,
        "current_activity",
        lambda: (permission_package, f"{permission_package}.GrantPermissionsActivity"),
    )
    monkeypatch.setattr(backend, "dump_ui", lambda: permission_xml)

    assert backend.dismiss_external_dialog() is True
    assert interactions == ["tap"]


def test_review_permissions_turns_off_checked_switches_before_continue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Adb:
        def shell(self, *_args: object, **_kwargs: object) -> object:
            return SimpleNamespace(stdout="")

    permission_package = "com.android.permissioncontroller"
    backend = AdbExplorerBackend(
        Adb(),  # type: ignore[arg-type]
        serial="FAKE_SERIAL",
        package="com.example.app",
        session_id="20260717-210000-abcdef",
        per_action_timeout=2,
    )
    checked = True
    interactions: list[tuple[int, int]] = []

    def review_xml() -> str:
        return _xml(
            _node(
                text="Contacts",
                resource=f"{permission_package}:id/permission_switch",
                class_name="android.widget.Switch",
                bounds="[10,10][300,100]",
                checked=checked,
                package=permission_package,
            ),
            _node(
                text="Continue",
                resource=f"{permission_package}:id/continue_button",
                bounds="[10,120][300,210]",
                package=permission_package,
            ),
        )

    monkeypatch.setattr(
        backend,
        "current_activity",
        lambda: (
            permission_package,
            f"{permission_package}.permission.ui.ReviewPermissionsActivity",
        ),
    )
    monkeypatch.setattr(backend, "dump_ui", lambda: review_xml())

    def tap(x: int, y: int, **_kwargs: object) -> None:
        nonlocal checked
        interactions.append((x, y))
        if y < 110:
            checked = False

    monkeypatch.setattr(backend, "tap", tap)

    assert backend.dismiss_external_dialog() is True
    assert backend.dismiss_external_dialog() is True
    assert interactions == [(155, 55), (155, 165)]


def test_review_permissions_does_not_continue_without_permission_switch_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Adb:
        def shell(self, *_args: object, **_kwargs: object) -> object:
            return SimpleNamespace(stdout="")

    permission_package = "com.android.permissioncontroller"
    backend = AdbExplorerBackend(
        Adb(),  # type: ignore[arg-type]
        serial="FAKE_SERIAL",
        package="com.example.app",
        session_id="20260717-210000-abcdef",
        per_action_timeout=2,
    )
    interactions: list[str] = []
    review_xml = _xml(
        _node(
            text="Continue",
            resource=f"{permission_package}:id/continue_button",
            package=permission_package,
        )
    )
    monkeypatch.setattr(
        backend,
        "current_activity",
        lambda: (
            permission_package,
            f"{permission_package}.permission.ui.ReviewPermissionsActivity",
        ),
    )
    monkeypatch.setattr(backend, "dump_ui", lambda: review_xml)
    monkeypatch.setattr(backend, "tap", lambda *_args, **_kwargs: interactions.append("tap"))

    assert backend.dismiss_external_dialog() is False
    assert interactions == []


def test_legacy_system_ack_dialog_is_dismissed_without_touching_foreign_ui(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Adb:
        def shell(self, *_args: object, **_kwargs: object) -> object:
            return SimpleNamespace(stdout="")

    backend = AdbExplorerBackend(
        Adb(),  # type: ignore[arg-type]
        serial="FAKE_SERIAL",
        package="com.example.app",
        session_id="20260717-210000-abcdef",
        per_action_timeout=2,
    )
    interactions: list[str] = []
    system_xml = _xml(
        _node(
            text="OK",
            resource="android:id/button1",
            package="android",
        )
    )
    monkeypatch.setattr(
        backend,
        "current_activity",
        lambda: ("android", "android.app.DeprecatedTargetSdkVersionDialog"),
    )
    monkeypatch.setattr(backend, "dump_ui", lambda: system_xml)
    monkeypatch.setattr(backend, "tap", lambda *_args, **_kwargs: interactions.append("tap"))

    assert backend.dismiss_external_dialog() is True
    assert interactions == ["tap"]


def test_dump_ui_retries_transient_uiautomation_registration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []
    dump_attempts = 0

    class Adb:
        def shell(self, _serial: str, arguments: tuple[str, ...], **_kwargs: object) -> object:
            nonlocal dump_attempts
            calls.append(arguments)
            if arguments[:2] == ("uiautomator", "dump"):
                dump_attempts += 1
                if dump_attempts == 1:
                    raise AdbError("ADB failed: UiAutomationService already registered")
            if arguments[:1] == ("cat",):
                return SimpleNamespace(stdout="<hierarchy />")
            return SimpleNamespace(stdout="")

    monkeypatch.setattr("android_assessor.explorer.time.sleep", lambda _seconds: None)
    backend = AdbExplorerBackend(
        Adb(),  # type: ignore[arg-type]
        serial="FAKE_SERIAL",
        package="com.example.app",
        session_id="20260717-210000-abcdef",
        per_action_timeout=2,
    )

    assert backend.dump_ui() == "<hierarchy />"
    assert dump_attempts == 2
    assert sum(arguments[:2] == ("uiautomator", "dump") for arguments in calls) == 2
    assert sum(arguments[:1] == ("cat",) for arguments in calls) == 1


def test_disabled_hidden_and_output_fields_are_not_input_candidates() -> None:
    xml = _xml(
        _node(
            text="",
            resource="com.example.app:id/enabled_input",
            class_name="android.widget.EditText",
            editable=True,
        ),
        _node(
            text="",
            resource="com.example.app:id/disabled_input",
            class_name="android.widget.EditText",
            editable=True,
            enabled=False,
        ),
        _node(
            text="",
            resource="com.example.app:id/hidden_input",
            class_name="android.widget.EditText",
            editable=True,
            visible=False,
        ),
        _node(
            text="digest",
            resource="com.example.app:id/ciphertext_result",
            class_name="android.widget.EditText",
            editable=True,
        ),
    )
    state = parse_ui_hierarchy(
        xml,
        expected_package="com.example.app",
        activity="com.example.app.FormActivity",
    )
    by_id = {node.resource_id: node for node in state.nodes}
    assert by_id["com.example.app:id/disabled_input"].enabled is False
    assert by_id["com.example.app:id/hidden_input"].visible is False
    assert is_input_candidate(by_id["com.example.app:id/enabled_input"]) is True
    assert is_input_candidate(by_id["com.example.app:id/disabled_input"]) is False
    assert is_input_candidate(by_id["com.example.app:id/hidden_input"]) is False
    assert is_input_candidate(by_id["com.example.app:id/ciphertext_result"]) is False


def test_parser_and_actions_enforce_package_boundary() -> None:
    xml = _xml(
        _node(text="Scoped", resource="com.example.app:id/scoped"),
        _node(
            text="Foreign",
            resource="org.foreign.app:id/action",
            package="org.foreign.app",
        ),
        _node(text="Overlay", resource="id/overlay", package=""),
    )
    state = parse_ui_hierarchy(
        xml,
        expected_package="com.example.app",
        activity="com.example.app.MainActivity",
    )
    assert {node.package for node in state.nodes} == {"com.example.app"}
    actions = build_actions(
        state,
        feedback=RuntimeFeedback(),
        allow_local_url=False,
        rng=__import__("random").Random(1),
    )
    assert all("foreign" not in action.label.casefold() for action in actions)


def test_explorer_leaving_package_is_a_structured_termination() -> None:
    class BoundaryBackend(FakeBackend):
        def __init__(self) -> None:
            super().__init__()
            self.state = "main"
            self.left_package = False

        def dump_ui(self) -> str:
            self._command()
            self.ui_dump_count += 1
            return _xml(
                _node(
                    text="Open",
                    resource="com.example.app:id/open",
                    bounds="[10,120][300,210]",
                )
            ) if self.state == "main" else _xml(
                _node(
                    text="Child screen",
                    resource="com.example.app:id/title",
                    clickable=False,
                )
            )

        def current_activity(self) -> tuple[str | None, str | None]:
            self._command()
            if self.left_package:
                return "com.android.launcher3", "com.android.launcher3.Launcher"
            return "com.example.app", f"com.example.app.{self.state.title()}Activity"

        def tap(self, x: int, y: int, *, long: bool = False) -> None:
            self._command()
            del x, y, long
            if self.state == "main":
                self.stack.append("main")
                self.state = "child"

        def back(self) -> None:
            self._command()
            if self.state == "child":
                self.left_package = True
                self.stack.clear()

    backend = BoundaryBackend()
    clock = FakeClock()
    explorer = AndroidExplorer(
        backend,
        package="com.example.app",
        session_id="20260717-210000-abcdef",
        manifest={},
        scope=ScopeConfig(
            devices=frozenset({"FAKE_SERIAL"}),
            packages=frozenset({"com.example.app"}),
            api_hosts=frozenset(),
            allowed_actions=frozenset({"inspect", "autonomous_exploration"}),
        ),
        config=ExplorerConfig(
            max_runtime_seconds=4,
            plateau_seconds=2,
            max_states=5,
            max_actions=10,
        ),
        network_guard_active=True,
        clock=clock,
        sleeper=clock.sleep,
    )

    result = explorer.run()

    assert result.status == "completed"
    assert result.termination_reason == "package_boundary"
    assert backend.cleanup_called is True
    assert any(item["event"] == "exploration_stopped" for item in explorer.trace)


def test_explorer_service_requires_strict_device_package_scope(tmp_path: Path) -> None:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
    repository = SessionRepository(paths)
    record = repository.initialize(serial="FAKE_SERIAL", package="com.example.app")
    calls: list[tuple[str, str, str | None]] = []

    class StrictScope:
        def require_device_package(
            self,
            serial: str,
            package: str,
            *,
            action: str | None = None,
        ) -> None:
            calls.append((serial, package, action))
            raise ScopeError("outside strict active scope")

    with pytest.raises(ScopeError, match="strict active scope"):
        ExplorerService(paths, repository).run(
            record.session_id,
            adb=object(),  # type: ignore[arg-type]
            scope=StrictScope(),  # type: ignore[arg-type]
            config=ExplorerConfig(max_runtime_seconds=1),
            feedback=lambda: RuntimeFeedback(),
            stop_requested=lambda: False,
        )
    assert calls == [("FAKE_SERIAL", "com.example.app", "inspect")]


def test_explorer_service_requires_autonomous_exploration_action(tmp_path: Path) -> None:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
    repository = SessionRepository(paths)
    record = repository.initialize(serial="FAKE_SERIAL", package="com.example.app")
    scope = ScopeConfig(
        devices=frozenset({"FAKE_SERIAL"}),
        packages=frozenset({"com.example.app"}),
        api_hosts=frozenset({"10.0.2.2"}),
        allowed_actions=frozenset({"inspect", "controlled_validation"}),
    )

    with pytest.raises(ScopeError, match="autonomous_exploration"):
        ExplorerService(paths, repository).run(
            record.session_id,
            adb=object(),  # type: ignore[arg-type]
            scope=scope,
            config=ExplorerConfig(max_runtime_seconds=1),
            feedback=lambda: RuntimeFeedback(),
            stop_requested=lambda: False,
        )


def test_explorer_service_accepts_autonomous_action_without_controlled_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
    repository = SessionRepository(paths)
    record = repository.initialize(serial="FAKE_SERIAL", package="com.example.app")
    scope = ScopeConfig(
        devices=frozenset({"FAKE_SERIAL"}),
        packages=frozenset({"com.example.app"}),
        api_hosts=frozenset({"10.0.2.2"}),
        allowed_actions=frozenset({"inspect", "autonomous_exploration"}),
    )

    class Explorer:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            self.trace: list[dict[str, object]] = []

        def run(self) -> ExplorerResult:
            return ExplorerResult(
                session_id=record.session_id,
                status="completed",
                termination_reason="coverage_plateau",
                duration_ms=1.0,
                states_visited=1,
                activities_visited=("com.example.app.MainActivity",),
                actions_executed=0,
                input_actions=0,
                scroll_actions=0,
                backtracks=0,
                process_restarts=0,
                crashes=0,
                runtime_categories=(),
                runtime_methods=0,
                runtime_events=0,
                activity_attempts=(),
                deep_link_attempts=(),
            )

    monkeypatch.setattr("android_assessor.explorer.AndroidExplorer", Explorer)
    result = ExplorerService(paths, repository).run(
        record.session_id,
        adb=object(),  # type: ignore[arg-type]
        scope=scope,
        config=ExplorerConfig(max_runtime_seconds=1),
        feedback=lambda: RuntimeFeedback(),
        stop_requested=lambda: False,
    )

    assert result.status == "completed"


def test_bounded_traversal_backtracks_and_activates_runtime_categories() -> None:
    backend = FakeBackend()
    result, _, explorer = _run(backend)
    assert result.states_visited >= 3
    assert {"crypto", "webview"}.issubset(result.runtime_categories)
    assert result.input_actions == 0
    assert result.backtracks >= 1
    assert result.termination_reason == "coverage_plateau"
    assert backend.cleanup_called is True
    assert all("Delete" not in item for item in backend.inputs)
    assert any(
        item.get("event") == "action_skipped"
        and item.get("reason") == "safety_denylist"
        for item in explorer.trace
    )
    assert "old@example.test" not in json.dumps(explorer.trace)


def test_form_aware_retry_fills_minimum_input_and_retries_once() -> None:
    backend = FormRetryBackend()
    result, _, explorer = _run(
        backend,
        package="org.lab.form",
        config=ExplorerConfig(
            max_runtime_seconds=10,
            plateau_seconds=1,
            max_states=5,
            max_actions=10,
            per_action_timeout_seconds=1,
            monkey_events=0,
        ),
    )
    retries = [item for item in explorer.trace if item.get("event") == "form_retry"]
    assert backend.button_taps == 2
    assert backend.inputs == ["test"]
    assert result.form_retries == 1
    assert len(retries) == 1
    assert retries[0]["input_count"] == 1
    assert "crypto" in result.runtime_categories


def test_form_aware_retry_uses_exact_session_canary_without_tracing_value() -> None:
    backend = FormRetryBackend()
    canary = "THESIS_CANARY_20260718T010203Z_deadbeefcafe"
    _result, _, explorer = _run(
        backend,
        package="org.lab.form",
        session_canary=canary,
        config=ExplorerConfig(
            max_runtime_seconds=10,
            plateau_seconds=1,
            max_states=5,
            max_actions=10,
            per_action_timeout_seconds=1,
            monkey_events=0,
        ),
    )

    assert backend.inputs == [canary]
    assert canary not in json.dumps(explorer.trace)


def test_seeded_traversal_is_deterministic_and_deduplicates_actions() -> None:
    first_backend = FakeBackend()
    first, _, first_explorer = _run(first_backend)
    second_backend = FakeBackend()
    second, _, second_explorer = _run(second_backend)

    def actions(trace: list[dict[str, object]]) -> list[tuple[object, ...]]:
        return [
            (item.get("kind"), item.get("label"), item.get("resource_id"))
            for item in trace
            if item.get("event") == "action"
        ]

    assert actions(first_explorer.trace) == actions(second_explorer.trace)
    assert len(first_backend.tap_history) == len(set(first_backend.tap_history))
    assert first.duplicate_actions_avoided > 0
    assert second.duplicate_actions_avoided == first.duplicate_actions_avoided


def test_explorer_result_exposes_performance_metrics() -> None:
    backend = FakeBackend()
    result, _, _ = _run(backend)
    payload = result.to_dict()
    expected = {
        "actions_attempted",
        "actions_succeeded",
        "form_retries",
        "duplicate_actions_avoided",
        "safety_skips",
        "adb_command_count",
        "ui_dump_count",
        "adb_operation_ms",
        "idle_ms",
        "exploring_ms",
        "runtime_wait_ms",
    }
    assert expected <= payload.keys()
    assert result.actions_attempted >= result.actions_succeeded >= 0
    assert result.actions_attempted == result.actions_executed
    assert result.safety_skips >= 1
    assert result.adb_command_count > 0
    assert result.ui_dump_count > 0
    assert result.adb_operation_ms >= 0
    assert result.exploring_ms >= 0
    assert result.idle_ms >= 0
    assert abs(result.duration_ms - result.exploring_ms - result.idle_ms) < 0.01
    assert result.runtime_wait_ms >= 0


def test_runtime_feedback_collector_reads_only_appended_complete_events(tmp_path: Path) -> None:
    root = tmp_path / "session"
    frida_dir = root / "frida"
    traffic_dir = root / "traffic"
    frida_dir.mkdir(parents=True)
    traffic_dir.mkdir()
    (frida_dir / "state.json").write_text(
        json.dumps({"raw_events_path": "frida/events.jsonl"}),
        encoding="utf-8",
    )
    events = frida_dir / "events.jsonl"
    events.write_text(
        json.dumps({"type": "observer_started"})
        + "\n"
        + json.dumps({"category": "crypto", "method": "cipher.init"})
        + "\n",
        encoding="utf-8",
    )
    collector = RuntimeFeedbackCollector(
        SimpleNamespace(root=root, frida_dir=frida_dir, traffic_dir=traffic_dir)
    )

    first = collector.poll()
    assert first.event_count == 1
    assert first.methods == frozenset({"cipher.init"})
    with events.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"category": "webview", "method": "webview.load_url"}))
    assert collector.poll().event_count == 1
    with events.open("a", encoding="utf-8") as stream:
        stream.write("\n")

    final = collector.poll()
    assert final.event_count == 2
    assert final.categories == frozenset({"crypto", "webview"})


def test_repeated_runtime_events_do_not_reset_novelty_plateau() -> None:
    before = RuntimeFeedback(
        categories=frozenset({"crypto"}),
        methods=frozenset({"cipher.init"}),
        traffic_hosts=frozenset(),
        event_count=1,
    )
    after = replace(before, event_count=50)

    assert AndroidExplorer._feedback_changed(before, after) is False


def test_same_control_can_run_once_per_distinct_ui_state() -> None:
    backend = RepeatedControlBackend()
    result, _, _ = _run(
        backend,
        package="org.lab.repeat",
        config=ExplorerConfig(
            max_runtime_seconds=8,
            plateau_seconds=1,
            max_states=5,
            max_actions=8,
            per_action_timeout_seconds=1,
            monkey_events=0,
        ),
    )

    assert result.states_visited == 2
    assert backend.run_taps == 2
    assert "crypto" in result.runtime_categories


def test_plateau_clock_advances_only_during_true_idle() -> None:
    backend = SlowTerminalBackend()
    result, clock, _ = _run(
        backend,
        package="org.lab.viewer",
        config=ExplorerConfig(
            max_runtime_seconds=15,
            plateau_seconds=1,
            max_states=5,
            max_actions=5,
            per_action_timeout_seconds=1,
            monkey_events=0,
        ),
    )
    assert result.termination_reason == "coverage_plateau"
    assert result.idle_ms >= 1_000
    assert result.exploring_ms > result.idle_ms
    assert clock.value >= 1.0 + (backend.ui_dump_count * 1.2)


def test_hard_timeout_stops_slow_active_exploration() -> None:
    backend = SlowTerminalBackend()
    result, clock, _ = _run(
        backend,
        package="org.lab.viewer",
        config=ExplorerConfig(
            max_runtime_seconds=3,
            plateau_seconds=2,
            max_states=5,
            max_actions=10,
            per_action_timeout_seconds=2,
            monkey_events=0,
        ),
    )
    assert result.termination_reason == "max_runtime"
    assert result.scroll_actions == 0
    assert clock.value < 3
    assert backend.cleanup_called is True


def test_random_monkey_fallback_is_refused_by_safety_policy() -> None:
    backend = FakeBackend()
    backend.state = "web"
    result, _, explorer = _run(
        backend,
        config=ExplorerConfig(
            max_runtime_seconds=5,
            plateau_seconds=1,
            max_states=3,
            max_actions=5,
            per_action_timeout_seconds=1,
            monkey_events=3,
        ),
    )
    assert backend.monkey_calls == 0
    assert result.safety_skips >= 1
    assert any(
        item.get("reason") == "unsafe_random_fallback_disabled"
        for item in explorer.trace
    )


def test_scroll_discovers_a_new_state_and_runtime_action() -> None:
    backend = ScrollBackend()
    result, _, _ = _run(
        backend,
        package="org.lab.catalog",
        config=ExplorerConfig(
            max_runtime_seconds=8,
            plateau_seconds=1,
            max_states=5,
            max_actions=8,
            per_action_timeout_seconds=1,
            monkey_events=0,
        ),
    )
    assert result.scroll_actions >= 1
    assert result.states_visited == 2
    assert "webview" in result.runtime_categories


def test_activity_and_deep_link_discovery_enforce_allowlisted_hosts() -> None:
    backend = FakeBackend()
    manifest = {
        "components": [
            {
                "component_type": "activity",
                "name": "com.example.app.ExportedActivity",
                "effective_exported": True,
                "enabled": True,
            },
            {
                "component_type": "activity",
                "name": "org.foreign.app.ExternalActivity",
                "effective_exported": True,
                "enabled": True,
            },
        ],
        "deep_links": [
            {
                "component": "com.example.app.ExportedActivity",
                "scheme": "https",
                "host": "10.0.2.2",
                "path": "/lab",
            },
            {
                "component": "com.example.app.ExportedActivity",
                "scheme": "https",
                "host": "external.example",
                "path": "/blocked",
            },
        ],
    }
    result, _, _ = _run(
        backend,
        manifest=manifest,
        config=ExplorerConfig(
            max_runtime_seconds=3,
            plateau_seconds=1,
            max_states=2,
            max_actions=2,
            per_action_timeout_seconds=1,
            monkey_events=0,
        ),
    )
    assert backend.started_activities == ["com.example.app.ExportedActivity"]
    assert backend.deep_links == ["https://10.0.2.2/lab?asl=canary"]
    assert {item["status"] for item in result.deep_link_attempts} == {"opened", "blocked"}
    assert any(
        item["status"] == "blocked" and item.get("reason") == "package_mismatch"
        for item in result.activity_attempts
    )
    assert any(
        item.get("component") == "com.example.app.ExportedActivity"
        and item["status"] == "blocked"
        and item.get("reason") == "activity_not_resumed"
        for item in result.activity_attempts
    )


def test_allowlisted_deep_link_uses_exact_session_canary() -> None:
    backend = FakeBackend()
    canary = "THESIS_CANARY_20260718T010203Z_deadbeefcafe"
    _run(
        backend,
        session_canary=canary,
        manifest={
            "deep_links": [
                {
                    "component": "com.example.app.MainActivity",
                    "scheme": "https",
                    "host": "10.0.2.2",
                    "path": "/lab",
                }
            ]
        },
        config=ExplorerConfig(
            max_runtime_seconds=3,
            plateau_seconds=1,
            max_states=2,
            max_actions=1,
            per_action_timeout_seconds=1,
            monkey_events=0,
        ),
    )

    assert backend.deep_links == [f"https://10.0.2.2/lab?asl={canary}"]


def test_deep_link_manifest_path_is_percent_encoded_before_dispatch() -> None:
    backend = FakeBackend()
    manifest = {
        "deep_links": [
            {
                "component": "com.example.app.MainActivity",
                "scheme": "https",
                "host": "10.0.2.2",
                "path": "/lab;touch /data/local/tmp/unsafe",
            }
        ]
    }
    _run(
        backend,
        manifest=manifest,
        config=ExplorerConfig(
            max_runtime_seconds=3,
            plateau_seconds=1,
            max_states=2,
            max_actions=1,
            per_action_timeout_seconds=1,
            monkey_events=0,
        ),
    )
    assert len(backend.deep_links) == 1
    assert ";" not in backend.deep_links[0]
    assert "%3B" in backend.deep_links[0]
    assert "%20" in backend.deep_links[0]


def test_process_crash_is_recovered_with_bounded_relaunch() -> None:
    backend = FakeBackend()
    backend.crash_on_encrypt = True
    result, _, _ = _run(backend)
    assert result.crashes == 1
    assert result.process_restarts == 1
    assert backend.launches == 1
    assert backend.cleanup_called is True


def test_cleanup_runs_when_backend_raises_an_unexpected_error() -> None:
    class BrokenBackend(FakeBackend):
        def dump_ui(self) -> str:
            self._command()
            raise RuntimeError("synthetic backend failure")

    backend = BrokenBackend()
    with pytest.raises(RuntimeError, match="synthetic backend failure"):
        _run(backend)
    assert backend.cleanup_called is True


def test_plateau_and_action_limits_are_distinct() -> None:
    backend = FakeBackend()
    result, _, _ = _run(
        backend,
        config=ExplorerConfig(
            max_runtime_seconds=10,
            plateau_seconds=5,
            max_states=10,
            max_actions=1,
            per_action_timeout_seconds=1,
            monkey_events=0,
        ),
    )
    assert result.termination_reason == "max_actions"


def test_production_explorer_has_no_benchmark_package_hardcode() -> None:
    root = Path(__file__).parent.parent
    production_roots = [root / name for name in ("android_assessor", "web", "hooks", "rules")]
    source = "\n".join(
        path.read_text(encoding="utf-8", errors="ignore")
        for production_root in production_roots
        for path in production_root.rglob("*")
        if path.is_file() and path.suffix in {".py", ".js", ".html", ".j2", ".yaml"}
    ).casefold()
    assert "com.htbridge.pivaa" not in source
    assert "pivaa" not in source
