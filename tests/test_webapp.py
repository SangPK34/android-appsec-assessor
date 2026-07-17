from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from android_assessor.errors import AndroidAssessorError, DeviceSelectionError
from android_assessor.paths import ProjectPaths
from android_assessor.webapp import create_app


class FakeWebBackend:
    def __init__(self) -> None:
        self.selected_serials: list[str] = []
        self.selected_packages: list[str] = []
        self.cleaned_sessions: list[str] = []
        self.scan_sessions: list[str] = []
        self.scan_profiles: list[str] = []
        self.scan_failure: Exception | None = None
        self.repair_starts = 0

    def environment(self) -> dict[str, Any]:
        return {
            "ready": True,
            "host": {"windows_admin": False},
            "components": [
                {
                    "name": "adb",
                    "status": "ok",
                    "required": True,
                    "version": "Android Debug Bridge 1.0.41",
                    "source": "portable",
                    "path": "D:/Lab/tools/platform-tools/adb.exe",
                    "error": None,
                }
            ],
        }

    def dashboard(self) -> dict[str, Any]:
        return {
            "environment": self.environment(),
            "device_count": 1,
            "authorized_count": 1,
            "device": {
                "manufacturer": "Google",
                "model": "Pixel 4 XL",
                "serial": "AB****7890",
                "android_version": "13",
                "sdk": "33",
                "security_patch": "2023-10-05",
                "build_id": "TQ3A",
                "abi": "arm64-v8a",
            },
            "device_error": None,
            "target_package": "com.example.lab",
            "proxy": None,
            "capabilities": [
                {
                    "name": "ANDROID_ROOT",
                    "state": "available",
                    "reason": "su returned uid=0.",
                },
                {
                    "name": "FRIDA_SERVER",
                    "state": "unavailable",
                    "reason": "No known Frida Server process was detected.",
                },
            ],
            "active_session": None,
            "session_count": 1,
            "pending_cleanup_count": 0,
            "device_lock": None,
        }

    def devices(self) -> dict[str, Any]:
        return {
            "active_serial": "ABCDEF7890",
            "active_serial_masked": "AB****7890",
            "selected_connected": True,
            "devices": [
                {
                    "serial": "AB****7890",
                    "serial_masked": "AB****7890",
                    "selection_value": "ABCDEF7890",
                    "state": "device",
                    "authorized": True,
                    "model": "Pixel_4_XL",
                    "product": "coral",
                    "device": "coral",
                    "transport_id": "1",
                    "selected": True,
                    "guidance": None,
                    "lock": None,
                }
            ],
        }

    def select_device(self, serial: str) -> dict[str, Any]:
        self.selected_serials.append(serial)
        return {"serial": "AB****7890"}

    def applications(self, query: str = "") -> dict[str, Any]:
        applications = [
            {
                "package": "com.example.lab",
                "uid": 10123,
                "apk_path": "/data/app/com.example.lab/base.apk",
                "selected": True,
            }
        ]
        if query and query.casefold() not in "com.example.lab":
            applications = []
        return {
            "serial_masked": "AB****7890",
            "selected_package": "com.example.lab",
            "query": query,
            "applications": applications,
        }

    def select_application(self, package: str) -> dict[str, Any]:
        self.selected_packages.append(package)
        return {"package": package}

    def sessions(self) -> list[dict[str, Any]]:
        return [
            {
                "session_id": "20260717-021530-a8f4c2",
                "created_at": "2026-07-17T02:15:30+00:00",
                "updated_at": "2026-07-17T02:16:30+00:00",
                "status": "cleanup_required",
                "serial": "AB****7890",
                "package": "com.example.lab",
                "last_error": None,
                "cleanup_action_count": 2,
                "pending_cleanup": True,
            }
        ]

    def app_inspection(self, session_id: str) -> dict[str, Any]:
        return {
            "session_id": session_id,
            "package": "com.example.lab",
            "inspection_status": "completed",
            "metadata": {"version_name": "1.0", "version_code": 1},
            "apks": [],
            "manifest": None,
        }

    def session_detail(self, session_id: str) -> dict[str, Any]:
        return {
            "session": {
                "session_id": session_id,
                "status": "active",
                "serial_masked": "AB****7890",
                "package": "com.example.lab",
                "pending_cleanup": False,
                "cleanup_success": None,
            },
            "app": {"inspection_status": "completed"},
            "scan": None,
            "traffic": None,
            "frida": None,
            "findings": [],
            "evidence_count": 0,
            "report_available": False,
        }

    def scan_session(self, session_id: str, profile: str = "quick") -> dict[str, Any]:
        self.scan_sessions.append(session_id)
        self.scan_profiles.append(profile)
        if self.scan_failure is not None:
            raise self.scan_failure
        return {"session_id": session_id, "status": "completed"}

    def cleanup_session(self, session_id: str) -> dict[str, Any]:
        self.cleaned_sessions.append(session_id)
        return {"success": True, "session_id": session_id}

    def repair_status(self) -> dict[str, Any]:
        return {"running": False, "pid": None, "exit_code": None}

    def start_repair(self) -> dict[str, Any]:
        self.repair_starts += 1
        return {"running": True, "pid": 4321, "exit_code": None}

    def setup_log(self) -> str:
        return "[OK] Setup complete.\n"


def make_client() -> tuple[TestClient, FakeWebBackend]:
    backend = FakeWebBackend()
    app = create_app(ProjectPaths.discover(), backend=backend)
    return TestClient(app), backend


def test_health_endpoint_is_local_service_identity() -> None:
    client, _backend = make_client()

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["service"] == "android-security-lab"
    assert response.json()["status"] == "ok"
    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_main_pages_render_local_htmx_ui_without_shell_controls() -> None:
    client, _backend = make_client()

    pages = {
        "/": "Capability detection",
        "/devices": "ADB inventory",
        "/applications": "Package inventory",
        "/sessions": "Session history",
        "/environment": "Environment / Diagnostics",
    }
    for path, expected in pages.items():
        response = client.get(path)
        assert response.status_code == 200
        assert expected in response.text
        assert 'src="/static/htmx.min.js"' in response.text
        assert "PowerShell command" not in response.text
        assert "ADB shell" not in response.text


def test_device_selection_requires_action_token() -> None:
    client, backend = make_client()

    denied = client.post(
        "/devices/select",
        data={"serial": "ABCDEF7890", "action_token": "wrong"},
    )
    accepted = client.post(
        "/devices/select",
        data={
            "serial": "ABCDEF7890",
            "action_token": client.app.state.action_token,
        },
        follow_redirects=False,
    )

    assert denied.status_code == 403
    assert backend.selected_serials == ["ABCDEF7890"]
    assert accepted.status_code == 303
    assert accepted.headers["location"].startswith("/devices?notice=")


def test_htmx_package_selection_returns_safe_local_redirect() -> None:
    client, backend = make_client()

    response = client.post(
        "/applications/select",
        data={
            "package": "com.example.lab",
            "action_token": client.app.state.action_token,
        },
        headers={"HX-Request": "true"},
    )

    assert response.status_code == 204
    assert response.headers["hx-redirect"].startswith("/applications?notice=")
    assert backend.selected_packages == ["com.example.lab"]


def test_app_scan_form_has_visible_progress_and_error_swap_contract() -> None:
    client, _backend = make_client()
    session_id = "20260717-021530-a8f4c2"

    response = client.get(f"/sessions/{session_id}/app")

    assert response.status_code == 200
    assert "Start MVP scan" not in response.text
    assert "Quick Scan" in response.text
    assert "Full Assessment" in response.text
    assert 'name="profile" value="quick"' in response.text
    assert 'name="profile" value="full"' in response.text
    assert f'hx-post="/sessions/{session_id}/scan"' in response.text
    assert 'hx-target="body"' in response.text
    assert 'hx-select="body"' in response.text
    assert 'hx-swap="outerHTML"' in response.text
    assert 'hx-disabled-elt="find button"' in response.text
    assert 'id="scan-feedback"' in response.text
    assert "Starting scan" in response.text


def test_scan_success_uses_single_backend_call_and_htmx_redirect() -> None:
    client, backend = make_client()
    session_id = "20260717-021530-a8f4c2"

    response = client.post(
        f"/sessions/{session_id}/scan",
        data={"action_token": client.app.state.action_token},
        headers={"HX-Request": "true"},
    )

    assert response.status_code == 204
    assert response.headers["hx-redirect"] == f"/sessions/{session_id}?notice=Quick+scan+completed."
    assert backend.scan_sessions == [session_id]
    assert backend.scan_profiles == ["quick"]


def test_full_assessment_profile_is_forwarded_once() -> None:
    client, backend = make_client()
    session_id = "20260717-021530-a8f4c2"

    response = client.post(
        f"/sessions/{session_id}/scan",
        data={
            "action_token": client.app.state.action_token,
            "profile": "full",
        },
        headers={"HX-Request": "true"},
    )

    assert response.status_code == 204
    assert backend.scan_sessions == [session_id]
    assert backend.scan_profiles == ["full"]


@pytest.mark.parametrize(
    "failure",
    [
        "Scope denied for action inspect.",
        "Device offline.",
        "Package does not exist.",
        "backend scan exception",
    ],
)
def test_scan_failure_is_visible_to_htmx(
    failure: str,
) -> None:
    client, backend = make_client()
    backend.scan_failure = AndroidAssessorError(failure)
    session_id = "20260717-021530-a8f4c2"

    response = client.post(
        f"/sessions/{session_id}/scan",
        data={"action_token": client.app.state.action_token},
        headers={"HX-Request": "true"},
    )

    assert response.status_code == 200
    assert failure in response.text
    assert "operation=scan" in response.text
    assert "device=AB****7890" in response.text
    assert "package=com.example.lab" in response.text
    assert f"session={session_id}" in response.text
    assert 'role="alert"' in response.text
    assert backend.scan_sessions == [session_id]


def test_scan_unexpected_failure_is_safe_and_visible_to_htmx() -> None:
    client, backend = make_client()
    backend.scan_failure = RuntimeError("fixture internal detail")
    session_id = "20260717-021530-a8f4c2"

    response = client.post(
        f"/sessions/{session_id}/scan",
        data={"action_token": client.app.state.action_token},
        headers={"HX-Request": "true"},
    )

    assert response.status_code == 200
    assert "category=internal_error" in response.text
    assert "internal error." in response.text
    assert "fixture internal detail" not in response.text
    assert 'role="alert"' in response.text


def test_cleanup_and_repair_are_fixed_token_protected_actions() -> None:
    client, backend = make_client()
    token = client.app.state.action_token
    session_id = "20260717-021530-a8f4c2"

    cleanup = client.post(
        f"/sessions/{session_id}/cleanup",
        data={"action_token": token},
        follow_redirects=False,
    )
    repair = client.post(
        "/environment/repair",
        data={"action_token": token},
        follow_redirects=False,
    )

    assert cleanup.status_code == 303
    assert repair.status_code == 303
    assert backend.cleaned_sessions == [session_id]
    assert backend.repair_starts == 1


def test_setup_log_and_local_htmx_asset_are_served() -> None:
    client, _backend = make_client()

    log = client.get("/environment/setup-log")
    htmx = client.get("/static/htmx.min.js")

    assert log.status_code == 200
    assert "Setup complete" in log.text
    assert htmx.status_code == 200
    assert len(htmx.content) >= 50_000


def test_applications_page_is_a_graceful_empty_state_without_selected_device() -> None:
    client, backend = make_client()

    def no_selected_device(_query: str = "") -> dict[str, Any]:
        raise DeviceSelectionError("No ADB devices are connected.")

    backend.applications = no_selected_device  # type: ignore[method-assign]

    response = client.get("/applications")

    assert response.status_code == 200
    assert "Không có package để hiển thị" in response.text
    assert "No ADB devices are connected" in response.text
