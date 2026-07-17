"""Local-only FastAPI, Jinja2, and HTMX web application."""

from __future__ import annotations

import logging
import os
import secrets
from contextlib import AbstractContextManager
from types import TracebackType
from typing import Annotated, Any
from urllib.parse import urlencode

import uvicorn
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import __version__
from .errors import AndroidAssessorError, ConfigurationError, DeviceBusyError
from .paths import ProjectPaths
from .redaction import redact_text
from .web_service import WebBackend, WebBackendProtocol

logger = logging.getLogger(__name__)


class WebInstanceLock(AbstractContextManager["WebInstanceLock"]):
    def __init__(self, paths: ProjectPaths) -> None:
        self.paths = paths
        self.handle = None
        self.lock_path = paths.state_dir / "web.lock"
        self.pid_path = paths.state_dir / "web.pid"

    def __enter__(self) -> WebInstanceLock:
        self.paths.state_dir.mkdir(parents=True, exist_ok=True)
        try:
            self.handle = self.lock_path.open("a+b")
            self.handle.seek(0)
            if self.handle.read(1) == b"":
                self.handle.seek(0)
                self.handle.write(b"0")
                self.handle.flush()
            self.handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if self.handle is not None:
                self.handle.close()
                self.handle = None
            raise ConfigurationError(
                "Another AndroidSecurityLab web instance is already running."
            ) from exc
        self.pid_path.write_text(str(os.getpid()) + "\n", encoding="ascii")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self.pid_path.exists():
            try:
                if self.pid_path.read_text(encoding="ascii").strip() == str(os.getpid()):
                    self.pid_path.unlink()
            except OSError:
                pass
        if self.handle is not None:
            try:
                self.handle.seek(0)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            finally:
                self.handle.close()
                self.handle = None


def create_app(
    paths: ProjectPaths | None = None,
    *,
    backend: WebBackendProtocol | None = None,
) -> FastAPI:
    project_paths = paths or ProjectPaths.discover()
    project_paths.ensure_layout()
    templates = Jinja2Templates(directory=project_paths.root / "web" / "templates")
    service = backend or WebBackend.create(project_paths)
    action_token = secrets.token_urlsafe(32)
    app = FastAPI(
        title="Android Security Lab",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.web_backend = service
    app.state.action_token = action_token
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["127.0.0.1", "localhost", "testserver"],
    )
    app.mount(
        "/static",
        StaticFiles(directory=project_paths.root / "web" / "static"),
        name="static",
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Any) -> Response:
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'self'"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    def expected_error(exc: Exception) -> str:
        return redact_text(str(exc))[:500]

    def query_notice(request: Request) -> str | None:
        value = request.query_params.get("notice")
        return redact_text(value)[:300] if value else None

    def render(
        request: Request,
        template: str,
        context: dict[str, Any],
        *,
        error: str | None = None,
        status_code: int = 200,
    ) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request,
            name=template,
            context={
                **context,
                "version": __version__,
                "current_path": request.url.path,
                "action_token": action_token,
                "notice": query_notice(request),
                "error": error,
            },
            status_code=status_code,
        )

    def verify_action_token(submitted: str) -> None:
        if not secrets.compare_digest(submitted, action_token):
            raise HTTPException(status_code=403, detail="Invalid local action token.")

    def action_redirect(request: Request, path: str, notice: str) -> Response:
        target = f"{path}?{urlencode({'notice': notice})}"
        if request.headers.get("HX-Request", "").casefold() == "true":
            return Response(status_code=204, headers={"HX-Redirect": target})
        return RedirectResponse(target, status_code=303)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "android-security-lab", "version": __version__}

    @app.get("/api/environment")
    def environment_api() -> dict[str, Any]:
        return service.environment()

    @app.get("/", response_class=HTMLResponse)
    def dashboard_page(request: Request) -> HTMLResponse:
        try:
            dashboard = service.dashboard()
            return render(request, "dashboard.html", {"dashboard": dashboard})
        except (AndroidAssessorError, OSError, ValueError) as exc:
            return render(
                request,
                "dashboard.html",
                {"dashboard": None},
                error=expected_error(exc),
                status_code=503,
            )

    @app.get("/devices", response_class=HTMLResponse)
    def devices_page(request: Request) -> HTMLResponse:
        try:
            inventory = service.devices()
            return render(request, "devices.html", {"inventory": inventory})
        except (AndroidAssessorError, OSError, ValueError) as exc:
            return render(
                request,
                "devices.html",
                {"inventory": {"devices": [], "active_serial_masked": None}},
                error=expected_error(exc),
                status_code=503,
            )

    @app.post("/devices/select")
    def select_device(
        request: Request,
        serial: Annotated[str, Form(min_length=1, max_length=128)],
        submitted_token: Annotated[str, Form(alias="action_token")],
    ) -> Response:
        verify_action_token(submitted_token)
        try:
            selected = service.select_device(serial)
        except (AndroidAssessorError, OSError, ValueError) as exc:
            try:
                inventory = service.devices()
            except (AndroidAssessorError, OSError, ValueError):
                inventory = {"devices": [], "active_serial_masked": None}
            return render(
                request,
                "devices.html",
                {"inventory": inventory},
                error=expected_error(exc),
                status_code=400,
            )
        return action_redirect(
            request,
            "/devices",
            f"Selected device {selected['serial']}.",
        )

    @app.get("/applications", response_class=HTMLResponse)
    def applications_page(request: Request, query: str = "") -> HTMLResponse:
        try:
            inventory = service.applications(query)
            return render(request, "applications.html", {"inventory": inventory})
        except (AndroidAssessorError, OSError, ValueError) as exc:
            return render(
                request,
                "applications.html",
                {
                    "inventory": {
                        "applications": [],
                        "selected_package": None,
                        "serial_masked": None,
                        "query": query[:100],
                    }
                },
                error=expected_error(exc),
                status_code=200,
            )

    @app.post("/applications/select")
    def select_application(
        request: Request,
        package: Annotated[str, Form(min_length=3, max_length=255)],
        submitted_token: Annotated[str, Form(alias="action_token")],
    ) -> Response:
        verify_action_token(submitted_token)
        try:
            selected = service.select_application(package)
        except (AndroidAssessorError, OSError, ValueError) as exc:
            try:
                inventory = service.applications()
            except (AndroidAssessorError, OSError, ValueError):
                inventory = {
                    "applications": [],
                    "selected_package": None,
                    "serial_masked": None,
                    "query": "",
                }
            return render(
                request,
                "applications.html",
                {"inventory": inventory},
                error=expected_error(exc),
                status_code=400,
            )
        return action_redirect(
            request,
            "/applications",
            f"Selected package {selected['package']}.",
        )

    @app.post("/applications/inspect")
    def inspect_application(
        request: Request,
        package: Annotated[str, Form(min_length=3, max_length=255)],
        submitted_token: Annotated[str, Form(alias="action_token")],
    ) -> Response:
        verify_action_token(submitted_token)
        try:
            inspection = service.inspect_application(package)
        except (AndroidAssessorError, OSError, ValueError) as exc:
            try:
                inventory = service.applications()
            except (AndroidAssessorError, OSError, ValueError):
                inventory = {
                    "applications": [],
                    "selected_package": None,
                    "serial_masked": None,
                    "query": "",
                }
            return render(
                request,
                "applications.html",
                {"inventory": inventory},
                error=expected_error(exc),
                status_code=400,
            )
        return action_redirect(
            request,
            f"/sessions/{inspection['session_id']}/app",
            "App inspection completed.",
        )

    @app.get("/sessions/{session_id}/app", response_class=HTMLResponse)
    def app_inspection_page(request: Request, session_id: str) -> HTMLResponse:
        try:
            inspection = service.app_inspection(session_id)
            return render(
                request,
                "app_detail.html",
                {"inspection": inspection},
            )
        except (AndroidAssessorError, OSError, ValueError) as exc:
            return render(
                request,
                "app_detail.html",
                {"inspection": None},
                error=expected_error(exc),
                status_code=404,
            )

    def render_session_detail(
        request: Request,
        session_id: str,
        *,
        error: str | None = None,
        status_code: int = 200,
    ) -> HTMLResponse:
        try:
            detail = service.session_detail(session_id)
        except (AndroidAssessorError, OSError, ValueError) as exc:
            return render(
                request,
                "scan.html",
                {"detail": None},
                error=error or expected_error(exc),
                status_code=404,
            )
        return render(
            request,
            "scan.html",
            {"detail": detail},
            error=error,
            status_code=status_code,
        )

    @app.get("/sessions/{session_id}", response_class=HTMLResponse)
    def session_detail_page(request: Request, session_id: str) -> HTMLResponse:
        return render_session_detail(request, session_id)

    @app.post("/sessions/{session_id}/scan")
    def scan_session(
        request: Request,
        session_id: str,
        submitted_token: Annotated[str, Form(alias="action_token")],
    ) -> Response:
        verify_action_token(submitted_token)
        is_hx_request = request.headers.get("HX-Request", "").casefold() == "true"

        def scan_context() -> tuple[str, str]:
            try:
                detail = service.session_detail(session_id)
                session = detail.get("session")
                if isinstance(session, dict):
                    device = str(session.get("serial_masked") or "unknown")[:128]
                    package = str(session.get("package") or "unknown")[:255]
                    return device, package
            except (AndroidAssessorError, OSError, ValueError):
                pass
            return "unknown", "unknown"

        try:
            service.scan_session(session_id)
        except (AndroidAssessorError, OSError, ValueError) as exc:
            safe_error = expected_error(exc)
            device, package = scan_context()
            category = type(exc).__name__
            message = (
                f"Scan failed operation=scan device={device} package={package} "
                f"session={session_id} category={category}: {safe_error}"
            )
            logger.exception(
                "web scan failed operation=scan device=%s package=%s session=%s "
                "error_category=%s error=%s",
                device,
                package,
                session_id,
                category,
                safe_error,
            )
            return render_session_detail(
                request,
                session_id,
                error=message,
                status_code=(
                    200
                    if is_hx_request
                    else 409
                    if isinstance(exc, DeviceBusyError)
                    else 400
                ),
            )
        except Exception:
            device, package = scan_context()
            logger.exception(
                "web scan failed operation=scan device=%s package=%s session=%s "
                "error_category=internal_error",
                device,
                package,
                session_id,
            )
            return render_session_detail(
                request,
                session_id,
                error=(
                    f"Scan failed operation=scan device={device} package={package} "
                    f"session={session_id} category=internal_error: internal error."
                ),
                status_code=200 if is_hx_request else 500,
            )
        return action_redirect(request, f"/sessions/{session_id}", "MVP scan completed.")

    @app.post("/sessions/{session_id}/findings/{finding_id}/validate")
    def validate_finding(
        request: Request,
        session_id: str,
        finding_id: str,
        submitted_token: Annotated[str, Form(alias="action_token")],
    ) -> Response:
        verify_action_token(submitted_token)
        try:
            finding = service.validate_finding(session_id, finding_id)
        except (AndroidAssessorError, OSError, ValueError) as exc:
            return render_session_detail(
                request,
                session_id,
                error=expected_error(exc),
                status_code=409 if isinstance(exc, DeviceBusyError) else 400,
            )
        validation = finding.get("validation") or {}
        notice = f"Validation: {validation.get('status', 'completed')}."
        return action_redirect(request, f"/sessions/{session_id}", notice)

    @app.post("/sessions/{session_id}/traffic/start")
    def start_traffic(
        request: Request,
        session_id: str,
        submitted_token: Annotated[str, Form(alias="action_token")],
    ) -> Response:
        verify_action_token(submitted_token)
        try:
            service.start_traffic(session_id)
        except (AndroidAssessorError, OSError, ValueError) as exc:
            return render_session_detail(
                request,
                session_id,
                error=expected_error(exc),
                status_code=409 if isinstance(exc, DeviceBusyError) else 400,
            )
        return action_redirect(request, f"/sessions/{session_id}", "Traffic capture started.")

    @app.post("/sessions/{session_id}/traffic/stop")
    def stop_traffic(
        request: Request,
        session_id: str,
        submitted_token: Annotated[str, Form(alias="action_token")],
    ) -> Response:
        verify_action_token(submitted_token)
        try:
            service.stop_traffic(session_id)
        except (AndroidAssessorError, OSError, ValueError) as exc:
            return render_session_detail(
                request,
                session_id,
                error=expected_error(exc),
                status_code=409 if isinstance(exc, DeviceBusyError) else 400,
            )
        return action_redirect(request, f"/sessions/{session_id}", "Traffic capture stopped.")

    @app.post("/sessions/{session_id}/frida/start")
    def start_frida(
        request: Request,
        session_id: str,
        submitted_token: Annotated[str, Form(alias="action_token")],
    ) -> Response:
        verify_action_token(submitted_token)
        try:
            service.start_frida(session_id)
        except (AndroidAssessorError, OSError, ValueError) as exc:
            return render_session_detail(
                request,
                session_id,
                error=expected_error(exc),
                status_code=409 if isinstance(exc, DeviceBusyError) else 400,
            )
        return action_redirect(request, f"/sessions/{session_id}", "Frida observer started.")

    @app.post("/sessions/{session_id}/frida/stop")
    def stop_frida(
        request: Request,
        session_id: str,
        submitted_token: Annotated[str, Form(alias="action_token")],
    ) -> Response:
        verify_action_token(submitted_token)
        try:
            service.stop_frida(session_id)
        except (AndroidAssessorError, OSError, ValueError) as exc:
            return render_session_detail(
                request,
                session_id,
                error=expected_error(exc),
                status_code=409 if isinstance(exc, DeviceBusyError) else 400,
            )
        return action_redirect(request, f"/sessions/{session_id}", "Frida observer stopped.")

    @app.post("/sessions/{session_id}/report")
    def generate_report(
        request: Request,
        session_id: str,
        submitted_token: Annotated[str, Form(alias="action_token")],
    ) -> Response:
        verify_action_token(submitted_token)
        try:
            service.generate_report(session_id)
        except (AndroidAssessorError, OSError, ValueError) as exc:
            return render_session_detail(
                request,
                session_id,
                error=expected_error(exc),
                status_code=400,
            )
        return action_redirect(request, f"/sessions/{session_id}", "Report generated.")

    @app.get("/sessions/{session_id}/report", response_class=FileResponse)
    def open_report(session_id: str) -> FileResponse:
        try:
            path = service.report_path(session_id)
        except (AndroidAssessorError, OSError, ValueError) as exc:
            raise HTTPException(status_code=404, detail=expected_error(exc)) from exc
        return FileResponse(path, media_type="text/html")

    @app.get("/sessions", response_class=HTMLResponse)
    def sessions_page(request: Request) -> HTMLResponse:
        try:
            records = service.sessions()
            return render(request, "sessions.html", {"sessions": records})
        except (AndroidAssessorError, OSError, ValueError) as exc:
            return render(
                request,
                "sessions.html",
                {"sessions": []},
                error=expected_error(exc),
                status_code=503,
            )

    @app.post("/sessions/{session_id}/cleanup")
    def cleanup_session(
        request: Request,
        session_id: str,
        submitted_token: Annotated[str, Form(alias="action_token")],
    ) -> Response:
        verify_action_token(submitted_token)
        try:
            result = service.cleanup_session(session_id)
            if not result["success"]:
                records = service.sessions()
                return render(
                    request,
                    "sessions.html",
                    {"sessions": records},
                    error="Cleanup finished with one or more failed actions.",
                    status_code=409,
                )
        except (AndroidAssessorError, OSError, ValueError) as exc:
            try:
                records = service.sessions()
            except (AndroidAssessorError, OSError, ValueError):
                records = []
            status_code = 409 if isinstance(exc, DeviceBusyError) else 400
            return render(
                request,
                "sessions.html",
                {"sessions": records},
                error=expected_error(exc),
                status_code=status_code,
            )
        return action_redirect(request, "/sessions", f"Cleaned session {session_id}.")

    @app.get("/environment", response_class=HTMLResponse)
    def environment_page(request: Request) -> HTMLResponse:
        try:
            report = service.environment()
            repair = service.repair_status()
            return render(
                request,
                "environment.html",
                {"report": report, "repair": repair},
            )
        except (AndroidAssessorError, OSError, ValueError) as exc:
            return render(
                request,
                "environment.html",
                {
                    "report": {"ready": False, "host": {}, "components": []},
                    "repair": {"running": False, "exit_code": None},
                },
                error=expected_error(exc),
                status_code=503,
            )

    @app.post("/environment/repair")
    def start_repair(
        request: Request,
        submitted_token: Annotated[str, Form(alias="action_token")],
    ) -> Response:
        verify_action_token(submitted_token)
        try:
            repair = service.start_repair()
        except (AndroidAssessorError, OSError, ValueError) as exc:
            try:
                report = service.environment()
                status = service.repair_status()
            except (AndroidAssessorError, OSError, ValueError):
                report = {"ready": False, "host": {}, "components": []}
                status = {"running": False, "exit_code": None}
            return render(
                request,
                "environment.html",
                {"report": report, "repair": status},
                error=expected_error(exc),
                status_code=409,
            )
        return action_redirect(
            request,
            "/environment",
            f"Repair started as process {repair['pid']}.",
        )

    @app.get("/environment/setup-log", response_class=PlainTextResponse)
    def setup_log() -> PlainTextResponse:
        try:
            return PlainTextResponse(service.setup_log())
        except (AndroidAssessorError, OSError, ValueError) as exc:
            return PlainTextResponse(expected_error(exc), status_code=500)

    return app


def run_web(*, paths: ProjectPaths, host: str, port: int) -> int:
    if host != "127.0.0.1":
        raise ConfigurationError("Refusing to bind the web server outside 127.0.0.1.")
    if not 1024 < port <= 65535:
        raise ConfigurationError("Web port must be between 1025 and 65535.")
    with WebInstanceLock(paths):
        uvicorn.run(
            create_app(paths),
            host=host,
            port=port,
            log_level="info",
            access_log=False,
        )
    return 0
