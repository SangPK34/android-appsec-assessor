# Giai đoạn 4 — Web MVP local

## Mục tiêu

Cung cấp giao diện chính chạy trên `127.0.0.1:8765` bằng FastAPI, Jinja2 và HTMX local, vẫn dùng cùng core/selection/session/cleanup với CLI. Không có terminal web, arbitrary command, frontend build pipeline hoặc auto-selection thiết bị.

## File tạo hoặc sửa

- `android_assessor/app.py`: parse user package và lưu target package theo selected device.
- `android_assessor/web_service.py`: facade cho device/app/session/environment và controller chỉ được chạy đúng `repair.cmd`.
- `android_assessor/webapp.py`: route, local action token, Trusted Host, CSP và security headers.
- `web/templates/*.html`, `web/static/app.css`: Dashboard, Devices, Applications, Sessions, Environment responsive.
- `web/static/htmx.min.js`: HTMX 2.0.10 được pin và kiểm SHA-256 qua `tools.lock.json`.
- `setup.ps1`: cài HTMX bằng download `.part`, checksum và atomic replace.
- `tests/test_app.py`, `tests/test_webapp.py`, `tests/test_web_service.py`: parser, selection, route, CSRF/action token và Repair.

## Kiến trúc

```text
Browser localhost
      |
FastAPI routes -- action token + fixed forms
      |
WebBackend
  +-- DeviceSelector / CapabilityDetector
  +-- ApplicationService
  +-- SessionRepository / CleanupExecutor / DeviceLock
  `-- Environment diagnostics / fixed RepairController
```

Mọi form thay đổi state chỉ gọi action đã định nghĩa. Serial chỉ hiển thị dạng mask; package/search/session được validator core kiểm tra trước khi qua process/filesystem boundary. HTMX chỉ progressive-enhance form/link nên trang vẫn dùng được khi JavaScript lỗi.

## Chạy trên Windows

```powershell
.\start.cmd
# hoặc
.\run.cmd web
```

Mở `http://127.0.0.1:8765`, vào **Devices** để chọn thiết bị rồi **Applications** để chọn package. **Sessions** chạy cleanup idempotent; **Environment** xem dependency hoặc chủ động bấm Repair. Web server từ chối bind ngoài `127.0.0.1`.

## Kiểm thử

```powershell
.\runtime\python\python.exe -m pytest -q
.\runtime\python\python.exe -m ruff check android_assessor tests
.\runtime\python\python.exe -m compileall -q android_assessor
.\run.cmd self-test
```

Unit test dùng fake ADB/backend, không tác động Pixel. HTTP smoke test trên server localhost thật xác nhận năm route, security header, HTMX local và trạng thái không cắm device. Visual/click pass bằng browser sidecar chưa chạy được vì môi trường thực thi không cung cấp browser. Không có tuyên bố test Pixel thật.

## Output mẫu

```text
GET /health       200 {"status":"ok","service":"android-security-lab","version":"0.4.0"}
GET /devices      200 (không tự chọn device)
POST action sai token -> 403
Environment       Ready / Repair required theo self-test thật
```

## Hoạt động, giới hạn và rủi ro

Hoạt động: Dashboard capability, device/package selection, session list/cleanup, setup-log và Repair; duplicate web instance vẫn bị khóa bởi PID/file lock. Chưa hoạt động: start/stop app, APK/manifest inspection, traffic, Frida control, scan/rules/report. Capability dashboard có thể mất vài giây vì cố ý probe trạng thái thật. Repair chạy khi người dùng bấm; nếu chính runtime Python hỏng và file đang bị Windows khóa, đóng web rồi chạy `repair.cmd` là đường phục hồi cuối.

## Bước tiếp theo

Giai đoạn 5: metadata/split APK pull/hash, aapt2 manifest/components/permission parsing và app inspection từ cả CLI lẫn Web UI.
