# Giai đoạn 3 — Device, capability, session và cleanup core

## Mục tiêu

Hoàn thiện lõi Python có thể kiểm thử không cần Pixel thật: lựa chọn thiết bị rõ ràng, mọi lệnh thiết bị đều có `adb -s SERIAL`, tự phát hiện capability, tạo session có evidence layout, khóa modifying operation theo thiết bị và cleanup đúng những gì framework đã tạo.

## Kiến trúc

```text
CLI / Web service
      |
      v
AppContext -- binary/config wiring
      |
      +-- DeviceSelector -> active-device.json
      +-- DeviceService -> getprop + CapabilityDetector
      +-- SessionService -> snapshot + session layout
      `-- CleanupExecutor -> DeviceLock + cleanup action ledger
```

PowerShell không chứa logic Android. Core không dùng `shell=True`, `os.system`, command string từ form hay thiết bị đầu tiên do ADB tự chọn.

## File chính

- `adb.py`: parse trạng thái, wrapper host/device, getprop, settings và reverse.
- `device.py`: selection state và normalized device identity.
- `capabilities.py`, `root.py`, `magisk.py`: 15 capability, không crash khi capability riêng lẻ thiếu.
- `session.py`, `snapshot.py`: session ID, cấu trúc kết quả, event/action ledger và initial state.
- `device_lock.py`: file lock cross-process theo hash serial; metadata chỉ lưu serial đã mask.
- `cleanup.py`, `host_process.py`: cleanup LIFO/idempotent, kiểm tra PID + executable + Windows creation time trước khi terminate.
- `services/device_service.py`, `services/session_service.py`: orchestration cho CLI/web.

## Session layout hiện có

```text
results/<session-id>/
├── session.json
├── device.json
├── app.json
├── environment.json
├── findings.json
├── events.jsonl
├── commands.jsonl
├── evidence/
├── raw/README.txt
├── screenshots/
├── traffic/
├── frida/
├── logcat/
└── apk/
```

Report chỉ được tạo khi report engine tồn tại; không tạo file HTML giả. `raw/README.txt` cảnh báo dữ liệu nhạy cảm ngay trong từng session.

## Snapshot và cleanup

Snapshot đọc HTTP proxy, reverse mappings, Frida Server state và package preexistence. Thay đổi tương lai phải ghi một action whitelist trước hoặc ngay sau khi thành công. Cleanup chạy action theo thứ tự ngược, lưu attempts/status/error, và không chạy lại action đã `completed`/`skipped`.

Action hiện hỗ trợ: restore proxy từ snapshot, remove đúng reverse endpoint đã tạo, remove file chỉ dưới `/data/local/tmp/android-security-lab/`, stop đúng Frida PID sau khi kiểm tra cmdline và stop host process sau khi khớp role/path/PID/creation time. Không có arbitrary ADB shell action.

## CLI

```powershell
.\run.cmd devices --show-serial
.\run.cmd select-device --serial SERIAL
.\run.cmd inspect-device [--package PACKAGE] [--json]
.\run.cmd session create --package PACKAGE
.\run.cmd session list
.\run.cmd session show --session SESSION_ID
.\run.cmd cleanup --session SESSION_ID
```

Khi chỉ có một thiết bị, framework đề xuất selection nhưng vẫn không tự lưu selection. `unauthorized`, `offline`, `recovery`, `sideload` và driver error có hướng dẫn riêng.

## Xác minh

- 65 unit tests chạy bằng Python portable; không test nào chạm Pixel.
- Ruff và Python compile pass.
- CLI thật trong trạng thái không cắm thiết bị trả thông báo/exit code có kiểm soát.
- Windows process identity được probe read-only trên chính process test; không terminate process thật.

## Chưa làm

Web hiện chưa dùng các service mới. Chưa có app inventory/APK inspection, modifying proxy workflow, process controller cho scrcpy/mitmproxy/Frida, rules, validations hoặc report. Các phần này thuộc Giai đoạn 4–9 và phải dùng session/device lock hiện có.
