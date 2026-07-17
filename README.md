# AndroidSecurityLab

Framework Windows native cho đề tài **“Design and Evaluation of a Root-Assisted Framework for Dynamic Testing and Automated Vulnerability Validation of Android Applications.”** Bản 0.5.1 nối workflow MVP từ app inspection đến scan, validation, report và cleanup. Framework tự dò capability, dùng được với Android có hoặc không có root; chưa tuyên bố đã kiểm thử trên ma trận thiết bị thật.

## Cài và chạy

Yêu cầu: Windows 10/11 x64, user thường, Internet HTTPS trong lần setup đầu.

```text
1. Double-click setup.cmd (đọc và xác nhận Android SDK License một lần).
2. Cắm thiết bị Android, bật USB debugging và chấp nhận RSA prompt.
3. Double-click start.cmd.
4. Mở http://127.0.0.1:8765 nếu trình duyệt chưa tự mở.
```

Trước thao tác Scan/Validation, copy `config\scope.example.yaml` thành `config\scope.yaml` và điền đúng serial/package/host lab; thiếu scope thì framework từ chối mọi thao tác thay đổi theo deny-by-default.

CLI:

```powershell
.\run.cmd check
.\run.cmd self-test --json
.\run.cmd devices
.\run.cmd devices --show-serial
.\run.cmd select-device --serial SERIAL
.\run.cmd inspect-device
.\run.cmd inspect-app --serial SERIAL --package com.example.app
.\run.cmd scan --serial SERIAL --package com.example.app
.\run.cmd report --session SESSION_ID
.\run.cmd validate --session SESSION_ID --finding finding-asl-mvp-004
.\run.cmd session list
.\run.cmd cleanup --session SESSION_ID
.\run.cmd web
```

Nếu thiếu/hỏng component, chạy `repair.cmd`; Repair probe binary và lock Python rồi chỉ cài lại phần thiếu hoặc sai version. `update_tools.cmd` chỉ cài lại version đã review trong `config\tools.lock.json`; không tự nâng latest. Dev dependency chỉ cài khi cần: `setup.cmd -IncludeDev`.

## Setup làm gì

- Ưu tiên Python 3.12 x64 có sẵn để tạo `runtime\venv`; nếu không có, cài CPython embeddable 3.12.10 vào `runtime\python`.
- Cài dependency có lock/hash vào runtime local; không chạm Python hệ thống.
- Tải Platform Tools 37.0.0, scrcpy 4.0, Build Tools 37.0.0, Temurin JRE 21 và Frida Server đúng version cho bốn ABI Android chính; kiểm SHA-256 rồi cài atomically.
- Ghi `logs\setup.log`, `lab_environment.json` và state trong `runtime\state`.
- Không sửa PATH/registry/firewall, không bind `0.0.0.0`, không cài service/certificate và không cần Administrator hằng ngày.

Nếu Windows chưa nhận thiết bị, cài USB driver chính thức của hãng theo [danh sách OEM Android](https://developer.android.com/studio/run/oem-usb). Thiết bị Google dùng Google USB Driver; framework không cài driver âm thầm.

## Trạng thái MVP

Đã có: bootstrap/Repair portable; ADB luôn dùng `-s SERIAL`; device/package selection; session/snapshot/device lock/cleanup ledger; APK và manifest inspection; mitmdump qua `adb reverse`; Frida observer cố định; logcat theo target PID (có fallback cho Android cũ); 5 rule; 3 controlled validation; report JSON/HTML; và Web UI FastAPI/Jinja2/HTMX trên localhost. Thiết bị không root vẫn chạy inspection, APK/manifest, traffic và các rule không cần root; tác vụ root/Frida được đánh dấu `skipped` khi thiếu capability.

Giới hạn MVP: không phải full static analyzer; framework chỉ tự khởi động Frida Server khi Android có root; TLS/CA phụ thuộc cấu hình thiết bị lab; mapping MASVS/MASTG/CWE chưa xác minh được giữ là `mapping_pending`. API BOLA và test nâng cao để sau.

Raw evidence ở các giai đoạn sau có thể chứa dữ liệu nhạy cảm và sẽ nằm trong `results\<session>\raw`; không chia sẻ nguyên thư mục này.
