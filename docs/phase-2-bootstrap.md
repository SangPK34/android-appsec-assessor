# Giai đoạn 2 — Quyết định bootstrap Windows

## Kiến trúc chốt

```text
setup.cmd / repair.cmd
        |
        v
setup.ps1  -- download, checksum, atomic extraction, local runtime
        |
        v
android_assessor (Python core)
   |-- CLI: check, self-test, devices, web
   |-- environment + binary resolver
   |-- subprocess wrapper + redacted command log
   `-- local diagnostics web page
```

PowerShell chỉ làm bootstrap Windows. Mọi logic nghiệp vụ lâu dài nằm trong Python. Binary resolver dùng thứ tự: path cấu hình → tool portable → user PATH. Không sửa system PATH, registry, firewall, certificate store hay `Program Files`.

## Python runtime

- Baseline duy nhất của bootstrap là CPython 3.12 x64.
- Nếu tìm thấy CPython 3.12 x64 trên host, setup tạo `runtime/venv` và chỉ cài package vào venv đó.
- Nếu không có, setup giải nén CPython embeddable 3.12.10 vào `runtime/python`, bật local `site-packages`, thêm project root bằng đường dẫn tương đối trong `_pth`, bootstrap pip từ wheel đã pin rồi cài dependency tại chỗ.
- Python 3.13/3.14 trên host không được dùng thay thế để tránh drift. Python 3.11 không được chọn vì mitmproxy 12.2.3 yêu cầu Python 3.12+.

## Tool portable và nguồn đã pin

Metadata được xác minh ngày 2026-07-17. `update_tools.cmd` chỉ cài lại version trong manifest; không tự dò latest.

| Thành phần | Version | Nguồn | SHA-256 |
| --- | --- | --- | --- |
| CPython embeddable x64 | 3.12.10 | `python.org/ftp/python/3.12.10` | `4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3` |
| pip wheel | 26.1.2 | `files.pythonhosted.org` qua PyPI | `382ff9f685ee3bc25864f820aa50505825f10f5458ffff07e30a6d96e5715cab` |
| Android Platform Tools | 37.0.0 stable | `dl.google.com/android/repository` | `4fe305812db074cea32903a489d061eb4454cbc90a49e8fea677f4b7af764918` |
| scrcpy Win64 | 4.0 | GitHub release chính thức `Genymobile/scrcpy` | `75dbeb5b00e6f64292f26f70900ae55ca397786bdfb0b9bbeb481a0549047457` |
| Android Build Tools | 37.0.0 | `dl.google.com/android/repository` | `68075aa319ed8a01cf1a565ed1e61a3c1a801dd49191c35851248dc293c33b1a` |

Build Tools được cài để lấy `aapt2.exe` và `apksigner.jar`. `aapt2` chạy độc lập; `apksigner` cần Java và được báo `degraded` nếu chưa có portable JRE/system Java. Setup không âm thầm cài Java hoặc sửa PATH ở giai đoạn này.

Python dependency được pin trong các lock file. Core/web dùng wheel-only. `frida-tools` chỉ phát hành source distribution nên được tách thành optional lock và build cục bộ; mitmproxy cũng là optional install để lỗi một tool không phá toàn bộ bootstrap. Dev tools chỉ cài khi chạy `setup.cmd -IncludeDev`.

Để các lock dùng chung một runtime mà vẫn nhất quán, core pin Pydantic 2.11.7 và `typing-extensions` 4.14.0; mitmproxy 12.2.3 khai báo trần `typing-extensions<=4.14` trên Python dưới 3.13. Setup so khớp toàn bộ lock và self-test chạy thêm `pip check`, tránh trạng thái cài xong nhưng dependency graph đã vỡ.

## Layout và ownership

- Download cache: `runtime/downloads`; file đang tải có hậu tố `.part`.
- Setup state: `runtime/state`; kết quả self-test: `lab_environment.json`.
- Tool chỉ được thay thế sau khi archive đã xác minh và giải nén vào thư mục staging thành công.
- Repair kiểm tra executable/package trước, chỉ cài lại component lỗi, không đụng `results` hoặc session.
- Google USB Driver không được cài âm thầm. Diagnostics chỉ dẫn tới tài liệu chính thức: <https://developer.android.com/studio/run/win-usb>.

## Giới hạn có chủ ý của Giai đoạn 2

- Web hiện chỉ là diagnostics local và health check, chưa phải Dashboard/Scan MVP.
- Chưa có session, proxy snapshot, Frida server controller, APK inspection hoặc report scanner.
- Chưa bundle portable JRE, nên `apksigner` có thể ở trạng thái degraded dù file jar đã có.
- Chưa kiểm thử trên Pixel thật; unit test không chạm thiết bị.
