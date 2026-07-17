# Giai đoạn 1 — Audit `android_usb_pentest.sh`

## Phạm vi và kết luận

Script đầu vào có 1.262 dòng, 48 function và một dispatcher ở cuối file. Ý tưởng nghiệp vụ ADB/scrcpy/report có thể tái sử dụng, nhưng cách triển khai hiện tại gắn chặt với Kali, Bash, `apt`, quyền root Linux và menu terminal. Không nên chuyển cú pháp từng dòng sang PowerShell; cần tách bootstrap Windows khỏi core Python và tách thao tác chỉ đọc khỏi thao tác làm thay đổi thiết bị.

Companion `android_remote_center_v6.py` được `web_control_center()` tham chiếu nhưng không có trong đầu vào, vì vậy web cũ không thể audit sâu hơn và không được tái sử dụng như dependency ẩn.

## Inventory và migration theo từng function

| Chức năng cũ | Giữ lại | Viết lại | Chuyển sang setup | Loại bỏ | Lý do |
| --- | ---: | ---: | ---: | ---: | --- |
| `log_file` |  | ✓ |  |  | Đổi sang structured log, UTF-8, rotation và redaction. |
| `ok` | ✓ | ✓ |  |  | Giữ mức trạng thái, dùng logger thay vì ANSI Bash. |
| `info` | ✓ | ✓ |  |  | Giữ mức trạng thái, ghi console và file có cấu trúc. |
| `warn` | ✓ | ✓ |  |  | Giữ mức trạng thái, không nuốt lỗi gốc. |
| `err` | ✓ | ✓ |  |  | Giữ mức trạng thái, kèm exception/exit code rõ ràng. |
| `is_root` |  | ✓ |  | ✓ | Root Linux không còn ý nghĩa; tách Windows admin, ADB shell và Android `su`. |
| `has_cmd` | ✓ | ✓ |  |  | Dùng resolver theo config → portable → user PATH. |
| `scrcpy_supports` | ✓ | ✓ |  |  | Probe một lần và cache capability, không gọi `--help` lặp lại. |
| `add_scrcpy_common_args` | ✓ | ✓ |  |  | Dùng list argument Python, title gắn session. |
| `add_scrcpy_size_args` | ✓ | ✓ |  |  | Chỉ giữ Normal/Low bandwidth/Record. |
| `run_scrcpy_compatible` | ✓ | ✓ |  |  | Process riêng, PID tracking, timeout khởi động và cleanup theo ownership. |
| `pause` |  |  |  | ✓ | Không phù hợp CLI tái lập hoặc web request. |
| `title` |  |  |  | ✓ | UI terminal toàn màn hình được thay bằng CLI/web. |
| `init_log` | ✓ | ✓ | ✓ |  | Setup tạo layout; Python cấu hình app log khi chạy. |
| `find_adb` | ✓ | ✓ |  |  | Thứ tự cũ ưu tiên PATH; bản mới ưu tiên config và portable. |
| `find_scrcpy` | ✓ | ✓ |  |  | Bản cũ gần như chỉ tìm system binary; bản mới tìm portable trước PATH. |
| `show_broken_scrcpy_hint` |  | ✓ |  | ✓ | Lỗi GLIBC biến mất trên Windows; thay bằng diagnostics và Repair. |
| `fix_scrcpy_kali` |  |  | ✓ | ✓ | Bỏ `apt`, root Linux và workaround GLIBC; Repair cài archive Windows đã pin. |
| `adb_cmd` | ✓ | ✓ |  |  | `subprocess` list args, timeout, command log redacted và exception riêng. |
| `print_install_help` | ✓ | ✓ | ✓ |  | Chuyển thành Environment/Diagnostics với repair hint cụ thể. |
| `check_network_basic` |  | ✓ | ✓ | ✓ | Bỏ route/DNS Kali; downloader chỉ kiểm tra HTTPS endpoint cần tải. |
| `write_repo_new` |  |  |  | ✓ | Không sửa `/etc/apt/sources.list`; còn dùng mirror HTTP. |
| `write_repo_old` |  |  |  | ✓ | Không có repository Linux trong thiết kế Windows native. |
| `apt_repair_install` |  |  |  | ✓ | Thay hoàn toàn bằng `setup.ps1`/`repair.cmd` không cần admin hằng ngày. |
| `download_file` | ✓ | ✓ | ✓ |  | Retry hữu hạn, timeout, `.part`, size, SHA-256 và atomic rename. |
| `extract_zip` | ✓ | ✓ | ✓ |  | Safe extraction chống path traversal và atomic directory swap. |
| `install_platform_tools_no_apt` | ✓ | ✓ | ✓ |  | Dùng archive Windows versioned từ Google, không sửa PATH. |
| `check_env` | ✓ | ✓ |  |  | Self-test JSON gồm version/path/status/error/repair hint. |
| `adb_start` | ✓ | ✓ |  |  | Chỉ start/restart khi cần; không kill server Android Studio vô cớ. |
| `first_device` |  |  |  | ✓ | Không tự chọn thiết bị đầu tiên; đây là lỗi scope khi có nhiều device. |
| `list_devices` | ✓ | ✓ |  |  | Parse đủ `device`, `unauthorized`, `offline`, recovery/sideload và metadata. |
| `require_device` | ✓ | ✓ |  |  | Chọn serial rõ ràng; một device có thể được đề xuất, nhiều device phải chọn. |
| `adb_shell` | ✓ | ✓ |  |  | Luôn `-s SERIAL`, timeout và không redirect mất stderr. |
| `vmware_checklist` |  | ✓ |  | ✓ | Thay bằng hướng dẫn Google USB Driver/USB debugging trên Windows thật. |
| `create_report` | ✓ | ✓ |  |  | Session/evidence hash/redaction/JSON+HTML; bỏ dump logcat raw mặc định và nmap. |
| `scrcpy_remote` | ✓ | ✓ |  |  | Web button/CLI typed action, không menu lồng nhau. |
| `modern_mouse_remote` | ✓ | ✓ |  |  | Gộp vào controller scrcpy; bỏ trùng logic profile. |
| `adb_basic_control` | ✓ | ✓ |  |  | Giữ screenshot/record cơ bản; validate input và track file tạm. |
| `app_control_menu` | ✓ | ✓ |  |  | Service typed cho list/start/stop/pull; install/uninstall phải có scope/session. |
| `network_pentest_menu` | ✓ | ✓ |  |  | Snapshot proxy/reverse trước sửa, validate port và cleanup đúng ownership. |
| `wireless_adb_menu` | ✓ | ✓ |  | ✓ | Giữ detection legacy TCP exposure; không đưa nút bật tcp/5555 vào MVP. |
| `remote_suite` |  | ✓ |  | ✓ | Menu tổng được thay bằng service layer và web action rõ trạng thái. |
| `basic_remote` |  |  |  | ✓ | Wrapper trùng được loại bỏ. |
| `watch_mode` | ✓ | ✓ |  |  | Polling có timeout/cancel, không vòng lặp vô hạn thiếu cleanup. |
| `hardening` | ✓ | ✓ |  |  | Chuyển vào report/remediation và giữ nội dung phòng thủ phù hợp. |
| `show_log` | ✓ | ✓ |  |  | Diagnostics hiển thị đường dẫn/log tail đã redact. |
| `web_control_center` | ✓ | ✓ |  |  | FastAPI local `127.0.0.1`; bỏ companion file thiếu và token URL ad-hoc. |
| `menu` |  |  |  | ✓ | Thay bằng `argparse` CLI và FastAPI/HTMX. |

Dispatcher cuối file cũng bị loại bỏ; `python -m android_assessor` trở thành entry point duy nhất phía core, còn `.cmd` chỉ là wrapper đường dẫn.

## Lỗi kỹ thuật và rủi ro chính

1. `set -u` nhưng không có `pipefail`; nhiều pipeline `... | tee` trả exit code của `tee`, sau đó hàng chục `|| true` che lỗi thật.
2. `first_device()` âm thầm lấy device đầu tiên. Khi có nhiều thiết bị, mọi thao tác sau có thể ra ngoài target đã định.
3. Proxy bị xóa bằng `settings delete` và reverse bị xóa bằng `--remove-all` mà không snapshot; có thể phá cấu hình tồn tại trước session.
4. Wireless ADB có thể được bật nhưng không có rollback bảo đảm khi script bị ngắt.
5. Report ghi raw serial, fingerprint, settings và 200 dòng logcat; không redact token/cookie/email, không hash evidence và không tách raw/redacted.
6. Download ghi thẳng file đích, không retry có giới hạn, không checksum, không minimum size và không atomic install.
7. Giải nén không kiểm tra đường dẫn entry; nhánh Python dùng `ZipFile.extractall()` trực tiếp.
8. `apt_repair_install()` sửa repository hệ thống, dùng HTTP mirror, xóa apt lists và cần root — trái hoàn toàn mục tiêu Windows standard user.
9. Input package/proxy/port/URL/toạ độ chưa có schema validation; thao tác modifying không có device lock.
10. External process không có timeout nhất quán, PID ownership hoặc cleanup khi Ctrl+C/crash.
11. `scrcpy --help` bị gọi nhiều lần cho mỗi launch và profile bị trùng lặp quá mức.
12. Report nhanh trộn collection, port scan, screenshot, HTML rendering và logging trong một function; không thể unit test độc lập.
13. `web_control_center()` phụ thuộc file không có trong bộ đầu vào nên chức năng web cũ không tái lập được.
14. Host root, ADB authorization, Android root và app privilege bị trộn khái niệm; không có capability model.

## Phần ý tưởng được giữ

- Portable ADB/scrcpy discovery, nhưng đảo đúng thứ tự ưu tiên.
- Parse thiết bị và hướng dẫn `unauthorized`.
- Thu Android properties, screenshot/screenrecord, app start/stop và APK path.
- Proxy, `adb reverse`, scrcpy record và report, nhưng đều phải nằm trong session có snapshot/cleanup.
- Hardening guidance sau thực nghiệm.

## Phần bị loại khỏi core

- Toàn bộ `apt`, Kali repository, `sudo`, GLIBC workaround và VMware checklist.
- `nmap` tự quét IP điện thoại trong report.
- Menu Bash, arbitrary text/URL control và nút bật legacy wireless ADB trong MVP.
- Xóa toàn bộ reverse/proxy không xét ownership.
- Auto-select device đầu tiên và raw logcat mặc định.
