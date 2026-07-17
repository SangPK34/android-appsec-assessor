# Android AppSec Assessor

Android AppSec Assessor là framework chạy trên Windows, hỗ trợ kiểm thử bảo mật ứng dụng Android thông qua phân tích APK, ADB, giám sát lưu lượng, quan sát runtime, xác minh có kiểm soát và tạo báo cáo bằng chứng.

## Tính năng chính

Framework cung cấp các nhóm chức năng sau:

- Phát hiện thiết bị Android qua ADB, lưu lựa chọn thiết bị và thu thập thông tin thiết bị cùng capability.
- Phân tích base APK và split APK được lấy từ package đã chọn.
- Phân tích manifest, permission, component được export, cờ debug/test-only, chính sách backup và cấu hình cleartext.
- Thu thập metadata lưu lượng qua mitmproxy và đánh giá hành vi cleartext, TLS và certificate trust trong môi trường được cấu hình.
- Thu thập logcat theo tiến trình mục tiêu để hỗ trợ phân tích dữ liệu nhạy cảm và canary.
- Quan sát runtime bằng Frida với hook cố định, observation-only cho crypto, storage, logging, TLS, WebView và root-detection behavior khi capability phù hợp.
- Phân tích có giới hạn private application storage khi có quyền truy cập dữ liệu ứng dụng phù hợp.
- Xác minh có kiểm soát bằng canary cho các finding được hỗ trợ, dựa trên bằng chứng quan sát được.
- Quản lý session, scope allowlist, hash SHA-256, provenance, redaction và cleanup ledger.
- Tạo báo cáo JSON, HTML và dữ liệu thực nghiệm dạng CSV.

Root và Frida là capability hỗ trợ cho các nhóm phân tích tăng cường; chúng không phải mục tiêu đánh giá. Các kiểm tra APK, manifest, nhiều kiểm tra thiết bị, traffic và logcat có thể hoạt động mà không cần root. Phân tích private storage, crypto hoặc root-detection runtime có thể yêu cầu root, Frida và capability tương ứng.

## Phạm vi kiểm tra

| Nhóm | Nội dung |
| --- | --- |
| Cấu hình ứng dụng | Debuggable, test-only, chính sách backup và cleartext configuration |
| Android components | Permission, Activity, Receiver, Provider và protection boundary của component được export |
| Network | Cleartext traffic, metadata nhạy cảm trong URL và hành vi TLS/certificate trust |
| Logging | Canary hoặc thông tin nhạy cảm trong logcat của tiến trình mục tiêu |
| Storage | SharedPreferences, SQLite, internal files và metadata private application storage trong phạm vi được phép |
| Runtime | Crypto API, TLS API, WebView, logging, storage và root-detection behavior |
| Evidence | Hash, provenance, redaction, liên kết evidence với finding và trạng thái cleanup |

Framework không mặc định coi mọi observation là vulnerability. Kết quả được phân loại theo bằng chứng và capability, gồm `pass`, `potential`, `confirmed`, `inconclusive`, `skipped` và `error`. Phân tích storage có thể dùng thêm trạng thái `post_compromise_observation` để tách khả năng đọc dữ liệu sau khi đã có quyền cao khỏi một finding của ứng dụng.

## Kiến trúc và workflow

```text
Windows Host
    │
    ├── Web UI / CLI
    ├── Session & Scope
    ├── ADB / APK Inspection
    ├── mitmproxy / Logcat / Frida
    ├── Rule & Validation Engine
    └── Evidence / Report / Cleanup
            │
            └── Android application under test
```

## Yêu cầu hệ thống

- Windows native 64-bit. `setup.cmd` kiểm tra môi trường Windows native và kiến trúc 64-bit; framework không cung cấp đường chạy cho Linux hoặc macOS.
- Windows PowerShell (`powershell.exe`), được gọi bởi `setup.cmd` và `repair.cmd`.
- Kết nối Internet qua HTTPS trong lần setup đầu tiên để tải các thành phần đã khóa phiên bản.
- Thiết bị Android có USB debugging, đã cấp quyền ADB và kết nối qua USB hoặc transport ADB hợp lệ.
- Android USB driver phù hợp với nhà sản xuất nếu Windows chưa nhận thiết bị. Framework không tự cài driver của hãng.
- Quyền chấp nhận Android SDK License khi setup cần tải Android Platform Tools hoặc Build Tools.

`setup.cmd` tự quản lý runtime và các tool portable trong thư mục dự án. Cấu hình khóa hiện bao gồm Python 3.12.10 x64, Python packages từ lock file, Android Platform Tools 37.0.0, scrcpy 4.0, Android Build Tools 37.0.0, Eclipse Temurin JRE 21.0.11+10, Frida Server 17.15.5 cho các ABI được hỗ trợ và HTMX 2.0.10. Không cần cài thủ công các thành phần này trước khi chạy setup.

Root/Magisk, Frida client/server và quyền đọc dữ liệu ứng dụng là tùy chọn cho các kiểm tra tăng cường. Việc tự khởi động Frida Server trên Android yêu cầu capability root phù hợp.

## Cài đặt nhanh

```powershell
git clone https://github.com/SangPK34/android-appsec-assessor.git
cd android-appsec-assessor
setup.cmd
```

Kiểm tra môi trường sau setup:

```powershell
run.cmd check
```

Nếu một thành phần đã cài bị thiếu hoặc không hợp lệ, chạy `repair.cmd` để thực hiện lại quy trình kiểm tra và sửa chữa theo manifest khóa phiên bản. Có thể thêm dependency dành cho phát triển bằng `setup.cmd -IncludeDev`.

## Cấu hình phạm vi

Tạo file cấu hình cục bộ từ file mẫu:

```powershell
Copy-Item config\scope.example.yaml config\scope.yaml
```

`config/scope.yaml` là cấu hình cục bộ và không nên commit. Scope dùng mô hình deny-by-default cho các thao tác thay đổi. Các trường chính:

- `devices`: danh sách serial thiết bị được phép.
- `packages`: danh sách package Android được phép.
- `api_hosts`: host được phép dùng trong controlled validation.
- `allowed_actions`: các action được bật, gồm `inspect`, `root_storage_read`, `frida_observe`, `traffic_capture` và `controlled_validation`.
- `limits`: giới hạn số validation request, timeout command và kích thước evidence.
- `allow_read_only_outside_scope`: cho phép inspection chỉ-đọc ngoài device/package allowlist khi được đặt rõ ràng.

Ví dụ an toàn dùng giá trị giả:

```yaml
schema_version: 1
devices:
  - EXAMPLE_DEVICE_SERIAL
packages:
  - com.example.app
api_hosts:
  - api.example.test
allowed_actions:
  - inspect
  - traffic_capture
  - frida_observe
  - root_storage_read
  - controlled_validation
limits:
  max_validation_requests: 10
  command_timeout_seconds: 30
  max_evidence_size_mb: 50
allow_read_only_outside_scope: false
```

Thay các giá trị ví dụ bằng device, package và host mà bạn sở hữu hoặc được phép kiểm thử. Scope phải được khai báo trước các thao tác scan, traffic, Frida hoặc controlled validation.

## Khởi chạy

### Web UI

```powershell
start.cmd
```

Web UI lắng nghe mặc định tại [http://127.0.0.1:8765](http://127.0.0.1:8765). `start.cmd` kiểm tra setup, khởi động dịch vụ local và mở trình duyệt khi endpoint `/health` đã sẵn sàng. Các khu vực chính gồm Devices, Applications, Sessions và Environment.

### CLI

Xem toàn bộ parser và option:

```powershell
run.cmd --help
```

Một số command thường dùng:

```powershell
run.cmd check
run.cmd self-test --json
run.cmd devices
run.cmd devices --show-serial
run.cmd select-device --serial SERIAL
run.cmd inspect-device --serial SERIAL --package PACKAGE
run.cmd inspect-app --serial SERIAL --package PACKAGE
run.cmd scan --serial SERIAL --package PACKAGE
run.cmd session create --serial SERIAL --package PACKAGE
run.cmd session list
run.cmd session show --session SESSION_ID
run.cmd report --session SESSION_ID
run.cmd validate --session SESSION_ID --finding FINDING_ID
run.cmd cleanup --session SESSION_ID
```

Các giá trị `SERIAL`, `PACKAGE`, `SESSION_ID` và `FINDING_ID` trong ví dụ là placeholder. Dùng `--json` cho các command hỗ trợ xuất dữ liệu máy đọc được; `--show-serial` chỉ nên dùng trong môi trường local được kiểm soát.

## Quy trình sử dụng cơ bản

1. Kết nối thiết bị, bật USB debugging và chấp nhận quyền ADB.
2. Khai báo device, package, host và action trong `config/scope.yaml`.
3. Chạy `run.cmd check` để kiểm tra runtime và tool.
4. Dùng `devices` và `select-device` để chọn thiết bị được phép.
5. Chọn package rồi chạy inspection hoặc tạo assessment session bằng `inspect-app` hoặc `session create`.
6. Chạy `scan` hoặc các thao tác traffic/Frida phù hợp với capability.
7. Xem finding và evidence trong session.
8. Chạy `validate` cho finding có hỗ trợ controlled validation và đủ precondition.
9. Tạo hoặc tạo lại report bằng `report`.
10. Chạy `cleanup` sau workflow để xử lý các resource do session sở hữu.

## Kết quả và báo cáo

Mỗi session được lưu dưới `results/<SESSION_ID>/` với các thành phần chính:

```text
results/<SESSION_ID>/
├── session.json
├── device.json
├── environment.json
├── app.json
├── scan.json
├── findings.json
├── evidence/index.json
├── report.json
├── report.html
├── experiment_results.csv
├── events.jsonl
├── commands.jsonl
├── apk/
├── traffic/
├── frida/
├── logcat/
├── raw/
└── redacted/
```

Kết quả bao gồm metadata session, device và application; danh sách finding; evidence index; SHA-256; artifact raw và redacted; report JSON/HTML; CSV dữ liệu thực nghiệm; cùng trạng thái cleanup. Artifact raw có thể chứa dữ liệu nhạy cảm, còn artifact redacted được dùng cho các bản ghi cần chia sẻ hoặc hiển thị. Hãy kiểm tra provenance, trạng thái finding và limitation trước khi diễn giải kết quả.

## Cấu trúc project

```text
android_assessor/  Logic framework, services, rule và report.
config/            Cấu hình lab, scope mẫu và tool manifest.
hooks/             Hook runtime cố định cho Frida và mitmproxy.
rules/             Khai báo rule đánh giá.
tests/             Test unit và fixture mô phỏng.
web/               Template và static asset của Web UI.
docs/              Tài liệu kỹ thuật và hướng dẫn chuyên sâu.
```

## Kiểm thử dành cho developer

```powershell
pytest -q
ruff check .
python -m compileall android_assessor
run.cmd check
```

## Sử dụng có trách nhiệm

Chỉ sử dụng framework với ứng dụng, thiết bị và hệ thống mà bạn sở hữu hoặc được phép kiểm thử. Các thao tác xác minh có thể thay đổi tạm thời proxy, process hoặc trạng thái ứng dụng; framework sử dụng session và cleanup ledger để quản lý các thay đổi này.

Hãy giới hạn scope ở hệ thống lab, xem xét artifact raw trước khi chia sẻ và chạy cleanup sau khi hoàn tất workflow.

## License

Repository chưa kèm file `LICENSE`; chưa có tuyên bố giấy phép cho việc sử dụng hoặc phân phối. Hãy xác định giấy phép phù hợp trước khi phát hành hoặc tích hợp dự án vào sản phẩm khác.
