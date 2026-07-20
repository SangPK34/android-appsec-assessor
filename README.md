# Android AppSec Assessor

Android AppSec Assessor là framework chạy local trên Windows để đánh giá bảo mật ứng dụng Android trong phạm vi được cho phép. Framework kết hợp phân tích APK, ADB, quan sát runtime, giám sát lưu lượng và xác minh có kiểm soát; mỗi kết luận phải liên kết với evidence và giới hạn quan sát cụ thể.

Framework không suy diễn khả năng khai thác chỉ từ manifest, API reference, chuỗi tĩnh, quyền root hay một lệnh ADB thành công. Khi một flow chưa được kích hoạt hoặc evidence không đủ attribution, kết quả phải giữ ở trạng thái không kết luận thay vì nâng thành lỗ hổng.

## Tính năng chính

Framework cung cấp các nhóm chức năng sau:

- Phát hiện thiết bị Android qua ADB, lưu lựa chọn thiết bị và thu thập thông tin thiết bị cùng capability.
- Phân tích base APK và split APK được lấy từ package đã chọn.
- Phân tích manifest, permission, component được export, cờ debug/test-only, chính sách backup và cấu hình cleartext.
- Phân tích DEX có giới hạn cho method reference, call-site, literal-to-sink và static behavior candidate; hardcoded-secret candidate chỉ được giữ khi có ngữ cảnh sink, ownership app/dependency đã xác định hoặc được đánh dấu chưa xác định một cách bảo thủ.
- Autonomous exploration và micro-scenario có quota/timeout để kích hoạt các route an toàn khi chạy `--auto`, đồng thời giữ lại coverage và lý do dừng của từng bước.
- Thu thập metadata lưu lượng qua mitmproxy và đánh giá hành vi cleartext, TLS và certificate trust trong môi trường được cấu hình.
- Thu thập logcat theo tiến trình mục tiêu để hỗ trợ phân tích dữ liệu nhạy cảm và canary.
- Quan sát runtime bằng Frida với hook cố định, observation-only cho crypto, storage, logging, TLS, WebView và root-detection behavior khi capability phù hợp.
- Phân tích có giới hạn private application storage khi có quyền truy cập dữ liệu ứng dụng phù hợp.
- Xác minh có kiểm soát bằng canary và IPC route bounded cho các finding được hỗ trợ, dựa trên evidence có attribution package, process và time window.
- Quản lý session, scope allowlist, hash SHA-256, provenance, redaction và cleanup ledger.
- Tạo báo cáo JSON, HTML và dữ liệu thực nghiệm dạng CSV.

Root và Frida là capability hỗ trợ cho các nhóm phân tích tăng cường; chúng không phải mục tiêu đánh giá. Các kiểm tra APK, manifest, nhiều kiểm tra thiết bị, traffic và logcat có thể hoạt động mà không cần root. Phân tích private storage, crypto hoặc root-detection runtime có thể yêu cầu root, Frida và capability tương ứng.

## Phạm vi kiểm tra

| Nhóm | Nội dung |
| --- | --- |
| Cấu hình ứng dụng | Debuggable, test-only, chính sách backup và cleartext configuration |
| Android components | Permission, Activity, Receiver, Provider và protection boundary của component được export |
| Static behavior | DEX call-site candidate, ownership application/dependency và ngữ cảnh sử dụng khi analyzer hỗ trợ |
| Network | Cleartext traffic, metadata nhạy cảm trong URL và hành vi TLS/certificate trust |
| Logging | Canary hoặc thông tin nhạy cảm trong logcat của tiến trình mục tiêu |
| Storage | SharedPreferences, SQLite, internal files và metadata private application storage trong phạm vi được phép |
| Runtime | Crypto API, TLS API, WebView, logging, storage và root-detection behavior |
| Evidence | Hash, provenance, redaction, liên kết evidence với finding và trạng thái cleanup |

Framework không mặc định coi mọi observation là vulnerability. Trạng thái finding thể hiện mức bằng chứng, không phải mức nghiêm trọng:

- `confirmed`: hành vi liên quan đã được tái hiện hoặc quan sát với attribution đúng scope.
- `potential`: có candidate hoặc cấu hình đáng xem xét, nhưng chưa có bằng chứng runtime đủ mạnh.
- `inconclusive`: đã đánh giá nhưng thiếu capability, activation hoặc evidence cần thiết.
- `pass`: điều kiện hoặc route đã kiểm tra không thỏa tiêu chí finding; không có nghĩa toàn bộ ứng dụng an toàn.
- `skipped` và `error`: thao tác không chạy được hoặc kết thúc lỗi, luôn kèm lý do trong report.

Controlled validation còn ghi kết quả riêng theo route, như `rejected_for_tested_route`, `not_exercised` hoặc `out_of_scope`. Phân tích storage có thể dùng `post_compromise_observation` để tách khả năng đọc dữ liệu sau khi đã có quyền cao khỏi finding của ứng dụng.

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

- Windows native 64-bit. `.\setup.cmd` kiểm tra môi trường Windows native và kiến trúc 64-bit; framework không cung cấp đường chạy cho Linux hoặc macOS.
- Windows PowerShell (`powershell.exe`), được gọi bởi `.\setup.cmd` và `.\repair.cmd`.
- Kết nối Internet qua HTTPS trong lần setup đầu tiên để tải các thành phần đã khóa phiên bản.
- Thiết bị Android có USB debugging, đã cấp quyền ADB và kết nối qua USB hoặc transport ADB hợp lệ.
- Android USB driver phù hợp với nhà sản xuất nếu Windows chưa nhận thiết bị. Framework không tự cài driver của hãng.
- Quyền chấp nhận Android SDK License khi setup cần tải Android Platform Tools hoặc Build Tools.

`.\setup.cmd` tải và quản lý runtime cùng các công cụ portable theo phiên bản và checksum được khai báo trong `config/tools.lock.json`; Python package được cài từ các lock file của dự án. Các thành phần được quản lý bao gồm Python, Android Platform Tools, scrcpy, Android Build Tools, Java, Frida Server cho các ABI được hỗ trợ và tài nguyên giao diện cần thiết. Không cần cài thủ công các thành phần này trước khi chạy setup.

Root/Magisk, Frida client/server và quyền đọc dữ liệu ứng dụng là tùy chọn cho các kiểm tra tăng cường. Việc tự khởi động Frida Server trên Android yêu cầu capability root phù hợp.

Khả năng thực hiện từng bài kiểm tra phụ thuộc vào phiên bản Android, ROM, quyền ADB, trạng thái root và khả năng tương thích của Frida. Các bài kiểm tra không đáp ứng capability cần thiết sẽ được phân loại riêng thay vì làm gián đoạn toàn bộ assessment session.

## Cài đặt nhanh

```powershell
git clone https://github.com/SangPK34/android-appsec-assessor.git
cd android-appsec-assessor
.\setup.cmd
```

Kiểm tra môi trường sau setup:

```powershell
.\run.cmd check
```

Nếu một thành phần đã cài bị thiếu hoặc không hợp lệ, chạy `.\repair.cmd` để thực hiện lại quy trình kiểm tra và sửa chữa theo manifest khóa phiên bản. Có thể thêm dependency dành cho phát triển bằng `.\setup.cmd -IncludeDev`.

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
.\start.cmd
```

Web UI lắng nghe mặc định tại [http://127.0.0.1:8765](http://127.0.0.1:8765). `.\start.cmd` kiểm tra setup, khởi động dịch vụ local và mở trình duyệt khi endpoint `/health` đã sẵn sàng. Các khu vực chính gồm Devices, Applications, Sessions và Environment.

### CLI

Xem toàn bộ parser và option:

```powershell
.\run.cmd --help
```

Một số command thường dùng:

```powershell
.\run.cmd check
.\run.cmd self-test --json
.\run.cmd devices
.\run.cmd devices --show-serial
.\run.cmd select-device --serial SERIAL
.\run.cmd inspect-device --serial SERIAL
.\run.cmd inspect-app --serial SERIAL --package PACKAGE
.\run.cmd scan --serial SERIAL --package PACKAGE
.\run.cmd scan --serial SERIAL --package PACKAGE --auto --max-runtime 60
.\run.cmd session create --serial SERIAL --package PACKAGE
.\run.cmd session list
.\run.cmd session show --session SESSION_ID
.\run.cmd report --session SESSION_ID
.\run.cmd validate --session SESSION_ID --finding FINDING_ID
.\run.cmd cleanup --session SESSION_ID
```

Các giá trị `SERIAL`, `PACKAGE`, `SESSION_ID` và `FINDING_ID` trong ví dụ là placeholder. Dùng `--json` cho các command hỗ trợ xuất dữ liệu máy đọc được; `--show-serial` chỉ nên dùng trong môi trường local được kiểm soát.

`scan --auto` chạy Full Assessment không cần thao tác UI của người dùng: nó dùng exploration, IPC validation và micro-scenario có quota/timeout riêng. Chế độ này vẫn không đoán credential, không lặp lại submit khi trạng thái không rõ, và báo `not_exercised` hoặc `inconclusive` khi không thể đi tới một flow.

## Quy trình sử dụng cơ bản

1. Kết nối thiết bị, bật USB debugging và chấp nhận quyền ADB.
2. Khai báo device, package, host và action trong `config/scope.yaml`.
3. Chạy `.\run.cmd check` để kiểm tra runtime và tool.
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
rules/             Catalog rule production (`core.yaml`) và coverage matrix (`coverage.yaml`).
tests/             Test unit và fixture mô phỏng.
benchmarks/        Profile và scenario dành riêng cho benchmark local, tách khỏi production engine.
web/               Template và static asset của Web UI.
docs/              Tài liệu kỹ thuật và hướng dẫn chuyên sâu.
```

## Kiểm thử dành cho developer

```powershell
pytest -q
ruff check .
python -m compileall android_assessor
.\run.cmd check
```

## Sử dụng có trách nhiệm

Chỉ sử dụng framework với ứng dụng, thiết bị và hệ thống mà bạn sở hữu hoặc được phép kiểm thử. Các thao tác xác minh có thể thay đổi tạm thời proxy, process hoặc trạng thái ứng dụng; framework sử dụng session và cleanup ledger để quản lý các thay đổi này.

Hãy giới hạn scope ở hệ thống lab, xem xét artifact raw trước khi chia sẻ và chạy cleanup sau khi hoàn tất workflow.
