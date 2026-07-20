# Rules

`core.yaml` là catalog rule production được `RuleEngine` tải và đánh giá. Mỗi rule nêu điều kiện evidence, capability cần thiết, loại validation và remediation; rule chỉ đưa ra kết luận trong phạm vi evidence mà engine đã thu thập.

`coverage.yaml` là coverage matrix machine-readable. File này mô tả mức triển khai theo vulnerability class, fixture, nguồn quan sát, ngưỡng xác nhận, giới hạn đã biết và bước tiếp theo. Matrix không tự tạo finding và không thay thế kết quả assessment.

`mapping_pending` nghĩa là MASVS, MASTG hoặc CWE mapping của rule đó chưa được duy trì và xác minh trong catalog. Đây không phải mapping ngầm định, cũng không ảnh hưởng đến evidence, severity hoặc trạng thái finding.

Khi thêm hoặc sửa rule, cập nhật cả catalog và coverage matrix tương ứng, kèm regression chứng minh detection, false-positive control và outcome phù hợp.
