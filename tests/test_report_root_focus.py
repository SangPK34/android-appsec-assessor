from __future__ import annotations

import csv
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from shutil import copyfile

from android_assessor.evidence import EvidenceRepository
from android_assessor.findings import (
    FindingRecord,
    FindingRepository,
    FindingStatus,
)
from android_assessor.paths import ProjectPaths
from android_assessor.report import ReportService
from android_assessor.session import SessionRepository
from android_assessor.storage import write_json_atomic

SESSION_SERIAL = "FIXTURE_SERIAL"
PACKAGE = "com.example.rootedlab"


def _finding(
    rule_id: str,
    *,
    root_required: bool,
    root_used: bool,
    frida_used: bool,
    evidence_ids: tuple[str, ...] = (),
    details: dict[str, object] | None = None,
) -> FindingRecord:
    now = datetime.now(UTC).isoformat()
    return FindingRecord(
        finding_id=f"finding-{rule_id.casefold()}",
        rule_id=rule_id,
        title=f"Fixture {rule_id}",
        category="fixture",
        description="Synthetic software-correctness result.",
        severity="medium",
        confidence="medium",
        status=FindingStatus.CONFIRMED,
        analysis_type="instrumentation" if frida_used else "static",
        root_required=root_required,
        root_used=root_used,
        frida_used=frida_used,
        validation_supported=False,
        validation=None,
        evidence_ids=evidence_ids,
        remediation="Fixture remediation.",
        mappings={},
        details=details or {},
        created_at=now,
        updated_at=now,
    )


def _project(tmp_path: Path) -> tuple[ProjectPaths, SessionRepository, str]:
    paths = ProjectPaths(tmp_path / "lab")
    paths.ensure_layout()
    templates = paths.root / "templates"
    templates.mkdir(exist_ok=True)
    source_template = Path(__file__).resolve().parent.parent / "templates" / "report.html.j2"
    copyfile(source_template, templates / "report.html.j2")
    repository = SessionRepository(paths)
    record = repository.initialize(serial=SESSION_SERIAL, package=PACKAGE)
    repository.activate(
        record.session_id,
        snapshot={},
        device={
            "device": {
                "model": "Fixture Android",
                "android_version": "14",
            },
            "capabilities": {
                "capabilities": [
                    {"name": "ANDROID_ROOT", "available": True},
                    {"name": "FRIDA_CLIENT", "available": True},
                    {"name": "FRIDA_SERVER", "available": True},
                ]
            },
        },
        environment={
            "fixture_or_physical": "fixture",
            "environment_type": "simulated",
        },
    )
    write_json_atomic(
        repository.paths_for(record.session_id).app_json,
        {"metadata": {"version_name": "1.0-fixture"}},
        root=paths.root,
    )
    return paths, repository, record.session_id


def test_fixture_report_cannot_claim_physical_pass_or_empirical_eligibility(
    tmp_path: Path,
) -> None:
    paths, repository, session_id = _project(tmp_path)
    session_paths = repository.paths_for(session_id)
    fixture_artifact = session_paths.redacted_dir / "fixture-observation.txt"
    fixture_artifact.write_text("synthetic observation\n", encoding="utf-8")
    evidence = EvidenceRepository(paths, repository).register_file(
        session_id,
        fixture_artifact,
        evidence_type="fixture_observation",
        source="fixture",
        description="Synthetic fixture evidence.",
        sensitive=False,
        redacted=True,
    )
    FindingRepository(paths, repository).save(
        session_id,
        [
            _finding(
                "ROOT-STORAGE-001",
                root_required=True,
                root_used=True,
                frida_used=True,
                evidence_ids=(evidence.evidence_id,),
                details={
                    "physical_validation_status": "PASSED",
                    "expected_result": "=fixture formula",
                    "duration_ms": 12,
                },
            ),
            _finding(
                "STATIC-001",
                root_required=False,
                root_used=False,
                frida_used=False,
            ),
        ],
    )

    report = ReportService(paths, repository).generate(session_id)

    assert report["schema_version"] == 2
    assert report["evidence_source"] == "fixture"
    assert report["experiment"] == {
        "fixture_or_physical": "fixture",
        "environment_type": "simulated",
        "eligible_for_empirical_metrics": False,
    }
    assert report["root_available"] is True
    assert report["frida_available"] is True
    assert report["root_required"] is True
    assert report["frida_required"] is True
    assert report["device_validation_status"] == "UNVERIFIED"
    assert all(
        item["device_validation_status"] == "UNVERIFIED"
        for item in report["findings"]
    )
    assert report["findings"][0]["validation_type"] == "instrumented_validation"
    assert report["findings"][0]["evidence_source"] == "fixture"
    assert report["findings"][1]["validation_type"] == "adb_assisted_validation"


def test_root_coverage_and_experiment_csv_are_bounded_and_hashed(tmp_path: Path) -> None:
    paths, repository, session_id = _project(tmp_path)
    FindingRepository(paths, repository).save(
        session_id,
        [
            _finding(
                "ASL-ROOT-CRYPTO",
                root_required=True,
                root_used=True,
                frida_used=True,
                details={"expected_result": "=ECB observed", "duration_ms": 7},
            )
        ],
    )

    report = ReportService(paths, repository).generate(session_id)
    session_paths = repository.paths_for(session_id)
    rows = list(
        csv.DictReader(
            session_paths.experiment_results_csv.read_text(encoding="utf-8").splitlines()
        )
    )

    coverage = {
        item["test_id"]: item for item in report["root_vs_non_root_coverage"]
    }
    assert len(coverage) == 11
    assert coverage["ASL-ROOT-CRYPTO"] == {
        "test_id": "ASL-ROOT-CRYPTO",
        "title": "Runtime cryptographic boundary observations",
        "available_without_root": False,
        "available_with_root": True,
        "requires_frida": True,
        "implementation_status": "IMPLEMENTED_UNVERIFIED",
        "physical_validation_status": "UNVERIFIED",
        "finding_status": "confirmed",
    }
    assert coverage["ASL-ROOT-STORAGE"]["finding_status"] == "skipped"
    assert len(rows) == 1
    assert rows[0]["fixture_or_physical"] == "fixture"
    assert rows[0]["environment_type"] == "simulated"
    assert rows[0]["physical_validation_status"] == "UNVERIFIED"
    assert rows[0]["expected_result"] == "'=ECB observed"
    assert rows[0]["root_required"] == "true"
    assert rows[0]["frida_required"] == "true"
    digest = hashlib.sha256(session_paths.experiment_results_csv.read_bytes()).hexdigest()
    assert report["report_artifacts"]["experiment_results_csv"]["sha256"] == digest
    html = session_paths.report_html.read_text(encoding="utf-8")
    assert "Root vs non-root coverage" in html
    assert "ASL-ROOT-CRYPTO" in html

    evidence_index = json.loads(session_paths.evidence_index.read_text(encoding="utf-8"))
    report_types = {
        item["evidence_type"]
        for item in evidence_index["evidence"]
        if item["source"] == "report_generator"
    }
    assert report_types == {
        "report_html",
        "report_json",
        "experiment_results_csv",
    }
