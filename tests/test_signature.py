from __future__ import annotations

from pathlib import Path

import pytest

from android_assessor import signature as signature_module
from android_assessor.signature import ApkSignatureInspector, parse_apksigner_output
from android_assessor.subprocess_utils import CommandResult

OUTPUT = """Verifies
Verified using v1 scheme (JAR signing): false
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Verified using v4 scheme (APK Signature Scheme v4): false
Signer #1 certificate DN: CN=Android Debug,O=Android,C=US
Signer #1 certificate SHA-256 digest: aabbccdd
Signer #1 certificate SHA-1 digest: 11223344
Signer #1 certificate MD5 digest: deadbeef
Signer #1 certificate public key algorithm: RSA
WARNING: META-INF/NOTICE is not protected by the signature.
"""


def command_result(stdout: str, *, exit_code: int = 0) -> CommandResult:
    return CommandResult(
        arguments=(),
        exit_code=exit_code,
        stdout=stdout,
        stderr="",
        started_at="2026-07-17T00:00:00+00:00",
        duration_ms=1,
        timed_out=False,
    )


def test_parses_signature_schemes_and_certificate() -> None:
    inspection = parse_apksigner_output(OUTPUT, exit_code=0)

    assert inspection.verified is True
    assert inspection.schemes == {"v1": False, "v2": True, "v3": True, "v4": False}
    assert inspection.certificates[0].distinguished_name == "CN=Android Debug,O=Android,C=US"
    assert inspection.certificates[0].sha256 == "aabbccdd"
    assert inspection.certificates[0].public_key_algorithm == "RSA"
    assert len(inspection.warnings) == 1


def test_nonzero_apksigner_result_is_preserved_as_error() -> None:
    inspection = parse_apksigner_output("DOES NOT VERIFY\nERROR: malformed APK", exit_code=1)

    assert inspection.verified is False
    assert inspection.error == "DOES NOT VERIFY"


def test_signature_inspector_uses_fixed_java_jar_command_and_redacts_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "lab"
    java = root / "tools" / "java" / "bin" / "java.exe"
    jar = root / "tools" / "build-tools" / "lib" / "apksigner.jar"
    apk = root / "results" / "session" / "apk" / "000-base.apk"
    output = apk.parent / "signature.txt"
    for path in (java, jar, apk):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x")
    calls: list[list[str]] = []

    def fake_run(arguments: list[Path | str], **_kwargs: object) -> CommandResult:
        calls.append([str(item) for item in arguments])
        return command_result(OUTPUT + "Signer #1 certificate DN: E=owner@example.com\n")

    monkeypatch.setattr(signature_module, "run_command", fake_run)

    inspection = ApkSignatureInspector(java, jar).inspect(
        apk,
        output_path=output,
        project_root=root,
    )

    assert calls[0][1:6] == ["-jar", str(jar), "verify", "--verbose", "--print-certs"]
    assert calls[0][6] == str(apk)
    assert inspection.verified is True
    assert "owner@example.com" not in output.read_text(encoding="utf-8")
    assert "<redacted>" in output.read_text(encoding="utf-8")
