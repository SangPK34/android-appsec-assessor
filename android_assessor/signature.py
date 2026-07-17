"""Optional apksigner verification and certificate metadata parsing."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .errors import ApkInspectionError, ExternalCommandError
from .redaction import redact_text
from .storage import require_under_root, write_text_atomic
from .subprocess_utils import run_command


@dataclass(frozen=True, slots=True)
class CertificateInfo:
    signer: int
    distinguished_name: str | None = None
    sha256: str | None = None
    sha1: str | None = None
    md5: str | None = None
    valid_from: str | None = None
    valid_until: str | None = None
    public_key_algorithm: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SignatureInspection:
    verified: bool
    schemes: dict[str, bool]
    certificates: tuple[CertificateInfo, ...]
    warnings: tuple[str, ...]
    error: str | None
    output_path: Path | None = None

    def to_dict(self, *, root: Path | None = None) -> dict[str, Any]:
        relative_path: str | None = None
        if self.output_path is not None:
            relative_path = (
                self.output_path.relative_to(root).as_posix()
                if root is not None
                else str(self.output_path)
            )
        return {
            "verified": self.verified,
            "schemes": dict(self.schemes),
            "certificates": [item.to_dict() for item in self.certificates],
            "warnings": list(self.warnings),
            "error": self.error,
            "output_path": relative_path,
        }


_SCHEME_PATTERN = re.compile(r"^Verified using (.+?):\s*(true|false)$", re.IGNORECASE)
_CERT_PATTERN = re.compile(r"^Signer #(\d+) certificate ([^:]+):\s*(.*)$")


def _scheme_name(description: str) -> str:
    version = re.search(r"\bv(\d+)\b", description, re.IGNORECASE)
    return f"v{version.group(1)}" if version else description.strip()


def parse_apksigner_output(output: str, *, exit_code: int) -> SignatureInspection:
    schemes: dict[str, bool] = {}
    certificate_values: dict[int, dict[str, str]] = {}
    warnings: list[str] = []
    for raw_line in output.replace("\r", "").splitlines():
        line = raw_line.strip()
        scheme_match = _SCHEME_PATTERN.match(line)
        if scheme_match:
            schemes[_scheme_name(scheme_match.group(1))] = (
                scheme_match.group(2).casefold() == "true"
            )
            continue
        certificate_match = _CERT_PATTERN.match(line)
        if certificate_match:
            signer = int(certificate_match.group(1))
            key = certificate_match.group(2).strip().casefold()
            certificate_values.setdefault(signer, {})[key] = certificate_match.group(3).strip()
            continue
        if line.startswith("WARNING:"):
            warnings.append(redact_text(line.removeprefix("WARNING:").strip())[:500])

    certificates = tuple(
        CertificateInfo(
            signer=signer,
            distinguished_name=values.get("dn"),
            sha256=values.get("sha-256 digest"),
            sha1=values.get("sha-1 digest"),
            md5=values.get("md5 digest"),
            valid_from=values.get("valid from"),
            valid_until=values.get("valid until"),
            public_key_algorithm=values.get("public key algorithm"),
        )
        for signer, values in sorted(certificate_values.items())
    )
    error = None
    if exit_code != 0:
        detail = next(
            (
                line.strip()
                for line in output.splitlines()
                if line.strip() and not line.strip().startswith("WARNING:")
            ),
            "apksigner reported that the APK did not verify.",
        )
        error = redact_text(detail)[:500]
    return SignatureInspection(
        verified=exit_code == 0,
        schemes=schemes,
        certificates=certificates,
        warnings=tuple(warnings),
        error=error,
    )


class ApkSignatureInspector:
    def __init__(
        self,
        java_executable: Path,
        apksigner_jar: Path,
        *,
        command_log: Path | None = None,
    ) -> None:
        self.java_executable = java_executable.resolve()
        self.apksigner_jar = apksigner_jar.resolve()
        self.command_log = command_log
        if not self.java_executable.is_file():
            raise ApkInspectionError("Java executable is unavailable for apksigner.")
        if not self.apksigner_jar.is_file():
            raise ApkInspectionError("apksigner.jar is unavailable.")

    def inspect(
        self,
        apk_path: Path,
        *,
        output_path: Path,
        project_root: Path,
    ) -> SignatureInspection:
        apk = require_under_root(apk_path, project_root)
        output = require_under_root(output_path, project_root)
        try:
            result = run_command(
                [
                    self.java_executable,
                    "-jar",
                    self.apksigner_jar,
                    "verify",
                    "--verbose",
                    "--print-certs",
                    apk,
                ],
                timeout=120,
                check=False,
                command_log=self.command_log,
            )
        except ExternalCommandError as exc:
            raise ApkInspectionError(f"Could not run apksigner: {exc}") from exc
        combined = result.stdout
        if result.stderr:
            combined += ("\n" if combined else "") + result.stderr
        redacted_output = redact_text(combined)
        write_text_atomic(output, redacted_output, root=project_root)
        parsed = parse_apksigner_output(redacted_output, exit_code=result.exit_code)
        return SignatureInspection(
            verified=parsed.verified,
            schemes=parsed.schemes,
            certificates=parsed.certificates,
            warnings=parsed.warnings,
            error=parsed.error,
            output_path=output,
        )
