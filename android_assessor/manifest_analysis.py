"""Conservative manifest policy checks that never confirm exploitability statically."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, replace
from typing import Any

from .findings import FindingStatus


@dataclass(frozen=True, slots=True)
class ManifestPolicyResult:
    test_id: str
    finding_status: FindingStatus
    confidence: str
    validation_type: str
    rationale: str
    details: dict[str, Any]
    source: str
    environment: str
    finding_eligible: bool
    physical_validation_status: str = "UNVERIFIED"

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["finding_status"] = self.finding_status.value
        return payload


_PROTECTION_FLAGS = {
    0x10: "privileged",
    0x20: "development",
    0x40: "appop",
    0x80: "pre23",
    0x100: "installer",
    0x200: "verifier",
    0x400: "preinstalled",
    0x800: "setup",
    0x1000: "instant",
    0x2000: "runtime",
    0x4000: "oem",
    0x8000: "vendor_privileged",
}


def _protection_details(
    permission: str | None,
    custom_permissions: dict[str, str | None],
) -> dict[str, Any]:
    if not permission:
        return {
            "permission": None,
            "classification": "missing",
            "base": None,
            "flags": [],
            "raw": None,
            "defined_by_application": False,
            "defaulted": False,
        }
    if permission not in custom_permissions:
        return {
            "permission": permission,
            "classification": "external_unknown",
            "base": None,
            "flags": [],
            "raw": None,
            "defined_by_application": False,
            "defaulted": False,
        }
    level = custom_permissions[permission]
    if level is None:
        return {
            "permission": permission,
            "classification": "weak",
            "base": "normal",
            "flags": [],
            "raw": None,
            "defined_by_application": True,
            "defaulted": True,
        }
    raw = str(level).strip()
    normalized = raw.casefold()
    flags: list[str] = []
    try:
        numeric = int(normalized, 0)
    except ValueError:
        numeric = None
    if numeric is not None and numeric >= 0:
        base_value = numeric & 0xF
        base = {
            0: "normal",
            1: "dangerous",
            2: "signature",
            3: "signatureOrSystem",
        }.get(base_value)
        remaining = numeric & ~0xF
        for value, name in _PROTECTION_FLAGS.items():
            if remaining & value:
                flags.append(name)
                remaining &= ~value
        if remaining:
            flags.append(hex(remaining))
    else:
        tokens = [item.strip() for item in normalized.split("|") if item.strip()]
        base_token = tokens[0] if tokens else ""
        base = {
            "normal": "normal",
            "dangerous": "dangerous",
            "signature": "signature",
            "signatureorsystem": "signatureOrSystem",
        }.get(base_token)
        flags = tokens[1:]
    classification = (
        "weak"
        if base in {"normal", "dangerous"}
        else "signature"
        if base == "signature"
        else "legacy_restricted"
        if base == "signatureOrSystem"
        else "malformed"
    )
    return {
        "permission": permission,
        "classification": classification,
        "base": base,
        "flags": flags,
        "raw": raw,
        "defined_by_application": True,
        "defaulted": False,
    }


def _protection_classification(
    permission: str | None,
    custom_permissions: dict[str, str | None],
) -> str:
    return str(_protection_details(permission, custom_permissions)["classification"])


def _is_launcher(component: dict[str, Any]) -> bool:
    filters = component.get("intent_filters", [])
    if not isinstance(filters, list):
        return False
    return any(
        isinstance(item, dict)
        and "android.intent.action.MAIN" in item.get("actions", [])
        and "android.intent.category.LAUNCHER" in item.get("categories", [])
        for item in filters
    )


def _permission_value(
    value: Any,
    *,
    source: str,
    fallback: tuple[str | None, str],
) -> tuple[str | None, str]:
    if isinstance(value, str) and value:
        return value, source
    if value is None:
        return fallback
    return None, "malformed"


def _boundary(
    operation: str,
    permission: str | None,
    source: str,
    custom_permissions: dict[str, str | None],
    *,
    matcher: dict[str, Any] | None = None,
) -> dict[str, Any]:
    protection = (
        {
            "permission": None,
            "classification": "malformed",
            "base": None,
            "flags": [],
            "raw": None,
            "defined_by_application": False,
            "defaulted": False,
        }
        if source == "malformed"
        else _protection_details(permission, custom_permissions)
    )
    value = {
        "operation": operation,
        "permission": permission,
        "source": source,
        "classification": protection["classification"],
        "protection": protection,
    }
    if matcher is not None:
        value["matcher"] = matcher
    return value


def _component_boundaries(
    component: dict[str, Any],
    application_permission: str | None,
    application_permission_source: str = "application",
) -> tuple[tuple[str | None, str, str, dict[str, Any] | None], ...]:
    application = (
        application_permission,
        application_permission_source if application_permission else (
            "malformed" if application_permission_source == "malformed" else "missing"
        ),
    )
    component_fallback = (
        (None, "missing")
        if component.get("component_type") == "activity-alias"
        else application
    )
    generic = _permission_value(
        component.get("permission"),
        source="component",
        fallback=component_fallback,
    )
    if component.get("component_type") == "provider":
        read = _permission_value(
            component.get("read_permission"),
            source="provider_read",
            fallback=generic,
        )
        write = _permission_value(
            component.get("write_permission"),
            source="provider_write",
            fallback=generic,
        )
        output: list[tuple[str | None, str, str, dict[str, Any] | None]] = [
            (read[0], read[1], "read", None),
            (write[0], write[1], "write", None),
        ]
        path_permissions = component.get("path_permissions", [])
        if not isinstance(path_permissions, list):
            output.append((None, "malformed", "path", None))
            return tuple(output)
        for item in path_permissions:
            if not isinstance(item, dict):
                output.append((None, "malformed", "path", None))
                continue
            path_generic = _permission_value(
                item.get("permission"),
                source="path_permission",
                fallback=(None, "missing"),
            )
            path_read_fallback = (
                path_generic if path_generic[1] != "missing" else read
            )
            path_write_fallback = (
                path_generic if path_generic[1] != "missing" else write
            )
            path_read = _permission_value(
                item.get("read_permission"),
                source="path_permission_read",
                fallback=path_read_fallback,
            )
            path_write = _permission_value(
                item.get("write_permission"),
                source="path_permission_write",
                fallback=path_write_fallback,
            )
            matcher = {
                key: item.get(key)
                for key in (
                    "path",
                    "path_prefix",
                    "path_pattern",
                    "path_suffix",
                    "path_advanced_pattern",
                )
                if item.get(key) is not None
            }
            output.extend(
                (
                    (path_read[0], path_read[1], "path_read", matcher),
                    (path_write[0], path_write[1], "path_write", matcher),
                )
            )
        return tuple(output)
    return ((generic[0], generic[1], "invoke", None),)


_FILE_PROVIDER_PATH_KINDS = {
    "root-path",
    "files-path",
    "cache-path",
    "external-path",
    "external-files-path",
    "external-cache-path",
    "external-media-path",
}


def _broad_file_provider_path(kind: str, path: str | None) -> bool:
    if kind == "root-path":
        return True
    if path is None or path.strip() in {"", ".", "./", "/"}:
        return True
    return ".." in path.replace("\\", "/").split("/")


def _normalized_file_provider_path(path: str | None) -> str:
    if path is None:
        return "."
    parts: list[str] = []
    for part in path.replace("\\", "/").split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            parts.append(part)
            continue
        parts.append(part)
    return "/".join(parts) or "."


def _file_provider_policy_result(
    manifest: dict[str, Any],
    custom_permissions: dict[str, str | None],
    application_permission: str | None,
    application_permission_source: str,
    application_enabled: bool | None,
    *,
    source: str,
    environment: str,
    finding_eligible: bool,
) -> ManifestPolicyResult:
    raw_configs = manifest.get("file_provider_paths")
    components = manifest.get("components")
    malformed: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    broad: list[dict[str, Any]] = []
    protected_broad: list[dict[str, Any]] = []
    unknown_reachability: list[dict[str, Any]] = []
    evaluated_configs = 0
    file_provider_limitations = manifest.get("file_provider_limitations", [])
    if isinstance(file_provider_limitations, list):
        unresolved.extend(
            {"reason": str(item)} for item in file_provider_limitations[:50]
        )
    else:
        malformed.append({"reason": "file_provider_limitations_not_a_list"})
    provider_rows = (
        [
            item
            for item in components
            if isinstance(item, dict)
            and item.get("component_type") == "provider"
            and item.get("name")
        ]
        if isinstance(components, list)
        else []
    )
    provider_definitions: dict[str, set[str]] = {}
    for item in provider_rows:
        provider = str(item["name"])
        payload = {key: value for key, value in item.items() if key != "source_apk"}
        provider_definitions.setdefault(provider, set()).add(
            json.dumps(payload, sort_keys=True, separators=(",", ":"))
        )
    conflicting_providers = {
        provider
        for provider, definitions in provider_definitions.items()
        if len(definitions) > 1
    }
    component_map = {
        str(item["name"]): item
        for item in provider_rows
        if str(item["name"]) not in conflicting_providers
    }
    if raw_configs is None:
        if not isinstance(components, list):
            malformed.append({"reason": "component_inventory_unavailable"})
            configs: list[Any] = []
        else:
            suspicious = [
                str(item.get("name", "<unnamed>"))
                for item in components
                if isinstance(item, dict)
                and item.get("component_type") == "provider"
                and (
                    str(item.get("name", "")).casefold().endswith("fileprovider")
                    or any(
                        isinstance(metadata, dict)
                        and metadata.get("name")
                        == "android.support.FILE_PROVIDER_PATHS"
                        for metadata in item.get("meta_data", [])
                        if isinstance(item.get("meta_data", []), list)
                    )
                )
            ]
            if suspicious:
                unresolved.extend(
                    {"provider": name, "reason": "normalized_paths_unavailable"}
                    for name in suspicious
                )
            configs = []
    elif not isinstance(raw_configs, list):
        malformed.append({"reason": "file_provider_paths_not_a_list"})
        configs = []
    else:
        configs = raw_configs

    for config in configs:
        if not isinstance(config, dict):
            malformed.append({"reason": "invalid_configuration"})
            continue
        provider = str(config.get("provider", "<unnamed>"))
        status = config.get("resolution_status")
        if not isinstance(status, str):
            malformed.append({"provider": provider, "reason": "invalid_status"})
            continue
        if status not in {"resolved", "resolved_partial"}:
            unresolved.append({"provider": provider, "reason": status})
            continue
        if status == "resolved_partial":
            unresolved.append(
                {"provider": provider, "reason": "resource_variant_inventory_incomplete"}
            )
        entries = config.get("entries")
        if not isinstance(entries, list) or not entries:
            malformed.append({"provider": provider, "reason": "missing_entries"})
            continue
        evaluated_configs += 1
        component = component_map.get(provider)
        if provider in conflicting_providers:
            access_state = "unknown"
            access_details = {"reason": "conflicting_provider_definitions"}
        elif component is None:
            configured_grants = config.get("grant_uri_permissions")
            access_state = "reachable" if configured_grants is True else "unknown"
            access_details: dict[str, Any] = {
                "reason": "provider_component_unavailable",
                "grant_uri_permissions": configured_grants is True,
            }
        else:
            exported = component.get("effective_exported")
            grant_value = component.get(
                "grant_uri_permissions",
                config.get("grant_uri_permissions"),
            )
            uri_patterns = component.get("uri_grant_patterns", [])
            if not isinstance(uri_patterns, list):
                uri_patterns = []
                grant_patterns_unknown = True
            else:
                grant_patterns_unknown = bool(uri_patterns)
            boundaries = tuple(
                _boundary(
                    operation,
                    permission,
                    permission_source,
                    custom_permissions,
                    matcher=matcher,
                )
                for permission, permission_source, operation, matcher in (
                    _component_boundaries(
                        component,
                        application_permission,
                        application_permission_source,
                    )
                )
            )
            classifications = {
                str(item["classification"]) for item in boundaries
            }
            exported_unprotected = exported is True and bool(
                classifications & {"missing", "weak"}
            )
            exported_unknown = (
                exported not in {True, False}
                or exported is True
                and bool(
                    classifications
                    & {
                        "external_unknown",
                        "legacy_restricted",
                        "malformed",
                        "unknown",
                    }
                )
            )
            grant_enabled = grant_value is True
            grant_unknown = grant_value not in {None, True, False}
            if application_enabled is False or component.get("enabled") is False:
                access_state = "protected"
            elif grant_enabled or exported_unprotected:
                access_state = "reachable"
            elif exported_unknown or grant_unknown or grant_patterns_unknown:
                access_state = "unknown"
            else:
                access_state = "protected"
            access_details = {
                "effective_exported": exported,
                "application_enabled": application_enabled,
                "component_enabled": component.get("enabled"),
                "grant_uri_permissions": grant_value is True,
                "uri_grant_pattern_count": len(uri_patterns),
                "effective_permissions": list(boundaries),
            }
        for entry in entries:
            if not isinstance(entry, dict):
                malformed.append({"provider": provider, "reason": "invalid_entry"})
                continue
            kind = entry.get("kind")
            path = entry.get("path")
            if not isinstance(kind, str) or kind not in _FILE_PROVIDER_PATH_KINDS:
                malformed.append(
                    {
                        "provider": provider,
                        "reason": "unsupported_path_kind",
                        "kind": kind,
                    }
                )
                continue
            if path is not None and not isinstance(path, str):
                malformed.append(
                    {"provider": provider, "reason": "invalid_path", "kind": kind}
                )
                continue
            if _broad_file_provider_path(kind, path):
                row = {
                    "provider": provider,
                    "source_apk": config.get("source_apk"),
                    "authority": config.get("authorities"),
                    "resource_path": config.get("resource_path"),
                    "kind": kind,
                    "name": entry.get("name"),
                    "path": path,
                    "normalized_path": _normalized_file_provider_path(path),
                    "access_state": access_state,
                    **access_details,
                }
                if access_state == "reachable":
                    broad.append(row)
                elif access_state == "unknown":
                    unknown_reachability.append(row)
                else:
                    protected_broad.append(row)

    if broad:
        status = FindingStatus.POTENTIAL
        confidence = "medium"
        rationale = "FileProvider configuration exposes a broad filesystem path mapping."
    elif unresolved or malformed or unknown_reachability:
        status = FindingStatus.INCONCLUSIVE
        confidence = "low"
        rationale = "FileProvider path metadata could not be classified safely."
    else:
        status = FindingStatus.PASS
        confidence = "high"
        rationale = "No broad FileProvider path mapping was identified."
    return ManifestPolicyResult(
        test_id="ASL-MANIFEST-FILEPROVIDER-PATHS",
        finding_status=status,
        confidence=confidence,
        validation_type="none",
        rationale=rationale,
        details={
            "broad_paths": broad,
            "protected_broad_paths": protected_broad,
            "unknown_reachability": unknown_reachability,
            "unresolved": unresolved,
            "malformed": malformed,
            "evaluated_configurations": evaluated_configs,
        },
        source=source,
        environment=environment,
        finding_eligible=finding_eligible,
    )


def _custom_permission_policy_result(
    manifest: dict[str, Any],
    custom_permissions: dict[str, str | None],
    *,
    source: str,
    environment: str,
    finding_eligible: bool,
) -> ManifestPolicyResult:
    values = manifest.get("custom_permissions")
    malformed: list[dict[str, Any]] = []
    definitions: list[dict[str, Any]] = []
    if not isinstance(values, list):
        malformed.append({"reason": "custom_permissions_not_a_list"})
    else:
        seen: set[str] = set()
        for item in values:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                malformed.append({"reason": "invalid_definition"})
                continue
            name = str(item["name"])
            if not name or name in seen:
                malformed.append(
                    {"permission": name or None, "reason": "duplicate_or_empty_name"}
                )
                continue
            seen.add(name)
            definitions.append(_protection_details(name, custom_permissions))
    weak = [item for item in definitions if item["classification"] == "weak"]
    unknown = [
        item
        for item in definitions
        if item["classification"] in {"legacy_restricted", "malformed"}
    ]
    if malformed or unknown:
        status = FindingStatus.INCONCLUSIVE
        confidence = "low"
        rationale = "Custom permission protection could not be classified safely."
    elif weak:
        status = FindingStatus.POTENTIAL
        confidence = "high"
        rationale = "One or more custom permissions use a weak base protection level."
    else:
        status = FindingStatus.PASS
        confidence = "high"
        rationale = "No weak custom permission definition was identified."
    return ManifestPolicyResult(
        test_id="ASL-MANIFEST-CUSTOM-PERMISSION",
        finding_status=status,
        confidence=confidence,
        validation_type="none",
        rationale=rationale,
        details={
            "definitions": definitions,
            "weak_permissions": weak,
            "unknown_permissions": unknown,
            "malformed": malformed,
        },
        source=source,
        environment=environment,
        finding_eligible=finding_eligible,
    )


def _deep_link_is_broad(link: dict[str, Any]) -> bool:
    scheme = link.get("scheme")
    host = link.get("host")
    if not isinstance(scheme, str) or not scheme:
        return True
    if not isinstance(host, str) or not host or host.startswith("*"):
        return True
    matchers = [
        link.get(key)
        for key in (
            "path",
            "path_prefix",
            "path_pattern",
            "path_suffix",
            "path_advanced_pattern",
        )
        if link.get(key) is not None
    ]
    if not matchers:
        return True
    return any(
        not isinstance(value, str)
        or value.strip() in {"", "/", ".*", "/.*", "/*"}
        for value in matchers
    )


def _deep_link_policy_result(
    manifest: dict[str, Any],
    custom_permissions: dict[str, str | None],
    application_permission: str | None,
    application_permission_source: str,
    application_enabled: bool | None,
    *,
    source: str,
    environment: str,
    finding_eligible: bool,
) -> ManifestPolicyResult:
    values = manifest.get("deep_links")
    components_value = manifest.get("components")
    component_rows = (
        [
            item
            for item in components_value
            if isinstance(item, dict) and item.get("name")
        ]
        if isinstance(components_value, list)
        else []
    )
    component_definitions: dict[str, set[str]] = {}
    for item in component_rows:
        component_name = str(item["name"])
        payload = {key: value for key, value in item.items() if key != "source_apk"}
        component_definitions.setdefault(component_name, set()).add(
            json.dumps(payload, sort_keys=True, separators=(",", ":"))
        )
    conflicting_components = {
        component_name
        for component_name, definitions in component_definitions.items()
        if len(definitions) > 1
    }
    components = {
        str(item["name"]): item
        for item in component_rows
        if str(item["name"]) not in conflicting_components
    }
    evaluated: list[dict[str, Any]] = []
    exposed: list[dict[str, Any]] = []
    unknown: list[dict[str, Any]] = []
    malformed: list[dict[str, Any]] = []
    if values is None:
        if not isinstance(components_value, list):
            malformed.append({"reason": "component_inventory_unavailable"})
        elif any(
            isinstance(component, dict)
            and any(
                isinstance(intent_filter, dict)
                and "android.intent.action.VIEW" in intent_filter.get("actions", [])
                and "android.intent.category.BROWSABLE"
                in intent_filter.get("categories", [])
                for intent_filter in component.get("intent_filters", [])
                if isinstance(component.get("intent_filters", []), list)
            )
            for component in components_value
        ):
            unknown.append({"reason": "normalized_deep_links_unavailable"})
        links = []
    elif not isinstance(values, list):
        malformed.append({"reason": "deep_links_not_a_list"})
        links: list[Any] = []
    else:
        links = values
    for link in links:
        if not isinstance(link, dict):
            malformed.append({"reason": "invalid_deep_link"})
            continue
        component_name = link.get("component")
        if not isinstance(component_name, str) or not isinstance(link.get("scheme"), str):
            malformed.append({"reason": "missing_component_or_scheme"})
            continue
        if component_name in conflicting_components:
            unknown.append(
                {"component": component_name, "reason": "conflicting_component_definitions"}
            )
            continue
        component = components.get(component_name, {})
        if application_enabled is False or component.get("enabled") is False:
            continue
        exported = link.get(
            "component_effective_exported",
            component.get("effective_exported"),
        )
        if not isinstance(exported, bool):
            unknown.append(
                {"component": component_name, "reason": "unknown_effective_export"}
            )
            continue
        if exported is False:
            continue
        permission_value = link.get(
            "component_permission",
            component.get("permission"),
        )
        component_type = link.get(
            "component_type",
            component.get("component_type"),
        )
        permission_fallback = (
            (None, "missing")
            if component_type == "activity-alias"
            else (
                application_permission,
                application_permission_source
                if application_permission
                else (
                    "malformed"
                    if application_permission_source == "malformed"
                    else "missing"
                ),
            )
        )
        permission, permission_source = _permission_value(
            permission_value,
            source="component",
            fallback=permission_fallback,
        )
        boundary = _boundary(
            "deep_link",
            permission,
            permission_source,
            custom_permissions,
        )
        row = {
            "component": component_name,
            "source_apk": link.get("source_apk"),
            "scheme": link.get("scheme"),
            "host": link.get("host"),
            "port": link.get("port"),
            "path": link.get("path"),
            "path_prefix": link.get("path_prefix"),
            "path_pattern": link.get("path_pattern"),
            "path_suffix": link.get("path_suffix"),
            "path_advanced_pattern": link.get("path_advanced_pattern"),
            "auto_verify_requested": link.get("auto_verify") is True,
            "broad_match": _deep_link_is_broad(link),
            "effective_permission": boundary,
        }
        evaluated.append(row)
        classification = str(boundary["classification"])
        if row["broad_match"] and classification in {"missing", "weak"}:
            exposed.append(row)
        elif classification in {
            "external_unknown",
            "legacy_restricted",
            "malformed",
            "unknown",
        }:
            unknown.append(row)
    if manifest.get("deep_links_truncated") is True:
        unknown.append({"reason": "deep_link_inventory_truncated"})
    elif manifest.get("deep_links_truncated") not in {None, False}:
        malformed.append({"reason": "invalid_truncation_marker"})
    if exposed:
        status = FindingStatus.POTENTIAL
        confidence = "medium"
        rationale = "An exported deep-link entry point has a broad, weakly protected URI match."
    elif unknown or malformed:
        status = FindingStatus.INCONCLUSIVE
        confidence = "low"
        rationale = "Deep-link exposure could not be classified safely."
    else:
        status = FindingStatus.PASS
        confidence = "high"
        rationale = "No broad, weakly protected deep-link entry point was identified."
    return ManifestPolicyResult(
        test_id="ASL-MANIFEST-DEEP-LINK-EXPOSURE",
        finding_status=status,
        confidence=confidence,
        validation_type="none",
        rationale=rationale,
        details={
            "evaluated_links": evaluated,
            "potentially_exposed": exposed,
            "unknown": unknown,
            "malformed": malformed,
            "auto_verify_is_not_verification_proof": True,
        },
        source=source,
        environment=environment,
        finding_eligible=finding_eligible,
    )


class ManifestSecurityAnalyzer:
    @staticmethod
    def analyze(
        manifest: dict[str, Any],
        *,
        source: str,
        environment: str,
    ) -> tuple[ManifestPolicyResult, ...]:
        if (source == "fixture") != (environment == "simulated"):
            raise ValueError("Manifest fixture requires simulated provenance.")
        simulated = source == "fixture" and environment == "simulated"
        allow_backup = manifest.get("allow_backup")
        if allow_backup is True:
            backup_status = FindingStatus.POTENTIAL
            backup_confidence = "medium"
            backup_rationale = (
                "Application backup is enabled; impact depends on Android version and data rules."
            )
        elif allow_backup is False:
            backup_status = FindingStatus.PASS
            backup_confidence = "high"
            backup_rationale = "Application backup is explicitly disabled."
        else:
            backup_status = FindingStatus.INCONCLUSIVE
            backup_confidence = "low"
            backup_rationale = "The effective application backup policy is unknown."
        results = [
            ManifestPolicyResult(
                test_id="ASL-MANIFEST-ALLOW-BACKUP",
                finding_status=backup_status,
                confidence=backup_confidence,
                validation_type="none",
                rationale=backup_rationale,
                details={"allow_backup": allow_backup},
                source=source,
                environment=environment,
                finding_eligible=not simulated,
            )
        ]

        custom_values = manifest.get("custom_permissions", [])
        custom_permissions: dict[str, str | None] = {}
        if isinstance(custom_values, list):
            for item in custom_values:
                if not isinstance(item, dict) or not item.get("name"):
                    continue
                name = str(item["name"])
                level = (
                    str(item["protection_level"])
                    if item.get("protection_level") is not None
                    else None
                )
                if name in custom_permissions and custom_permissions[name] != level:
                    custom_permissions[name] = "__conflicting_definition__"
                elif name not in custom_permissions:
                    custom_permissions[name] = level
        application_permission_value = manifest.get("application_permission")
        if isinstance(application_permission_value, str) and application_permission_value:
            application_permission = application_permission_value
            application_permission_source = "application"
        elif application_permission_value is None:
            application_permission = None
            application_permission_source = "missing"
        else:
            application_permission = None
            application_permission_source = "malformed"
        application_enabled_value = manifest.get("application_enabled")
        application_enabled = (
            application_enabled_value
            if isinstance(application_enabled_value, bool)
            else None
        )
        components = manifest.get("components")
        components_valid = isinstance(components, list)
        values = components if components_valid else []
        for component_type, test_id in (
            ("activity", "ASL-MANIFEST-EXPORTED-ACTIVITY"),
            ("service", "ASL-MANIFEST-EXPORTED-SERVICE"),
            ("receiver", "ASL-MANIFEST-EXPORTED-RECEIVER"),
            ("provider", "ASL-MANIFEST-EXPORTED-PROVIDER"),
        ):
            if not components_valid:
                results.append(
                    ManifestPolicyResult(
                        test_id=test_id,
                        finding_status=FindingStatus.INCONCLUSIVE,
                        confidence="low",
                        validation_type="none",
                        rationale="The normalized component inventory is unavailable.",
                        details={"inventory_error": "components_not_a_list"},
                        source=source,
                        environment=environment,
                        finding_eligible=not simulated,
                    )
                )
                continue
            category_rows = [
                item
                for item in values
                if isinstance(item, dict)
                and item.get("component_type") in {
                    component_type,
                    "activity-alias" if component_type == "activity" else component_type,
                }
            ]
            grouped_components: dict[tuple[str, str], set[str]] = {}
            for item in category_rows:
                key = (str(item.get("component_type")), str(item.get("name")))
                payload = {
                    field: value
                    for field, value in item.items()
                    if field != "source_apk"
                }
                grouped_components.setdefault(key, set()).add(
                    json.dumps(payload, sort_keys=True, separators=(",", ":"))
                )
            conflicting_components = {
                key for key, definitions in grouped_components.items() if len(definitions) > 1
            }
            relevant = [
                item
                for item in category_rows
                if item.get("enabled") is not False
                and not (component_type == "activity" and _is_launcher(item))
                and application_enabled is not False
                and (str(item.get("component_type")), str(item.get("name")))
                not in conflicting_components
            ]
            exposed: list[dict[str, Any]] = []
            unknown_export: list[str] = sorted(
                {name for _kind, name in conflicting_components}
            )
            for component in relevant:
                exported = component.get("effective_exported")
                if exported is None:
                    unknown_export.append(str(component.get("name", "<unnamed>")))
                    continue
                if not isinstance(exported, bool):
                    unknown_export.append(str(component.get("name", "<unnamed>")))
                    continue
                if exported is not True:
                    continue
                boundary_values = _component_boundaries(
                    component,
                    application_permission,
                    application_permission_source,
                )
                boundaries = tuple(
                    _boundary(
                        operation,
                        permission,
                        permission_source,
                        custom_permissions,
                        matcher=matcher,
                    )
                    for permission, permission_source, operation, matcher in boundary_values
                )
                classifications = tuple(
                    str(item["classification"]) for item in boundaries
                )
                exposed.append(
                    {
                        "name": str(component.get("name", "<unnamed>")),
                        "source_apk": component.get("source_apk"),
                        "component_type": component.get("component_type"),
                        "intent_actions": sorted(
                            {
                                str(action)
                                for intent_filter in component.get(
                                    "intent_filters",
                                    [],
                                )
                                if isinstance(intent_filter, dict)
                                for action in intent_filter.get("actions", [])
                                if isinstance(action, str)
                            }
                        ),
                        "foreground_service_type": component.get(
                            "foreground_service_type"
                        ),
                        "authorities": component.get("authorities"),
                        "grant_uri_permissions": component.get(
                            "grant_uri_permissions"
                        ),
                        "direct_boot_aware": component.get("direct_boot_aware"),
                        "multiprocess": component.get("multiprocess"),
                        "boundary": list(classifications),
                        "effective_permissions": list(boundaries),
                    }
                )
            unsafe = [
                item
                for item in exposed
                if any(value in {"missing", "weak"} for value in item["boundary"])
            ]
            unknown = [
                item
                for item in exposed
                if not any(value in {"missing", "weak"} for value in item["boundary"])
                and any(
                    value
                    in {
                        "external_unknown",
                        "legacy_restricted",
                        "malformed",
                        "unknown",
                    }
                    for value in item["boundary"]
                )
            ]
            if unsafe:
                status = FindingStatus.POTENTIAL
                confidence = "medium"
                rationale = "Exported component metadata lacks a strong permission boundary."
            elif unknown or unknown_export:
                status = FindingStatus.INCONCLUSIVE
                confidence = "low"
                rationale = "Export or permission protection could not be classified safely."
            else:
                status = FindingStatus.PASS
                confidence = "high"
                rationale = "No unprotected exported component was identified in this category."
            results.append(
                ManifestPolicyResult(
                    test_id=test_id,
                    finding_status=status,
                    confidence=confidence,
                    validation_type="none",
                    rationale=rationale,
                    details={
                        "evaluated_components": exposed,
                        "potentially_unprotected": unsafe,
                        "unknown_protection": unknown,
                        "unknown_export": unknown_export,
                        "conflicting_components": [
                            {"component_type": kind, "name": name}
                            for kind, name in sorted(conflicting_components)
                        ],
                    },
                    source=source,
                    environment=environment,
                    finding_eligible=not simulated,
                )
            )
        results.append(
            _custom_permission_policy_result(
                manifest,
                custom_permissions,
                source=source,
                environment=environment,
                finding_eligible=not simulated,
            )
        )
        results.append(
            _file_provider_policy_result(
                manifest,
                custom_permissions,
                application_permission,
                application_permission_source,
                application_enabled,
                source=source,
                environment=environment,
                finding_eligible=not simulated,
            )
        )
        results.append(
            _deep_link_policy_result(
                manifest,
                custom_permissions,
                application_permission,
                application_permission_source,
                application_enabled,
                source=source,
                environment=environment,
                finding_eligible=not simulated,
            )
        )
        raw_limitations = manifest.get("manifest_limitations", [])
        coverage_limitations = (
            [str(item) for item in raw_limitations[:50]]
            if isinstance(raw_limitations, list)
            else ["manifest_limitations_not_a_list"]
        )
        if manifest.get("manifest_complete") is False and not coverage_limitations:
            coverage_limitations.append("manifest_coverage_incomplete")
        coverage_sensitive = {
            "ASL-MANIFEST-EXPORTED-ACTIVITY",
            "ASL-MANIFEST-EXPORTED-SERVICE",
            "ASL-MANIFEST-EXPORTED-RECEIVER",
            "ASL-MANIFEST-EXPORTED-PROVIDER",
            "ASL-MANIFEST-CUSTOM-PERMISSION",
            "ASL-MANIFEST-FILEPROVIDER-PATHS",
            "ASL-MANIFEST-DEEP-LINK-EXPOSURE",
        }
        if coverage_limitations:
            results = [
                replace(
                    item,
                    finding_status=FindingStatus.INCONCLUSIVE,
                    confidence="low",
                    rationale=(
                        "Manifest coverage is incomplete, so absence of this condition "
                        "cannot be established."
                    ),
                    details={
                        **item.details,
                        "manifest_coverage_limitations": coverage_limitations,
                    },
                )
                if item.test_id in coverage_sensitive
                and item.finding_status is FindingStatus.PASS
                else replace(
                    item,
                    details={
                        **item.details,
                        "manifest_coverage_limitations": coverage_limitations,
                    },
                )
                if item.test_id in coverage_sensitive
                else item
                for item in results
            ]
        return tuple(results)
