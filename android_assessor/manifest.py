"""AAPT2 manifest-tree parsing for focused dynamic-test support."""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field, replace
from itertools import product
from pathlib import Path
from typing import Any

from .apk import BadgingInfo, parse_aapt_badging
from .errors import ApkInspectionError, ExternalCommandError
from .redaction import REDACTED, redact_text
from .storage import require_under_root, write_text_atomic
from .subprocess_utils import run_command_bounded_output as run_command


@dataclass(slots=True)
class ManifestNode:
    tag: str
    indent: int
    attributes: dict[str, str | bool | int] = field(default_factory=dict)
    children: list[ManifestNode] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class PermissionUse:
    name: str
    max_sdk: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class CustomPermission:
    name: str
    protection_level: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ManifestMetaData:
    name: str
    value: str | bool | int | None = None
    resource: str | int | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "name": self.name,
            "resource": self.resource,
            "value": self.value if isinstance(self.value, (bool, int)) else None,
        }
        if isinstance(self.value, str):
            payload["value_sha256"] = hashlib.sha256(
                self.value.encode("utf-8", errors="replace")
            ).hexdigest()
            payload["value_length"] = len(self.value)
        return payload


@dataclass(frozen=True, slots=True)
class PathPermission:
    permission: str | None = None
    read_permission: str | None = None
    write_permission: str | None = None
    path: str | None = None
    path_prefix: str | None = None
    path_pattern: str | None = None
    path_suffix: str | None = None
    path_advanced_pattern: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class IntentData:
    scheme: str | None = None
    host: str | None = None
    port: str | None = None
    path: str | None = None
    path_prefix: str | None = None
    path_pattern: str | None = None
    path_suffix: str | None = None
    path_advanced_pattern: str | None = None
    mime_type: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class IntentFilter:
    actions: tuple[str, ...]
    categories: tuple[str, ...]
    data: tuple[IntentData, ...]
    priority: int | None = None
    auto_verify: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "actions": list(self.actions),
            "categories": list(self.categories),
            "data": [item.to_dict() for item in self.data],
            "priority": self.priority,
            "auto_verify": self.auto_verify,
        }


@dataclass(frozen=True, slots=True)
class ComponentInfo:
    component_type: str
    name: str
    exported: bool | None
    effective_exported: bool | None
    exported_source: str
    enabled: bool | None
    permission: str | None
    read_permission: str | None
    write_permission: str | None
    authorities: str | None
    process: str | None
    intent_filters: tuple[IntentFilter, ...]
    grant_uri_permissions: bool | None = None
    direct_boot_aware: bool | None = None
    stop_with_task: bool | None = None
    isolated_process: bool | None = None
    multiprocess: bool | None = None
    foreground_service_type: str | None = None
    meta_data: tuple[ManifestMetaData, ...] = ()
    path_permissions: tuple[PathPermission, ...] = ()
    uri_grant_patterns: tuple[PathPermission, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "component_type": self.component_type,
            "name": self.name,
            "exported": self.exported,
            "effective_exported": self.effective_exported,
            "exported_source": self.exported_source,
            "enabled": self.enabled,
            "permission": self.permission,
            "read_permission": self.read_permission,
            "write_permission": self.write_permission,
            "authorities": self.authorities,
            "process": self.process,
            "intent_filters": [item.to_dict() for item in self.intent_filters],
            "grant_uri_permissions": self.grant_uri_permissions,
            "direct_boot_aware": self.direct_boot_aware,
            "stop_with_task": self.stop_with_task,
            "isolated_process": self.isolated_process,
            "multiprocess": self.multiprocess,
            "foreground_service_type": self.foreground_service_type,
            "meta_data": [item.to_dict() for item in self.meta_data],
            "path_permissions": [item.to_dict() for item in self.path_permissions],
            "uri_grant_patterns": [
                item.to_dict() for item in self.uri_grant_patterns
            ],
        }


@dataclass(frozen=True, slots=True)
class DeepLink:
    component: str
    scheme: str
    host: str | None
    port: str | None
    path: str | None
    path_prefix: str | None
    path_pattern: str | None
    auto_verify: bool | None
    path_suffix: str | None = None
    path_advanced_pattern: str | None = None
    component_type: str = "activity"
    component_effective_exported: bool | None = None
    component_exported_source: str = "unknown"
    component_permission: str | None = None
    filter_index: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class FileProviderPathEntry:
    kind: str
    name: str | None
    path: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class FileProviderPaths:
    provider: str
    authorities: str | None
    grant_uri_permissions: bool | None
    resource_reference: str | int | None
    resource_path: str | None
    resolution_status: str
    entries: tuple[FileProviderPathEntry, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "entries": [item.to_dict() for item in self.entries],
        }


@dataclass(frozen=True, slots=True)
class ManifestInspection:
    package: str | None
    debuggable: bool | None
    test_only: bool | None
    uses_cleartext_traffic: bool | None
    network_security_config: str | None
    allow_backup: bool | None
    application_enabled: bool | None
    application_permission: str | None
    permissions: tuple[PermissionUse, ...]
    custom_permissions: tuple[CustomPermission, ...]
    components: tuple[ComponentInfo, ...]
    deep_links: tuple[DeepLink, ...]
    file_provider_paths: tuple[FileProviderPaths, ...] = ()
    deep_links_truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "debuggable": self.debuggable,
            "test_only": self.test_only,
            "uses_cleartext_traffic": self.uses_cleartext_traffic,
            "network_security_config": self.network_security_config,
            "allow_backup": self.allow_backup,
            "application_enabled": self.application_enabled,
            "application_permission": self.application_permission,
            "permissions": [item.to_dict() for item in self.permissions],
            "custom_permissions": [item.to_dict() for item in self.custom_permissions],
            "components": [item.to_dict() for item in self.components],
            "deep_links": [item.to_dict() for item in self.deep_links],
            "file_provider_paths": [item.to_dict() for item in self.file_provider_paths],
            "deep_links_truncated": self.deep_links_truncated,
        }


@dataclass(frozen=True, slots=True)
class AaptInspection:
    badging: BadgingInfo
    manifest: ManifestInspection
    badging_path: Path
    xmltree_path: Path
    resource_xmltree_paths: tuple[Path, ...] = ()
    resource_table_path: Path | None = None


_ELEMENT_PATTERN = re.compile(r"^(?P<indent>\s*)E:\s+(?P<tag>[A-Za-z0-9_.-]+)")
_ATTRIBUTE_PATTERN = re.compile(r"^(?P<indent>\s*)A:\s+(?P<label>.+?)=(?P<value>.*)$")
_RAW_VALUE_PATTERN = re.compile(
    r'\(Raw:\s*"((?:\\.|[^"\\])*)"\)',
    re.IGNORECASE,
)
_SYMBOLIC_XML_REFERENCE = re.compile(
    r"^@(?:(?:[A-Za-z0-9_.]+):)?xml/(?P<name>[A-Za-z0-9_.-]+)$"
)
_RESOURCE_DECLARATION_PATTERN = re.compile(
    r"\bresource\s+(?P<identifier>0x[0-9a-fA-F]+)(?:\s+(?P<name>\S+))?"
)
_RESOURCE_XML_PATH_PATTERN = re.compile(
    r"\b(res/xml(?:-[A-Za-z0-9_+]+)*/[A-Za-z0-9_.-]+\.xml)\b"
)
_AAPT_STRING_PATTERN = re.compile(r"^\s*String\s+#\d+\s*:\s?(?P<value>.*)$")
_FILE_PROVIDER_META_DATA = "android.support.FILE_PROVIDER_PATHS"
_MAX_DEEP_LINK_COMBINATIONS = 256
_MAX_FILE_PROVIDER_RESOURCES = 16
_MAX_FILE_PROVIDER_PATH_ENTRIES = 256
_MAX_RESOURCE_STRINGS = 50_000
_MAX_RESOURCE_STRING_LENGTH = 4096


def _canonical_boolean_numeric(value: int) -> bool | None:
    if value == 0:
        return False
    if value in {-1, 1, 0xFFFFFFFF}:
        return True
    return None


def _parse_attribute_value(raw: str) -> str | bool | int:
    value = raw.strip()
    raw_match = _RAW_VALUE_PATTERN.search(value)
    if raw_match:
        return raw_match.group(1).replace(r"\"", '"').replace(r"\\", "\\")
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1].replace(r"\"", '"').replace(r"\\", "\\")
    typed = re.fullmatch(r"\(type 0x([0-9a-fA-F]+)\)(0x[0-9a-fA-F]+|-?\d+)", value)
    if typed:
        type_id = int(typed.group(1), 16)
        numeric = int(typed.group(2), 0)
        if type_id == 0x12:
            normalized = _canonical_boolean_numeric(numeric)
            return normalized if normalized is not None else value
        return numeric
    return value


def parse_aapt_xmltree(output: str) -> list[ManifestNode]:
    roots: list[ManifestNode] = []
    stack: list[ManifestNode] = []
    for raw_line in output.replace("\r", "").splitlines():
        element_match = _ELEMENT_PATTERN.match(raw_line)
        if element_match:
            indent = len(element_match.group("indent"))
            node = ManifestNode(tag=element_match.group("tag"), indent=indent)
            while stack and stack[-1].indent >= indent:
                stack.pop()
            if stack:
                stack[-1].children.append(node)
            else:
                roots.append(node)
            stack.append(node)
            continue
        attribute_match = _ATTRIBUTE_PATTERN.match(raw_line)
        if not attribute_match or not stack:
            continue
        indent = len(attribute_match.group("indent"))
        owner = next((node for node in reversed(stack) if node.indent < indent), None)
        if owner is None:
            continue
        label = re.sub(r"\(0x[0-9a-fA-F]+\)$", "", attribute_match.group("label"))
        name = label.rsplit(":", 1)[-1].strip()
        owner.attributes[name] = _parse_attribute_value(attribute_match.group("value"))
    return roots


def parse_aapt_strings(output: str) -> tuple[str, ...]:
    """Parse a bounded AAPT2 resource string pool without retaining headers."""

    values: list[str] = []
    seen: set[str] = set()
    for line in output.replace("\r", "").splitlines():
        match = _AAPT_STRING_PATTERN.match(line)
        if match is None:
            continue
        value = match.group("value")
        if not value:
            continue
        if len(value) > _MAX_RESOURCE_STRING_LENGTH:
            value = value[: _MAX_RESOURCE_STRING_LENGTH + 1]
        if value in seen:
            continue
        seen.add(value)
        values.append(value)
        # Retain one sentinel beyond the scanner budget so downstream analysis can
        # distinguish a complete inventory from a bounded/truncated one.
        if len(values) > _MAX_RESOURCE_STRINGS:
            break
    return tuple(values)


def redact_aapt_xmltree(output: str) -> str:
    """Redact AAPT XML-tree values in one bounded, line-oriented pass."""

    redacted: list[str] = []
    for raw_line in output.replace("\r", "").splitlines():
        match = _ATTRIBUTE_PATTERN.match(raw_line)
        if match is not None:
            label = re.sub(r"\(0x[0-9a-fA-F]+\)$", "", match.group("label"))
            name = label.rsplit(":", 1)[-1].strip().casefold()
            if name == "value":
                prefix = raw_line[: match.start("value")]
                redacted.append(f"{prefix}{REDACTED}")
                continue
        redacted.append(redact_text(raw_line))
    suffix = "\n" if output.endswith(("\n", "\r")) else ""
    return "\n".join(redacted) + suffix


def _text_attribute(node: ManifestNode, name: str) -> str | None:
    value = node.attributes.get(name)
    return value if isinstance(value, str) and value else None


def _attribute_value(
    node: ManifestNode,
    name: str,
) -> str | bool | int | None:
    value = node.attributes.get(name)
    return value if isinstance(value, (str, bool, int)) else None


def _bool_attribute(node: ManifestNode, name: str) -> bool | None:
    value = node.attributes.get(name)
    if isinstance(value, bool):
        return value
    if not isinstance(value, str):
        return None
    candidate = value.strip().casefold()
    typed = re.fullmatch(
        r"(?:\(type\s+0x12\)|type\s*=\s*0x12\s+data\s*=\s*)"
        r"(?P<value>0x[0-9a-f]+|-?\d+)",
        candidate,
    )
    if typed is not None:
        candidate = typed.group("value")
    if candidate == "true":
        return True
    if candidate == "false":
        return False
    if re.fullmatch(r"0x[0-9a-f]+|-?\d+", candidate):
        try:
            numeric = int(candidate, 0)
        except ValueError:
            return None
        return _canonical_boolean_numeric(numeric)
    return None


def _int_attribute(node: ManifestNode, name: str) -> int | None:
    value = node.attributes.get(name)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _children(node: ManifestNode, *tags: str) -> list[ManifestNode]:
    accepted = set(tags)
    return [child for child in node.children if child.tag in accepted]


def _component_name(package: str | None, raw_name: str | None) -> str:
    if raw_name is None:
        return "<unnamed>"
    if package is None or raw_name.startswith(package):
        return raw_name
    if raw_name.startswith("."):
        return package + raw_name
    if "." not in raw_name:
        return f"{package}.{raw_name}"
    return raw_name


def _intent_filter(node: ManifestNode) -> IntentFilter:
    actions = tuple(
        name
        for child in _children(node, "action")
        if (name := _text_attribute(child, "name")) is not None
    )
    categories = tuple(
        name
        for child in _children(node, "category")
        if (name := _text_attribute(child, "name")) is not None
    )
    data = tuple(
        IntentData(
            scheme=_text_attribute(child, "scheme"),
            host=_text_attribute(child, "host"),
            port=_text_attribute(child, "port"),
            path=_text_attribute(child, "path"),
            path_prefix=_text_attribute(child, "pathPrefix"),
            path_pattern=_text_attribute(child, "pathPattern"),
            path_suffix=_text_attribute(child, "pathSuffix"),
            path_advanced_pattern=_text_attribute(child, "pathAdvancedPattern"),
            mime_type=_text_attribute(child, "mimeType"),
        )
        for child in _children(node, "data")
    )
    return IntentFilter(
        actions=actions,
        categories=categories,
        data=data,
        priority=_int_attribute(node, "priority"),
        auto_verify=_bool_attribute(node, "autoVerify"),
    )


def _meta_data(node: ManifestNode) -> tuple[ManifestMetaData, ...]:
    return tuple(
        ManifestMetaData(
            name=name,
            value=_attribute_value(child, "value"),
            resource=_attribute_value(child, "resource"),
        )
        for child in _children(node, "meta-data")
        if (name := _text_attribute(child, "name")) is not None
    )


def _path_permissions(node: ManifestNode) -> tuple[PathPermission, ...]:
    return tuple(
        PathPermission(
            permission=_text_attribute(child, "permission"),
            read_permission=_text_attribute(child, "readPermission"),
            write_permission=_text_attribute(child, "writePermission"),
            path=_text_attribute(child, "path"),
            path_prefix=_text_attribute(child, "pathPrefix"),
            path_pattern=_text_attribute(child, "pathPattern"),
            path_suffix=_text_attribute(child, "pathSuffix"),
            path_advanced_pattern=_text_attribute(child, "pathAdvancedPattern"),
        )
        for child in _children(node, "path-permission")
    )


def _uri_grant_patterns(node: ManifestNode) -> tuple[PathPermission, ...]:
    return tuple(
        PathPermission(
            path=_text_attribute(child, "path"),
            path_prefix=_text_attribute(child, "pathPrefix"),
            path_pattern=_text_attribute(child, "pathPattern"),
            path_suffix=_text_attribute(child, "pathSuffix"),
            path_advanced_pattern=_text_attribute(child, "pathAdvancedPattern"),
        )
        for child in _children(node, "grant-uri-permission")
    )


def _unique(values: list[Any]) -> list[Any]:
    return list(dict.fromkeys(values))


def _deep_links_for_filter(
    component: ComponentInfo,
    intent_filter: IntentFilter,
    *,
    filter_index: int,
    application_permission: str | None,
    remaining: int,
) -> tuple[list[DeepLink], bool]:
    if remaining <= 0:
        return [], True
    schemes = _unique(
        [item.scheme for item in intent_filter.data if item.scheme is not None]
    )
    if not schemes:
        return [], False
    authorities = _unique(
        [
            (item.host, item.port)
            for item in intent_filter.data
            if item.host is not None
        ]
    ) or [(None, None)]
    path_values = _unique(
        [
            (
                item.path,
                item.path_prefix,
                item.path_pattern,
                item.path_suffix,
                item.path_advanced_pattern,
            )
            for item in intent_filter.data
            if any(
                value is not None
                for value in (
                    item.path,
                    item.path_prefix,
                    item.path_pattern,
                    item.path_suffix,
                    item.path_advanced_pattern,
                )
            )
        ]
    ) or [(None, None, None, None, None)]
    links: list[DeepLink] = []
    truncated = False
    for scheme, authority, paths in product(schemes, authorities, path_values):
        if len(links) >= remaining:
            truncated = True
            break
        host, port = authority
        path, path_prefix, path_pattern, path_suffix, path_advanced_pattern = paths
        links.append(
            DeepLink(
                component=component.name,
                scheme=scheme,
                host=host,
                port=port,
                path=path,
                path_prefix=path_prefix,
                path_pattern=path_pattern,
                path_suffix=path_suffix,
                path_advanced_pattern=path_advanced_pattern,
                auto_verify=intent_filter.auto_verify,
                component_type=component.component_type,
                component_effective_exported=component.effective_exported,
                component_exported_source=component.exported_source,
                component_permission=(
                    component.permission
                    if component.component_type == "activity-alias"
                    else component.permission or application_permission
                ),
                filter_index=filter_index,
            )
        )
    return links, truncated


def _file_provider_path_declarations(
    components: list[ComponentInfo],
) -> tuple[FileProviderPaths, ...]:
    declarations: list[FileProviderPaths] = []
    for component in components:
        if component.component_type != "provider":
            continue
        metadata = [
            item for item in component.meta_data if item.name == _FILE_PROVIDER_META_DATA
        ]
        if not metadata:
            if component.name.casefold().endswith("fileprovider"):
                declarations.append(
                    FileProviderPaths(
                        provider=component.name,
                        authorities=component.authorities,
                        grant_uri_permissions=component.grant_uri_permissions,
                        resource_reference=None,
                        resource_path=None,
                        resolution_status="missing_metadata",
                    )
                )
            continue
        seen: set[str] = set()
        for item in metadata:
            reference = item.resource
            marker = repr(reference)
            if marker in seen:
                continue
            seen.add(marker)
            declarations.append(
                FileProviderPaths(
                    provider=component.name,
                    authorities=component.authorities,
                    grant_uri_permissions=component.grant_uri_permissions,
                    resource_reference=reference,
                    resource_path=None,
                    resolution_status=(
                        "unresolved" if reference is not None else "missing_resource"
                    ),
                )
            )
    return tuple(declarations)


def parse_file_provider_paths_tree(
    roots: list[ManifestNode],
) -> tuple[tuple[FileProviderPathEntry, ...], str]:
    paths = next((node for node in roots if node.tag == "paths"), None)
    if paths is None:
        return (), "malformed"
    entries = tuple(
        FileProviderPathEntry(
            kind=child.tag,
            name=_text_attribute(child, "name"),
            path=_text_attribute(child, "path"),
        )
        for child in paths.children[:_MAX_FILE_PROVIDER_PATH_ENTRIES]
    )
    if len(paths.children) > _MAX_FILE_PROVIDER_PATH_ENTRIES:
        return entries, "limit_exceeded"
    if not entries:
        return (), "malformed"
    return entries, "resolved"


def _normalize_resource_identifier(value: str | int | None) -> str | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return f"0x{value:08x}"
    if not isinstance(value, str):
        return None
    candidate = value.strip().removeprefix("@").casefold()
    if not re.fullmatch(r"0x[0-9a-f]+", candidate):
        return None
    return f"0x{int(candidate, 16):08x}"


def _symbolic_xml_path(value: str | int | None) -> str | None:
    if not isinstance(value, str):
        return None
    match = _SYMBOLIC_XML_REFERENCE.fullmatch(value.strip())
    if match is None:
        return None
    return f"res/xml/{match.group('name')}.xml"


def _valid_apk_xml_path(value: str) -> bool:
    return bool(
        _RESOURCE_XML_PATH_PATTERN.fullmatch(value)
        and ".." not in value.split("/")
        and "\\" not in value
    )


def parse_aapt_resource_xml_paths(output: str) -> dict[str, tuple[str, ...]]:
    candidates: dict[str, list[str]] = {}
    inferred: dict[str, str] = {}
    current: str | None = None
    current_symbolic: str | None = None
    for line in output.replace("\r", "").splitlines():
        declaration = _RESOURCE_DECLARATION_PATTERN.search(line)
        if declaration is not None:
            current = _normalize_resource_identifier(declaration.group("identifier"))
            name = declaration.group("name") or ""
            symbolic = re.search(r"(?:^|:)xml/([A-Za-z0-9_.-]+)$", name)
            current_symbolic = f"@xml/{symbolic.group(1)}" if symbolic else None
            if current and current_symbolic:
                inferred[current] = f"res/xml/{symbolic.group(1)}.xml"
                inferred[current_symbolic] = f"res/xml/{symbolic.group(1)}.xml"
        resource_path = _RESOURCE_XML_PATH_PATTERN.search(line)
        if current and resource_path and _valid_apk_xml_path(resource_path.group(1)):
            path = resource_path.group(1)
            candidates.setdefault(current, []).append(path)
            if current_symbolic:
                candidates.setdefault(current_symbolic, []).append(path)
    for identifier, path in inferred.items():
        candidates.setdefault(identifier, [path])
    return {
        identifier: tuple(dict.fromkeys(paths))
        for identifier, paths in candidates.items()
    }


def _effective_exported(
    component_type: str,
    explicit: bool | None,
    has_filters: bool,
    target_sdk: int | None,
) -> tuple[bool | None, str]:
    if explicit is not None:
        return explicit, "explicit"
    if component_type == "provider":
        if target_sdk is None:
            return None, "unknown_provider_default"
        if target_sdk is not None and target_sdk < 17:
            return True, "legacy_provider_default"
        return False, "provider_default"
    if not has_filters:
        return False, "no_intent_filter_default"
    if target_sdk is not None and target_sdk < 31:
        return True, "legacy_intent_filter_default"
    return None, "missing_explicit_exported"


def inspect_manifest_tree(
    roots: list[ManifestNode],
    *,
    target_sdk: int | None = None,
) -> ManifestInspection:
    manifest = next((node for node in roots if node.tag == "manifest"), None)
    if manifest is None:
        raise ApkInspectionError("AAPT2 XML tree did not contain a manifest element.")
    package = _text_attribute(manifest, "package")
    permissions: list[PermissionUse] = []
    for permission in _children(manifest, "uses-permission", "uses-permission-sdk-23"):
        name = _text_attribute(permission, "name")
        if name and not any(item.name == name for item in permissions):
            permissions.append(
                PermissionUse(
                    name=name,
                    max_sdk=_int_attribute(permission, "maxSdkVersion"),
                )
            )
    custom_permissions = tuple(
        CustomPermission(
            name=name,
            protection_level=(
                str(permission.attributes["protectionLevel"])
                if "protectionLevel" in permission.attributes
                else None
            ),
        )
        for permission in _children(manifest, "permission")
        if (name := _text_attribute(permission, "name")) is not None
    )
    application = next(iter(_children(manifest, "application")), None)
    if application is None:
        return ManifestInspection(
            package=package,
            debuggable=None,
            test_only=None,
            uses_cleartext_traffic=None,
            network_security_config=None,
            allow_backup=None,
            application_enabled=None,
            application_permission=None,
            permissions=tuple(permissions),
            custom_permissions=custom_permissions,
            components=(),
            deep_links=(),
        )

    application_enabled = _bool_attribute(application, "enabled")
    components: list[ComponentInfo] = []
    deep_links: list[DeepLink] = []
    deep_links_truncated = False
    component_tags = ("activity", "activity-alias", "service", "receiver", "provider")
    for component_node in _children(application, *component_tags):
        name = _component_name(package, _text_attribute(component_node, "name"))
        filters = tuple(
            _intent_filter(filter_node)
            for filter_node in _children(component_node, "intent-filter")
        )
        explicit_exported = _bool_attribute(component_node, "exported")
        component_enabled = _bool_attribute(component_node, "enabled")
        effective, source = _effective_exported(
            component_node.tag,
            explicit_exported,
            bool(filters),
            target_sdk,
        )
        if application_enabled is False:
            effective, source = False, "application_disabled"
        elif component_enabled is False:
            effective, source = False, "component_disabled"
        component = ComponentInfo(
            component_type=component_node.tag,
            name=name,
            exported=explicit_exported,
            effective_exported=effective,
            exported_source=source,
            enabled=component_enabled,
            permission=_text_attribute(component_node, "permission"),
            read_permission=_text_attribute(component_node, "readPermission"),
            write_permission=_text_attribute(component_node, "writePermission"),
            authorities=_text_attribute(component_node, "authorities"),
            process=_text_attribute(component_node, "process"),
            intent_filters=filters,
            grant_uri_permissions=_bool_attribute(
                component_node,
                "grantUriPermissions",
            ),
            direct_boot_aware=_bool_attribute(component_node, "directBootAware"),
            stop_with_task=_bool_attribute(component_node, "stopWithTask"),
            isolated_process=_bool_attribute(component_node, "isolatedProcess"),
            multiprocess=_bool_attribute(component_node, "multiprocess"),
            foreground_service_type=_text_attribute(
                component_node,
                "foregroundServiceType",
            ),
            meta_data=_meta_data(component_node),
            path_permissions=_path_permissions(component_node),
            uri_grant_patterns=_uri_grant_patterns(component_node),
        )
        components.append(component)
        for filter_index, intent_filter in enumerate(filters):
            if component.component_type not in {"activity", "activity-alias"}:
                continue
            is_view = "android.intent.action.VIEW" in intent_filter.actions
            is_browsable = "android.intent.category.BROWSABLE" in intent_filter.categories
            is_default = "android.intent.category.DEFAULT" in intent_filter.categories
            if not (is_view and is_browsable and is_default):
                continue
            filter_links, truncated = _deep_links_for_filter(
                component,
                intent_filter,
                filter_index=filter_index,
                application_permission=_text_attribute(application, "permission"),
                remaining=_MAX_DEEP_LINK_COMBINATIONS - len(deep_links),
            )
            deep_links.extend(filter_links)
            if truncated:
                deep_links_truncated = True
    file_provider_paths = _file_provider_path_declarations(components)
    return ManifestInspection(
        package=package,
        debuggable=_bool_attribute(application, "debuggable"),
        test_only=_bool_attribute(application, "testOnly"),
        uses_cleartext_traffic=_bool_attribute(application, "usesCleartextTraffic"),
        network_security_config=_text_attribute(application, "networkSecurityConfig"),
        allow_backup=_bool_attribute(application, "allowBackup"),
        application_enabled=application_enabled,
        application_permission=_text_attribute(application, "permission"),
        permissions=tuple(permissions),
        custom_permissions=custom_permissions,
        components=tuple(components),
        deep_links=tuple(deep_links),
        file_provider_paths=file_provider_paths,
        deep_links_truncated=deep_links_truncated,
    )


class Aapt2Inspector:
    def __init__(self, executable: Path, *, command_log: Path | None = None) -> None:
        self.executable = executable.resolve()
        self.command_log = command_log
        if not self.executable.is_file():
            raise ApkInspectionError(f"aapt2 executable not found: {self.executable}")

    def _run(self, arguments: tuple[str, ...], operation: str) -> str:
        try:
            result = run_command(
                [self.executable, *arguments],
                timeout=90,
                max_stdout_bytes=20_000_000,
                max_stderr_bytes=1_000_000,
                check=True,
                command_log=self.command_log,
            )
        except ExternalCommandError as exc:
            raise ApkInspectionError(f"AAPT2 failed while {operation}: {exc}") from exc
        if len(result.stdout) > 20_000_000:
            raise ApkInspectionError("AAPT2 output exceeded the 20 MB inspection limit.")
        return result.stdout

    def dump_strings(self, apk_path: Path, *, project_root: Path) -> tuple[str, ...]:
        apk = require_under_root(apk_path, project_root)
        output = self._run(
            ("dump", "strings", str(apk)),
            "dumping the APK resource string pool",
        )
        return parse_aapt_strings(output)

    def _resolve_file_provider_paths(
        self,
        manifest: ManifestInspection,
        apk: Path,
        *,
        destination: Path,
        project_root: Path,
    ) -> tuple[ManifestInspection, tuple[Path, ...], Path | None]:
        declarations = list(manifest.file_provider_paths)
        if not declarations:
            return manifest, (), None

        resource_mapping: dict[str, tuple[str, ...]] = {}
        resource_inventory_loaded = False
        resource_table_path: Path | None = None
        if declarations:
            try:
                resources_output = self._run(
                    ("dump", "resources", str(apk)),
                    "resolving referenced XML resources",
                )
            except ApkInspectionError:
                resources_output = ""
            if resources_output:
                resource_inventory_loaded = True
                resource_table_path = destination / "resources.txt"
                write_text_atomic(
                    resource_table_path,
                    resources_output,
                    root=project_root,
                )
                resource_mapping = parse_aapt_resource_xml_paths(resources_output)

        resolved_paths: list[tuple[tuple[str, ...], bool]] = []
        unique_paths: list[str] = []
        for item in declarations:
            symbolic_path = _symbolic_xml_path(item.resource_reference)
            symbolic_key = (
                f"@xml/{Path(symbolic_path).stem}" if symbolic_path is not None else None
            )
            identifier = _normalize_resource_identifier(item.resource_reference)
            paths = resource_mapping.get(identifier or "", ())
            if not paths and symbolic_key is not None:
                paths = resource_mapping.get(symbolic_key, ())
            inventory_complete = bool(paths) and resource_inventory_loaded
            if not paths and symbolic_path is not None:
                paths = (symbolic_path,)
            valid_paths = tuple(path for path in paths if _valid_apk_xml_path(path))
            for path in valid_paths:
                if path not in unique_paths:
                    unique_paths.append(path)
            resolved_paths.append((valid_paths, inventory_complete))

        allowed_paths = set(unique_paths[:_MAX_FILE_PROVIDER_RESOURCES])
        parsed_by_path: dict[
            str,
            tuple[tuple[FileProviderPathEntry, ...], str],
        ] = {}
        raw_paths: list[Path] = []
        for index, resource_path in enumerate(unique_paths[:_MAX_FILE_PROVIDER_RESOURCES]):
            try:
                resource_output = self._run(
                    ("dump", "xmltree", "--file", resource_path, str(apk)),
                    f"dumping {resource_path}",
                )
            except ApkInspectionError:
                parsed_by_path[resource_path] = ((), "unresolved")
                continue
            safe_name = re.sub(
                r"[^A-Za-z0-9_.-]+",
                "-",
                Path(resource_path).stem,
            ).strip("-.") or "resource"
            raw_path = destination / (
                f"file-provider-{index:02d}-{safe_name}-xmltree.txt"
            )
            write_text_atomic(raw_path, resource_output, root=project_root)
            raw_paths.append(raw_path)
            parsed_by_path[resource_path] = parse_file_provider_paths_tree(
                parse_aapt_xmltree(resource_output)
            )

        resolved: list[FileProviderPaths] = []
        for item, resolved_value in zip(declarations, resolved_paths, strict=True):
            resource_paths, inventory_complete = resolved_value
            if not resource_paths:
                resolved.append(item)
                continue
            for resource_path in resource_paths:
                if resource_path not in allowed_paths:
                    resolved.append(
                        replace(
                            item,
                            resource_path=resource_path,
                            resolution_status="limit_exceeded",
                        )
                    )
                    continue
                entries, status = parsed_by_path.get(resource_path, ((), "unresolved"))
                if status == "resolved" and not inventory_complete:
                    status = "resolved_partial"
                resolved.append(
                    replace(
                        item,
                        resource_path=resource_path,
                        resolution_status=status,
                        entries=entries,
                    )
                )
        return (
            replace(manifest, file_provider_paths=tuple(resolved)),
            tuple(raw_paths),
            resource_table_path,
        )

    def inspect(
        self,
        apk_path: Path,
        *,
        output_dir: Path,
        project_root: Path,
        target_sdk: int | None,
    ) -> AaptInspection:
        apk = require_under_root(apk_path, project_root)
        destination = require_under_root(output_dir, project_root)
        destination.mkdir(parents=True, exist_ok=True)
        badging_output = self._run(("dump", "badging", str(apk)), "dumping APK badging")
        xmltree_output = self._run(
            ("dump", "xmltree", "--file", "AndroidManifest.xml", str(apk)),
            "dumping AndroidManifest.xml",
        )
        badging_path = destination / "badging.txt"
        xmltree_path = destination / "manifest-xmltree.txt"
        badging = parse_aapt_badging(badging_output)
        manifest = inspect_manifest_tree(
            parse_aapt_xmltree(xmltree_output),
            target_sdk=target_sdk if target_sdk is not None else badging.target_sdk,
        )
        manifest, resource_paths, resource_table_path = self._resolve_file_provider_paths(
            manifest,
            apk,
            destination=destination,
            project_root=project_root,
        )
        write_text_atomic(badging_path, badging_output, root=project_root)
        write_text_atomic(xmltree_path, xmltree_output, root=project_root)
        return AaptInspection(
            badging=badging,
            manifest=manifest,
            badging_path=badging_path,
            xmltree_path=xmltree_path,
            resource_xmltree_paths=resource_paths,
            resource_table_path=resource_table_path,
        )
