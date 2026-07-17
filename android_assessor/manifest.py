"""AAPT2 manifest-tree parsing for focused dynamic-test support."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .apk import BadgingInfo, parse_aapt_badging
from .errors import ApkInspectionError, ExternalCommandError
from .storage import require_under_root, write_text_atomic
from .subprocess_utils import run_command


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
class IntentData:
    scheme: str | None = None
    host: str | None = None
    port: str | None = None
    path: str | None = None
    path_prefix: str | None = None
    path_pattern: str | None = None
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

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ManifestInspection:
    package: str | None
    debuggable: bool | None
    test_only: bool | None
    uses_cleartext_traffic: bool | None
    network_security_config: str | None
    allow_backup: bool | None
    application_permission: str | None
    permissions: tuple[PermissionUse, ...]
    custom_permissions: tuple[CustomPermission, ...]
    components: tuple[ComponentInfo, ...]
    deep_links: tuple[DeepLink, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "debuggable": self.debuggable,
            "test_only": self.test_only,
            "uses_cleartext_traffic": self.uses_cleartext_traffic,
            "network_security_config": self.network_security_config,
            "allow_backup": self.allow_backup,
            "application_permission": self.application_permission,
            "permissions": [item.to_dict() for item in self.permissions],
            "custom_permissions": [item.to_dict() for item in self.custom_permissions],
            "components": [item.to_dict() for item in self.components],
            "deep_links": [item.to_dict() for item in self.deep_links],
        }


@dataclass(frozen=True, slots=True)
class AaptInspection:
    badging: BadgingInfo
    manifest: ManifestInspection
    badging_path: Path
    xmltree_path: Path


_ELEMENT_PATTERN = re.compile(r"^(?P<indent>\s*)E:\s+(?P<tag>[A-Za-z0-9_.-]+)")
_ATTRIBUTE_PATTERN = re.compile(r"^(?P<indent>\s*)A:\s+(?P<label>.+?)=(?P<value>.*)$")
_RAW_VALUE_PATTERN = re.compile(r'\(Raw:\s*"((?:\\.|[^"\\])*)"\)')


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
            return numeric != 0
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


def _text_attribute(node: ManifestNode, name: str) -> str | None:
    value = node.attributes.get(name)
    return value if isinstance(value, str) and value else None


def _bool_attribute(node: ManifestNode, name: str) -> bool | None:
    value = node.attributes.get(name)
    return value if isinstance(value, bool) else None


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


def _effective_exported(
    component_type: str,
    explicit: bool | None,
    has_filters: bool,
    target_sdk: int | None,
) -> tuple[bool | None, str]:
    if explicit is not None:
        return explicit, "explicit"
    if component_type == "provider":
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
            application_permission=None,
            permissions=tuple(permissions),
            custom_permissions=custom_permissions,
            components=(),
            deep_links=(),
        )

    components: list[ComponentInfo] = []
    deep_links: list[DeepLink] = []
    component_tags = ("activity", "activity-alias", "service", "receiver", "provider")
    for component_node in _children(application, *component_tags):
        name = _component_name(package, _text_attribute(component_node, "name"))
        filters = tuple(
            _intent_filter(filter_node)
            for filter_node in _children(component_node, "intent-filter")
        )
        explicit_exported = _bool_attribute(component_node, "exported")
        effective, source = _effective_exported(
            component_node.tag,
            explicit_exported,
            bool(filters),
            target_sdk,
        )
        component = ComponentInfo(
            component_type=component_node.tag,
            name=name,
            exported=explicit_exported,
            effective_exported=effective,
            exported_source=source,
            enabled=_bool_attribute(component_node, "enabled"),
            permission=_text_attribute(component_node, "permission"),
            read_permission=_text_attribute(component_node, "readPermission"),
            write_permission=_text_attribute(component_node, "writePermission"),
            authorities=_text_attribute(component_node, "authorities"),
            process=_text_attribute(component_node, "process"),
            intent_filters=filters,
        )
        components.append(component)
        for intent_filter in filters:
            is_view = "android.intent.action.VIEW" in intent_filter.actions
            is_browsable = "android.intent.category.BROWSABLE" in intent_filter.categories
            if not (is_view and is_browsable):
                continue
            for data in intent_filter.data:
                if data.scheme:
                    deep_links.append(
                        DeepLink(
                            component=name,
                            scheme=data.scheme,
                            host=data.host,
                            port=data.port,
                            path=data.path,
                            path_prefix=data.path_prefix,
                            path_pattern=data.path_pattern,
                            auto_verify=intent_filter.auto_verify,
                        )
                    )
    return ManifestInspection(
        package=package,
        debuggable=_bool_attribute(application, "debuggable"),
        test_only=_bool_attribute(application, "testOnly"),
        uses_cleartext_traffic=_bool_attribute(application, "usesCleartextTraffic"),
        network_security_config=_text_attribute(application, "networkSecurityConfig"),
        allow_backup=_bool_attribute(application, "allowBackup"),
        application_permission=_text_attribute(application, "permission"),
        permissions=tuple(permissions),
        custom_permissions=custom_permissions,
        components=tuple(components),
        deep_links=tuple(deep_links),
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
                check=True,
                command_log=self.command_log,
            )
        except ExternalCommandError as exc:
            raise ApkInspectionError(f"AAPT2 failed while {operation}: {exc}") from exc
        if len(result.stdout) > 20_000_000:
            raise ApkInspectionError("AAPT2 output exceeded the 20 MB inspection limit.")
        return result.stdout

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
        write_text_atomic(badging_path, badging_output, root=project_root)
        write_text_atomic(xmltree_path, xmltree_output, root=project_root)
        return AaptInspection(
            badging=parse_aapt_badging(badging_output),
            manifest=inspect_manifest_tree(
                parse_aapt_xmltree(xmltree_output),
                target_sdk=target_sdk,
            ),
            badging_path=badging_path,
            xmltree_path=xmltree_path,
        )
