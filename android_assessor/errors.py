"""Project-specific exceptions."""


class AndroidAssessorError(Exception):
    """Base exception for expected framework failures."""


class ConfigurationError(AndroidAssessorError):
    """Raised when local configuration is invalid."""


class ExternalCommandError(AndroidAssessorError):
    """Raised when a managed external command exits unsuccessfully."""


class CommandTimeoutError(ExternalCommandError):
    """Raised when a managed external command exceeds its timeout."""


class AdbError(AndroidAssessorError):
    """Raised for ADB discovery, parsing, or execution failures."""


class AdbTimeoutError(AdbError):
    """Raised when a bounded ADB operation exceeds its timeout."""


class DeviceSelectionError(AdbError):
    """Raised when no explicit, authorized Android device can be selected."""


class CapabilityError(AndroidAssessorError):
    """Raised when capability inspection cannot be completed safely."""


class SessionError(AndroidAssessorError):
    """Raised for invalid, missing, or inconsistent assessment sessions."""


class DeviceBusyError(SessionError):
    """Raised when another modifying operation owns a device lock."""


class CleanupError(SessionError):
    """Raised when a whitelisted cleanup action cannot be completed."""


class CleanupConflictError(CleanupError):
    """Raised when a resource changed after the framework acquired ownership."""


class ProxyError(AndroidAssessorError):
    """Raised for managed Android proxy operations."""


class FridaError(AndroidAssessorError):
    """Raised for managed Frida client or server operations."""


class ApkInspectionError(AndroidAssessorError):
    """Raised for package metadata, APK pull, or manifest inspection failures."""


class EnvironmentCheckError(AndroidAssessorError):
    """Raised when mandatory host components are not healthy."""


class ScopeError(AndroidAssessorError):
    """Raised when a requested target is outside the explicit lab allowlist."""
