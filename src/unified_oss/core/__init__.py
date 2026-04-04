"""Core framework components for Unified OSS Framework."""

from .config import Config, ConfigLoader
from .logging import setup_logging, get_logger
from .exceptions import (
    UnifiedOSSError,
    ConnectionError,
    ValidationError,
    ConfigurationError,
    TimeoutError,
)
from .constants import (
    VENDOR_ERICSSON,
    VENDOR_HUAWEI,
    SEVERITY_CRITICAL,
    SEVERITY_MAJOR,
    SEVERITY_MINOR,
    SEVERITY_WARNING,
)

__all__ = [
    "Config",
    "ConfigLoader",
    "setup_logging",
    "get_logger",
    "UnifiedOSSError",
    "ConnectionError",
    "ValidationError",
    "ConfigurationError",
    "TimeoutError",
    "VENDOR_ERICSSON",
    "VENDOR_HUAWEI",
    "SEVERITY_CRITICAL",
    "SEVERITY_MAJOR",
    "SEVERITY_MINOR",
    "SEVERITY_WARNING",
]
