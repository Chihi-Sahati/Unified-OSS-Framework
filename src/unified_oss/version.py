"""
Version information for the Unified OSS Framework.

Provides version retrieval and comparison utilities.
"""

from dataclasses import dataclass
from typing import Tuple


@dataclass(frozen=True)
class VersionInfo:
    """Immutable version information container."""
    
    major: int
    minor: int
    patch: int
    prerelease: str = ""
    build: str = ""
    
    def __str__(self) -> str:
        """Return string representation of version."""
        version = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            version += f"-{self.prerelease}"
        if self.build:
            version += f"+{self.build}"
        return version
    
    def __lt__(self, other: "VersionInfo") -> bool:
        """Compare versions for less-than ordering."""
        return (self.major, self.minor, self.patch) < (other.major, other.minor, other.patch)
    
    def __le__(self, other: "VersionInfo") -> bool:
        """Compare versions for less-than-or-equal ordering."""
        return (self.major, self.minor, self.patch) <= (other.major, other.minor, other.patch)
    
    def __gt__(self, other: "VersionInfo") -> bool:
        """Compare versions for greater-than ordering."""
        return (self.major, self.minor, self.patch) > (other.major, other.minor, other.patch)
    
    def __ge__(self, other: "VersionInfo") -> bool:
        """Compare versions for greater-than-or-equal ordering."""
        return (self.major, self.minor, self.patch) >= (other.major, other.minor, other.patch)
    
    def to_tuple(self) -> Tuple[int, int, int]:
        """Return version as tuple."""
        return (self.major, self.minor, self.patch)


VERSION = "1.0.0"
VERSION_INFO = VersionInfo(major=1, minor=0, patch=0)


def get_version() -> str:
    """
    Get the current version string.
    
    Returns:
        Version string in semantic versioning format.
    
    Example:
        >>> get_version()
        '1.0.0'
    """
    return VERSION


def get_version_info() -> VersionInfo:
    """
    Get detailed version information.
    
    Returns:
        VersionInfo object with major, minor, patch components.
    
    Example:
        >>> info = get_version_info()
        >>> info.major
        1
        >>> info.minor
        0
        >>> info.patch
        0
    """
    return VERSION_INFO
