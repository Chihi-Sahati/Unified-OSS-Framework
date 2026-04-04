"""
Configuration Manager Module for Unified OSS Framework.

This module provides comprehensive configuration management functionality
including version control, multi-vendor normalization, and audit trail
integration for network element configurations.

Features:
    - Configuration profile management
    - Version control with rollback capability
    - Multi-vendor configuration normalization
    - Configuration validation
    - Audit trail integration
    - Transaction management

Author: Unified OSS Framework Team
Version: 1.0.0
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

# Configure module logger
logger = logging.getLogger(__name__)


# =============================================================================
# Enums and Constants
# =============================================================================


class ConfigStatus(Enum):
    """Configuration status enumeration."""
    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    STAGED = "staged"
    DEPLOYED = "deployed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class ConfigOperation(Enum):
    """Configuration operation types."""
    CREATE = "create"
    MERGE = "merge"
    REPLACE = "replace"
    DELETE = "delete"
    NONE = "none"


class VendorType(Enum):
    """Supported vendor types for configuration normalization."""
    ERICSSON = "ericsson"
    HUAWEI = "huawei"
    NOKIA = "nokia"
    CISCO = "cisco"
    GENERIC = "generic"


class ValidationLevel(Enum):
    """Configuration validation levels."""
    SYNTAX = "syntax"
    SEMANTIC = "semantic"
    BUSINESS = "business"
    FULL = "full"


# =============================================================================
# Exceptions
# =============================================================================


class ConfigurationError(Exception):
    """Base exception for configuration management errors."""

    def __init__(
        self,
        message: str,
        config_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Initialize configuration error.

        Args:
            message: Error message.
            config_id: Configuration identifier.
            details: Additional error details.
        """
        super().__init__(message)
        self.config_id = config_id
        self.details = details or {}


class VersionNotFoundError(ConfigurationError):
    """Exception raised when configuration version is not found."""
    pass


class ValidationFailedError(ConfigurationError):
    """Exception raised when configuration validation fails."""

    def __init__(
        self,
        message: str,
        errors: List[str],
        config_id: Optional[str] = None
    ) -> None:
        """Initialize validation error.

        Args:
            message: Error message.
            errors: List of validation errors.
            config_id: Configuration identifier.
        """
        super().__init__(message, config_id, {"errors": errors})
        self.errors = errors


class RollbackError(ConfigurationError):
    """Exception raised when rollback operation fails."""
    pass


# =============================================================================
# Dataclasses
# =============================================================================


@dataclass
class ConfigVersion:
    """Represents a configuration version.

    Attributes:
        version_id: Unique version identifier.
        version_number: Sequential version number.
        config_id: Parent configuration identifier.
        content: Configuration content (XML/JSON).
        content_hash: SHA-256 hash of content.
        status: Version status.
        created_at: Creation timestamp.
        created_by: User who created the version.
        comment: Version comment/description.
        parent_version_id: Parent version identifier for rollback.
        changes: List of changes from previous version.
    """

    version_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    version_number: int = 1
    config_id: str = ""
    content: str = ""
    content_hash: str = ""
    status: ConfigStatus = ConfigStatus.DRAFT
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str = ""
    comment: str = ""
    parent_version_id: Optional[str] = None
    changes: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Calculate content hash after initialization."""
        if self.content and not self.content_hash:
            self.content_hash = self._calculate_hash()

    def _calculate_hash(self) -> str:
        """Calculate SHA-256 hash of content.

        Returns:
            Hexadecimal hash string.
        """
        return hashlib.sha256(self.content.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary representation of version.
        """
        return {
            "version_id": self.version_id,
            "version_number": self.version_number,
            "config_id": self.config_id,
            "content_hash": self.content_hash,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "created_by": self.created_by,
            "comment": self.comment,
            "parent_version_id": self.parent_version_id,
            "changes": self.changes,
        }


@dataclass
class ConfigSnapshot:
    """Represents a configuration snapshot for comparison and backup.

    Attributes:
        snapshot_id: Unique snapshot identifier.
        config_id: Configuration identifier.
        ne_id: Network element identifier.
        content: Configuration content.
        content_hash: Content hash.
        vendor: Vendor type.
        created_at: Creation timestamp.
        metadata: Additional metadata.
        baseline: Whether this is a baseline snapshot.
    """

    snapshot_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    config_id: str = ""
    ne_id: str = ""
    content: str = ""
    content_hash: str = ""
    vendor: VendorType = VendorType.GENERIC
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)
    baseline: bool = False

    def __post_init__(self) -> None:
        """Calculate content hash after initialization."""
        if self.content and not self.content_hash:
            self.content_hash = hashlib.sha256(self.content.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary representation of snapshot.
        """
        return {
            "snapshot_id": self.snapshot_id,
            "config_id": self.config_id,
            "ne_id": self.ne_id,
            "content_hash": self.content_hash,
            "vendor": self.vendor.value,
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata,
            "baseline": self.baseline,
        }


@dataclass
class AuditEntry:
    """Audit trail entry for configuration changes.

    Attributes:
        entry_id: Unique entry identifier.
        config_id: Configuration identifier.
        version_id: Version identifier.
        action: Action performed.
        user: User who performed the action.
        timestamp: Action timestamp.
        details: Additional details.
        before_hash: Hash before change.
        after_hash: Hash after change.
    """

    entry_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    config_id: str = ""
    version_id: str = ""
    action: str = ""
    user: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    details: Dict[str, Any] = field(default_factory=dict)
    before_hash: str = ""
    after_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary representation of audit entry.
        """
        return {
            "entry_id": self.entry_id,
            "config_id": self.config_id,
            "version_id": self.version_id,
            "action": self.action,
            "user": self.user,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details,
            "before_hash": self.before_hash,
            "after_hash": self.after_hash,
        }


# =============================================================================
# Vendor Normalizer
# =============================================================================


class VendorNormalizer:
    """Multi-vendor configuration normalization.

    Provides vendor-specific configuration normalization to convert
    vendor-specific formats to a unified format.

    Attributes:
        vendor: Vendor type for normalization.
    """

    # Vendor-specific namespace mappings
    NAMESPACES: Dict[VendorType, Dict[str, str]] = {
        VendorType.ERICSSON: {
            "er": "urn:ericsson:params:xml:ns:yang:mods",
            "ericsson": "urn:ericsson:params:xml:ns:yang:ericsson",
        },
        VendorType.HUAWEI: {
            "hw": "urn:huawei:params:xml:ns:yang:huawei-module",
            "huawei": "urn:huawei:params:xml:ns:yang:huawei",
        },
        VendorType.NOKIA: {
            "nk": "urn:nokia:params:xml:ns:yang:nokia-mods",
        },
        VendorType.CISCO: {
            "cisco": "urn:cisco:params:xml:ns:yang:cisco",
        },
        VendorType.GENERIC: {},
    }

    def __init__(self, vendor: VendorType = VendorType.GENERIC) -> None:
        """Initialize vendor normalizer.

        Args:
            vendor: Vendor type for normalization.
        """
        self.vendor = vendor
        self._namespaces = self.NAMESPACES.get(vendor, {})

    def normalize(self, config_content: str) -> str:
        """Normalize configuration content.

        Args:
            config_content: Configuration content to normalize.

        Returns:
            Normalized configuration content.
        """
        if self.vendor == VendorType.ERICSSON:
            return self._normalize_ericsson(config_content)
        elif self.vendor == VendorType.HUAWEI:
            return self._normalize_huawei(config_content)
        elif self.vendor == VendorType.NOKIA:
            return self._normalize_nokia(config_content)
        elif self.vendor == VendorType.CISCO:
            return self._normalize_cisco(config_content)
        return config_content

    def _normalize_ericsson(self, content: str) -> str:
        """Normalize Ericsson configuration.

        Args:
            content: Configuration content.

        Returns:
            Normalized content.
        """
        # Remove Ericsson-specific prefixes
        normalized = content
        for prefix in ["er:", "ericsson:"]:
            normalized = normalized.replace(prefix, "")
        return normalized

    def _normalize_huawei(self, content: str) -> str:
        """Normalize Huawei configuration.

        Args:
            content: Configuration content.

        Returns:
            Normalized content.
        """
        # Remove Huawei-specific prefixes
        normalized = content
        for prefix in ["hw:", "huawei:"]:
            normalized = normalized.replace(prefix, "")
        return normalized

    def _normalize_nokia(self, content: str) -> str:
        """Normalize Nokia configuration.

        Args:
            content: Configuration content.

        Returns:
            Normalized content.
        """
        # Remove Nokia-specific prefixes
        normalized = content
        for prefix in ["nk:", "nokia:"]:
            normalized = normalized.replace(prefix, "")
        return normalized

    def _normalize_cisco(self, content: str) -> str:
        """Normalize Cisco configuration.

        Args:
            content: Configuration content.

        Returns:
            Normalized content.
        """
        # Remove Cisco-specific prefixes
        normalized = content
        for prefix in ["cisco:"]:
            normalized = normalized.replace(prefix, "")
        return normalized

    def denormalize(self, config_content: str) -> str:
        """Denormalize configuration content for vendor-specific format.

        Args:
            config_content: Unified configuration content.

        Returns:
            Vendor-specific configuration content.
        """
        # Add vendor-specific prefixes if needed
        return config_content


# =============================================================================
# Configuration Validator
# =============================================================================


class ConfigurationValidator:
    """Configuration validation with multiple validation levels.

    Provides syntax, semantic, and business rule validation for
    configuration content.

    Attributes:
        validation_rules: List of validation rules.
    """

    def __init__(self, validation_level: ValidationLevel = ValidationLevel.FULL) -> None:
        """Initialize configuration validator.

        Args:
            validation_level: Level of validation to perform.
        """
        self.validation_level = validation_level
        self._validation_errors: List[str] = []
        self._custom_rules: List[Callable[[str], Tuple[bool, str]]] = []

    def validate(
        self,
        config_content: str,
        vendor: Optional[VendorType] = None
    ) -> Tuple[bool, List[str]]:
        """Validate configuration content.

        Args:
            config_content: Configuration content to validate.
            vendor: Optional vendor type for vendor-specific validation.

        Returns:
            Tuple of (is_valid, list_of_errors).
        """
        self._validation_errors = []

        if not config_content or config_content.strip() == "":
            self._validation_errors.append("Configuration content is empty")
            return False, self._validation_errors.copy()

        # Syntax validation
        if self.validation_level in (ValidationLevel.SYNTAX, ValidationLevel.FULL):
            self._validate_syntax(config_content)

        # Semantic validation
        if self.validation_level in (ValidationLevel.SEMANTIC, ValidationLevel.FULL):
            self._validate_semantics(config_content)

        # Business rule validation
        if self.validation_level in (ValidationLevel.BUSINESS, ValidationLevel.FULL):
            self._validate_business_rules(config_content)

        # Custom validation rules
        self._apply_custom_rules(config_content)

        return len(self._validation_errors) == 0, self._validation_errors.copy()

    def _validate_syntax(self, content: str) -> None:
        """Validate configuration syntax.

        Args:
            content: Configuration content.
        """
        # Check for balanced brackets/braces
        bracket_count = content.count("{") - content.count("}")
        if bracket_count != 0:
            self._validation_errors.append(
                f"Unbalanced braces: {abs(bracket_count)} {'opening' if bracket_count > 0 else 'closing'} brace(s) unmatched"
            )

        # Check for valid XML if content looks like XML
        if content.strip().startswith("<"):
            try:
                import xml.etree.ElementTree as ET
                ET.fromstring(content)
            except ET.ParseError as e:
                self._validation_errors.append(f"XML parsing error: {e}")

        # Check for invalid characters
        invalid_chars = set(content) & set('\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f')
        if invalid_chars:
            self._validation_errors.append(
                f"Invalid characters found: {invalid_chars}"
            )

    def _validate_semantics(self, content: str) -> None:
        """Validate configuration semantics.

        Args:
            content: Configuration content.
        """
        # Check for required elements
        if "interface" not in content.lower() and "interfaces" not in content.lower():
            # Not necessarily an error, but worth noting
            logger.debug("No interface configuration found")

        # Check for valid IP addresses if present
        import re
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, content)
        for ip in ips:
            octets = ip.split(".")
            if any(int(octet) > 255 for octet in octets):
                self._validation_errors.append(f"Invalid IP address: {ip}")

    def _validate_business_rules(self, content: str) -> None:
        """Validate business rules.

        Args:
            content: Configuration content.
        """
        # Check for potentially dangerous configurations
        dangerous_patterns = [
            ("shutdown all", "Potential service disruption: 'shutdown all' found"),
            ("no security", "Security disabled in configuration"),
            ("password.*plain", "Plain text password detected"),
        ]

        for pattern, message in dangerous_patterns:
            if pattern.lower() in content.lower():
                self._validation_errors.append(message)

    def _apply_custom_rules(self, content: str) -> None:
        """Apply custom validation rules.

        Args:
            content: Configuration content.
        """
        for rule in self._custom_rules:
            try:
                is_valid, message = rule(content)
                if not is_valid:
                    self._validation_errors.append(message)
            except Exception as e:
                self._validation_errors.append(f"Custom rule error: {e}")

    def add_rule(self, rule: Callable[[str], Tuple[bool, str]]) -> None:
        """Add a custom validation rule.

        Args:
            rule: Validation function that returns (is_valid, message).
        """
        self._custom_rules.append(rule)

    def get_errors(self) -> List[str]:
        """Get validation errors.

        Returns:
            List of validation error messages.
        """
        return self._validation_errors.copy()


# =============================================================================
# Configuration Manager
# =============================================================================


class ConfigManager:
    """Central configuration management with version control.

    Provides comprehensive configuration management including
    version control, validation, rollback, and audit trail.

    Attributes:
        validator: Configuration validator instance.
        normalizer: Vendor normalizer instance.
        versions: Dictionary of configuration versions.
        snapshots: Dictionary of configuration snapshots.
        audit_log: List of audit entries.

    Example:
        >>> manager = ConfigManager()
        >>> version = await manager.apply_config(
        ...     config_id="router-001",
        ...     content="<config>...</config>",
        ...     user="admin"
        ... )
    """

    def __init__(
        self,
        max_versions: int = 50,
        default_vendor: VendorType = VendorType.GENERIC
    ) -> None:
        """Initialize configuration manager.

        Args:
            max_versions: Maximum number of versions to retain.
            default_vendor: Default vendor type for normalization.
        """
        self.max_versions = max_versions
        self.default_vendor = default_vendor

        self.validator = ConfigurationValidator()
        self.normalizer = VendorNormalizer(default_vendor)

        self._versions: Dict[str, List[ConfigVersion]] = {}
        self._snapshots: Dict[str, ConfigSnapshot] = {}
        self._audit_log: List[AuditEntry] = []
        self._current_versions: Dict[str, str] = {}  # config_id -> version_id
        self._lock = asyncio.Lock()

        logger.info("ConfigManager initialized with max_versions=%d", max_versions)

    async def get_config(
        self,
        config_id: str,
        version_id: Optional[str] = None
    ) -> Optional[ConfigVersion]:
        """Retrieve a configuration version.

        Args:
            config_id: Configuration identifier.
            version_id: Optional specific version ID. If None, returns current.

        Returns:
            Configuration version or None if not found.

        Raises:
            VersionNotFoundError: If specified version not found.
        """
        async with self._lock:
            versions = self._versions.get(config_id, [])

            if not versions:
                logger.warning("No versions found for config_id: %s", config_id)
                return None

            if version_id:
                for version in versions:
                    if version.version_id == version_id:
                        return version
                raise VersionNotFoundError(
                    f"Version {version_id} not found",
                    config_id=config_id
                )

            # Return current (latest deployed) version
            current_version_id = self._current_versions.get(config_id)
            if current_version_id:
                for version in versions:
                    if version.version_id == current_version_id:
                        return version

            # Return latest version if no current deployed
            return versions[-1] if versions else None

    async def apply_config(
        self,
        config_id: str,
        content: str,
        user: str,
        comment: str = "",
        operation: ConfigOperation = ConfigOperation.MERGE,
        vendor: Optional[VendorType] = None,
        skip_validation: bool = False
    ) -> ConfigVersion:
        """Apply a new configuration version.

        Args:
            config_id: Configuration identifier.
            content: Configuration content.
            user: User applying the configuration.
            comment: Version comment.
            operation: Configuration operation type.
            vendor: Vendor type for normalization.
            skip_validation: Whether to skip validation.

        Returns:
            Created configuration version.

        Raises:
            ValidationFailedError: If validation fails.
            ConfigurationError: If apply fails.
        """
        vendor = vendor or self.default_vendor

        # Normalize configuration
        normalizer = VendorNormalizer(vendor)
        normalized_content = normalizer.normalize(content)

        # Validate configuration
        if not skip_validation:
            is_valid, errors = self.validator.validate(normalized_content, vendor)
            if not is_valid:
                raise ValidationFailedError(
                    "Configuration validation failed",
                    errors=errors,
                    config_id=config_id
                )

        async with self._lock:
            # Get existing versions
            versions = self._versions.get(config_id, [])
            version_number = len(versions) + 1

            # Determine parent version
            parent_version_id = None
            if versions:
                parent_version_id = versions[-1].version_id

            # Create new version
            new_version = ConfigVersion(
                config_id=config_id,
                version_number=version_number,
                content=normalized_content,
                status=ConfigStatus.DEPLOYED,
                created_by=user,
                comment=comment,
                parent_version_id=parent_version_id,
            )

            # Calculate changes
            if versions:
                prev_content = versions[-1].content
                new_version.changes = self._calculate_changes(
                    prev_content, normalized_content
                )

            # Store version
            if config_id not in self._versions:
                self._versions[config_id] = []
            self._versions[config_id].append(new_version)

            # Update current version
            self._current_versions[config_id] = new_version.version_id

            # Enforce max versions
            await self._enforce_max_versions(config_id)

            # Create audit entry
            audit_entry = AuditEntry(
                config_id=config_id,
                version_id=new_version.version_id,
                action="APPLY",
                user=user,
                details={
                    "operation": operation.value,
                    "comment": comment,
                    "vendor": vendor.value,
                },
                before_hash=versions[-1].content_hash if versions else "",
                after_hash=new_version.content_hash,
            )
            self._audit_log.append(audit_entry)

            logger.info(
                "Applied config %s version %d by %s",
                config_id, version_number, user
            )

            return new_version

    async def validate_config(
        self,
        content: str,
        vendor: Optional[VendorType] = None
    ) -> Tuple[bool, List[str], Dict[str, Any]]:
        """Validate configuration content without applying.

        Args:
            content: Configuration content to validate.
            vendor: Vendor type for validation.

        Returns:
            Tuple of (is_valid, errors, warnings).
        """
        vendor = vendor or self.default_vendor

        # Normalize first
        normalizer = VendorNormalizer(vendor)
        normalized = normalizer.normalize(content)

        # Validate
        is_valid, errors = self.validator.validate(normalized, vendor)

        warnings: Dict[str, Any] = {}
        if is_valid:
            # Generate warnings for review
            if "password" in normalized.lower():
                warnings["security"] = "Configuration contains password-related content"
            if len(normalized) > 100000:
                warnings["size"] = "Large configuration may impact performance"

        return is_valid, errors, warnings

    async def rollback_config(
        self,
        config_id: str,
        target_version_id: str,
        user: str,
        reason: str = ""
    ) -> ConfigVersion:
        """Rollback configuration to a previous version.

        Args:
            config_id: Configuration identifier.
            target_version_id: Version ID to rollback to.
            user: User performing the rollback.
            reason: Reason for rollback.

        Returns:
            New configuration version created from rollback.

        Raises:
            VersionNotFoundError: If target version not found.
            RollbackError: If rollback fails.
        """
        async with self._lock:
            # Find target version
            versions = self._versions.get(config_id, [])
            target_version = None

            for version in versions:
                if version.version_id == target_version_id:
                    target_version = version
                    break

            if not target_version:
                raise VersionNotFoundError(
                    f"Target version {target_version_id} not found",
                    config_id=config_id
                )

            # Get current version for audit
            current_version_id = self._current_versions.get(config_id)
            current_version = None
            if current_version_id:
                for v in versions:
                    if v.version_id == current_version_id:
                        current_version = v
                        break

            # Create rollback version
            version_number = len(versions) + 1
            rollback_version = ConfigVersion(
                config_id=config_id,
                version_number=version_number,
                content=target_version.content,
                status=ConfigStatus.ROLLED_BACK,
                created_by=user,
                comment=f"Rollback to version {target_version.version_number}: {reason}",
                parent_version_id=current_version_id,
            )

            # Store version
            self._versions[config_id].append(rollback_version)
            self._current_versions[config_id] = rollback_version.version_id

            # Create audit entry
            audit_entry = AuditEntry(
                config_id=config_id,
                version_id=rollback_version.version_id,
                action="ROLLBACK",
                user=user,
                details={
                    "target_version": target_version_id,
                    "target_version_number": target_version.version_number,
                    "reason": reason,
                },
                before_hash=current_version.content_hash if current_version else "",
                after_hash=rollback_version.content_hash,
            )
            self._audit_log.append(audit_entry)

            logger.info(
                "Rolled back config %s to version %d by %s",
                config_id, target_version.version_number, user
            )

            return rollback_version

    async def get_version_history(
        self,
        config_id: str,
        limit: int = 50,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Get version history for a configuration.

        Args:
            config_id: Configuration identifier.
            limit: Maximum number of versions to return.
            offset: Number of versions to skip.

        Returns:
            List of version information dictionaries.
        """
        async with self._lock:
            versions = self._versions.get(config_id, [])

            # Sort by version number descending
            sorted_versions = sorted(
                versions,
                key=lambda v: v.version_number,
                reverse=True
            )

            # Apply pagination
            paginated = sorted_versions[offset:offset + limit]

            return [v.to_dict() for v in paginated]

    async def create_snapshot(
        self,
        config_id: str,
        ne_id: str,
        content: str,
        vendor: VendorType,
        metadata: Optional[Dict[str, Any]] = None,
        baseline: bool = False
    ) -> ConfigSnapshot:
        """Create a configuration snapshot.

        Args:
            config_id: Configuration identifier.
            ne_id: Network element identifier.
            content: Configuration content.
            vendor: Vendor type.
            metadata: Additional metadata.
            baseline: Whether this is a baseline snapshot.

        Returns:
            Created snapshot.
        """
        async with self._lock:
            snapshot = ConfigSnapshot(
                config_id=config_id,
                ne_id=ne_id,
                content=content,
                vendor=vendor,
                metadata=metadata or {},
                baseline=baseline,
            )

            self._snapshots[snapshot.snapshot_id] = snapshot

            logger.info(
                "Created snapshot %s for config %s (baseline=%s)",
                snapshot.snapshot_id[:8], config_id, baseline
            )

            return snapshot

    async def get_snapshot(self, snapshot_id: str) -> Optional[ConfigSnapshot]:
        """Retrieve a snapshot by ID.

        Args:
            snapshot_id: Snapshot identifier.

        Returns:
            Snapshot or None if not found.
        """
        return self._snapshots.get(snapshot_id)

    async def get_audit_log(
        self,
        config_id: Optional[str] = None,
        user: Optional[str] = None,
        action: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get audit log entries with filtering.

        Args:
            config_id: Filter by configuration ID.
            user: Filter by user.
            action: Filter by action type.
            start_time: Filter by start time.
            end_time: Filter by end time.
            limit: Maximum entries to return.

        Returns:
            List of audit entries.
        """
        entries = self._audit_log

        # Apply filters
        if config_id:
            entries = [e for e in entries if e.config_id == config_id]
        if user:
            entries = [e for e in entries if e.user == user]
        if action:
            entries = [e for e in entries if e.action == action]
        if start_time:
            entries = [e for e in entries if e.timestamp >= start_time]
        if end_time:
            entries = [e for e in entries if e.timestamp <= end_time]

        # Sort by timestamp descending and limit
        sorted_entries = sorted(entries, key=lambda e: e.timestamp, reverse=True)

        return [e.to_dict() for e in sorted_entries[:limit]]

    def _calculate_changes(
        self,
        old_content: str,
        new_content: str
    ) -> List[Dict[str, Any]]:
        """Calculate changes between two configurations.

        Args:
            old_content: Previous configuration content.
            new_content: New configuration content.

        Returns:
            List of change descriptions.
        """
        changes: List[Dict[str, Any]] = []

        old_lines = old_content.splitlines()
        new_lines = new_content.splitlines()

        # Simple line-based diff
        old_set = set(old_lines)
        new_set = set(new_lines)

        added = new_set - old_set
        removed = old_set - new_set

        for line in added:
            if line.strip():
                changes.append({"type": "added", "content": line})

        for line in removed:
            if line.strip():
                changes.append({"type": "removed", "content": line})

        return changes[:100]  # Limit to 100 changes

    async def _enforce_max_versions(self, config_id: str) -> None:
        """Enforce maximum number of versions for a configuration.

        Args:
            config_id: Configuration identifier.
        """
        versions = self._versions.get(config_id, [])

        if len(versions) > self.max_versions:
            # Keep the most recent versions
            self._versions[config_id] = versions[-self.max_versions:]
            logger.debug(
                "Trimmed versions for config %s to %d",
                config_id, self.max_versions
            )

    async def delete_config(self, config_id: str, user: str) -> bool:
        """Delete a configuration and all its versions.

        Args:
            config_id: Configuration identifier.
            user: User performing the deletion.

        Returns:
            True if successful.
        """
        async with self._lock:
            if config_id not in self._versions:
                return False

            # Create audit entry
            audit_entry = AuditEntry(
                config_id=config_id,
                action="DELETE",
                user=user,
                details={"deleted_versions": len(self._versions[config_id])},
            )
            self._audit_log.append(audit_entry)

            # Remove configuration
            del self._versions[config_id]
            if config_id in self._current_versions:
                del self._current_versions[config_id]

            logger.info("Deleted config %s by %s", config_id, user)
            return True

    async def get_config_count(self) -> Dict[str, int]:
        """Get configuration statistics.

        Returns:
            Dictionary with configuration counts.
        """
        total_versions = sum(len(v) for v in self._versions.values())

        return {
            "total_configs": len(self._versions),
            "total_versions": total_versions,
            "total_snapshots": len(self._snapshots),
            "audit_entries": len(self._audit_log),
        }
