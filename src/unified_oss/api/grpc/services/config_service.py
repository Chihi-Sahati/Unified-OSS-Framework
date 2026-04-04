"""
Configuration Service gRPC Implementation for Unified OSS Framework.

This module provides the gRPC service implementation for configuration
management operations, integrating with the fcaps.configuration module.

Features:
    - Configuration application with validation
    - Configuration rollback capability
    - Configuration diff comparison
    - Version history tracking
    - Integration with ConfigManager from fcaps.configuration module

Example:
    >>> from unified_oss.api.grpc.services.config_service import ConfigurationServiceServicer
    >>> from unified_oss.fcaps.configuration.config_manager import ConfigManager
    >>> config_manager = ConfigManager()
    >>> servicer = ConfigurationServiceServicer(config_manager)
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import (
    Any,
    Dict,
    List,
    Optional,
    TYPE_CHECKING,
)

# gRPC imports
try:
    import grpc
    from grpc import aio
    GRPC_AVAILABLE = True
except ImportError:
    GRPC_AVAILABLE = False
    grpc = None
    aio = None

# Import from fcaps module
from unified_oss.fcaps.configuration.config_manager import (
    ConfigManager,
    ConfigVersion,
    ConfigSnapshot,
    AuditEntry,
    ConfigStatus,
    ConfigOperation,
    VendorType,
    ConfigurationError,
    VersionNotFoundError,
    ValidationFailedError,
    RollbackError,
)

# Configure module logger
logger = logging.getLogger(__name__)


def status_to_enum(status: ConfigStatus) -> int:
    """Convert ConfigStatus to proto enum value.
    
    Args:
        status: ConfigStatus enum value.
        
    Returns:
        Integer value for proto ConfigStatus enum.
    """
    mapping = {
        ConfigStatus.DRAFT: 1,
        ConfigStatus.PENDING_APPROVAL: 2,
        ConfigStatus.APPROVED: 3,
        ConfigStatus.STAGED: 4,
        ConfigStatus.DEPLOYED: 5,
        ConfigStatus.FAILED: 6,
        ConfigStatus.ROLLED_BACK: 7,
    }
    return mapping.get(status, 0)


def operation_to_enum(operation: ConfigOperation) -> int:
    """Convert ConfigOperation to proto enum value.
    
    Args:
        operation: ConfigOperation enum value.
        
    Returns:
        Integer value for proto ConfigOperation enum.
    """
    mapping = {
        ConfigOperation.CREATE: 1,
        ConfigOperation.MERGE: 2,
        ConfigOperation.REPLACE: 3,
        ConfigOperation.DELETE: 4,
        ConfigOperation.NONE: 5,
    }
    return mapping.get(operation, 0)


def vendor_to_enum(vendor: VendorType) -> int:
    """Convert VendorType to proto enum value.
    
    Args:
        vendor: VendorType enum value.
        
    Returns:
        Integer value for proto Vendor enum.
    """
    mapping = {
        VendorType.ERICSSON: 1,
        VendorType.HUAWEI: 2,
        VendorType.NOKIA: 3,
        VendorType.CISCO: 4,
        VendorType.GENERIC: 0,
    }
    return mapping.get(vendor, 0)


def vendor_from_enum(value: int) -> VendorType:
    """Convert proto enum value to VendorType.
    
    Args:
        value: Proto enum integer value.
        
    Returns:
        VendorType enum value.
    """
    mapping = {
        1: VendorType.ERICSSON,
        2: VendorType.HUAWEI,
        3: VendorType.NOKIA,
        4: VendorType.CISCO,
        0: VendorType.GENERIC,
    }
    return mapping.get(value, VendorType.GENERIC)


@dataclass
class ApplyOperation:
    """Tracks an ongoing configuration apply operation.
    
    Attributes:
        operation_id: Unique operation identifier.
        config_id: Configuration identifier.
        status: Operation status.
        started_at: Operation start time.
        completed_at: Operation completion time.
        error_message: Error message if failed.
        warnings: List of warnings generated.
    """
    operation_id: str
    config_id: str
    status: str = "in_progress"
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    error_message: str = ""
    warnings: List[str] = field(default_factory=list)


class ConfigurationServiceServicer:
    """gRPC servicer for ConfigurationService operations.
    
    Provides configuration management operations including apply,
    rollback, diff comparison, and history tracking.
    
    Attributes:
        config_manager: ConfigManager instance from fcaps.configuration module.
        active_operations: Currently active apply operations.
    
    Example:
        >>> config_manager = ConfigManager()
        >>> servicer = ConfigurationServiceServicer(config_manager)
        >>> # Register with gRPC server
        >>> add_ConfigurationServiceServicer_to_server(servicer, server)
    """

    def __init__(
        self,
        config_manager: ConfigManager,
        max_concurrent_applies: int = 10,
    ) -> None:
        """Initialize the ConfigurationService servicer.
        
        Args:
            config_manager: ConfigManager instance for config operations.
            max_concurrent_applies: Maximum concurrent apply operations.
        """
        self._config_manager = config_manager
        self._max_concurrent_applies = max_concurrent_applies
        self._active_operations: Dict[str, ApplyOperation] = {}
        self._lock = asyncio.Lock()
        self._apply_semaphore = asyncio.Semaphore(max_concurrent_applies)

        logger.info("ConfigurationServiceServicer initialized")

    async def ApplyConfig(
        self,
        request: Any,
        context: Any,
    ) -> Any:
        """Apply a configuration version.
        
        Validates and applies a new configuration version with optional
        dry-run mode and validation skipping.
        
        Args:
            request: ApplyConfigRequest with config content and options.
            context: gRPC context.
            
        Returns:
            ApplyConfigResponse with created version and status.
        """
        operation_id = str(uuid.uuid4())

        try:
            # Extract parameters
            config_id = getattr(request, "config_id", "")
            content = getattr(request, "content", "")
            content_type = getattr(request, "content_type", "xml")
            operation = getattr(request, "operation", 2)  # Default MERGE
            vendor = getattr(request, "vendor", 0)
            comment = getattr(request, "comment", "")
            skip_validation = getattr(request, "skip_validation", False)
            dry_run = getattr(request, "dry_run", False)

            # Extract metadata
            metadata = getattr(request, "metadata", None)
            user = getattr(metadata, "user_id", "system") if metadata else "system"

            if not config_id:
                await context.abort(
                    grpc.StatusCode.INVALID_ARGUMENT if GRPC_AVAILABLE else 3,
                    "config_id is required"
                )

            if not content:
                await context.abort(
                    grpc.StatusCode.INVALID_ARGUMENT if GRPC_AVAILABLE else 3,
                    "content is required"
                )

            # Convert enums
            operation_enum = {
                1: ConfigOperation.CREATE,
                2: ConfigOperation.MERGE,
                3: ConfigOperation.REPLACE,
                4: ConfigOperation.DELETE,
                5: ConfigOperation.NONE,
            }.get(operation, ConfigOperation.MERGE)

            vendor_enum = vendor_from_enum(vendor)

            # Create operation tracker
            operation = ApplyOperation(
                operation_id=operation_id,
                config_id=config_id,
            )

            async with self._lock:
                self._active_operations[operation_id] = operation

            # Acquire semaphore for concurrent control
            async with self._apply_semaphore:
                logger.info(
                    f"Starting config apply for {config_id} "
                    f"(operation={operation_id}, dry_run={dry_run})"
                )

                if dry_run:
                    # Only validate without applying
                    is_valid, errors, warnings = await self._config_manager.validate_config(
                        content=content,
                        vendor=vendor_enum,
                    )

                    operation.status = "completed"
                    operation.completed_at = datetime.now(timezone.utc)
                    operation.warnings = list(warnings.keys())

                    return {
                        "version": None,
                        "success": is_valid,
                        "validation_errors": errors,
                        "warnings": list(warnings.keys()),
                        "applied_at": None,
                    }

                # Apply the configuration
                try:
                    version = await self._config_manager.apply_config(
                        config_id=config_id,
                        content=content,
                        user=user,
                        comment=comment,
                        operation=operation_enum,
                        vendor=vendor_enum,
                        skip_validation=skip_validation,
                    )

                    operation.status = "completed"
                    operation.completed_at = datetime.now(timezone.utc)

                    logger.info(
                        f"Config {config_id} applied successfully "
                        f"as version {version.version_number}"
                    )

                    return {
                        "version": self._version_to_dict(version),
                        "success": True,
                        "validation_errors": [],
                        "warnings": [],
                        "applied_at": version.created_at,
                    }

                except ValidationFailedError as e:
                    operation.status = "failed"
                    operation.completed_at = datetime.now(timezone.utc)
                    operation.error_message = str(e)

                    logger.warning(
                        f"Config {config_id} validation failed: {e}"
                    )

                    return {
                        "version": None,
                        "success": False,
                        "validation_errors": e.errors,
                        "warnings": [],
                        "applied_at": None,
                    }

                except ConfigurationError as e:
                    operation.status = "failed"
                    operation.completed_at = datetime.now(timezone.utc)
                    operation.error_message = str(e)

                    logger.error(
                        f"Config {config_id} apply failed: {e}"
                    )

                    if GRPC_AVAILABLE:
                        await context.abort(
                            grpc.StatusCode.INTERNAL,
                            f"Configuration apply failed: {str(e)}"
                        )

        except Exception as e:
            logger.error(f"ApplyConfig error: {e}")
            if operation_id in self._active_operations:
                self._active_operations[operation_id].status = "failed"
                self._active_operations[operation_id].error_message = str(e)

            if GRPC_AVAILABLE:
                await context.abort(
                    grpc.StatusCode.INTERNAL,
                    f"Failed to apply configuration: {str(e)}"
                )

        finally:
            # Cleanup old operations (keep last 100)
            if len(self._active_operations) > 100:
                # Remove oldest completed operations
                to_remove = []
                for op_id, op in self._active_operations.items():
                    if op.status != "in_progress" and op.completed_at:
                        to_remove.append(op_id)

                for op_id in to_remove[:len(to_remove) - 50]:
                    del self._active_operations[op_id]

    def _version_to_dict(self, version: ConfigVersion) -> Dict[str, Any]:
        """Convert ConfigVersion to proto-compatible dictionary.
        
        Args:
            version: ConfigVersion instance.
            
        Returns:
            Dictionary with proto-compatible fields.
        """
        return {
            "version_id": version.version_id,
            "version_number": version.version_number,
            "config_id": version.config_id,
            "content_hash": version.content_hash,
            "status": status_to_enum(version.status),
            "created_at": version.created_at,
            "created_by": version.created_by,
            "comment": version.comment,
            "parent_version_id": version.parent_version_id,
            "changes": version.changes,
        }

    async def RollbackConfig(
        self,
        request: Any,
        context: Any,
    ) -> Any:
        """Rollback to a previous configuration version.
        
        Rolls back the configuration to a specified version with
        audit trail and reason tracking.
        
        Args:
            request: RollbackConfigRequest with config_id and target_version.
            context: gRPC context.
            
        Returns:
            RollbackConfigResponse with new rollback version.
        """
        try:
            # Extract parameters
            config_id = getattr(request, "config_id", "")
            target_version_id = getattr(request, "target_version_id", "")
            reason = getattr(request, "reason", "")

            # Extract metadata
            metadata = getattr(request, "metadata", None)
            user = getattr(metadata, "user_id", "system") if metadata else "system"

            if not config_id:
                await context.abort(
                    grpc.StatusCode.INVALID_ARGUMENT if GRPC_AVAILABLE else 3,
                    "config_id is required"
                )

            if not target_version_id:
                await context.abort(
                    grpc.StatusCode.INVALID_ARGUMENT if GRPC_AVAILABLE else 3,
                    "target_version_id is required"
                )

            # Perform rollback
            try:
                rollback_version = await self._config_manager.rollback_config(
                    config_id=config_id,
                    target_version_id=target_version_id,
                    user=user,
                    reason=reason,
                )

                logger.info(
                    f"Config {config_id} rolled back to version "
                    f"{rollback_version.version_number} by {user}"
                )

                return {
                    "version": self._version_to_dict(rollback_version),
                    "success": True,
                    "previous_version_id": rollback_version.parent_version_id,
                    "rolled_back_at": rollback_version.created_at,
                }

            except VersionNotFoundError as e:
                await context.abort(
                    grpc.StatusCode.NOT_FOUND if GRPC_AVAILABLE else 5,
                    f"Target version not found: {str(e)}"
                )

            except RollbackError as e:
                await context.abort(
                    grpc.StatusCode.FAILED_PRECONDITION if GRPC_AVAILABLE else 9,
                    f"Rollback failed: {str(e)}"
                )

        except Exception as e:
            logger.error(f"RollbackConfig error: {e}")
            if GRPC_AVAILABLE:
                await context.abort(
                    grpc.StatusCode.INTERNAL,
                    f"Failed to rollback configuration: {str(e)}"
                )

    async def GetDiff(
        self,
        request: Any,
        context: Any,
    ) -> Any:
        """Get diff between two configuration versions.
        
        Compares two configuration versions and returns the differences
        with various output format options.
        
        Args:
            request: GetDiffRequest with version IDs and format options.
            context: gRPC context.
            
        Returns:
            GetDiffResponse with changes and statistics.
        """
        try:
            # Extract parameters
            config_id = getattr(request, "config_id", "")
            version_id_1 = getattr(request, "version_id_1", "")
            version_id_2 = getattr(request, "version_id_2", "")
            include_content = getattr(request, "include_content", False)
            diff_format = getattr(request, "diff_format", "unified")

            if not config_id:
                await context.abort(
                    grpc.StatusCode.INVALID_ARGUMENT if GRPC_AVAILABLE else 3,
                    "config_id is required"
                )

            # Get both versions
            version1 = await self._config_manager.get_config(
                config_id=config_id,
                version_id=version_id_1 if version_id_1 else None,
            )
            version2 = await self._config_manager.get_config(
                config_id=config_id,
                version_id=version_id_2 if version_id_2 else None,
            )

            if not version1:
                await context.abort(
                    grpc.StatusCode.NOT_FOUND if GRPC_AVAILABLE else 5,
                    f"Version {version_id_1} not found"
                )

            if not version2:
                await context.abort(
                    grpc.StatusCode.NOT_FOUND if GRPC_AVAILABLE else 5,
                    f"Version {version_id_2} not found"
                )

            # Calculate diff
            changes = self._calculate_diff(
                version1.content,
                version2.content,
                diff_format,
            )

            # Count change types
            additions = sum(1 for c in changes if c.get("type") == "added")
            deletions = sum(1 for c in changes if c.get("type") == "removed")
            modifications = sum(1 for c in changes if c.get("type") == "modified")

            # Generate diff text
            diff_text = self._generate_diff_text(changes, diff_format)

            logger.info(
                f"GetDiff for {config_id}: {additions} additions, "
                f"{deletions} deletions, {modifications} modifications"
            )

            return {
                "changes": changes,
                "diff_text": diff_text,
                "additions": additions,
                "deletions": deletions,
                "modifications": modifications,
            }

        except Exception as e:
            logger.error(f"GetDiff error: {e}")
            if GRPC_AVAILABLE:
                await context.abort(
                    grpc.StatusCode.INTERNAL,
                    f"Failed to get diff: {str(e)}"
                )

    def _calculate_diff(
        self,
        content1: str,
        content2: str,
        diff_format: str,
    ) -> List[Dict[str, Any]]:
        """Calculate differences between two configurations.
        
        Args:
            content1: First configuration content.
            content2: Second configuration content.
            diff_format: Output format (unified, side_by_side, json).
            
        Returns:
            List of change dictionaries.
        """
        changes = []

        lines1 = content1.splitlines()
        lines2 = content2.splitlines()

        set1 = set(lines1)
        set2 = set(lines2)

        added = set2 - set1
        removed = set1 - set2

        for line in added:
            if line.strip():
                changes.append({
                    "change_type": "added",
                    "xpath": "",
                    "old_value": "",
                    "new_value": line,
                    "description": f"Added line: {line[:50]}...",
                })

        for line in removed:
            if line.strip():
                changes.append({
                    "change_type": "removed",
                    "xpath": "",
                    "old_value": line,
                    "new_value": "",
                    "description": f"Removed line: {line[:50]}...",
                })

        # Detect modifications (lines in both but different positions/context)
        # This is a simplified diff - production would use proper diff algorithms

        return changes[:200]  # Limit to 200 changes

    def _generate_diff_text(
        self,
        changes: List[Dict[str, Any]],
        diff_format: str,
    ) -> str:
        """Generate formatted diff text.
        
        Args:
            changes: List of changes.
            diff_format: Output format.
            
        Returns:
            Formatted diff text.
        """
        lines = []

        for change in changes:
            change_type = change.get("change_type", "")
            old_value = change.get("old_value", "")
            new_value = change.get("new_value", "")

            if diff_format == "unified":
                if change_type == "added":
                    lines.append(f"+ {new_value}")
                elif change_type == "removed":
                    lines.append(f"- {old_value}")
                elif change_type == "modified":
                    lines.append(f"- {old_value}")
                    lines.append(f"+ {new_value}")
            elif diff_format == "side_by_side":
                lines.append(f"{old_value:40} | {new_value}")
            else:
                lines.append(f"{change_type}: {old_value} -> {new_value}")

        return "\n".join(lines)

    async def GetConfigHistory(
        self,
        request: Any,
        context: Any,
    ) -> Any:
        """Get configuration version history.
        
        Retrieves the history of configuration versions with optional
        filtering by status, user, and time range.
        
        Args:
            request: GetConfigHistoryRequest with config_id and filters.
            context: gRPC context.
            
        Returns:
            GetConfigHistoryResponse with version list.
        """
        try:
            # Extract parameters
            config_id = getattr(request, "config_id", "")
            limit = getattr(request, "limit", 50)
            offset_token = getattr(request, "offset_token", "")
            status_filter = getattr(request, "status_filter", 0)
            user_filter = getattr(request, "user_filter", "")

            # Extract time range
            time_range = getattr(request, "time_range", None)
            start_time = None
            end_time = None
            if time_range:
                start_time = getattr(time_range, "start_time", None)
                end_time = getattr(time_range, "end_time", None)

            if not config_id:
                await context.abort(
                    grpc.StatusCode.INVALID_ARGUMENT if GRPC_AVAILABLE else 3,
                    "config_id is required"
                )

            # Convert offset token
            offset = 0
            if offset_token:
                try:
                    offset = int(offset_token)
                except ValueError:
                    pass

            # Get version history
            versions = await self._config_manager.get_version_history(
                config_id=config_id,
                limit=limit,
                offset=offset,
            )

            # Apply filters
            if status_filter:
                status_enum = {
                    1: ConfigStatus.DRAFT,
                    2: ConfigStatus.PENDING_APPROVAL,
                    3: ConfigStatus.APPROVED,
                    4: ConfigStatus.STAGED,
                    5: ConfigStatus.DEPLOYED,
                    6: ConfigStatus.FAILED,
                    7: ConfigStatus.ROLLED_BACK,
                }.get(status_filter)
                if status_enum:
                    versions = [v for v in versions if v.get("status") == status_enum.value]

            if user_filter:
                versions = [v for v in versions if v.get("created_by") == user_filter]

            # Get current version
            current_version = await self._config_manager.get_config(config_id)
            current_version_number = current_version.version_number if current_version else 0

            # Build next page token
            next_token = ""
            if len(versions) >= limit:
                next_token = str(offset + limit)

            logger.info(
                f"GetConfigHistory for {config_id} returned {len(versions)} versions"
            )

            return {
                "versions": versions,
                "pagination": {
                    "next_page_token": next_token,
                    "total_count": len(versions),
                    "has_more": bool(next_token),
                },
                "current_version_number": current_version_number,
            }

        except Exception as e:
            logger.error(f"GetConfigHistory error: {e}")
            if GRPC_AVAILABLE:
                await context.abort(
                    grpc.StatusCode.INTERNAL,
                    f"Failed to get config history: {str(e)}"
                )

    def get_active_operations_count(self) -> int:
        """Get count of active configuration operations.
        
        Returns:
            Number of operations in progress.
        """
        return sum(
            1 for op in self._active_operations.values()
            if op.status == "in_progress"
        )

    def get_stats(self) -> Dict[str, Any]:
        """Get service statistics.
        
        Returns:
            Dictionary with service statistics.
        """
        config_stats = self._config_manager.get_config_count()
        return {
            "active_operations": self.get_active_operations_count(),
            "total_operations": len(self._active_operations),
            "config_manager_stats": config_stats,
        }
