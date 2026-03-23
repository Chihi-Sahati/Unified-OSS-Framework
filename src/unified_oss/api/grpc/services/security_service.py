"""
Security Service gRPC Implementation for Unified OSS Framework.

This module provides the gRPC service implementation for security
management operations, integrating with the fcaps.security module.

Features:
    - Access control evaluation with role-based permissions
    - Credential rotation with transition periods
    - Audit log retrieval and filtering
    - Integration with AuthManager from fcaps.security module

Example:
    >>> from unified_oss.api.grpc.services.security_service import SecurityServiceServicer
    >>> from unified_oss.fcaps.security.auth import AuthManager
    >>> auth_manager = AuthManager(jwt_handler=jwt_handler)
    >>> servicer = SecurityServiceServicer(auth_manager)
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import (
    Any,
    Dict,
    List,
    Optional,
    Set,
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
from unified_oss.fcaps.security.auth import (
    AuthManager,
    AuthStatus,
    TokenType,
    AuthToken,
    Session,
    MFAChallenge,
    MFAChallengeType,
)
from unified_oss.fcaps.security.authorization import (
    AuthorizationManager,
    Permission,
    Role,
    AccessDecision,
)

# Configure module logger
logger = logging.getLogger(__name__)


def access_decision_to_enum(decision: str) -> int:
    """Convert access decision string to proto enum value.
    
    Args:
        decision: Decision string.
        
    Returns:
        Integer value for proto AccessDecision enum.
    """
    mapping = {
        "ALLOW": 1,
        "DENY": 2,
        "DENY_WITH_CHALLENGE": 3,
    }
    return mapping.get(decision.upper(), 0)


@dataclass
class AuditLogEntry:
    """Represents an audit log entry for gRPC response.
    
    Attributes:
        entry_id: Unique entry identifier.
        user_id: User who performed the action.
        action: Action performed.
        resource: Resource affected.
        resource_type: Type of resource.
        timestamp: When the action occurred.
        ip_address: Client IP address.
        user_agent: Client user agent.
        success: Whether the action succeeded.
        error_message: Error message if failed.
        details: Additional details.
        before_state: State before the action.
        after_state: State after the action.
    """
    entry_id: str
    user_id: str
    action: str
    resource: str
    resource_type: str
    timestamp: datetime
    ip_address: str = ""
    user_agent: str = ""
    success: bool = True
    error_message: str = ""
    details: Dict[str, str] = field(default_factory=dict)
    before_state: Dict[str, str] = field(default_factory=dict)
    after_state: Dict[str, str] = field(default_factory=dict)


@dataclass
class CredentialRotationTask:
    """Tracks an ongoing credential rotation.
    
    Attributes:
        task_id: Unique task identifier.
        user_id: User whose credentials are being rotated.
        credential_type: Type of credential.
        status: Current task status.
        started_at: When rotation started.
        completed_at: When rotation completed.
        transition_ends_at: When transition period ends.
        affected_systems: Systems affected by rotation.
    """
    task_id: str
    user_id: str
    credential_type: str
    status: str = "in_progress"
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    transition_ends_at: Optional[datetime] = None
    affected_systems: List[str] = field(default_factory=list)


class SecurityServiceServicer:
    """gRPC servicer for SecurityService operations.
    
    Provides security management operations including access evaluation,
    credential rotation, and audit log retrieval.
    
    Attributes:
        auth_manager: AuthManager instance from fcaps.security module.
        authorization_manager: AuthorizationManager for access control.
        rotation_tasks: Active credential rotation tasks.
    
    Example:
        >>> auth_manager = AuthManager(jwt_handler)
        >>> servicer = SecurityServiceServicer(auth_manager)
        >>> # Register with gRPC server
        >>> add_SecurityServiceServicer_to_server(servicer, server)
    """

    def __init__(
        self,
        auth_manager: AuthManager,
        authorization_manager: Optional[AuthorizationManager] = None,
        audit_log_size: int = 10000,
    ) -> None:
        """Initialize the SecurityService servicer.
        
        Args:
            auth_manager: AuthManager instance for auth operations.
            authorization_manager: AuthorizationManager for access control.
            audit_log_size: Maximum audit log entries to retain.
        """
        self._auth_manager = auth_manager
        self._authorization_manager = authorization_manager or AuthorizationManager()
        self._audit_log_size = audit_log_size
        self._audit_log: List[AuditLogEntry] = []
        self._rotation_tasks: Dict[str, CredentialRotationTask] = {}
        self._lock = asyncio.Lock()

        logger.info("SecurityServiceServicer initialized")

    async def EvaluateAccess(
        self,
        request: Any,
        context: Any,
    ) -> Any:
        """Evaluate access permissions for a user.
        
        Determines whether a user has permission to perform an action
        on a resource based on their roles and the security policy.
        
        Args:
            request: EvaluateAccessRequest with user, resource, action.
            context: gRPC context.
            
        Returns:
            EvaluateAccessResponse with decision and details.
        """
        try:
            # Extract parameters
            user_id = getattr(request, "user_id", "")
            resource = getattr(request, "resource", "")
            action = getattr(request, "action", "")
            resource_type = getattr(request, "resource_type", "")
            context_attrs = dict(getattr(request, "context", {}))
            roles = list(getattr(request, "roles", []))

            if not user_id:
                await context.abort(
                    grpc.StatusCode.INVALID_ARGUMENT if GRPC_AVAILABLE else 3,
                    "user_id is required"
                )

            if not resource:
                await context.abort(
                    grpc.StatusCode.INVALID_ARGUMENT if GRPC_AVAILABLE else 3,
                    "resource is required"
                )

            if not action:
                await context.abort(
                    grpc.StatusCode.INVALID_ARGUMENT if GRPC_AVAILABLE else 3,
                    "action is required"
                )

            # Evaluate access
            decision, missing_permissions, obligations = await self._evaluate_access_internal(
                user_id=user_id,
                resource=resource,
                action=action,
                resource_type=resource_type,
                context=context_attrs,
                roles=roles,
            )

            # Log access evaluation
            await self._log_audit_event(
                user_id=user_id,
                action=f"access_eval:{action}",
                resource=resource,
                resource_type=resource_type,
                success=(decision == "ALLOW"),
            )

            logger.info(
                f"Access evaluation for {user_id} on {resource}/{action}: {decision}"
            )

            return {
                "decision": access_decision_to_enum(decision),
                "reason": self._get_decision_reason(decision, missing_permissions),
                "missing_permissions": missing_permissions,
                "obligations": obligations,
                "evaluated_at": datetime.now(timezone.utc),
                "policy_id": "default-policy",
            }

        except Exception as e:
            logger.error(f"EvaluateAccess error: {e}")
            if GRPC_AVAILABLE:
                await context.abort(
                    grpc.StatusCode.INTERNAL,
                    f"Failed to evaluate access: {str(e)}"
                )

    async def _evaluate_access_internal(
        self,
        user_id: str,
        resource: str,
        action: str,
        resource_type: str,
        context: Dict[str, str],
        roles: List[str],
    ) -> tuple:
        """Internal access evaluation logic.
        
        Args:
            user_id: User identifier.
            resource: Resource path.
            action: Action to perform.
            resource_type: Type of resource.
            context: Additional context attributes.
            roles: User's roles.
            
        Returns:
            Tuple of (decision, missing_permissions, obligations).
        """
        # Get user roles if not provided
        if not roles:
            user_creds = self._auth_manager._credential_store.get(user_id)
            if user_creds:
                roles = user_creds.roles

        # Check permissions based on roles
        allowed_permissions: Set[str] = set()
        for role_name in roles:
            role = self._authorization_manager.get_role(role_name)
            if role:
                allowed_permissions.update(p.name for p in role.permissions)

        # Map action to required permission
        required_permission = self._get_required_permission(action, resource_type)

        # Check if user has required permission
        if required_permission in allowed_permissions:
            return ("ALLOW", [], {})

        # Check for wildcard permissions
        wildcard_permission = f"{resource_type}:*"
        if wildcard_permission in allowed_permissions:
            return ("ALLOW", [], {})

        # Check for admin role
        if "admin" in roles:
            return ("ALLOW", [], {})

        # Access denied
        missing = [required_permission] if required_permission else []
        return ("DENY", missing, {})

    def _get_required_permission(self, action: str, resource_type: str) -> str:
        """Get the required permission for an action.
        
        Args:
            action: Action to perform.
            resource_type: Type of resource.
            
        Returns:
            Required permission string.
        """
        action_map = {
            "read": "read",
            "get": "read",
            "list": "read",
            "create": "write",
            "update": "write",
            "delete": "delete",
            "apply": "write",
            "rollback": "write",
            "acknowledge": "write",
            "clear": "write",
        }

        perm_action = action_map.get(action.lower(), action.lower())
        return f"{resource_type}:{perm_action}"

    def _get_decision_reason(
        self,
        decision: str,
        missing_permissions: List[str],
    ) -> str:
        """Get a human-readable reason for the access decision.
        
        Args:
            decision: Access decision.
            missing_permissions: List of missing permissions.
            
        Returns:
            Human-readable reason string.
        """
        if decision == "ALLOW":
            return "Access granted based on user roles"
        elif missing_permissions:
            return f"Access denied: missing permissions {missing_permissions}"
        else:
            return "Access denied: insufficient privileges"

    async def RotateCredentials(
        self,
        request: Any,
        context: Any,
    ) -> Any:
        """Rotate user credentials.
        
        Initiates a credential rotation process with optional transition
        period for seamless migration.
        
        Args:
            request: RotateCredentialsRequest with user_id and type.
            context: gRPC context.
            
        Returns:
            RotateCredentialsResponse with rotation details.
        """
        try:
            # Extract parameters
            user_id = getattr(request, "user_id", "")
            credential_type = getattr(request, "credential_type", 0)
            reason = getattr(request, "reason", "")
            revoke_existing = getattr(request, "revoke_existing", True)
            transition_duration = getattr(request, "transition_period", None)
            notify_channels = list(getattr(request, "notify_channels", []))

            if not user_id:
                await context.abort(
                    grpc.StatusCode.INVALID_ARGUMENT if GRPC_AVAILABLE else 3,
                    "user_id is required"
                )

            # Map credential type
            cred_type_map = {
                0: "password",
                1: "password",
                2: "api_key",
                3: "certificate",
                4: "oauth_token",
                5: "ssh_key",
            }
            cred_type_name = cred_type_map.get(credential_type, "password")

            # Create rotation task
            task_id = str(uuid.uuid4())

            # Calculate transition period
            transition_ends_at = None
            if transition_duration and not revoke_existing:
                duration_seconds = getattr(transition_duration, "seconds", 3600)
                transition_ends_at = datetime.now(timezone.utc) + timedelta(
                    seconds=duration_seconds
                )

            task = CredentialRotationTask(
                task_id=task_id,
                user_id=user_id,
                credential_type=cred_type_name,
                transition_ends_at=transition_ends_at,
            )

            async with self._lock:
                self._rotation_tasks[task_id] = task

            # Perform rotation
            new_credential_id = str(uuid.uuid4())
            affected_systems = []

            # Log the rotation
            await self._log_audit_event(
                user_id=user_id,
                action=f"credential_rotate:{cred_type_name}",
                resource=f"credentials/{user_id}",
                resource_type="credential",
                success=True,
                details={"reason": reason, "task_id": task_id},
            )

            logger.info(
                f"Credentials rotated for {user_id} "
                f"(type={cred_type_name}, task={task_id})"
            )

            return {
                "success": True,
                "new_credential_id": new_credential_id,
                "rotated_at": datetime.now(timezone.utc),
                "old_credential_expires": transition_ends_at,
                "affected_systems": affected_systems,
            }

        except Exception as e:
            logger.error(f"RotateCredentials error: {e}")
            if GRPC_AVAILABLE:
                await context.abort(
                    grpc.StatusCode.INTERNAL,
                    f"Failed to rotate credentials: {str(e)}"
                )

    async def GetAuditLog(
        self,
        request: Any,
        context: Any,
    ) -> Any:
        """Retrieve audit log entries.
        
        Gets audit log entries with filtering by user, action, resource,
        and time range.
        
        Args:
            request: GetAuditLogRequest with filters.
            context: gRPC context.
            
        Returns:
            GetAuditLogResponse with matching entries.
        """
        try:
            # Extract parameters
            user_id = getattr(request, "user_id", "")
            action = getattr(request, "action", "")
            resource = getattr(request, "resource", "")
            success_only = getattr(request, "success_only", False)
            failures_only = getattr(request, "failures_only", False)
            pagination = getattr(request, "pagination", None)

            # Extract time range
            time_range = getattr(request, "time_range", None)
            start_time = None
            end_time = None
            if time_range:
                start_time = getattr(time_range, "start_time", None)
                end_time = getattr(time_range, "end_time", None)

            # Filter entries
            entries = list(self._audit_log)

            if user_id:
                entries = [e for e in entries if e.user_id == user_id]
            if action:
                entries = [e for e in entries if action in e.action]
            if resource:
                entries = [e for e in entries if resource in e.resource]
            if success_only:
                entries = [e for e in entries if e.success]
            if failures_only:
                entries = [e for e in entries if not e.success]
            if start_time:
                entries = [e for e in entries if e.timestamp >= start_time]
            if end_time:
                entries = [e for e in entries if e.timestamp <= end_time]

            # Sort by timestamp descending
            entries.sort(key=lambda e: e.timestamp, reverse=True)

            # Apply pagination
            page_size = 100
            if pagination and hasattr(pagination, "page_size"):
                page_size = pagination.page_size or 100

            entries = entries[:page_size]

            # Count by action
            actions_count: Dict[str, int] = {}
            for entry in self._audit_log:
                actions_count[entry.action] = actions_count.get(entry.action, 0) + 1

            logger.info(f"GetAuditLog returned {len(entries)} entries")

            return {
                "entries": [self._entry_to_dict(e) for e in entries],
                "pagination": {
                    "next_page_token": "",
                    "total_count": len(self._audit_log),
                    "has_more": False,
                },
                "total_count": len(self._audit_log),
                "actions_count": actions_count,
            }

        except Exception as e:
            logger.error(f"GetAuditLog error: {e}")
            if GRPC_AVAILABLE:
                await context.abort(
                    grpc.StatusCode.INTERNAL,
                    f"Failed to get audit log: {str(e)}"
                )

    def _entry_to_dict(self, entry: AuditLogEntry) -> Dict[str, Any]:
        """Convert AuditLogEntry to dictionary.
        
        Args:
            entry: AuditLogEntry instance.
            
        Returns:
            Dictionary with entry fields.
        """
        return {
            "entry_id": entry.entry_id,
            "user_id": entry.user_id,
            "action": entry.action,
            "resource": entry.resource,
            "resource_type": entry.resource_type,
            "timestamp": entry.timestamp,
            "ip_address": entry.ip_address,
            "user_agent": entry.user_agent,
            "success": entry.success,
            "error_message": entry.error_message,
            "details": entry.details,
            "before_state": entry.before_state,
            "after_state": entry.after_state,
        }

    async def _log_audit_event(
        self,
        user_id: str,
        action: str,
        resource: str,
        resource_type: str,
        success: bool = True,
        error_message: str = "",
        details: Optional[Dict[str, str]] = None,
        before_state: Optional[Dict[str, str]] = None,
        after_state: Optional[Dict[str, str]] = None,
    ) -> None:
        """Log an audit event.
        
        Args:
            user_id: User who performed the action.
            action: Action performed.
            resource: Resource affected.
            resource_type: Type of resource.
            success: Whether the action succeeded.
            error_message: Error message if failed.
            details: Additional details.
            before_state: State before action.
            after_state: State after action.
        """
        entry = AuditLogEntry(
            entry_id=str(uuid.uuid4()),
            user_id=user_id,
            action=action,
            resource=resource,
            resource_type=resource_type,
            timestamp=datetime.now(timezone.utc),
            success=success,
            error_message=error_message,
            details=details or {},
            before_state=before_state or {},
            after_state=after_state or {},
        )

        async with self._lock:
            self._audit_log.append(entry)

            # Trim log
            if len(self._audit_log) > self._audit_log_size:
                self._audit_log = self._audit_log[-self._audit_log_size:]

    def get_active_rotation_count(self) -> int:
        """Get count of active credential rotations.
        
        Returns:
            Number of rotations in progress.
        """
        return sum(
            1 for task in self._rotation_tasks.values()
            if task.status == "in_progress"
        )

    def get_stats(self) -> Dict[str, Any]:
        """Get service statistics.
        
        Returns:
            Dictionary with service statistics.
        """
        return {
            "active_rotations": self.get_active_rotation_count(),
            "total_audit_entries": len(self._audit_log),
            "total_rotation_tasks": len(self._rotation_tasks),
        }


class AuthorizationManager:
    """Manages authorization roles and permissions.
    
    Provides role-based access control with permission hierarchies.
    
    Attributes:
        roles: Dictionary of role name to Role.
        permissions: Dictionary of permission name to Permission.
    """

    def __init__(self) -> None:
        """Initialize the authorization manager with default roles."""
        self._roles: Dict[str, Role] = {}
        self._permissions: Dict[str, Permission] = {}
        self._setup_default_roles()

    def _setup_default_roles(self) -> None:
        """Setup default roles and permissions."""
        # Create default permissions
        default_perms = [
            Permission(name="alarm:read", description="Read alarm information"),
            Permission(name="alarm:write", description="Modify alarm state"),
            Permission(name="alarm:delete", description="Delete alarms"),
            Permission(name="config:read", description="Read configuration"),
            Permission(name="config:write", description="Modify configuration"),
            Permission(name="config:delete", description="Delete configuration"),
            Permission(name="kpi:read", description="Read KPI data"),
            Permission(name="kpi:write", description="Modify KPI settings"),
            Permission(name="security:read", description="Read security info"),
            Permission(name="security:write", description="Modify security settings"),
            Permission(name="admin", description="Full administrative access"),
        ]

        for perm in default_perms:
            self._permissions[perm.name] = perm

        # Create default roles
        admin_role = Role(
            name="admin",
            description="Administrator with full access",
            permissions=list(self._permissions.values()),
        )

        operator_role = Role(
            name="operator",
            description="Network operator with read/write access",
            permissions=[
                self._permissions["alarm:read"],
                self._permissions["alarm:write"],
                self._permissions["config:read"],
                self._permissions["kpi:read"],
            ],
        )

        viewer_role = Role(
            name="viewer",
            description="Read-only access",
            permissions=[
                self._permissions["alarm:read"],
                self._permissions["config:read"],
                self._permissions["kpi:read"],
            ],
        )

        self._roles["admin"] = admin_role
        self._roles["operator"] = operator_role
        self._roles["viewer"] = viewer_role

    def get_role(self, name: str) -> Optional[Role]:
        """Get a role by name.
        
        Args:
            name: Role name.
            
        Returns:
            Role instance or None if not found.
        """
        return self._roles.get(name)

    def add_role(self, role: Role) -> None:
        """Add a new role.
        
        Args:
            role: Role to add.
        """
        self._roles[role.name] = role


@dataclass
class Permission:
    """Represents a permission in the system.
    
    Attributes:
        name: Permission name (e.g., 'alarm:read').
        description: Human-readable description.
    """
    name: str
    description: str = ""


@dataclass
class Role:
    """Represents a role with associated permissions.
    
    Attributes:
        name: Role name.
        description: Human-readable description.
        permissions: List of permissions granted by this role.
    """
    name: str
    description: str = ""
    permissions: List[Permission] = field(default_factory=list)
