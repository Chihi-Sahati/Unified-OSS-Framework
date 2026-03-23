"""
Authorization Module for Unified OSS Framework Security Management.

This module provides comprehensive authorization capabilities including Role-Based
Access Control (RBAC), permission management, policy evaluation, and audit
logging for access decisions within the FCAPS Security Management domain.

Features:
    - Role-Based Access Control (RBAC)
    - Hierarchical permission management
    - Policy-based access control (PBAC)
    - Resource-based permissions
    - Attribute-based access control (ABAC) support
    - Comprehensive audit logging for access decisions

Example:
    >>> from unified_oss.fcaps.security.authorization import (
    ...     AuthorizationEngine, Permission, Role, Policy
    ... )
    >>> engine = AuthorizationEngine()
    >>> has_access = await engine.check_permission("user123", "network:read", "router-01")
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger(__name__)


class PermissionEffect(Enum):
    """Permission evaluation effect.

    Attributes:
        ALLOW: Access is allowed.
        DENY: Access is denied.
        NOT_APPLICABLE: Policy does not apply.
    """

    ALLOW = "allow"
    DENY = "deny"
    NOT_APPLICABLE = "not_applicable"


class ResourceType(Enum):
    """Resource type enumeration for OSS resources.

    Attributes:
        NETWORK_ELEMENT: Network element (router, switch, etc.).
        ALARM: Alarm object.
        PERFORMANCE_METRIC: Performance metric data.
        CONFIGURATION: Configuration object.
        SERVICE: Service instance.
        USER: User object.
        ROLE: Role object.
        POLICY: Policy object.
        AUDIT_LOG: Audit log entry.
    """

    NETWORK_ELEMENT = "network_element"
    ALARM = "alarm"
    PERFORMANCE_METRIC = "performance_metric"
    CONFIGURATION = "configuration"
    SERVICE = "service"
    USER = "user"
    ROLE = "role"
    POLICY = "policy"
    AUDIT_LOG = "audit_log"


class ActionType(Enum):
    """Action type enumeration.

    Attributes:
        CREATE: Create operation.
        READ: Read operation.
        UPDATE: Update operation.
        DELETE: Delete operation.
        EXECUTE: Execute operation.
        ADMIN: Administrative operation.
        ALL: All operations.
    """

    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    EXECUTE = "execute"
    ADMIN = "admin"
    ALL = "*"


@dataclass
class Permission:
    """Permission definition for access control.

    A permission represents a specific access right to perform an action
    on a resource type, optionally constrained by conditions.

    Attributes:
        permission_id: Unique permission identifier.
        name: Human-readable permission name.
        resource_type: Type of resource this permission applies to.
        actions: List of allowed actions.
        conditions: Optional conditions for permission applicability.
        description: Permission description.
        created_at: Permission creation timestamp.
    """

    permission_id: str
    name: str
    resource_type: ResourceType
    actions: List[ActionType]
    conditions: Dict[str, Any] = field(default_factory=dict)
    description: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def matches_action(self, action: ActionType) -> bool:
        """Check if permission matches an action.

        Args:
            action: Action to check.

        Returns:
            True if permission matches the action.
        """
        return ActionType.ALL in self.actions or action in self.actions

    def matches_resource(self, resource_type: ResourceType) -> bool:
        """Check if permission matches a resource type.

        Args:
            resource_type: Resource type to check.

        Returns:
            True if permission matches the resource type.
        """
        return self.resource_type == resource_type

    def to_dict(self) -> Dict[str, Any]:
        """Convert permission to dictionary representation.

        Returns:
            Dictionary representation of the permission.
        """
        return {
            "permission_id": self.permission_id,
            "name": self.name,
            "resource_type": self.resource_type.value,
            "actions": [a.value for a in self.actions],
            "conditions": self.conditions,
            "description": self.description,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class Role:
    """Role definition for RBAC.

    A role is a collection of permissions that can be assigned to users.
    Roles support inheritance through parent roles.

    Attributes:
        role_id: Unique role identifier.
        name: Human-readable role name.
        permissions: Set of permission IDs assigned to this role.
        parent_roles: Set of parent role IDs for inheritance.
        description: Role description.
        is_system: Whether this is a system role (cannot be deleted).
        created_at: Role creation timestamp.
        updated_at: Role last update timestamp.
    """

    role_id: str
    name: str
    permissions: Set[str] = field(default_factory=set)
    parent_roles: Set[str] = field(default_factory=set)
    description: str = ""
    is_system: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def add_permission(self, permission_id: str) -> None:
        """Add a permission to the role.

        Args:
            permission_id: Permission ID to add.
        """
        self.permissions.add(permission_id)
        self.updated_at = datetime.now(timezone.utc)

    def remove_permission(self, permission_id: str) -> bool:
        """Remove a permission from the role.

        Args:
            permission_id: Permission ID to remove.

        Returns:
            True if permission was removed, False if not found.
        """
        if permission_id in self.permissions:
            self.permissions.remove(permission_id)
            self.updated_at = datetime.now(timezone.utc)
            return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        """Convert role to dictionary representation.

        Returns:
            Dictionary representation of the role.
        """
        return {
            "role_id": self.role_id,
            "name": self.name,
            "permissions": list(self.permissions),
            "parent_roles": list(self.parent_roles),
            "description": self.description,
            "is_system": self.is_system,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass
class PolicyCondition:
    """Condition for policy evaluation.

    Attributes:
        attribute: Attribute name to evaluate.
        operator: Comparison operator (eq, ne, in, not_in, gt, lt, gte, lte, regex).
        value: Value to compare against.
    """

    attribute: str
    operator: str  # eq, ne, in, not_in, gt, lt, gte, lte, regex
    value: Any

    def evaluate(self, context: Dict[str, Any]) -> bool:
        """Evaluate the condition against a context.

        Args:
            context: Context dictionary with attribute values.

        Returns:
            True if condition is satisfied, False otherwise.
        """
        attr_value = context.get(self.attribute)

        if attr_value is None:
            return False

        if self.operator == "eq":
            return attr_value == self.value
        elif self.operator == "ne":
            return attr_value != self.value
        elif self.operator == "in":
            return attr_value in self.value
        elif self.operator == "not_in":
            return attr_value not in self.value
        elif self.operator == "gt":
            return attr_value > self.value
        elif self.operator == "lt":
            return attr_value < self.value
        elif self.operator == "gte":
            return attr_value >= self.value
        elif self.operator == "lte":
            return attr_value <= self.value
        elif self.operator == "regex":
            return bool(re.match(self.value, str(attr_value)))
        else:
            logger.warning(f"Unknown operator: {self.operator}")
            return False


@dataclass
class Policy:
    """Access control policy definition.

    Policies define rules for access control that can be evaluated
    against a request context to determine allow/deny decisions.

    Attributes:
        policy_id: Unique policy identifier.
        name: Human-readable policy name.
        description: Policy description.
        effect: Policy effect (allow or deny).
        resource_pattern: Pattern for matching resources (supports wildcards).
        actions: List of actions this policy applies to.
        conditions: List of conditions that must be satisfied.
        priority: Policy evaluation priority (higher = evaluated first).
        enabled: Whether the policy is enabled.
        created_at: Policy creation timestamp.
        updated_at: Policy last update timestamp.
    """

    policy_id: str
    name: str
    description: str = ""
    effect: PermissionEffect = PermissionEffect.ALLOW
    resource_pattern: str = "*"
    actions: List[ActionType] = field(default_factory=lambda: [ActionType.ALL])
    conditions: List[PolicyCondition] = field(default_factory=list)
    priority: int = 0
    enabled: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def matches_resource(self, resource: str) -> bool:
        """Check if policy matches a resource.

        Args:
            resource: Resource identifier to check.

        Returns:
            True if policy matches the resource.
        """
        if self.resource_pattern == "*":
            return True

        # Convert wildcard pattern to regex
        pattern = self.resource_pattern.replace("*", ".*").replace("?", ".")
        return bool(re.match(f"^{pattern}$", resource))

    def matches_action(self, action: ActionType) -> bool:
        """Check if policy matches an action.

        Args:
            action: Action to check.

        Returns:
            True if policy matches the action.
        """
        return ActionType.ALL in self.actions or action in self.actions

    def evaluate_conditions(self, context: Dict[str, Any]) -> bool:
        """Evaluate all conditions against a context.

        Args:
            context: Context dictionary with attribute values.

        Returns:
            True if all conditions are satisfied, False otherwise.
        """
        if not self.conditions:
            return True

        return all(condition.evaluate(context) for condition in self.conditions)

    def evaluate(
        self,
        resource: str,
        action: ActionType,
        context: Dict[str, Any],
    ) -> PermissionEffect:
        """Evaluate the policy for a given request.

        Args:
            resource: Resource identifier.
            action: Action being performed.
            context: Request context.

        Returns:
            PermissionEffect indicating the result.
        """
        if not self.enabled:
            return PermissionEffect.NOT_APPLICABLE

        if not self.matches_resource(resource):
            return PermissionEffect.NOT_APPLICABLE

        if not self.matches_action(action):
            return PermissionEffect.NOT_APPLICABLE

        if not self.evaluate_conditions(context):
            return PermissionEffect.NOT_APPLICABLE

        return self.effect

    def to_dict(self) -> Dict[str, Any]:
        """Convert policy to dictionary representation.

        Returns:
            Dictionary representation of the policy.
        """
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "description": self.description,
            "effect": self.effect.value,
            "resource_pattern": self.resource_pattern,
            "actions": [a.value for a in self.actions],
            "conditions": [
                {"attribute": c.attribute, "operator": c.operator, "value": c.value}
                for c in self.conditions
            ],
            "priority": self.priority,
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass
class AccessDecision:
    """Access decision result.

    Attributes:
        allowed: Whether access is allowed.
        user_id: User identifier.
        resource: Resource identifier.
        action: Action performed.
        matched_policies: List of matched policy IDs.
        effective_permissions: Effective permissions applied.
        context: Decision context.
        timestamp: Decision timestamp.
        reason: Reason for the decision.
    """

    allowed: bool
    user_id: str
    resource: str
    action: ActionType
    matched_policies: List[str] = field(default_factory=list)
    effective_permissions: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert decision to dictionary representation.

        Returns:
            Dictionary representation of the decision.
        """
        return {
            "allowed": self.allowed,
            "user_id": self.user_id,
            "resource": self.resource,
            "action": self.action.value,
            "matched_policies": self.matched_policies,
            "effective_permissions": self.effective_permissions,
            "context": self.context,
            "timestamp": self.timestamp.isoformat(),
            "reason": self.reason,
        }


@dataclass
class AuditEntry:
    """Audit log entry for access decisions.

    Attributes:
        entry_id: Unique entry identifier.
        timestamp: Entry timestamp.
        user_id: User identifier.
        action: Action performed.
        resource: Resource accessed.
        allowed: Whether access was allowed.
        decision: Access decision details.
        ip_address: Client IP address.
        user_agent: Client user agent.
        session_id: Session identifier.
        additional_data: Additional audit data.
    """

    entry_id: str
    timestamp: datetime
    user_id: str
    action: ActionType
    resource: str
    allowed: bool
    decision: AccessDecision
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    additional_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert audit entry to dictionary representation.

        Returns:
            Dictionary representation of the audit entry.
        """
        return {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "action": self.action.value,
            "resource": self.resource,
            "allowed": self.allowed,
            "decision": self.decision.to_dict(),
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "session_id": self.session_id,
            "additional_data": self.additional_data,
        }


class AuthorizationEngine:
    """Main authorization engine for RBAC and policy evaluation.

    This class provides comprehensive authorization capabilities including
    role management, permission checking, policy evaluation, and audit logging.

    Attributes:
        policies: Dictionary of registered policies.
        roles: Dictionary of defined roles.
        permissions: Dictionary of defined permissions.
        user_roles: Mapping of user IDs to role IDs.
    """

    def __init__(self) -> None:
        """Initialize the authorization engine."""
        self._policies: Dict[str, Policy] = {}
        self._roles: Dict[str, Role] = {}
        self._permissions: Dict[str, Permission] = {}
        self._user_roles: Dict[str, Set[str]] = {}
        self._role_cache: Dict[str, Set[str]] = {}  # Cache for role permissions
        self._audit_log: List[AuditEntry] = []
        self._lock = asyncio.Lock()

        # Initialize with default system roles and permissions
        self._initialize_defaults()

        logger.info("AuthorizationEngine initialized")

    def _initialize_defaults(self) -> None:
        """Initialize default system roles and permissions."""
        # Create default permissions
        default_permissions = [
            Permission(
                permission_id="network:read",
                name="Network Read",
                resource_type=ResourceType.NETWORK_ELEMENT,
                actions=[ActionType.READ],
                description="Read access to network elements",
            ),
            Permission(
                permission_id="network:write",
                name="Network Write",
                resource_type=ResourceType.NETWORK_ELEMENT,
                actions=[ActionType.CREATE, ActionType.UPDATE, ActionType.DELETE],
                description="Write access to network elements",
            ),
            Permission(
                permission_id="network:admin",
                name="Network Admin",
                resource_type=ResourceType.NETWORK_ELEMENT,
                actions=[ActionType.ALL],
                description="Full administrative access to network elements",
            ),
            Permission(
                permission_id="alarm:read",
                name="Alarm Read",
                resource_type=ResourceType.ALARM,
                actions=[ActionType.READ],
                description="Read access to alarms",
            ),
            Permission(
                permission_id="alarm:write",
                name="Alarm Write",
                resource_type=ResourceType.ALARM,
                actions=[ActionType.CREATE, ActionType.UPDATE],
                description="Write access to alarms",
            ),
            Permission(
                permission_id="config:read",
                name="Configuration Read",
                resource_type=ResourceType.CONFIGURATION,
                actions=[ActionType.READ],
                description="Read access to configurations",
            ),
            Permission(
                permission_id="config:write",
                name="Configuration Write",
                resource_type=ResourceType.CONFIGURATION,
                actions=[ActionType.CREATE, ActionType.UPDATE, ActionType.DELETE],
                description="Write access to configurations",
            ),
            Permission(
                permission_id="performance:read",
                name="Performance Read",
                resource_type=ResourceType.PERFORMANCE_METRIC,
                actions=[ActionType.READ],
                description="Read access to performance metrics",
            ),
            Permission(
                permission_id="user:admin",
                name="User Admin",
                resource_type=ResourceType.USER,
                actions=[ActionType.ALL],
                description="Full administrative access to users",
            ),
            Permission(
                permission_id="audit:read",
                name="Audit Read",
                resource_type=ResourceType.AUDIT_LOG,
                actions=[ActionType.READ],
                description="Read access to audit logs",
            ),
        ]

        for permission in default_permissions:
            self._permissions[permission.permission_id] = permission

        # Create default roles
        viewer_role = Role(
            role_id="viewer",
            name="Viewer",
            permissions={"network:read", "alarm:read", "config:read", "performance:read"},
            description="Read-only access to network resources",
            is_system=True,
        )

        operator_role = Role(
            role_id="operator",
            name="Operator",
            permissions={
                "network:read",
                "alarm:read",
                "alarm:write",
                "config:read",
                "performance:read",
            },
            description="Operational access to network resources",
            is_system=True,
        )

        engineer_role = Role(
            role_id="engineer",
            name="Engineer",
            permissions={
                "network:read",
                "network:write",
                "alarm:read",
                "alarm:write",
                "config:read",
                "config:write",
                "performance:read",
            },
            description="Engineering access to network resources",
            is_system=True,
        )

        admin_role = Role(
            role_id="admin",
            name="Administrator",
            permissions={
                "network:admin",
                "alarm:read",
                "alarm:write",
                "config:read",
                "config:write",
                "performance:read",
                "user:admin",
                "audit:read",
            },
            description="Full administrative access",
            is_system=True,
        )

        self._roles["viewer"] = viewer_role
        self._roles["operator"] = operator_role
        self._roles["engineer"] = engineer_role
        self._roles["admin"] = admin_role

    async def check_permission(
        self,
        user_id: str,
        permission_name: str,
        resource: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Check if a user has a specific permission.

        Args:
            user_id: User identifier.
            permission_name: Permission name to check.
            resource: Optional resource identifier for context.
            context: Optional additional context for policy evaluation.

        Returns:
            True if user has the permission, False otherwise.
        """
        # Get all permissions for the user
        user_permissions = await self.get_permissions(user_id)

        if permission_name in user_permissions:
            return True

        # Check for wildcard permissions
        parts = permission_name.split(":")
        if len(parts) == 2:
            resource_type, action = parts
            wildcard = f"{resource_type}:*"
            if wildcard in user_permissions:
                return True

        # Check policies
        action = self._parse_action_from_permission(permission_name)
        if action and resource:
            decision = await self.evaluate_policy(user_id, resource, action, context)
            return decision.allowed

        return False

    def _parse_action_from_permission(self, permission_name: str) -> Optional[ActionType]:
        """Parse action type from permission name.

        Args:
            permission_name: Permission name (e.g., "network:read").

        Returns:
            ActionType or None.
        """
        parts = permission_name.split(":")
        if len(parts) == 2:
            action_str = parts[1].upper()
            try:
                return ActionType[action_str]
            except KeyError:
                if action_str == "*":
                    return ActionType.ALL
        return None

    async def evaluate_policy(
        self,
        user_id: str,
        resource: str,
        action: ActionType,
        context: Optional[Dict[str, Any]] = None,
    ) -> AccessDecision:
        """Evaluate policies for an access request.

        Policies are evaluated in priority order (highest first).
        The first matching policy determines the decision.

        Args:
            user_id: User identifier.
            resource: Resource identifier.
            action: Action being performed.
            context: Request context.

        Returns:
            AccessDecision with the evaluation result.
        """
        ctx = context or {}
        ctx["user_id"] = user_id

        # Get user permissions
        effective_permissions = list(await self.get_permissions(user_id))

        # Sort policies by priority (highest first)
        sorted_policies = sorted(
            self._policies.values(),
            key=lambda p: p.priority,
            reverse=True,
        )

        matched_policies: List[str] = []
        deny_reason = ""

        for policy in sorted_policies:
            effect = policy.evaluate(resource, action, ctx)

            if effect != PermissionEffect.NOT_APPLICABLE:
                matched_policies.append(policy.policy_id)

                if effect == PermissionEffect.DENY:
                    deny_reason = f"Denied by policy: {policy.name}"
                    # Deny takes precedence, return immediately
                    decision = AccessDecision(
                        allowed=False,
                        user_id=user_id,
                        resource=resource,
                        action=action,
                        matched_policies=matched_policies,
                        effective_permissions=effective_permissions,
                        context=ctx,
                        reason=deny_reason,
                    )
                    await self._log_access_decision(decision, ctx)
                    return decision

        # Check RBAC permissions
        permission_name = self._get_permission_name(resource, action)
        has_permission = permission_name in effective_permissions

        # Check wildcard permission
        if not has_permission:
            resource_prefix = permission_name.split(":")[0] if ":" in permission_name else ""
            if resource_prefix:
                wildcard_permission = f"{resource_prefix}:*"
                has_permission = wildcard_permission in effective_permissions

        decision = AccessDecision(
            allowed=has_permission,
            user_id=user_id,
            resource=resource,
            action=action,
            matched_policies=matched_policies,
            effective_permissions=effective_permissions,
            context=ctx,
            reason="Access granted by RBAC" if has_permission else "No matching permission found",
        )

        await self._log_access_decision(decision, ctx)
        return decision

    def _get_permission_name(self, resource: str, action: ActionType) -> str:
        """Get permission name from resource and action.

        Args:
            resource: Resource identifier.
            action: Action type.

        Returns:
            Permission name string.
        """
        # Map resource to permission prefix
        resource_lower = resource.lower()
        if "network" in resource_lower or "router" in resource_lower or "switch" in resource_lower:
            prefix = "network"
        elif "alarm" in resource_lower:
            prefix = "alarm"
        elif "config" in resource_lower:
            prefix = "config"
        elif "performance" in resource_lower or "metric" in resource_lower:
            prefix = "performance"
        elif "user" in resource_lower:
            prefix = "user"
        else:
            prefix = resource_lower.split("-")[0] if "-" in resource_lower else resource_lower

        return f"{prefix}:{action.value}"

    async def get_permissions(self, user_id: str) -> Set[str]:
        """Get all effective permissions for a user.

        This includes permissions from all assigned roles and
        inherited roles.

        Args:
            user_id: User identifier.

        Returns:
            Set of permission names.
        """
        async with self._lock:
            # Check cache
            cache_key = f"perms:{user_id}"
            if cache_key in self._role_cache:
                return self._role_cache[cache_key].copy()

            permissions: Set[str] = set()
            role_ids = self._user_roles.get(user_id, set())

            for role_id in role_ids:
                role_permissions = self._get_role_permissions(role_id)
                permissions.update(role_permissions)

            # Cache the result
            self._role_cache[cache_key] = permissions.copy()

            return permissions

    def _get_role_permissions(self, role_id: str, visited: Optional[Set[str]] = None) -> Set[str]:
        """Get all permissions for a role including inherited permissions.

        Args:
            role_id: Role identifier.
            visited: Set of visited role IDs to prevent infinite loops.

        Returns:
            Set of permission names.
        """
        if visited is None:
            visited = set()

        if role_id in visited:
            return set()

        visited.add(role_id)

        role = self._roles.get(role_id)
        if role is None:
            return set()

        permissions = role.permissions.copy()

        # Add inherited permissions
        for parent_id in role.parent_roles:
            parent_permissions = self._get_role_permissions(parent_id, visited)
            permissions.update(parent_permissions)

        return permissions

    async def grant_role(
        self,
        user_id: str,
        role_id: str,
        granted_by: Optional[str] = None,
    ) -> bool:
        """Grant a role to a user.

        Args:
            user_id: User identifier.
            role_id: Role identifier to grant.
            granted_by: User ID of the grantor.

        Returns:
            True if role was granted, False if not found or already granted.
        """
        async with self._lock:
            if role_id not in self._roles:
                logger.warning(f"Role {role_id} not found")
                return False

            if user_id not in self._user_roles:
                self._user_roles[user_id] = set()

            if role_id in self._user_roles[user_id]:
                logger.debug(f"User {user_id} already has role {role_id}")
                return False

            self._user_roles[user_id].add(role_id)

            # Invalidate cache
            cache_key = f"perms:{user_id}"
            if cache_key in self._role_cache:
                del self._role_cache[cache_key]

            logger.info(f"Granted role {role_id} to user {user_id} by {granted_by}")

            # Audit log
            await self._audit_role_change(user_id, role_id, "grant", granted_by)

            return True

    async def revoke_role(
        self,
        user_id: str,
        role_id: str,
        revoked_by: Optional[str] = None,
    ) -> bool:
        """Revoke a role from a user.

        Args:
            user_id: User identifier.
            role_id: Role identifier to revoke.
            revoked_by: User ID of the revoker.

        Returns:
            True if role was revoked, False if not found.
        """
        async with self._lock:
            if user_id not in self._user_roles:
                return False

            if role_id not in self._user_roles[user_id]:
                return False

            self._user_roles[user_id].remove(role_id)

            # Invalidate cache
            cache_key = f"perms:{user_id}"
            if cache_key in self._role_cache:
                del self._role_cache[cache_key]

            logger.info(f"Revoked role {role_id} from user {user_id} by {revoked_by}")

            # Audit log
            await self._audit_role_change(user_id, role_id, "revoke", revoked_by)

            return True

    def create_permission(
        self,
        permission_id: str,
        name: str,
        resource_type: ResourceType,
        actions: List[ActionType],
        conditions: Optional[Dict[str, Any]] = None,
        description: str = "",
    ) -> Permission:
        """Create a new permission.

        Args:
            permission_id: Unique permission identifier.
            name: Human-readable permission name.
            resource_type: Resource type this permission applies to.
            actions: List of allowed actions.
            conditions: Optional conditions for permission applicability.
            description: Permission description.

        Returns:
            Created Permission object.

        Raises:
            ValueError: If permission ID already exists.
        """
        if permission_id in self._permissions:
            raise ValueError(f"Permission {permission_id} already exists")

        permission = Permission(
            permission_id=permission_id,
            name=name,
            resource_type=resource_type,
            actions=actions,
            conditions=conditions or {},
            description=description,
        )

        self._permissions[permission_id] = permission
        logger.info(f"Created permission: {permission_id}")

        return permission

    def create_role(
        self,
        role_id: str,
        name: str,
        permissions: Optional[Set[str]] = None,
        parent_roles: Optional[Set[str]] = None,
        description: str = "",
    ) -> Role:
        """Create a new role.

        Args:
            role_id: Unique role identifier.
            name: Human-readable role name.
            permissions: Set of permission IDs.
            parent_roles: Set of parent role IDs.
            description: Role description.

        Returns:
            Created Role object.

        Raises:
            ValueError: If role ID already exists.
        """
        if role_id in self._roles:
            raise ValueError(f"Role {role_id} already exists")

        role = Role(
            role_id=role_id,
            name=name,
            permissions=permissions or set(),
            parent_roles=parent_roles or set(),
            description=description,
        )

        self._roles[role_id] = role
        logger.info(f"Created role: {role_id}")

        return role

    def create_policy(
        self,
        policy_id: str,
        name: str,
        effect: PermissionEffect = PermissionEffect.ALLOW,
        resource_pattern: str = "*",
        actions: Optional[List[ActionType]] = None,
        conditions: Optional[List[PolicyCondition]] = None,
        priority: int = 0,
        description: str = "",
    ) -> Policy:
        """Create a new access policy.

        Args:
            policy_id: Unique policy identifier.
            name: Human-readable policy name.
            effect: Policy effect (allow or deny).
            resource_pattern: Pattern for matching resources.
            actions: List of actions this policy applies to.
            conditions: List of conditions.
            priority: Evaluation priority.
            description: Policy description.

        Returns:
            Created Policy object.

        Raises:
            ValueError: If policy ID already exists.
        """
        if policy_id in self._policies:
            raise ValueError(f"Policy {policy_id} already exists")

        policy = Policy(
            policy_id=policy_id,
            name=name,
            description=description,
            effect=effect,
            resource_pattern=resource_pattern,
            actions=actions or [ActionType.ALL],
            conditions=conditions or [],
            priority=priority,
        )

        self._policies[policy_id] = policy
        logger.info(f"Created policy: {policy_id}")

        return policy

    def get_user_roles(self, user_id: str) -> List[Role]:
        """Get all roles assigned to a user.

        Args:
            user_id: User identifier.

        Returns:
            List of Role objects.
        """
        role_ids = self._user_roles.get(user_id, set())
        return [self._roles[rid] for rid in role_ids if rid in self._roles]

    def get_permission(self, permission_id: str) -> Optional[Permission]:
        """Get a permission by ID.

        Args:
            permission_id: Permission identifier.

        Returns:
            Permission if found, None otherwise.
        """
        return self._permissions.get(permission_id)

    def get_role(self, role_id: str) -> Optional[Role]:
        """Get a role by ID.

        Args:
            role_id: Role identifier.

        Returns:
            Role if found, None otherwise.
        """
        return self._roles.get(role_id)

    def get_policy(self, policy_id: str) -> Optional[Policy]:
        """Get a policy by ID.

        Args:
            policy_id: Policy identifier.

        Returns:
            Policy if found, None otherwise.
        """
        return self._policies.get(policy_id)

    def delete_role(self, role_id: str) -> bool:
        """Delete a role.

        Args:
            role_id: Role identifier.

        Returns:
            True if deleted, False if not found or system role.
        """
        role = self._roles.get(role_id)
        if role is None:
            return False

        if role.is_system:
            logger.warning(f"Cannot delete system role: {role_id}")
            return False

        # Remove role from all users
        for user_id in self._user_roles:
            self._user_roles[user_id].discard(role_id)

        # Remove from parent_roles of other roles
        for other_role in self._roles.values():
            other_role.parent_roles.discard(role_id)

        del self._roles[role_id]

        # Clear all caches
        self._role_cache.clear()

        logger.info(f"Deleted role: {role_id}")
        return True

    def delete_policy(self, policy_id: str) -> bool:
        """Delete a policy.

        Args:
            policy_id: Policy identifier.

        Returns:
            True if deleted, False if not found.
        """
        if policy_id not in self._policies:
            return False

        del self._policies[policy_id]
        logger.info(f"Deleted policy: {policy_id}")
        return True

    async def _log_access_decision(
        self,
        decision: AccessDecision,
        context: Dict[str, Any],
    ) -> None:
        """Log an access decision to the audit log.

        Args:
            decision: Access decision to log.
            context: Request context.
        """
        import secrets

        entry = AuditEntry(
            entry_id=secrets.token_urlsafe(16),
            timestamp=datetime.now(timezone.utc),
            user_id=decision.user_id,
            action=decision.action,
            resource=decision.resource,
            allowed=decision.allowed,
            decision=decision,
            ip_address=context.get("ip_address"),
            user_agent=context.get("user_agent"),
            session_id=context.get("session_id"),
            additional_data={"matched_policies": decision.matched_policies},
        )

        self._audit_log.append(entry)

        # Keep audit log manageable (last 10000 entries)
        if len(self._audit_log) > 10000:
            self._audit_log = self._audit_log[-10000:]

    async def _audit_role_change(
        self,
        user_id: str,
        role_id: str,
        action: str,
        performed_by: Optional[str],
    ) -> None:
        """Log a role change to the audit log.

        Args:
            user_id: User whose role was changed.
            role_id: Role that was changed.
            action: Action type (grant or revoke).
            performed_by: User who performed the action.
        """
        import secrets

        entry = AuditEntry(
            entry_id=secrets.token_urlsafe(16),
            timestamp=datetime.now(timezone.utc),
            user_id=performed_by or "system",
            action=ActionType.ADMIN,
            resource=f"role:{role_id}:user:{user_id}",
            allowed=True,
            decision=AccessDecision(
                allowed=True,
                user_id=performed_by or "system",
                resource=f"role:{role_id}",
                action=ActionType.ADMIN,
                reason=f"Role {action}",
            ),
            additional_data={"action": action, "target_user": user_id, "role_id": role_id},
        )

        self._audit_log.append(entry)

    def get_audit_log(
        self,
        user_id: Optional[str] = None,
        resource: Optional[str] = None,
        action: Optional[ActionType] = None,
        allowed: Optional[bool] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[AuditEntry]:
        """Query the audit log with filters.

        Args:
            user_id: Filter by user ID.
            resource: Filter by resource.
            action: Filter by action type.
            allowed: Filter by allowed status.
            start_time: Filter by start time.
            end_time: Filter by end time.
            limit: Maximum number of entries to return.

        Returns:
            List of matching audit entries.
        """
        entries = self._audit_log.copy()

        if user_id is not None:
            entries = [e for e in entries if e.user_id == user_id]

        if resource is not None:
            entries = [e for e in entries if resource in e.resource]

        if action is not None:
            entries = [e for e in entries if e.action == action]

        if allowed is not None:
            entries = [e for e in entries if e.allowed == allowed]

        if start_time is not None:
            entries = [e for e in entries if e.timestamp >= start_time]

        if end_time is not None:
            entries = [e for e in entries if e.timestamp <= end_time]

        return entries[-limit:]

    def export_audit_log(self, format: str = "json") -> str:
        """Export audit log to a specific format.

        Args:
            format: Export format (json, csv).

        Returns:
            Exported audit log string.
        """
        if format == "json":
            return json.dumps(
                [entry.to_dict() for entry in self._audit_log],
                indent=2,
            )
        elif format == "csv":
            lines = [
                "entry_id,timestamp,user_id,action,resource,allowed,ip_address,session_id"
            ]
            for entry in self._audit_log:
                lines.append(
                    f"{entry.entry_id},{entry.timestamp.isoformat()},"
                    f"{entry.user_id},{entry.action.value},{entry.resource},"
                    f"{entry.allowed},{entry.ip_address or ''},{entry.session_id or ''}"
                )
            return "\n".join(lines)
        else:
            raise ValueError(f"Unsupported format: {format}")
