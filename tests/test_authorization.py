"""
Unit tests for Security Authorization module.

Tests cover RBAC, policy evaluation, and access control.
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from unified_oss.fcaps.security.authorization import (
    AuthorizationEngine,
    Permission,
    Role,
    Policy,
    PolicyCondition,
    AccessDecision,
    AuditEntry,
    PermissionEffect,
    ResourceType,
    ActionType,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def authz_engine():
    """Create an AuthorizationEngine instance for testing."""
    return AuthorizationEngine()


@pytest.fixture
def sample_permission():
    """Create a sample permission."""
    return Permission(
        permission_id="network:read",
        name="Network Read",
        resource_type=ResourceType.NETWORK_ELEMENT,
        actions=[ActionType.READ],
        description="Read access to network elements",
    )


@pytest.fixture
def sample_role():
    """Create a sample role."""
    return Role(
        role_id="engineer",
        name="Network Engineer",
        permissions={"network:read", "network:write", "alarm:read"},
        description="Network engineering role",
    )


@pytest.fixture
def sample_policy():
    """Create a sample policy."""
    return Policy(
        policy_id="policy-001",
        name="Admin Access Policy",
        effect=PermissionEffect.ALLOW,
        resource_pattern="*",
        actions=[ActionType.ALL],
        priority=100,
    )


# =============================================================================
# AuthorizationEngine Tests
# =============================================================================

class TestAuthorizationEngine:
    """Tests for AuthorizationEngine class."""

    def test_initialization(self, authz_engine):
        """Test engine initialization."""
        assert len(authz_engine._roles) > 0  # Should have default roles
        assert len(authz_engine._permissions) > 0

    @pytest.mark.asyncio
    async def test_check_permission_allowed(self, authz_engine):
        """Test permission check when allowed."""
        # Grant viewer role to user
        await authz_engine.grant_role("user-001", "viewer")
        
        result = await authz_engine.check_permission(
            user_id="user-001",
            permission_name="network:read",
        )
        
        assert result is True

    @pytest.mark.asyncio
    async def test_check_permission_denied(self, authz_engine):
        """Test permission check when denied."""
        # No role granted
        result = await authz_engine.check_permission(
            user_id="user-002",
            permission_name="network:admin",
        )
        
        assert result is False

    @pytest.mark.asyncio
    async def test_grant_role(self, authz_engine):
        """Test granting role to user."""
        result = await authz_engine.grant_role("user-001", "viewer")
        
        assert result is True
        
        roles = authz_engine.get_user_roles("user-001")
        assert len(roles) == 1
        assert roles[0].role_id == "viewer"

    @pytest.mark.asyncio
    async def test_grant_nonexistent_role(self, authz_engine):
        """Test granting non-existent role."""
        result = await authz_engine.grant_role("user-001", "nonexistent")
        
        assert result is False

    @pytest.mark.asyncio
    async def test_revoke_role(self, authz_engine):
        """Test revoking role from user."""
        await authz_engine.grant_role("user-001", "viewer")
        result = await authz_engine.revoke_role("user-001", "viewer")
        
        assert result is True
        
        roles = authz_engine.get_user_roles("user-001")
        assert len(roles) == 0

    @pytest.mark.asyncio
    async def test_get_permissions(self, authz_engine):
        """Test getting user permissions."""
        await authz_engine.grant_role("user-001", "admin")
        
        permissions = await authz_engine.get_permissions("user-001")
        
        assert len(permissions) > 0
        assert "network:admin" in permissions

    @pytest.mark.asyncio
    async def test_evaluate_policy(self, authz_engine):
        """Test policy evaluation."""
        decision = await authz_engine.evaluate_policy(
            user_id="user-001",
            resource="router-001",
            action=ActionType.READ,
        )
        
        assert decision is not None
        assert decision.allowed in [True, False]

    @pytest.mark.asyncio
    async def test_evaluate_policy_with_context(self, authz_engine):
        """Test policy evaluation with context."""
        context = {
            "time_of_day": "business_hours",
            "location": "office",
        }
        
        decision = await authz_engine.evaluate_policy(
            user_id="user-001",
            resource="router-001",
            action=ActionType.READ,
            context=context,
        )
        
        assert decision is not None

    def test_create_permission(self, authz_engine):
        """Test creating a new permission."""
        permission = authz_engine.create_permission(
            permission_id="custom:action",
            name="Custom Action",
            resource_type=ResourceType.NETWORK_ELEMENT,
            actions=[ActionType.READ, ActionType.EXECUTE],
        )
        
        assert permission.permission_id == "custom:action"
        
        retrieved = authz_engine.get_permission("custom:action")
        assert retrieved is not None

    def test_create_duplicate_permission(self, authz_engine):
        """Test creating duplicate permission."""
        authz_engine.create_permission(
            permission_id="test:perm",
            name="Test",
            resource_type=ResourceType.NETWORK_ELEMENT,
            actions=[ActionType.READ],
        )
        
        with pytest.raises(ValueError):
            authz_engine.create_permission(
                permission_id="test:perm",
                name="Test Duplicate",
                resource_type=ResourceType.NETWORK_ELEMENT,
                actions=[ActionType.READ],
            )

    def test_create_role(self, authz_engine):
        """Test creating a new role."""
        role = authz_engine.create_role(
            role_id="custom_role",
            name="Custom Role",
            permissions={"network:read"},
        )
        
        assert role.role_id == "custom_role"
        
        retrieved = authz_engine.get_role("custom_role")
        assert retrieved is not None

    def test_create_policy(self, authz_engine):
        """Test creating a new policy."""
        policy = authz_engine.create_policy(
            policy_id="custom_policy",
            name="Custom Policy",
            effect=PermissionEffect.ALLOW,
            resource_pattern="router-*",
        )
        
        assert policy.policy_id == "custom_policy"
        
        retrieved = authz_engine.get_policy("custom_policy")
        assert retrieved is not None

    def test_delete_role(self, authz_engine):
        """Test deleting a role."""
        authz_engine.create_role(
            role_id="temp_role",
            name="Temporary Role",
        )
        
        result = authz_engine.delete_role("temp_role")
        
        assert result is True
        assert authz_engine.get_role("temp_role") is None

    def test_delete_system_role(self, authz_engine):
        """Test deleting system role (should fail)."""
        result = authz_engine.delete_role("admin")
        
        assert result is False

    def test_delete_policy(self, authz_engine):
        """Test deleting a policy."""
        authz_engine.create_policy(
            policy_id="temp_policy",
            name="Temporary Policy",
        )
        
        result = authz_engine.delete_policy("temp_policy")
        
        assert result is True


# =============================================================================
# Permission Tests
# =============================================================================

class TestPermission:
    """Tests for Permission dataclass."""

    def test_permission_creation(self, sample_permission):
        """Test creating a permission."""
        assert sample_permission.permission_id == "network:read"
        assert sample_permission.resource_type == ResourceType.NETWORK_ELEMENT

    def test_matches_action(self, sample_permission):
        """Test action matching."""
        assert sample_permission.matches_action(ActionType.READ) is True
        assert sample_permission.matches_action(ActionType.UPDATE) is False

    def test_matches_action_all(self):
        """Test matching with ALL action type."""
        permission = Permission(
            permission_id="test",
            name="Test",
            resource_type=ResourceType.NETWORK_ELEMENT,
            actions=[ActionType.ALL],
        )
        
        assert permission.matches_action(ActionType.READ) is True
        assert permission.matches_action(ActionType.UPDATE) is True
        assert permission.matches_action(ActionType.DELETE) is True

    def test_permission_to_dict(self, sample_permission):
        """Test permission serialization."""
        perm_dict = sample_permission.to_dict()
        
        assert "permission_id" in perm_dict
        assert "actions" in perm_dict


# =============================================================================
# Role Tests
# =============================================================================

class TestRole:
    """Tests for Role dataclass."""

    def test_role_creation(self, sample_role):
        """Test creating a role."""
        assert sample_role.role_id == "engineer"
        assert len(sample_role.permissions) == 3

    def test_add_permission(self, sample_role):
        """Test adding permission to role."""
        sample_role.add_permission("alarm:write")
        
        assert "alarm:write" in sample_role.permissions

    def test_remove_permission(self, sample_role):
        """Test removing permission from role."""
        result = sample_role.remove_permission("network:read")
        
        assert result is True
        assert "network:read" not in sample_role.permissions

    def test_remove_nonexistent_permission(self, sample_role):
        """Test removing non-existent permission."""
        result = sample_role.remove_permission("nonexistent")
        
        assert result is False

    def test_role_to_dict(self, sample_role):
        """Test role serialization."""
        role_dict = sample_role.to_dict()
        
        assert "role_id" in role_dict
        assert "permissions" in role_dict


# =============================================================================
# Policy Tests
# =============================================================================

class TestPolicy:
    """Tests for Policy dataclass."""

    def test_policy_creation(self, sample_policy):
        """Test creating a policy."""
        assert sample_policy.policy_id == "policy-001"
        assert sample_policy.effect == PermissionEffect.ALLOW

    def test_matches_resource(self, sample_policy):
        """Test resource matching."""
        assert sample_policy.matches_resource("router-001") is True
        assert sample_policy.matches_resource("switch-001") is True

    def test_matches_resource_pattern(self):
        """Test resource pattern matching."""
        policy = Policy(
            policy_id="test",
            name="Test",
            resource_pattern="router-*",
        )
        
        assert policy.matches_resource("router-001") is True
        assert policy.matches_resource("switch-001") is False

    def test_matches_action(self, sample_policy):
        """Test action matching."""
        assert sample_policy.matches_action(ActionType.READ) is True
        assert sample_policy.matches_action(ActionType.UPDATE) is True

    def test_evaluate_conditions(self):
        """Test condition evaluation."""
        policy = Policy(
            policy_id="test",
            name="Test",
            conditions=[
                PolicyCondition(
                    attribute="department",
                    operator="eq",
                    value="engineering",
                ),
            ],
        )
        
        context = {"department": "engineering"}
        assert policy.evaluate_conditions(context) is True
        
        context = {"department": "sales"}
        assert policy.evaluate_conditions(context) is False

    def test_policy_to_dict(self, sample_policy):
        """Test policy serialization."""
        policy_dict = sample_policy.to_dict()
        
        assert "policy_id" in policy_dict
        assert "effect" in policy_dict


# =============================================================================
# PolicyCondition Tests
# =============================================================================

class TestPolicyCondition:
    """Tests for PolicyCondition dataclass."""

    def test_equality_operator(self):
        """Test equality operator."""
        condition = PolicyCondition(
            attribute="status",
            operator="eq",
            value="active",
        )
        
        assert condition.evaluate({"status": "active"}) is True
        assert condition.evaluate({"status": "inactive"}) is False

    def test_not_equal_operator(self):
        """Test not equal operator."""
        condition = PolicyCondition(
            attribute="status",
            operator="ne",
            value="inactive",
        )
        
        assert condition.evaluate({"status": "active"}) is True
        assert condition.evaluate({"status": "inactive"}) is False

    def test_in_operator(self):
        """Test 'in' operator."""
        condition = PolicyCondition(
            attribute="role",
            operator="in",
            value=["admin", "operator"],
        )
        
        assert condition.evaluate({"role": "admin"}) is True
        assert condition.evaluate({"role": "viewer"}) is False

    def test_comparison_operators(self):
        """Test comparison operators."""
        # Greater than
        condition = PolicyCondition(attribute="level", operator="gt", value=5)
        assert condition.evaluate({"level": 10}) is True
        assert condition.evaluate({"level": 3}) is False
        
        # Less than
        condition = PolicyCondition(attribute="level", operator="lt", value=10)
        assert condition.evaluate({"level": 5}) is True
        assert condition.evaluate({"level": 15}) is False

    def test_regex_operator(self):
        """Test regex operator."""
        condition = PolicyCondition(
            attribute="name",
            operator="regex",
            value=r"router-\d+",
        )
        
        assert condition.evaluate({"name": "router-001"}) is True
        assert condition.evaluate({"name": "switch-001"}) is False

    def test_missing_attribute(self):
        """Test evaluation with missing attribute."""
        condition = PolicyCondition(
            attribute="missing",
            operator="eq",
            value="value",
        )
        
        assert condition.evaluate({}) is False


# =============================================================================
# AccessDecision Tests
# =============================================================================

class TestAccessDecision:
    """Tests for AccessDecision dataclass."""

    def test_decision_allowed(self):
        """Test allowed access decision."""
        decision = AccessDecision(
            allowed=True,
            user_id="user-001",
            resource="router-001",
            action=ActionType.READ,
        )
        
        assert decision.allowed is True
        assert decision.reason == ""

    def test_decision_denied(self):
        """Test denied access decision."""
        decision = AccessDecision(
            allowed=False,
            user_id="user-001",
            resource="router-001",
            action=ActionType.UPDATE,
            reason="Insufficient permissions",
        )
        
        assert decision.allowed is False
        assert "Insufficient" in decision.reason

    def test_decision_to_dict(self):
        """Test decision serialization."""
        decision = AccessDecision(
            allowed=True,
            user_id="user-001",
            resource="router-001",
            action=ActionType.READ,
        )
        
        decision_dict = decision.to_dict()
        
        assert "allowed" in decision_dict
        assert "user_id" in decision_dict


# =============================================================================
# AuditEntry Tests
# =============================================================================

class TestAuditEntry:
    """Tests for AuditEntry dataclass."""

    def test_entry_creation(self):
        """Test creating audit entry."""
        decision = AccessDecision(
            allowed=True,
            user_id="user-001",
            resource="router-001",
            action=ActionType.READ,
        )
        
        entry = AuditEntry(
            entry_id="entry-001",
            timestamp=datetime.now(timezone.utc),
            user_id="user-001",
            action=ActionType.READ,
            resource="router-001",
            allowed=True,
            decision=decision,
        )
        
        assert entry.allowed is True

    def test_entry_to_dict(self):
        """Test audit entry serialization."""
        decision = AccessDecision(
            allowed=True,
            user_id="user-001",
            resource="router-001",
            action=ActionType.READ,
        )
        
        entry = AuditEntry(
            entry_id="entry-001",
            timestamp=datetime.now(timezone.utc),
            user_id="user-001",
            action=ActionType.READ,
            resource="router-001",
            allowed=True,
            decision=decision,
        )
        
        entry_dict = entry.to_dict()
        
        assert "entry_id" in entry_dict
        assert "allowed" in entry_dict


# =============================================================================
# Integration Tests
# =============================================================================

class TestAuthorizationIntegration:
    """Integration tests for authorization."""

    @pytest.mark.asyncio
    async def test_full_authorization_workflow(self, authz_engine):
        """Test complete authorization workflow."""
        # Create custom permission
        authz_engine.create_permission(
            permission_id="custom:feature",
            name="Custom Feature",
            resource_type=ResourceType.SERVICE,
            actions=[ActionType.READ, ActionType.EXECUTE],
        )
        
        # Create custom role
        authz_engine.create_role(
            role_id="custom_role",
            name="Custom Role",
            permissions={"custom:feature", "network:read"},
        )
        
        # Grant role to user
        await authz_engine.grant_role("user-001", "custom_role")
        
        # Check permissions
        result = await authz_engine.check_permission(
            user_id="user-001",
            permission_name="custom:feature",
        )
        assert result is True
        
        result = await authz_engine.check_permission(
            user_id="user-001",
            permission_name="network:read",
        )
        assert result is True
        
        result = await authz_engine.check_permission(
            user_id="user-001",
            permission_name="network:admin",
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_role_inheritance(self, authz_engine):
        """Test role inheritance."""
        # Create parent role
        authz_engine.create_role(
            role_id="base_role",
            name="Base Role",
            permissions={"network:read"},
        )
        
        # Create child role with parent
        authz_engine.create_role(
            role_id="extended_role",
            name="Extended Role",
            permissions={"network:write"},
            parent_roles={"base_role"},
        )
        
        # Grant child role
        await authz_engine.grant_role("user-001", "extended_role")
        
        # Should have both permissions
        permissions = await authz_engine.get_permissions("user-001")
        
        assert "network:read" in permissions
        assert "network:write" in permissions


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
