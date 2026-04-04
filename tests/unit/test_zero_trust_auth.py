"""
Unit tests for Zero Trust Authorization Engine.
"""

import pytest
import asyncio
from datetime import datetime, timedelta, timezone, time as dt_time
from unittest.mock import Mock, AsyncMock, patch

from unified_oss.fcaps.security.zero_trust import (
    ZeroTrustEngine,
    AnomalyScorer,
    AccessDecision,
    TrustLevel,
    AnomalyType,
    AccessDecisionResult,
    UserBehaviorProfile,
)
from unified_oss.fcaps.security.auth import (
    AuthManager,
    JWTHandler,
    SessionManager,
    AuthStatus,
    AuthToken,
    TokenType,
)
from unified_oss.fcaps.security.authorization import (
    AuthorizationEngine,
    Permission,
    Role,
    Policy,
    ActionType,
    ResourceType,
    PermissionEffect,
)


@pytest.fixture
def zero_trust_engine():
    """Create ZeroTrustEngine instance for testing."""
    return ZeroTrustEngine()


@pytest.fixture
def anomaly_scorer():
    """Create AnomalyScorer instance for testing."""
    return AnomalyScorer()


@pytest.fixture
def jwt_handler():
    """Create JWTHandler instance."""
    return JWTHandler(secret_key="test-secret-key")


@pytest.fixture
def auth_manager(jwt_handler):
    """Create AuthManager instance for testing."""
    return AuthManager(jwt_handler=jwt_handler)


@pytest.fixture
def authz_engine():
    """Create AuthorizationEngine instance for testing."""
    return AuthorizationEngine()


class TestZeroTrustEngine:
    """Test cases for ZeroTrustEngine."""
    
    @pytest.mark.asyncio
    async def test_evaluate_access_permits_valid_request(self, zero_trust_engine):
        """Test that valid access request is permitted."""
        result = await zero_trust_engine.evaluate_access(
            user_id="test-user",
            resource="/api/v1/alarms",
            action="read",
            context={
                "ip_address": "10.0.0.1",
                "user_agent": "test-client",
                "access_time": datetime.now(timezone.utc),
            }
        )
        
        assert result.result == AccessDecisionResult.ALLOW
    
    @pytest.mark.asyncio
    async def test_evaluate_access_denies_high_anomaly(self, zero_trust_engine):
        """Test that high anomaly score results in denial or challenge."""
        result = await zero_trust_engine.evaluate_access(
            user_id="suspicious-user",
            resource="/api/v1/admin/prod/config",
            action="configure",
            context={
                "ip_address": "8.8.8.8",  # Public external IP
                "access_time": datetime.now(timezone.utc).replace(hour=2),  # Highly unusual hour (2 AM)
                "device_fingerprint": "unknown-device-id",  # Unknown device
            }
        )
        
        # Result should be CHALLENGE, DENY or STEP_UP based on defaults
        assert result.result in [
            AccessDecisionResult.CHALLENGE, 
            AccessDecisionResult.DENY, 
            AccessDecisionResult.STEP_UP
        ]
        assert result.mfa_required is (result.result == AccessDecisionResult.CHALLENGE)
    
    @pytest.mark.asyncio
    async def test_trust_level_assignment(self, zero_trust_engine):
        """Test manual trust level assignment."""
        zero_trust_engine.set_trust_level("admin-user", TrustLevel.HIGH)
        trust_level = zero_trust_engine.get_trust_level("admin-user")
        assert trust_level == TrustLevel.HIGH


class TestAnomalyScorer:
    """Test cases for AnomalyScorer."""
    
    @pytest.mark.asyncio
    async def test_time_based_anomaly_normal_hours(self, anomaly_scorer):
        """Test that normal hours have low anomaly score."""
        # 10 AM on a weekday
        normal_time = datetime.now(timezone.utc).replace(hour=10)
        score = await anomaly_scorer._calculate_time_anomaly({"access_time": normal_time})
        assert score < 0.3
    
    @pytest.mark.asyncio
    async def test_time_based_anomaly_unusual_hours(self, anomaly_scorer):
        """Test that unusual hours have higher anomaly score."""
        # 2 AM
        unusual_time = datetime.now(timezone.utc).replace(hour=2)
        score = await anomaly_scorer._calculate_time_anomaly({"access_time": unusual_time})
        assert score > 0.5
    
    @pytest.mark.asyncio
    async def test_location_based_anomaly_known_ip(self, anomaly_scorer):
        """Test that known IP has low anomaly score."""
        profile = UserBehaviorProfile(user_id="user1")
        profile.typical_ip_ranges = ["192.168.1.0/24"]
        score = await anomaly_scorer._calculate_location_anomaly(
            user_id="user1",
            context={"ip_address": "192.168.1.50"},
            profile=profile
        )
        assert score == 0.0
    
    @pytest.mark.asyncio
    async def test_location_based_anomaly_unknown_ip(self, anomaly_scorer):
        """Test that unknown IP has higher anomaly score."""
        profile = UserBehaviorProfile(user_id="user1")
        profile.typical_ip_ranges = ["192.168.1.0/24"]
        score = await anomaly_scorer._calculate_location_anomaly(
            user_id="user1",
            context={"ip_address": "8.8.8.8"},
            profile=profile
        )
        assert score >= 0.6
    
    @pytest.mark.asyncio
    async def test_behavior_based_anomaly_normal_pattern(self, anomaly_scorer):
        """Test normal behavior pattern."""
        profile = UserBehaviorProfile(user_id="user1")
        profile.typical_resources = {"/api/v1/metrics"}
        score = await anomaly_scorer._calculate_behavior_anomaly(
            user_id="user1",
            resource="/api/v1/metrics",
            action="read",
            profile=profile
        )
        assert score < 0.4
    
    @pytest.mark.asyncio
    async def test_behavior_based_anomaly_unusual_pattern(self, anomaly_scorer):
        """Test unusual behavior pattern."""
        profile = UserBehaviorProfile(user_id="user1")
        profile.typical_resources = {"/api/v1/metrics"}
        score = await anomaly_scorer._calculate_behavior_anomaly(
            user_id="user1",
            resource="/api/v1/security/admin",
            action="delete",
            profile=profile
        )
        assert score > 0.5
    
    @pytest.mark.asyncio
    async def test_resource_based_anomaly_normal_resource(self, anomaly_scorer):
        """Test normal resource access."""
        score = await anomaly_scorer._calculate_resource_anomaly(
            resource="/api/v1/alarms",
            action="read"
        )
        assert score < 0.3
    
    @pytest.mark.asyncio
    async def test_resource_based_anomaly_sensitive_resource(self, anomaly_scorer):
        """Test sensitive resource access has higher score."""
        score = await anomaly_scorer._calculate_resource_anomaly(
            resource="/api/v1/security/credentials",
            action="delete"
        )
        assert score > 0.5
    
    @pytest.mark.asyncio
    async def test_combined_anomaly_score(self, anomaly_scorer):
        """Test combined anomaly score calculation."""
        # Test calculation via calculate_anomaly_score
        score = await anomaly_scorer.calculate_anomaly_score(
            user_id="test-user",
            resource="/api/v1/alarms",
            action="read",
            context={"ip_address": "127.0.0.1"}
        )
        assert 0.0 <= score.total_score <= 1.0


class TestAuthManager:
    """Test cases for AuthManager."""
    
    @pytest.mark.asyncio
    async def test_authenticate_success(self, auth_manager):
        """Test successful authentication."""
        auth_manager.register_user(
            username="test_user",
            email="test@example.com",
            password="correct_password"
        )
        result = await auth_manager.authenticate(
            username="test_user",
            password="correct_password"
        )
        assert result.status == AuthStatus.SUCCESS
    
    @pytest.mark.asyncio
    async def test_authenticate_failure(self, auth_manager):
        """Test failed authentication with wrong password."""
        auth_manager.register_user(
            username="test_user",
            email="test@example.com",
            password="correct_password"
        )
        result = await auth_manager.authenticate(
            username="test_user",
            password="wrong_password"
        )
        assert result.status == AuthStatus.FAILED
    
    @pytest.mark.asyncio
    async def test_generate_token(self, auth_manager):
        """Test JWT token generation."""
        token = await auth_manager.generate_token(
            user_id="test-user",
            scope=["viewer"]
        )
        assert token is not None
        assert isinstance(token, AuthToken)
    
    @pytest.mark.asyncio
    async def test_validate_token(self, auth_manager):
        """Test JWT token validation."""
        token = await auth_manager.generate_token(
            user_id="test-user",
            scope=["viewer"]
        )
        is_valid, payload = await auth_manager.validate_token(token.token_value)
        assert is_valid is True
        assert payload.get("sub") == "test-user"


class TestJWTHandler:
    """Test cases for JWTHandler."""
    
    @pytest.fixture
    def jwt_handler(self):
        """Create JWTHandler instance."""
        return JWTHandler(secret_key="test-secret-key")
    
    def test_encode_decode_token(self, jwt_handler):
        """Test token encoding and decoding."""
        token = jwt_handler.generate_token(
            user_id="test-user",
            token_type=TokenType.ACCESS,
            scope=["admin"]
        )
        is_valid, payload = jwt_handler.validate_token(token.token_value)
        assert is_valid is True
        assert payload["sub"] == "test-user"
    
    def test_expired_token_fails(self, jwt_handler):
        """Test that expired token validation fails."""
        jwt_handler.access_token_expiry = timedelta(seconds=-1)
        token = jwt_handler.generate_token(
            user_id="test-user",
            token_type=TokenType.ACCESS
        )
        is_valid, payload = jwt_handler.validate_token(token.token_value)
        assert is_valid is False
    
    def test_token_expiry_time(self, jwt_handler):
        """Test token expiry time configuration."""
        jwt_handler.access_token_expiry = timedelta(minutes=5)
        token = jwt_handler.generate_token(
            user_id="test-user",
            token_type=TokenType.ACCESS
        )
        is_valid, payload = jwt_handler.validate_token(token.token_value)
        assert is_valid is True
        assert payload["exp"] > datetime.now(timezone.utc).timestamp()


class TestAuthorizationEngine:
    """Test cases for AuthorizationEngine."""
    
    @pytest.mark.asyncio
    async def test_check_permission_allowed(self, authz_engine):
        """Test checking allowed permission."""
        await authz_engine.grant_role("test-user", "viewer")
        result = await authz_engine.check_permission(
            user_id="test-user",
            permission_name="network:read",
            resource="router-01"
        )
        assert result is True
    
    @pytest.mark.asyncio
    async def test_check_permission_denied(self, authz_engine):
        """Test checking denied permission."""
        await authz_engine.grant_role("test-user", "viewer")
        result = await authz_engine.check_permission(
            user_id="test-user",
            permission_name="network:write",
            resource="router-01"
        )
        assert result is False
    
    @pytest.mark.asyncio
    async def test_evaluate_policy(self, authz_engine):
        """Test policy evaluation."""
        authz_engine.create_policy(
            policy_id="test-policy",
            name="Test Policy",
            effect=PermissionEffect.DENY,
            resource_pattern="router-sensitive-*",
            actions=[ActionType.READ]
        )
        
        decision = await authz_engine.evaluate_policy(
            user_id="test-user",
            resource="router-sensitive-01",
            action=ActionType.READ
        )
        assert decision.allowed is False
    
    @pytest.mark.asyncio
    async def test_grant_role(self, authz_engine):
        """Test granting role to user."""
        success = await authz_engine.grant_role("test-user", "operator")
        assert success is True
        roles = authz_engine.get_user_roles("test-user")
        assert any(r.role_id == "operator" for r in roles)
    
    @pytest.mark.asyncio
    async def test_revoke_role(self, authz_engine):
        """Test revoking role from user."""
        await authz_engine.grant_role("test-user", "operator")
        success = await authz_engine.revoke_role("test-user", "operator")
        assert success is True
        roles = authz_engine.get_user_roles("test-user")
        assert not any(r.role_id == "operator" for r in roles)


class TestPermission:
    """Test cases for Permission class."""
    
    def test_permission_matches_resource(self):
        """Test permission resource matching."""
        perm = Permission(
            permission_id="p1",
            name="P1",
            resource_type=ResourceType.NETWORK_ELEMENT,
            actions=[ActionType.READ]
        )
        assert perm.matches_resource(ResourceType.NETWORK_ELEMENT) is True
        assert perm.matches_resource(ResourceType.ALARM) is False
    
    def test_permission_wildcard_action(self):
        """Test permission wildcard action matching."""
        perm = Permission(
            permission_id="p1",
            name="P1",
            resource_type=ResourceType.NETWORK_ELEMENT,
            actions=[ActionType.ALL]
        )
        assert perm.matches_action(ActionType.READ) is True
        assert perm.matches_action(ActionType.DELETE) is True


class TestRole:
    """Test cases for Role class."""
    
    def test_role_has_permission(self):
        """Test role permission assignment."""
        role = Role(
            role_id="r1",
            name="R1",
            permissions={"network:read"}
        )
        assert "network:read" in role.permissions
    
    def test_role_inheritance(self):
        """Test role hierarchical inheritance."""
        # Note: Inheritance logic is in AuthorizationEngine._get_role_permissions
        engine = AuthorizationEngine()
        engine.create_role(role_id="parent", name="Parent", permissions={"p1"})
        engine.create_role(role_id="child", name="Child", permissions={"p2"}, parent_roles={"parent"})
        
        perms = engine._get_role_permissions("child")
        assert "p1" in perms
        assert "p2" in perms
