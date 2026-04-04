"""
Unit tests for Security Authentication module.

Tests cover JWT token handling, session management, and MFA support.
"""

import asyncio
import hashlib
import hmac
import json
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from unified_oss.fcaps.security.auth import (
    AuthManager,
    JWTHandler,
    SessionManager,
    UserCredentials,
    AuthToken,
    Session,
    MFAChallenge,
    AuthResult,
    AuthStatus,
    TokenType,
    MFAChallengeType,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def jwt_handler():
    """Create a JWTHandler instance for testing."""
    return JWTHandler(
        secret_key="test-secret-key-for-unit-testing",
        algorithm="HS256",
        access_token_expiry=timedelta(minutes=5),
    )


@pytest.fixture
def session_manager():
    """Create a SessionManager instance for testing."""
    return SessionManager(
        session_timeout=timedelta(minutes=30),
        max_sessions_per_user=5,
    )


@pytest.fixture
def auth_manager(jwt_handler, session_manager):
    """Create an AuthManager instance for testing."""
    return AuthManager(
        jwt_handler=jwt_handler,
        session_manager=session_manager,
        max_login_attempts=3,
    )


@pytest.fixture
def sample_user_credentials():
    """Create sample user credentials."""
    return {
        "username": "testuser",
        "email": "test@example.com",
        "password": "SecurePassword123!",
        "roles": ["user", "operator"],
    }


# =============================================================================
# JWTHandler Tests
# =============================================================================

class TestJWTHandler:
    """Tests for JWTHandler class."""

    def test_generate_access_token(self, jwt_handler):
        """Test generating access token."""
        token = jwt_handler.generate_token(
            user_id="user-001",
            token_type=TokenType.ACCESS,
        )
        
        assert token.token_type == TokenType.ACCESS
        assert token.user_id == "user-001"
        assert not token.is_expired()

    def test_generate_refresh_token(self, jwt_handler):
        """Test generating refresh token."""
        token = jwt_handler.generate_token(
            user_id="user-001",
            token_type=TokenType.REFRESH,
        )
        
        assert token.token_type == TokenType.REFRESH
        assert token.expires_at > datetime.now(timezone.utc) + timedelta(days=1)

    def test_validate_token(self, jwt_handler):
        """Test validating JWT token."""
        token = jwt_handler.generate_token(
            user_id="user-001",
            token_type=TokenType.ACCESS,
        )
        
        is_valid, payload = jwt_handler.validate_token(token.token_value)
        
        assert is_valid is True
        assert payload is not None
        assert payload["sub"] == "user-001"

    def test_validate_invalid_token(self, jwt_handler):
        """Test validating invalid token."""
        is_valid, payload = jwt_handler.validate_token("invalid.token.here")
        
        assert is_valid is False
        assert payload is None

    def test_validate_expired_token(self, jwt_handler):
        """Test validating expired token."""
        # Create token that's already expired
        jwt_handler.access_token_expiry = timedelta(seconds=-1)
        token = jwt_handler.generate_token(user_id="user-001")
        
        # Wait a moment
        time.sleep(0.1)
        
        is_valid, payload = jwt_handler.validate_token(token.token_value)
        
        assert is_valid is False

    def test_validate_tampered_token(self, jwt_handler):
        """Test validating tampered token."""
        token = jwt_handler.generate_token(user_id="user-001")
        
        # Tamper with the token
        parts = token.token_value.split(".")
        tampered_token = parts[0] + "." + parts[1] + ".tampered"
        
        is_valid, payload = jwt_handler.validate_token(tampered_token)
        
        assert is_valid is False

    def test_refresh_token(self, jwt_handler):
        """Test refreshing access token."""
        refresh_token = jwt_handler.generate_token(
            user_id="user-001",
            token_type=TokenType.REFRESH,
        )
        
        new_access_token = jwt_handler.refresh_token(refresh_token.token_value)
        
        assert new_access_token is not None
        assert new_access_token.token_type == TokenType.ACCESS
        assert new_access_token.parent_token_id == refresh_token.token_id

    def test_revoke_token(self, jwt_handler):
        """Test revoking token."""
        token = jwt_handler.generate_token(user_id="user-001")
        
        result = jwt_handler.revoke_token(token.token_id)
        
        assert result is True
        
        # Should not validate after revocation
        is_valid, _ = jwt_handler.validate_token(token.token_value)
        assert is_valid is False

    def test_token_with_scope(self, jwt_handler):
        """Test token with custom scope."""
        token = jwt_handler.generate_token(
            user_id="user-001",
            scope=["read", "write"],
        )
        
        assert "read" in token.scope
        assert "write" in token.scope

    def test_token_with_custom_claims(self, jwt_handler):
        """Test token with custom claims."""
        custom_claims = {
            "department": "engineering",
            "region": "us-east",
        }
        
        token = jwt_handler.generate_token(
            user_id="user-001",
            custom_claims=custom_claims,
        )
        
        is_valid, payload = jwt_handler.validate_token(token.token_value)
        
        assert payload["department"] == "engineering"
        assert payload["region"] == "us-east"


# =============================================================================
# SessionManager Tests
# =============================================================================

class TestSessionManager:
    """Tests for SessionManager class."""

    @pytest.mark.asyncio
    async def test_create_session(self, session_manager):
        """Test creating a session."""
        session = await session_manager.create_session(
            user_id="user-001",
            ip_address="192.168.1.100",
            user_agent="TestAgent/1.0",
        )
        
        assert session is not None
        assert session.user_id == "user-001"
        assert session.ip_address == "192.168.1.100"

    @pytest.mark.asyncio
    async def test_validate_session(self, session_manager):
        """Test validating a session."""
        session = await session_manager.create_session(user_id="user-001")
        
        is_valid, retrieved = await session_manager.validate_session(session.session_id)
        
        assert is_valid is True
        assert retrieved is not None

    @pytest.mark.asyncio
    async def test_validate_expired_session(self, session_manager):
        """Test validating expired session."""
        session_manager.session_timeout = timedelta(seconds=-1)
        session = await session_manager.create_session(user_id="user-001")
        
        time.sleep(0.1)
        
        is_valid, retrieved = await session_manager.validate_session(session.session_id)
        
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_revoke_session(self, session_manager):
        """Test revoking a session."""
        session = await session_manager.create_session(user_id="user-001")
        
        result = await session_manager.revoke_session(session.session_id)
        
        assert result is True
        
        is_valid, _ = await session_manager.validate_session(session.session_id)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_revoke_all_user_sessions(self, session_manager):
        """Test revoking all sessions for a user."""
        # Create multiple sessions
        await session_manager.create_session(user_id="user-001")
        await session_manager.create_session(user_id="user-001")
        await session_manager.create_session(user_id="user-001")
        
        count = await session_manager.revoke_all_user_sessions("user-001")
        
        assert count == 3

    @pytest.mark.asyncio
    async def test_max_sessions_per_user(self, session_manager):
        """Test maximum sessions per user limit."""
        session_manager.max_sessions_per_user = 3
        
        # Create more sessions than limit
        for i in range(5):
            await session_manager.create_session(user_id="user-001")
        
        sessions = await session_manager.get_user_sessions("user-001")
        
        # Should have at most max_sessions_per_user sessions
        assert len(sessions) <= session_manager.max_sessions_per_user


# =============================================================================
# AuthManager Tests
# =============================================================================

class TestAuthManager:
    """Tests for AuthManager class."""

    @pytest.mark.asyncio
    async def test_register_user(self, auth_manager, sample_user_credentials):
        """Test user registration."""
        credentials = auth_manager.register_user(**sample_user_credentials)
        
        assert credentials.username == sample_user_credentials["username"]
        assert credentials.email == sample_user_credentials["email"]
        assert credentials.mfa_enabled is False

    @pytest.mark.asyncio
    async def test_authenticate_success(self, auth_manager, sample_user_credentials):
        """Test successful authentication."""
        auth_manager.register_user(**sample_user_credentials)
        
        result = await auth_manager.authenticate(
            username=sample_user_credentials["username"],
            password=sample_user_credentials["password"],
        )
        
        assert result.status == AuthStatus.SUCCESS
        assert result.access_token is not None
        assert result.refresh_token is not None

    @pytest.mark.asyncio
    async def test_authenticate_invalid_password(self, auth_manager, sample_user_credentials):
        """Test authentication with invalid password."""
        auth_manager.register_user(**sample_user_credentials)
        
        result = await auth_manager.authenticate(
            username=sample_user_credentials["username"],
            password="WrongPassword",
        )
        
        assert result.status == AuthStatus.FAILED

    @pytest.mark.asyncio
    async def test_authenticate_unknown_user(self, auth_manager):
        """Test authentication with unknown user."""
        result = await auth_manager.authenticate(
            username="unknown",
            password="password",
        )
        
        assert result.status == AuthStatus.FAILED

    @pytest.mark.asyncio
    async def test_authenticate_account_lockout(self, auth_manager, sample_user_credentials):
        """Test account lockout after failed attempts."""
        auth_manager.register_user(**sample_user_credentials)
        
        # Attempt failed logins
        for _ in range(auth_manager.max_login_attempts + 1):
            await auth_manager.authenticate(
                username=sample_user_credentials["username"],
                password="WrongPassword",
            )
        
        # Should be locked
        result = await auth_manager.authenticate(
            username=sample_user_credentials["username"],
            password=sample_user_credentials["password"],
        )
        
        assert result.status == AuthStatus.LOCKED

    @pytest.mark.asyncio
    async def test_authenticate_with_mfa(self, auth_manager):
        """Test authentication with MFA enabled."""
        credentials = auth_manager.register_user(
            username="mfa_user",
            email="mfa@example.com",
            password="Password123!",
            mfa_enabled=True,
        )
        
        result = await auth_manager.authenticate(
            username="mfa_user",
            password="Password123!",
        )
        
        assert result.status == AuthStatus.PENDING_MFA
        assert result.mfa_required is True
        assert result.mfa_challenge is not None

    def test_hash_password(self, auth_manager):
        """Test password hashing."""
        password = "TestPassword123!"
        
        hash1, salt = auth_manager.hash_password(password)
        hash2, _ = auth_manager.hash_password(password, salt)
        
        # Same password with same salt should produce same hash
        assert hash1 == hash2
        
        # Different passwords should produce different hashes
        different_hash, _ = auth_manager.hash_password("DifferentPassword")
        assert hash1 != different_hash

    @pytest.mark.asyncio
    async def test_verify_mfa_success(self, auth_manager):
        """Test successful MFA verification."""
        credentials = auth_manager.register_user(
            username="mfa_user",
            email="mfa@example.com",
            password="Password123!",
            mfa_enabled=True,
        )
        
        result = await auth_manager.authenticate(
            username="mfa_user",
            password="Password123!",
        )
        
        # Get challenge ID
        challenge_id = result.mfa_challenge.challenge_id
        
        # Verify MFA
        verify_result = await auth_manager.verify_mfa(
            user_id=credentials.user_id,
            challenge_id=challenge_id,
            code=result.mfa_challenge.code,  # Use the code from challenge
        )
        
        assert verify_result.status == AuthStatus.SUCCESS


# =============================================================================
# UserCredentials Tests
# =============================================================================

class TestUserCredentials:
    """Tests for UserCredentials dataclass."""

    def test_credentials_creation(self):
        """Test creating user credentials."""
        creds = UserCredentials(
            user_id="user-001",
            username="testuser",
            email="test@example.com",
            password_hash="hashed_password",
            salt="random_salt",
        )
        
        assert creds.mfa_enabled is False
        assert creds.failed_attempts == 0

    def test_credentials_with_roles(self):
        """Test credentials with roles."""
        creds = UserCredentials(
            user_id="user-001",
            username="testuser",
            email="test@example.com",
            password_hash="hash",
            salt="salt",
            roles=["admin", "operator"],
        )
        
        assert "admin" in creds.roles
        assert "operator" in creds.roles


# =============================================================================
# AuthToken Tests
# =============================================================================

class TestAuthToken:
    """Tests for AuthToken dataclass."""

    def test_token_creation(self):
        """Test creating auth token."""
        token = AuthToken(
            token_id="token-001",
            token_type=TokenType.ACCESS,
            token_value="jwt_token_string",
            user_id="user-001",
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        )
        
        assert token.is_valid() is True
        assert not token.is_expired()

    def test_token_expiry(self):
        """Test token expiry check."""
        token = AuthToken(
            token_id="token-001",
            token_type=TokenType.ACCESS,
            token_value="jwt_token",
            user_id="user-001",
            issued_at=datetime.now(timezone.utc) - timedelta(hours=1),
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        )
        
        assert token.is_expired() is True
        assert not token.is_valid()

    def test_token_revoked(self):
        """Test revoked token."""
        token = AuthToken(
            token_id="token-001",
            token_type=TokenType.ACCESS,
            token_value="jwt_token",
            user_id="user-001",
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            revoked=True,
        )
        
        assert not token.is_valid()


# =============================================================================
# Session Tests
# =============================================================================

class TestSession:
    """Tests for Session dataclass."""

    def test_session_creation(self):
        """Test creating a session."""
        session = Session(
            session_id="session-001",
            user_id="user-001",
            created_at=datetime.now(timezone.utc),
            last_activity=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
        )
        
        assert session.is_valid() is True

    def test_session_expiry(self):
        """Test session expiry."""
        session = Session(
            session_id="session-001",
            user_id="user-001",
            created_at=datetime.now(timezone.utc) - timedelta(hours=1),
            last_activity=datetime.now(timezone.utc) - timedelta(hours=1),
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        )
        
        assert session.is_expired() is True


# =============================================================================
# MFAChallenge Tests
# =============================================================================

class TestMFAChallenge:
    """Tests for MFAChallenge dataclass."""

    def test_challenge_creation(self):
        """Test creating MFA challenge."""
        challenge = MFAChallenge(
            challenge_id="challenge-001",
            user_id="user-001",
            challenge_type=MFAChallengeType.TOTP,
        )
        
        assert challenge.verified is False
        assert challenge.can_attempt() is True

    def test_challenge_attempts(self):
        """Test challenge attempt limits."""
        challenge = MFAChallenge(
            challenge_id="challenge-001",
            user_id="user-001",
            challenge_type=MFAChallengeType.TOTP,
            attempts=3,
            max_attempts=3,
        )
        
        assert challenge.can_attempt() is False

    def test_challenge_expiry(self):
        """Test challenge expiry."""
        challenge = MFAChallenge(
            challenge_id="challenge-001",
            user_id="user-001",
            challenge_type=MFAChallengeType.TOTP,
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        )
        
        assert challenge.is_expired() is True


# =============================================================================
# AuthResult Tests
# =============================================================================

class TestAuthResult:
    """Tests for AuthResult dataclass."""

    def test_success_result(self):
        """Test successful auth result."""
        result = AuthResult(
            status=AuthStatus.SUCCESS,
            user_id="user-001",
            message="Authentication successful",
        )
        
        assert result.status == AuthStatus.SUCCESS
        assert result.error_code is None

    def test_failure_result(self):
        """Test failed auth result."""
        result = AuthResult(
            status=AuthStatus.FAILED,
            message="Invalid credentials",
            error_code="AUTH_INVALID_CREDENTIALS",
        )
        
        assert result.status == AuthStatus.FAILED
        assert result.error_code is not None


# =============================================================================
# Integration Tests
# =============================================================================

class TestAuthIntegration:
    """Integration tests for authentication."""

    @pytest.mark.asyncio
    async def test_full_auth_workflow(self, auth_manager):
        """Test complete authentication workflow."""
        # Register
        credentials = auth_manager.register_user(
            username="integration_user",
            email="integration@example.com",
            password="Password123!",
        )
        
        # Authenticate
        result = await auth_manager.authenticate(
            username="integration_user",
            password="Password123!",
        )
        
        assert result.status == AuthStatus.SUCCESS
        
        # Validate token
        jwt_handler = auth_manager.jwt_handler
        is_valid, payload = jwt_handler.validate_token(
            result.access_token.token_value
        )
        
        assert is_valid is True
        
        # Validate session
        is_valid, session = await auth_manager.session_manager.validate_session(
            result.session_id
        )
        
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_token_refresh_workflow(self, auth_manager):
        """Test token refresh workflow."""
        # Register and authenticate
        auth_manager.register_user(
            username="refresh_user",
            email="refresh@example.com",
            password="Password123!",
        )
        
        result = await auth_manager.authenticate(
            username="refresh_user",
            password="Password123!",
        )
        
        # Use refresh token
        new_access = auth_manager.jwt_handler.refresh_token(
            result.refresh_token.token_value
        )
        
        assert new_access is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
