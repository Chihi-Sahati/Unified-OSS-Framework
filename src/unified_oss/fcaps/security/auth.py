"""
Authentication Module for Unified OSS Framework Security Management.

This module provides comprehensive authentication capabilities including OAuth 2.0 JWT
authentication, token management, session handling, and multi-factor authentication (MFA)
support for the FCAPS Security Management domain.

Features:
    - OAuth 2.0 JWT token generation with configurable expiry
    - Token validation and refresh mechanisms
    - Session management with activity tracking
    - MFA challenge/response support
    - Cryptographic hashing for secure token storage
    - Database integration for audit logging

Example:
    >>> from unified_oss.fcaps.security.auth import AuthManager, JWTHandler
    >>> jwt_handler = JWTHandler(secret_key="your-secret-key")
    >>> auth_manager = AuthManager(jwt_handler=jwt_handler)
    >>> result = await auth_manager.authenticate("user@example.com", "password")
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger(__name__)


class AuthStatus(Enum):
    """Authentication status enumeration.

    Attributes:
        SUCCESS: Authentication successful.
        FAILED: Authentication failed.
        EXPIRED: Token or session expired.
        REVOKED: Token or session revoked.
        PENDING_MFA: Awaiting MFA challenge response.
        LOCKED: Account locked due to failed attempts.
    """

    SUCCESS = "success"
    FAILED = "failed"
    EXPIRED = "expired"
    REVOKED = "revoked"
    PENDING_MFA = "pending_mfa"
    LOCKED = "locked"


class TokenType(Enum):
    """Token type enumeration.

    Attributes:
        ACCESS: Access token for API requests.
        REFRESH: Refresh token for obtaining new access tokens.
        MFA: Token for MFA challenge verification.
    """

    ACCESS = "access"
    REFRESH = "refresh"
    MFA = "mfa"


class MFAChallengeType(Enum):
    """MFA challenge type enumeration.

    Attributes:
        TOTP: Time-based one-time password.
        SMS: SMS-based verification code.
        EMAIL: Email-based verification code.
        PUSH: Push notification approval.
        BACKUP_CODE: Backup code verification.
    """

    TOTP = "totp"
    SMS = "sms"
    EMAIL = "email"
    PUSH = "push"
    BACKUP_CODE = "backup_code"


@dataclass
class UserCredentials:
    """User credentials data structure.

    Attributes:
        user_id: Unique user identifier.
        username: Username for authentication.
        email: User email address.
        password_hash: Hashed password (never store plaintext).
        salt: Salt used for password hashing.
        mfa_enabled: Whether MFA is enabled for this user.
        mfa_secret: TOTP secret if MFA is enabled.
        mfa_challenge_types: Available MFA challenge types.
        roles: Assigned user roles.
        created_at: Account creation timestamp.
        last_login: Last successful login timestamp.
        failed_attempts: Count of consecutive failed login attempts.
        locked_until: Account locked until this timestamp.
    """

    user_id: str
    username: str
    email: str
    password_hash: str
    salt: str
    mfa_enabled: bool = False
    mfa_secret: Optional[str] = None
    mfa_challenge_types: List[MFAChallengeType] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_login: Optional[datetime] = None
    failed_attempts: int = 0
    locked_until: Optional[datetime] = None


@dataclass
class AuthToken:
    """Authentication token data structure.

    Attributes:
        token_id: Unique token identifier.
        token_type: Type of token (access, refresh, mfa).
        token_value: The actual token string.
        user_id: Associated user identifier.
        issued_at: Token issuance timestamp.
        expires_at: Token expiration timestamp.
        scope: Token scope/permissions.
        client_id: OAuth client identifier.
        revoked: Whether token has been revoked.
        parent_token_id: Parent token for refresh tokens.
    """

    token_id: str
    token_type: TokenType
    token_value: str
    user_id: str
    issued_at: datetime
    expires_at: datetime
    scope: List[str] = field(default_factory=list)
    client_id: Optional[str] = None
    revoked: bool = False
    parent_token_id: Optional[str] = None

    def is_expired(self) -> bool:
        """Check if token has expired.

        Returns:
            True if token has expired, False otherwise.
        """
        return datetime.now(timezone.utc) > self.expires_at

    def is_valid(self) -> bool:
        """Check if token is valid (not expired and not revoked).

        Returns:
            True if token is valid, False otherwise.
        """
        return not self.is_expired() and not self.revoked


@dataclass
class Session:
    """User session data structure.

    Attributes:
        session_id: Unique session identifier.
        user_id: Associated user identifier.
        created_at: Session creation timestamp.
        last_activity: Last activity timestamp.
        expires_at: Session expiration timestamp.
        ip_address: Client IP address.
        user_agent: Client user agent string.
        device_fingerprint: Device fingerprint for device recognition.
        active: Whether session is active.
        mfa_verified: Whether MFA has been verified for this session.
        metadata: Additional session metadata.
    """

    session_id: str
    user_id: str
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    device_fingerprint: Optional[str] = None
    active: bool = True
    mfa_verified: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        """Check if session has expired.

        Returns:
            True if session has expired, False otherwise.
        """
        return datetime.now(timezone.utc) > self.expires_at

    def is_valid(self) -> bool:
        """Check if session is valid (not expired and active).

        Returns:
            True if session is valid, False otherwise.
        """
        return not self.is_expired() and self.active


@dataclass
class MFAChallenge:
    """MFA challenge data structure.

    Attributes:
        challenge_id: Unique challenge identifier.
        user_id: Associated user identifier.
        challenge_type: Type of MFA challenge.
        code: Challenge code (for SMS, EMAIL, BACKUP_CODE).
        created_at: Challenge creation timestamp.
        expires_at: Challenge expiration timestamp.
        verified: Whether challenge has been verified.
        attempts: Number of verification attempts.
        max_attempts: Maximum allowed attempts.
    """

    challenge_id: str
    user_id: str
    challenge_type: MFAChallengeType
    code: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc) + timedelta(minutes=5)
    )
    verified: bool = False
    attempts: int = 0
    max_attempts: int = 3

    def is_expired(self) -> bool:
        """Check if challenge has expired.

        Returns:
            True if challenge has expired, False otherwise.
        """
        return datetime.now(timezone.utc) > self.expires_at

    def can_attempt(self) -> bool:
        """Check if more verification attempts are allowed.

        Returns:
            True if attempts remaining, False otherwise.
        """
        return self.attempts < self.max_attempts


@dataclass
class AuthResult:
    """Authentication result data structure.

    Attributes:
        status: Authentication status.
        user_id: Authenticated user identifier (if successful).
        access_token: Access token (if successful).
        refresh_token: Refresh token (if successful).
        session_id: Session identifier (if successful).
        mfa_required: Whether MFA is required.
        mfa_challenge: MFA challenge (if MFA required).
        message: Result message.
        error_code: Error code (if failed).
    """

    status: AuthStatus
    user_id: Optional[str] = None
    access_token: Optional[AuthToken] = None
    refresh_token: Optional[AuthToken] = None
    session_id: Optional[str] = None
    mfa_required: bool = False
    mfa_challenge: Optional[MFAChallenge] = None
    message: str = ""
    error_code: Optional[str] = None


class JWTHandler:
    """JWT token handler for OAuth 2.0 authentication.

    This class provides JWT token generation, validation, and refresh
    capabilities following OAuth 2.0 standards.

    Attributes:
        secret_key: Secret key for token signing.
        algorithm: JWT signing algorithm.
        access_token_expiry: Access token expiry duration.
        refresh_token_expiry: Refresh token expiry duration.
        issuer: Token issuer identifier.
        audience: Token audience.
    """

    def __init__(
        self,
        secret_key: str,
        algorithm: str = "HS256",
        access_token_expiry: timedelta = timedelta(minutes=5),
        refresh_token_expiry: timedelta = timedelta(days=7),
        issuer: str = "unified-oss",
        audience: str = "unified-oss-api",
    ) -> None:
        """Initialize JWT handler.

        Args:
            secret_key: Secret key for token signing.
            algorithm: JWT signing algorithm (default: HS256).
            access_token_expiry: Access token expiry duration (default: 5 minutes).
            refresh_token_expiry: Refresh token expiry duration (default: 7 days).
            issuer: Token issuer identifier.
            audience: Token audience.
        """
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.access_token_expiry = access_token_expiry
        self.refresh_token_expiry = refresh_token_expiry
        self.issuer = issuer
        self.audience = audience
        self._token_store: Dict[str, AuthToken] = {}
        self._blacklist: Set[str] = set()
        logger.info(f"JWTHandler initialized with {algorithm} algorithm")

    def _base64url_encode(self, data: bytes) -> str:
        """Base64url encode without padding.

        Args:
            data: Data to encode.

        Returns:
            Base64url encoded string.
        """
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

    def _base64url_decode(self, data: str) -> bytes:
        """Base64url decode with padding.

        Args:
            data: Data to decode.

        Returns:
            Decoded bytes.
        """
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data)

    def _create_signature(self, data: str) -> str:
        """Create HMAC signature for JWT.

        Args:
            data: Data to sign.

        Returns:
            Signature string.
        """
        if self.algorithm == "HS256":
            signature = hmac.new(
                self.secret_key.encode("utf-8"),
                data.encode("utf-8"),
                hashlib.sha256,
            ).digest()
        elif self.algorithm == "HS384":
            signature = hmac.new(
                self.secret_key.encode("utf-8"),
                data.encode("utf-8"),
                hashlib.sha384,
            ).digest()
        elif self.algorithm == "HS512":
            signature = hmac.new(
                self.secret_key.encode("utf-8"),
                data.encode("utf-8"),
                hashlib.sha512,
            ).digest()
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")

        return self._base64url_encode(signature)

    def generate_token(
        self,
        user_id: str,
        token_type: TokenType = TokenType.ACCESS,
        scope: Optional[List[str]] = None,
        client_id: Optional[str] = None,
        parent_token_id: Optional[str] = None,
        custom_claims: Optional[Dict[str, Any]] = None,
    ) -> AuthToken:
        """Generate a JWT token.

        Args:
            user_id: User identifier for the token.
            token_type: Type of token to generate.
            scope: Token scope/permissions.
            client_id: OAuth client identifier.
            parent_token_id: Parent token ID for refresh tokens.
            custom_claims: Additional custom claims.

        Returns:
            Generated AuthToken object.
        """
        token_id = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)

        if token_type == TokenType.ACCESS:
            expiry = now + self.access_token_expiry
        elif token_type == TokenType.REFRESH:
            expiry = now + self.refresh_token_expiry
        else:
            expiry = now + timedelta(minutes=10)  # MFA tokens are short-lived

        # Build JWT header
        header = {
            "alg": self.algorithm,
            "typ": "JWT",
        }

        # Build JWT payload
        payload = {
            "jti": token_id,
            "sub": user_id,
            "iss": self.issuer,
            "aud": self.audience,
            "iat": int(now.timestamp()),
            "exp": int(expiry.timestamp()),
            "type": token_type.value,
            "scope": scope or [],
        }

        if client_id:
            payload["client_id"] = client_id

        if parent_token_id:
            payload["parent_jti"] = parent_token_id

        if custom_claims:
            payload.update(custom_claims)

        # Encode header and payload
        header_encoded = self._base64url_encode(
            json.dumps(header, separators=(",", ":")).encode("utf-8")
        )
        payload_encoded = self._base64url_encode(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        )

        # Create signature
        signing_data = f"{header_encoded}.{payload_encoded}"
        signature = self._create_signature(signing_data)

        # Combine to form JWT
        token_value = f"{signing_data}.{signature}"

        auth_token = AuthToken(
            token_id=token_id,
            token_type=token_type,
            token_value=token_value,
            user_id=user_id,
            issued_at=now,
            expires_at=expiry,
            scope=scope or [],
            client_id=client_id,
            parent_token_id=parent_token_id,
        )

        self._token_store[token_id] = auth_token
        logger.debug(f"Generated {token_type.value} token for user {user_id}")

        return auth_token

    def validate_token(self, token_value: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Validate a JWT token.

        Args:
            token_value: Token string to validate.

        Returns:
            Tuple of (is_valid, payload_or_none).
        """
        try:
            parts = token_value.split(".")
            if len(parts) != 3:
                logger.warning("Invalid token format")
                return False, None

            header_encoded, payload_encoded, signature = parts

            # Verify signature
            expected_signature = self._create_signature(f"{header_encoded}.{payload_encoded}")
            if not hmac.compare_digest(signature, expected_signature):
                logger.warning("Invalid token signature")
                return False, None

            # Decode payload
            payload_json = self._base64url_decode(payload_encoded).decode("utf-8")
            payload = json.loads(payload_json)

            # Check if token is blacklisted
            token_id = payload.get("jti")
            if token_id in self._blacklist:
                logger.warning(f"Token {token_id} is blacklisted")
                return False, None

            # Check expiration
            exp = payload.get("exp")
            if exp and datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc):
                logger.warning("Token has expired")
                return False, None

            # Verify issuer
            if payload.get("iss") != self.issuer:
                logger.warning("Invalid token issuer")
                return False, None

            logger.debug(f"Token {token_id} validated successfully")
            return True, payload

        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return False, None

    def refresh_token(
        self, refresh_token_value: str, scope: Optional[List[str]] = None
    ) -> Optional[AuthToken]:
        """Refresh an access token using a refresh token.

        Args:
            refresh_token_value: Refresh token string.
            scope: New scope for the access token (optional).

        Returns:
            New access token or None if refresh failed.
        """
        is_valid, payload = self.validate_token(refresh_token_value)

        if not is_valid:
            logger.warning("Invalid refresh token")
            return None

        if payload.get("type") != TokenType.REFRESH.value:
            logger.warning("Token is not a refresh token")
            return None

        token_id = payload.get("jti")
        if token_id and token_id in self._token_store:
            stored_token = self._token_store[token_id]
            if stored_token.revoked:
                logger.warning("Refresh token has been revoked")
                return None

        user_id = payload.get("sub")
        client_id = payload.get("client_id")

        # Generate new access token
        new_access_token = self.generate_token(
            user_id=user_id,
            token_type=TokenType.ACCESS,
            scope=scope or payload.get("scope", []),
            client_id=client_id,
            parent_token_id=token_id,
        )

        logger.info(f"Refreshed access token for user {user_id}")
        return new_access_token

    def revoke_token(self, token_id: str) -> bool:
        """Revoke a token by adding it to the blacklist.

        Args:
            token_id: Token identifier to revoke.

        Returns:
            True if token was revoked, False if not found.
        """
        if token_id in self._token_store:
            self._token_store[token_id].revoked = True
            self._blacklist.add(token_id)
            logger.info(f"Token {token_id} has been revoked")
            return True
        return False

    def get_token(self, token_id: str) -> Optional[AuthToken]:
        """Get token by ID.

        Args:
            token_id: Token identifier.

        Returns:
            AuthToken if found, None otherwise.
        """
        return self._token_store.get(token_id)


class SessionManager:
    """Session management for user sessions.

    This class provides session creation, validation, and revocation
    with activity tracking and configurable timeout.

    Attributes:
        session_timeout: Session timeout duration.
        max_sessions_per_user: Maximum concurrent sessions per user.
        absolute_timeout: Absolute session timeout (regardless of activity).
    """

    def __init__(
        self,
        session_timeout: timedelta = timedelta(minutes=30),
        max_sessions_per_user: int = 5,
        absolute_timeout: timedelta = timedelta(hours=8),
    ) -> None:
        """Initialize session manager.

        Args:
            session_timeout: Session idle timeout duration.
            max_sessions_per_user: Maximum concurrent sessions per user.
            absolute_timeout: Absolute session timeout.
        """
        self.session_timeout = session_timeout
        self.max_sessions_per_user = max_sessions_per_user
        self.absolute_timeout = absolute_timeout
        self._sessions: Dict[str, Session] = {}
        self._user_sessions: Dict[str, List[str]] = {}
        self._lock = asyncio.Lock()
        logger.info("SessionManager initialized")

    async def create_session(
        self,
        user_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        device_fingerprint: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Session:
        """Create a new user session.

        Args:
            user_id: User identifier.
            ip_address: Client IP address.
            user_agent: Client user agent.
            device_fingerprint: Device fingerprint.
            metadata: Additional session metadata.

        Returns:
            Created Session object.
        """
        async with self._lock:
            # Check and enforce max sessions limit
            if user_id in self._user_sessions:
                user_session_ids = self._user_sessions[user_id]
                if len(user_session_ids) >= self.max_sessions_per_user:
                    # Remove oldest session
                    oldest_session_id = user_session_ids.pop(0)
                    if oldest_session_id in self._sessions:
                        self._sessions[oldest_session_id].active = False
                        del self._sessions[oldest_session_id]
                    logger.info(
                        f"Removed oldest session for user {user_id} "
                        f"(max sessions: {self.max_sessions_per_user})"
                    )

            session_id = secrets.token_urlsafe(32)
            now = datetime.now(timezone.utc)

            session = Session(
                session_id=session_id,
                user_id=user_id,
                created_at=now,
                last_activity=now,
                expires_at=now + self.session_timeout,
                ip_address=ip_address,
                user_agent=user_agent,
                device_fingerprint=device_fingerprint,
                metadata=metadata or {},
            )

            self._sessions[session_id] = session

            if user_id not in self._user_sessions:
                self._user_sessions[user_id] = []
            self._user_sessions[user_id].append(session_id)

            logger.info(f"Created session {session_id} for user {user_id}")
            return session

    async def validate_session(self, session_id: str) -> Tuple[bool, Optional[Session]]:
        """Validate a session and update activity.

        Args:
            session_id: Session identifier.

        Returns:
            Tuple of (is_valid, session_or_none).
        """
        async with self._lock:
            session = self._sessions.get(session_id)

            if session is None:
                logger.debug(f"Session {session_id} not found")
                return False, None

            # Check if session is active
            if not session.active:
                logger.debug(f"Session {session_id} is inactive")
                return False, None

            # Check absolute timeout
            if datetime.now(timezone.utc) - session.created_at > self.absolute_timeout:
                session.active = False
                logger.debug(f"Session {session_id} exceeded absolute timeout")
                return False, None

            # Check idle timeout
            if session.is_expired():
                session.active = False
                logger.debug(f"Session {session_id} has expired")
                return False, None

            # Update activity and extend expiry
            session.last_activity = datetime.now(timezone.utc)
            session.expires_at = datetime.now(timezone.utc) + self.session_timeout

            return True, session

    async def revoke_session(self, session_id: str) -> bool:
        """Revoke a session.

        Args:
            session_id: Session identifier.

        Returns:
            True if session was revoked, False if not found.
        """
        async with self._lock:
            session = self._sessions.get(session_id)

            if session is None:
                return False

            session.active = False
            del self._sessions[session_id]

            if session.user_id in self._user_sessions:
                try:
                    self._user_sessions[session.user_id].remove(session_id)
                except ValueError:
                    pass

            logger.info(f"Session {session_id} has been revoked")
            return True

    async def revoke_all_user_sessions(self, user_id: str) -> int:
        """Revoke all sessions for a user.

        Args:
            user_id: User identifier.

        Returns:
            Number of sessions revoked.
        """
        async with self._lock:
            if user_id not in self._user_sessions:
                return 0

            session_ids = self._user_sessions[user_id].copy()
            revoked_count = 0

            for session_id in session_ids:
                if session_id in self._sessions:
                    self._sessions[session_id].active = False
                    del self._sessions[session_id]
                    revoked_count += 1

            del self._user_sessions[user_id]

            logger.info(f"Revoked {revoked_count} sessions for user {user_id}")
            return revoked_count

    async def get_user_sessions(self, user_id: str) -> List[Session]:
        """Get all active sessions for a user.

        Args:
            user_id: User identifier.

        Returns:
            List of active sessions.
        """
        async with self._lock:
            if user_id not in self._user_sessions:
                return []

            sessions = []
            invalid_session_ids = []

            for session_id in self._user_sessions[user_id]:
                session = self._sessions.get(session_id)
                if session and session.is_valid():
                    sessions.append(session)
                else:
                    invalid_session_ids.append(session_id)

            # Clean up invalid sessions
            for session_id in invalid_session_ids:
                try:
                    self._user_sessions[user_id].remove(session_id)
                except ValueError:
                    pass

            return sessions

    def get_session(self, session_id: str) -> Optional[Session]:
        """Get session by ID without validation.

        Args:
            session_id: Session identifier.

        Returns:
            Session if found, None otherwise.
        """
        return self._sessions.get(session_id)


class AuthManager:
    """Main authentication manager coordinating all auth operations.

    This class provides a unified interface for authentication operations
    including credential validation, token management, session handling,
    and MFA support.

    Attributes:
        jwt_handler: JWT token handler.
        session_manager: Session manager.
        mfa_timeout: MFA challenge timeout duration.
        max_login_attempts: Maximum login attempts before lockout.
        lockout_duration: Account lockout duration.
    """

    def __init__(
        self,
        jwt_handler: JWTHandler,
        session_manager: Optional[SessionManager] = None,
        mfa_timeout: timedelta = timedelta(minutes=5),
        max_login_attempts: int = 5,
        lockout_duration: timedelta = timedelta(minutes=15),
        credential_store: Optional[Dict[str, UserCredentials]] = None,
    ) -> None:
        """Initialize authentication manager.

        Args:
            jwt_handler: JWT token handler.
            session_manager: Session manager (optional, created if not provided).
            mfa_timeout: MFA challenge timeout.
            max_login_attempts: Maximum login attempts before lockout.
            lockout_duration: Account lockout duration.
            credential_store: User credentials store (for demo/testing).
        """
        self.jwt_handler = jwt_handler
        self.session_manager = session_manager or SessionManager()
        self.mfa_timeout = mfa_timeout
        self.max_login_attempts = max_login_attempts
        self.lockout_duration = lockout_duration
        self._credential_store = credential_store or {}
        self._mfa_challenges: Dict[str, MFAChallenge] = {}
        self._audit_log: List[Dict[str, Any]] = []
        self._lock = asyncio.Lock()
        logger.info("AuthManager initialized")

    @staticmethod
    def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
        """Hash a password with salt.

        Args:
            password: Password to hash.
            salt: Salt to use (generated if not provided).

        Returns:
            Tuple of (password_hash, salt).
        """
        if salt is None:
            salt = secrets.token_hex(16)

        password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations=100000,
        ).hex()

        return password_hash, salt

    def register_user(
        self,
        username: str,
        email: str,
        password: str,
        roles: Optional[List[str]] = None,
        mfa_enabled: bool = False,
    ) -> UserCredentials:
        """Register a new user.

        Args:
            username: Username for the new user.
            email: Email address for the new user.
            password: Password for the new user.
            roles: Roles to assign to the user.
            mfa_enabled: Whether to enable MFA.

        Returns:
            Created UserCredentials object.
        """
        user_id = secrets.token_urlsafe(16)
        password_hash, salt = self.hash_password(password)

        credentials = UserCredentials(
            user_id=user_id,
            username=username,
            email=email,
            password_hash=password_hash,
            salt=salt,
            roles=roles or ["user"],
            mfa_enabled=mfa_enabled,
            mfa_secret=secrets.token_urlsafe(20) if mfa_enabled else None,
        )

        if mfa_enabled:
            credentials.mfa_challenge_types = [MFAChallengeType.TOTP]

        self._credential_store[username] = credentials
        logger.info(f"Registered user: {username} (ID: {user_id})")

        return credentials

    async def authenticate(
        self,
        username: str,
        password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        device_fingerprint: Optional[str] = None,
        scope: Optional[List[str]] = None,
    ) -> AuthResult:
        """Authenticate a user with credentials.

        Args:
            username: Username for authentication.
            password: Password for authentication.
            ip_address: Client IP address.
            user_agent: Client user agent.
            device_fingerprint: Device fingerprint.
            scope: Requested token scope.

        Returns:
            AuthResult with authentication outcome.
        """
        async with self._lock:
            credentials = self._credential_store.get(username)

            if credentials is None:
                self._log_audit_event(
                    event="authentication_failed",
                    username=username,
                    ip_address=ip_address,
                    reason="user_not_found",
                )
                return AuthResult(
                    status=AuthStatus.FAILED,
                    message="Invalid credentials",
                    error_code="AUTH_INVALID_CREDENTIALS",
                )

            # Check if account is locked
            if credentials.locked_until and credentials.locked_until > datetime.now(timezone.utc):
                self._log_audit_event(
                    event="authentication_failed",
                    username=username,
                    user_id=credentials.user_id,
                    ip_address=ip_address,
                    reason="account_locked",
                )
                return AuthResult(
                    status=AuthStatus.LOCKED,
                    message=f"Account locked until {credentials.locked_until.isoformat()}",
                    error_code="AUTH_ACCOUNT_LOCKED",
                )

            # Verify password
            password_hash, _ = self.hash_password(password, credentials.salt)

            if not hmac.compare_digest(password_hash, credentials.password_hash):
                credentials.failed_attempts += 1

                # Lock account if max attempts exceeded
                if credentials.failed_attempts >= self.max_login_attempts:
                    credentials.locked_until = (
                        datetime.now(timezone.utc) + self.lockout_duration
                    )
                    self._log_audit_event(
                        event="account_locked",
                        username=username,
                        user_id=credentials.user_id,
                        ip_address=ip_address,
                        reason="max_attempts_exceeded",
                    )
                    return AuthResult(
                        status=AuthStatus.LOCKED,
                        message="Account locked due to too many failed attempts",
                        error_code="AUTH_ACCOUNT_LOCKED",
                    )

                self._log_audit_event(
                    event="authentication_failed",
                    username=username,
                    user_id=credentials.user_id,
                    ip_address=ip_address,
                    reason="invalid_password",
                )
                return AuthResult(
                    status=AuthStatus.FAILED,
                    message="Invalid credentials",
                    error_code="AUTH_INVALID_CREDENTIALS",
                )

            # Reset failed attempts on successful password verification
            credentials.failed_attempts = 0
            credentials.locked_until = None

            # Check if MFA is required
            if credentials.mfa_enabled:
                mfa_challenge = await self._create_mfa_challenge(credentials)

                self._log_audit_event(
                    event="mfa_challenge_created",
                    username=username,
                    user_id=credentials.user_id,
                    ip_address=ip_address,
                    challenge_type=mfa_challenge.challenge_type.value,
                )

                return AuthResult(
                    status=AuthStatus.PENDING_MFA,
                    user_id=credentials.user_id,
                    mfa_required=True,
                    mfa_challenge=mfa_challenge,
                    message="MFA verification required",
                )

            # Generate tokens and create session
            access_token = self.jwt_handler.generate_token(
                user_id=credentials.user_id,
                token_type=TokenType.ACCESS,
                scope=scope or credentials.roles,
            )
            refresh_token = self.jwt_handler.generate_token(
                user_id=credentials.user_id,
                token_type=TokenType.REFRESH,
                scope=scope or credentials.roles,
                parent_token_id=access_token.token_id,
            )

            session = await self.session_manager.create_session(
                user_id=credentials.user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                device_fingerprint=device_fingerprint,
            )

            credentials.last_login = datetime.now(timezone.utc)

            self._log_audit_event(
                event="authentication_success",
                username=username,
                user_id=credentials.user_id,
                ip_address=ip_address,
                session_id=session.session_id,
            )

            return AuthResult(
                status=AuthStatus.SUCCESS,
                user_id=credentials.user_id,
                access_token=access_token,
                refresh_token=refresh_token,
                session_id=session.session_id,
                message="Authentication successful",
            )

    async def verify_mfa(
        self,
        user_id: str,
        challenge_id: str,
        code: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        scope: Optional[List[str]] = None,
    ) -> AuthResult:
        """Verify MFA challenge and complete authentication.

        Args:
            user_id: User identifier.
            challenge_id: MFA challenge identifier.
            code: MFA verification code.
            ip_address: Client IP address.
            user_agent: Client user agent.
            scope: Requested token scope.

        Returns:
            AuthResult with authentication outcome.
        """
        async with self._lock:
            challenge = self._mfa_challenges.get(challenge_id)

            if challenge is None:
                return AuthResult(
                    status=AuthStatus.FAILED,
                    message="Invalid MFA challenge",
                    error_code="MFA_INVALID_CHALLENGE",
                )

            if challenge.user_id != user_id:
                return AuthResult(
                    status=AuthStatus.FAILED,
                    message="Challenge does not belong to user",
                    error_code="MFA_USER_MISMATCH",
                )

            if challenge.is_expired():
                del self._mfa_challenges[challenge_id]
                return AuthResult(
                    status=AuthStatus.EXPIRED,
                    message="MFA challenge has expired",
                    error_code="MFA_CHALLENGE_EXPIRED",
                )

            if not challenge.can_attempt():
                del self._mfa_challenges[challenge_id]
                return AuthResult(
                    status=AuthStatus.FAILED,
                    message="Maximum MFA attempts exceeded",
                    error_code="MFA_MAX_ATTEMPTS",
                )

            challenge.attempts += 1

            # Verify code (simplified - in production, use proper TOTP validation)
            if challenge.code and not hmac.compare_digest(code, challenge.code):
                self._log_audit_event(
                    event="mfa_verification_failed",
                    user_id=user_id,
                    ip_address=ip_address,
                    challenge_type=challenge.challenge_type.value,
                )
                return AuthResult(
                    status=AuthStatus.FAILED,
                    message="Invalid MFA code",
                    error_code="MFA_INVALID_CODE",
                )

            challenge.verified = True
            del self._mfa_challenges[challenge_id]

            # Find user credentials
            credentials = None
            for cred in self._credential_store.values():
                if cred.user_id == user_id:
                    credentials = cred
                    break

            if credentials is None:
                return AuthResult(
                    status=AuthStatus.FAILED,
                    message="User not found",
                    error_code="AUTH_USER_NOT_FOUND",
                )

            # Generate tokens and create session
            access_token = self.jwt_handler.generate_token(
                user_id=user_id,
                token_type=TokenType.ACCESS,
                scope=scope or credentials.roles,
            )
            refresh_token = self.jwt_handler.generate_token(
                user_id=user_id,
                token_type=TokenType.REFRESH,
                scope=scope or credentials.roles,
                parent_token_id=access_token.token_id,
            )

            session = await self.session_manager.create_session(
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent,
            )
            session.mfa_verified = True

            credentials.last_login = datetime.now(timezone.utc)

            self._log_audit_event(
                event="mfa_verification_success",
                user_id=user_id,
                ip_address=ip_address,
                session_id=session.session_id,
            )

            return AuthResult(
                status=AuthStatus.SUCCESS,
                user_id=user_id,
                access_token=access_token,
                refresh_token=refresh_token,
                session_id=session.session_id,
                message="Authentication successful",
            )

    async def generate_token(
        self,
        user_id: str,
        token_type: TokenType = TokenType.ACCESS,
        scope: Optional[List[str]] = None,
    ) -> AuthToken:
        """Generate a token for a user.

        Args:
            user_id: User identifier.
            token_type: Type of token to generate.
            scope: Token scope.

        Returns:
            Generated AuthToken.
        """
        return self.jwt_handler.generate_token(
            user_id=user_id,
            token_type=token_type,
            scope=scope,
        )

    async def validate_token(self, token_value: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Validate a token.

        Args:
            token_value: Token string to validate.

        Returns:
            Tuple of (is_valid, payload_or_none).
        """
        return self.jwt_handler.validate_token(token_value)

    async def refresh_token(
        self, refresh_token_value: str, scope: Optional[List[str]] = None
    ) -> Optional[AuthToken]:
        """Refresh an access token.

        Args:
            refresh_token_value: Refresh token string.
            scope: New scope for the access token.

        Returns:
            New access token or None.
        """
        return self.jwt_handler.refresh_token(refresh_token_value, scope)

    async def revoke_session(self, session_id: str) -> bool:
        """Revoke a session.

        Args:
            session_id: Session identifier.

        Returns:
            True if session was revoked.
        """
        return await self.session_manager.revoke_session(session_id)

    async def revoke_all_sessions(self, user_id: str) -> int:
        """Revoke all sessions for a user.

        Args:
            user_id: User identifier.

        Returns:
            Number of sessions revoked.
        """
        return await self.session_manager.revoke_all_user_sessions(user_id)

    async def _create_mfa_challenge(
        self, credentials: UserCredentials
    ) -> MFAChallenge:
        """Create an MFA challenge for a user.

        Args:
            credentials: User credentials.

        Returns:
            Created MFAChallenge.
        """
        challenge_id = secrets.token_urlsafe(16)
        challenge_type = (
            credentials.mfa_challenge_types[0]
            if credentials.mfa_challenge_types
            else MFAChallengeType.TOTP
        )

        # Generate challenge code for SMS/Email
        code = None
        if challenge_type in (MFAChallengeType.SMS, MFAChallengeType.EMAIL):
            code = "".join(secrets.choice("0123456789") for _ in range(6))

        challenge = MFAChallenge(
            challenge_id=challenge_id,
            user_id=credentials.user_id,
            challenge_type=challenge_type,
            code=code,
            expires_at=datetime.now(timezone.utc) + self.mfa_timeout,
        )

        self._mfa_challenges[challenge_id] = challenge

        # In production, send SMS/Email here
        if code:
            logger.info(f"MFA code generated for user {credentials.user_id}: {code}")

        return challenge

    def _log_audit_event(
        self,
        event: str,
        username: Optional[str] = None,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Log an audit event.

        Args:
            event: Event type.
            username: Username (if applicable).
            user_id: User ID (if applicable).
            ip_address: Client IP address.
            **kwargs: Additional event details.
        """
        event_record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "username": username,
            "user_id": user_id,
            "ip_address": ip_address,
            **kwargs,
        }
        self._audit_log.append(event_record)
        logger.info(f"Audit event: {event} - user={username or user_id}")

    def get_audit_log(
        self,
        user_id: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get audit log entries.

        Args:
            user_id: Filter by user ID.
            event_type: Filter by event type.
            limit: Maximum number of entries to return.

        Returns:
            List of audit log entries.
        """
        entries = self._audit_log.copy()

        if user_id:
            entries = [e for e in entries if e.get("user_id") == user_id]

        if event_type:
            entries = [e for e in entries if e.get("event") == event_type]

        return entries[-limit:]
