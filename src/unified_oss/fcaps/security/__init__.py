"""
Security Management Module for Unified OSS Framework.

This module provides comprehensive security management capabilities for the FCAPS
(Fault, Configuration, Accounting, Performance, Security) framework, implementing
OAuth 2.0 JWT authentication, Role-Based Access Control (RBAC), and Zero Trust
Architecture (NIST SP 800-207) for telecom network operations.

The module is organized into three main components:

1. **Authentication (auth.py)**: 
   - OAuth 2.0 JWT token generation with 5-minute expiry
   - Token validation and refresh mechanisms
   - Session management with activity tracking
   - Multi-Factor Authentication (MFA) support

2. **Authorization (authorization.py)**:
   - Role-Based Access Control (RBAC)
   - Permission and policy management
   - Resource-based permissions
   - Audit logging for access decisions

3. **Zero Trust (zero_trust.py)**:
   - Zero Trust Architecture (NIST SP 800-207)
   - Multi-factor anomaly scoring (time, location, behavior, resource)
   - Rule-based access control with priority ordering
   - Continuous verification capabilities

Example Usage:
    >>> from unified_oss.fcaps.security import AuthManager, JWTHandler
    >>> from unified_oss.fcaps.security import AuthorizationEngine
    >>> from unified_oss.fcaps.security import ZeroTrustEngine
    >>>
    >>> # Initialize authentication
    >>> jwt_handler = JWTHandler(secret_key="your-secret-key")
    >>> auth_manager = AuthManager(jwt_handler=jwt_handler)
    >>>
    >>> # Initialize authorization
    >>> authz_engine = AuthorizationEngine()
    >>> await authz_engine.grant_role("user123", "engineer")
    >>>
    >>> # Initialize Zero Trust
    >>> zta_engine = ZeroTrustEngine()
    >>> decision = await zta_engine.evaluate_access(
    ...     user_id="user123",
    ...     resource="router-01",
    ...     action="configure"
    ... )
"""

from unified_oss.fcaps.security.auth import (
    AuthManager,
    AuthResult,
    AuthStatus,
    AuthToken,
    JWTHandler,
    MFAChallenge,
    MFAChallengeType,
    Session,
    SessionManager,
    TokenType,
    UserCredentials,
)

from unified_oss.fcaps.security.authorization import (
    AccessDecision,
    ActionType,
    AuditEntry,
    AuthorizationEngine,
    Permission,
    PermissionEffect,
    Policy,
    PolicyCondition,
    ResourceType,
    Role,
)

from unified_oss.fcaps.security.zero_trust import (
    AccessDecision as ZTAccessDecision,
    AccessDecisionResult,
    AccessRule,
    AccessRulePriority,
    AnomalyScore,
    AnomalyScorer,
    AnomalyType,
    MFAChallenge as ZTMFAChallenge,
    TrustLevel,
    UserBehaviorProfile,
    ZeroTrustEngine,
)

__all__ = [
    # Authentication module
    "AuthManager",
    "AuthResult",
    "AuthStatus",
    "AuthToken",
    "JWTHandler",
    "MFAChallenge",
    "MFAChallengeType",
    "Session",
    "SessionManager",
    "TokenType",
    "UserCredentials",
    # Authorization module
    "AccessDecision",
    "ActionType",
    "AuditEntry",
    "AuthorizationEngine",
    "Permission",
    "PermissionEffect",
    "Policy",
    "PolicyCondition",
    "ResourceType",
    "Role",
    # Zero Trust module
    "ZTAccessDecision",
    "AccessDecisionResult",
    "AccessRule",
    "AccessRulePriority",
    "AnomalyScore",
    "AnomalyScorer",
    "AnomalyType",
    "ZTMFAChallenge",
    "TrustLevel",
    "UserBehaviorProfile",
    "ZeroTrustEngine",
]

__version__ = "1.0.0"
