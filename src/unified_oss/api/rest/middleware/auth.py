"""
Authentication Middleware for REST API.
"""

import time
from typing import Callable, Optional
from datetime import datetime, timedelta

from fastapi import Request, Response, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import structlog

from unified_oss.core.constants import ROLE_ADMIN, ROLE_OPERATOR, ROLE_ENGINEER, ROLE_VIEWER

logger = structlog.get_logger()


class RateLimitEntry:
    """Rate limit tracking entry."""
    
    def __init__(self, requests_per_minute: int):
        self.requests_per_minute = requests_per_minute
        self.requests: dict[str, list[float]] = {}
    
    def is_allowed(self, key: str) -> bool:
        """Check if request is allowed for key."""
        now = time.time()
        
        if key not in self.requests:
            self.requests[key] = []
        
        # Remove old requests
        self.requests[key] = [t for t in self.requests[key] if now - t < 60]
        
        if len(self.requests[key]) >= self.requests_per_minute:
            return False
        
        self.requests[key].append(now)
        return True


class AuthMiddleware(BaseHTTPMiddleware):
    """
    JWT authentication middleware.
    
    Validates JWT tokens on protected routes and extracts user context.
    """
    
    PUBLIC_PATHS = [
        "/health",
        "/ready",
        "/metrics",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/api/v1/security/authenticate",
    ]
    
    def __init__(
        self,
        app: ASGIApp,
        jwt_secret: str = "change-me-in-production",
        jwt_algorithm: str = "HS256",
        token_expiry_hours: int = 24,
    ):
        super().__init__(app)
        self.jwt_secret = jwt_secret
        self.jwt_algorithm = jwt_algorithm
        self.token_expiry_hours = token_expiry_hours
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request through authentication."""
        
        # Allow public paths
        if request.url.path in self.PUBLIC_PATHS:
            return await call_next(request)
        
        # Allow WebSocket upgrades
        if request.headers.get("upgrade", "").lower() == "websocket":
            return await call_next(request)
        
        # Extract token
        auth_header = request.headers.get("Authorization", "")
        
        if not auth_header.startswith("Bearer "):
            return Response(
                content='{"error": "Missing or invalid authorization header"}',
                status_code=401,
                media_type="application/json",
            )
        
        token = auth_header.replace("Bearer ", "")
        
        # Validate token (simplified - in production use proper JWT library)
        user_context = await self._validate_token(token)
        
        if not user_context:
            return Response(
                content='{"error": "Invalid or expired token"}',
                status_code=401,
                media_type="application/json",
            )
        
        # Add user context to request state
        request.state.user = user_context
        
        return await call_next(request)
    
    async def _validate_token(self, token: str) -> Optional[dict]:
        """Validate JWT token and return user context."""
        # Simplified validation - in production use jose or pyjwt
        try:
            # Mock validation for development
            if token == "test-token":
                return {
                    "user_id": "test-user",
                    "username": "test",
                    "roles": ["admin"],
                    "permissions": ["*"],
                    "exp": datetime.utcnow() + timedelta(hours=1),
                }
            
            # Production: validate JWT signature and claims
            return None
        except Exception as e:
            logger.error(f"Token validation failed: {e}")
            return None


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware.
    
    Limits requests per minute per client IP or user.
    """
    
    def __init__(
        self,
        app: ASGIApp,
        requests_per_minute: int = 100,
    ):
        super().__init__(app)
        self.rate_limiter = RateLimitEntry(requests_per_minute)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request with rate limiting."""
        
        # Get client identifier (IP or user ID)
        client_id = self._get_client_id(request)
        
        if not self.rate_limiter.is_allowed(client_id):
            return Response(
                content='{"error": "Rate limit exceeded", "retry_after": 60}',
                status_code=429,
                media_type="application/json",
                headers={"Retry-After": "60"},
            )
        
        return await call_next(request)
    
    def _get_client_id(self, request: Request) -> str:
        """Get client identifier for rate limiting."""
        # Use user ID if authenticated, otherwise IP
        if hasattr(request.state, "user"):
            return request.state.user.get("user_id", "anonymous")
        
        # Get real IP from headers (for reverse proxy)
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
        
        return request.client.host if request.client else "unknown"
