"""
Rate Limiting Middleware for REST API.
"""

import time
from typing import Callable
from collections import defaultdict
from threading import Lock

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp


class InMemoryRateLimiter:
    """Thread-safe in-memory rate limiter."""
    
    def __init__(self):
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()
    
    def is_allowed(self, key: str, max_requests: int, window_seconds: int = 60) -> bool:
        """Check if request is allowed."""
        with self._lock:
            now = time.time()
            cutoff = now - window_seconds
            
            # Clean old requests
            self._requests[key] = [t for t in self._requests[key] if t > cutoff]
            
            if len(self._requests[key]) >= max_requests:
                return False
            
            self._requests[key].append(now)
            return True
    
    def get_remaining(self, key: str, max_requests: int, window_seconds: int = 60) -> int:
        """Get remaining requests allowed."""
        with self._lock:
            now = time.time()
            cutoff = now - window_seconds
            
            self._requests[key] = [t for t in self._requests[key] if t > cutoff]
            
            return max(0, max_requests - len(self._requests[key]))


# Global rate limiter instance
rate_limiter = InMemoryRateLimiter()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware.
    
    Limits requests per minute per client IP or user.
    """
    
    PUBLIC_PATHS = [
        "/health",
        "/ready",
        "/metrics",
        "/docs",
        "/redoc",
        "/openapi.json",
    ]
    
    def __init__(
        self,
        app: ASGIApp,
        requests_per_minute: int = 100,
    ):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request with rate limiting."""
        
        # Skip public paths
        if request.url.path in self.PUBLIC_PATHS:
            return await call_next(request)
        
        # Get client identifier
        client_id = self._get_client_id(request)
        
        # Check rate limit
        if not rate_limiter.is_allowed(client_id, self.requests_per_minute, 60):
            remaining = rate_limiter.get_remaining(client_id, self.requests_per_minute, 60)
            
            return Response(
                content='{"error": "RATE_LIMIT_EXCEEDED", "message": "Too many requests"}',
                status_code=429,
                media_type="application/json",
                headers={
                    "X-RateLimit-Limit": str(self.requests_per_minute),
                    "X-RateLimit-Remaining": str(remaining),
                    "X-RateLimit-Reset": "60",
                    "Retry-After": "60",
                },
            )
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers
        remaining = rate_limiter.get_remaining(client_id, self.requests_per_minute, 60)
        response.headers["X-RateLimit-Limit"] = str(self.requests_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        
        return response
    
    def _get_client_id(self, request: Request) -> str:
        """Get client identifier for rate limiting."""
        # Use user ID if authenticated
        if hasattr(request.state, "user"):
            user_id = request.state.user.get("user_id")
            if user_id:
                return f"user:{user_id}"
        
        # Use IP address
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            ip = forwarded.split(",")[0].strip()
            return f"ip:{ip}"
        
        if request.client:
            return f"ip:{request.client.host}"
        
        return "ip:unknown"
