"""
Logging Middleware for REST API.
"""

import time
import uuid
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import structlog

logger = structlog.get_logger()


class LoggingMiddleware(BaseHTTPMiddleware):
    """
    Request/response logging middleware.
    
    Logs all incoming requests and outgoing responses with timing.
    """
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request with logging."""
        
        # Generate request ID
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        
        # Start timing
        start_time = time.time()
        
        # Log request
        logger.info(
            "request_started",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            query=str(request.query_params),
            client=request.client.host if request.client else None,
            user_agent=request.headers.get("User-Agent", ""),
        )
        
        # Add request ID to state
        request.state.request_id = request_id
        
        # Process request
        try:
            response = await call_next(request)
        except Exception as e:
            logger.exception(
                "request_failed",
                request_id=request_id,
                error=str(e),
            )
            raise
        
        # Calculate duration
        duration_ms = (time.time() - start_time) * 1000
        
        # Log response
        logger.info(
            "request_completed",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=round(duration_ms, 2),
        )
        
        # Add headers
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time"] = f"{duration_ms:.2f}ms"
        
        return response
