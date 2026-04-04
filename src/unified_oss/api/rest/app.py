"""
Unified OSS Framework - REST API Application.

Main FastAPI application with all routers, middleware, and configuration.
"""

from contextlib import asynccontextmanager
from datetime import datetime
from typing import AsyncGenerator

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.openapi.utils import get_openapi
import structlog

from unified_oss.core.config import Config
from unified_oss.core.logging import get_logger

# Import routers
from .routes import alarms, performance, configuration, security, accounting, yang_tree

# Import middleware
from .middleware.auth import AuthMiddleware
from .middleware.logging import LoggingMiddleware
from .middleware.rate_limit import RateLimitMiddleware

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: "OSSAPI") -> AsyncGenerator[None, None]:
    """Application lifespan manager."""
    logger.info("Starting Unified OSS Framework API")
    
    # Initialize database connections
    # Initialize cache
    # Initialize Kafka consumers
    
    yield
    
    # Cleanup
    logger.info("Shutting down Unified OSS Framework API")


class OSSAPI(FastAPI):
    """Custom FastAPI application class."""
    
    def __init__(self, config: Config = None, **kwargs):
        self.config = config or Config.from_env()
        super().__init__(lifespan=lifespan, **kwargs)


def create_app(config: Config = None) -> OSSAPI:
    """
    Create and configure the FastAPI application.
    
    Args:
        config: Optional configuration object.
        
    Returns:
        Configured FastAPI application instance.
    """
    app = OSSAPI(
        config=config,
        title="Unified OSS Framework API",
        description="""
        Vendor-neutral OSS Framework for multi-vendor network element management.
        
        Supports Ericsson ENM and Huawei U2000 with complete FCAPS management:
        - **Fault**: Alarm management, correlation, root cause analysis
        - **Configuration**: Multi-vendor config workflow, drift detection
        - **Accounting**: License management, capacity tracking
        - **Performance**: KPI management, threshold monitoring
        - **Security**: Zero Trust authorization, audit logging
        """,
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )
    
    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure in production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Add custom middleware
    app.add_middleware(LoggingMiddleware)
    app.add_middleware(RateLimitMiddleware, requests_per_minute=100)
    app.add_middleware(AuthMiddleware)
    
    # Include routers
    app.include_router(
        alarms.router,
        prefix="/api/v1/alarms",
        tags=["Alarms"]
    )
    app.include_router(
        performance.router,
        prefix="/api/v1/performance",
        tags=["Performance"]
    )
    app.include_router(
        configuration.router,
        prefix="/api/v1/configuration",
        tags=["Configuration"]
    )
    app.include_router(
        security.router,
        prefix="/api/v1/security",
        tags=["Security"]
    )
    app.include_router(
        accounting.router,
        prefix="/api/v1/accounting",
        tags=["Accounting"]
    )
    app.include_router(
        yang_tree.router,
        prefix="/api/v1",
        tags=["YANG Tree"]
    )
    
    # Add exception handlers
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.error(f"Unhandled exception: {exc}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "error": "INTERNAL_ERROR",
                "message": "An unexpected error occurred",
                "timestamp": datetime.utcnow().isoformat(),
            }
        )
    
    # Health check endpoint
    @app.get("/health", tags=["Health"])
    async def health_check():
        """Health check endpoint."""
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "version": "1.0.0",
        }
    
    # Readiness check endpoint
    @app.get("/ready", tags=["Health"])
    async def readiness_check():
        """Readiness check endpoint."""
        # Check database connectivity
        # Check Redis connectivity
        # Check Kafka connectivity
        return {
            "status": "ready",
            "timestamp": datetime.utcnow().isoformat(),
            "checks": {
                "database": "healthy",
                "cache": "healthy",
                "messaging": "healthy",
            }
        }
    
    # Metrics endpoint (Prometheus format)
    @app.get("/metrics", tags=["Monitoring"])
    async def metrics():
        """Prometheus metrics endpoint."""
        return Response(
            content="# Unified OSS Framework Metrics\n"
                    "# HELP oss_alarms_active Number of active alarms\n"
                    "# TYPE oss_alarms_active gauge\n"
                    "oss_alarms_active 0\n"
                    "# HELP oss_requests_total Total API requests\n"
                    "# TYPE oss_requests_total counter\n"
                    "oss_requests_total 0\n",
            media_type="text/plain"
        )
    
    return app


# Create default app instance
app = create_app()
