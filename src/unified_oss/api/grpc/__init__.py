"""
gRPC API Module for Unified OSS Framework.

This module provides gRPC services for the Unified OSS Framework,
implementing the FCAPS management services:

Services:
    - AlarmService: Fault management operations
    - PerformanceService: Performance monitoring and KPI management  
    - ConfigurationService: Configuration management and versioning
    - SecurityService: Security and access control management
    - AccountingService: License and capacity management

Example:
    >>> from unified_oss.api.grpc import GRPCServer, ServerConfig
    >>> from unified_oss.api.grpc.services import (
    ...     AlarmServiceServicer,
    ...     PerformanceServiceServicer,
    ... )
    >>>
    >>> config = ServerConfig(port=50051)
    >>> server = GRPCServer(config=config)
    >>> await server.start()
"""

from unified_oss.api.grpc.server import (
    GRPCServer,
    ServerConfig,
    ServerState,
    ServiceRegistry,
    create_and_run_server,
)
from unified_oss.api.grpc.services.alarm_service import AlarmServiceServicer
from unified_oss.api.grpc.services.performance_service import PerformanceServiceServicer
from unified_oss.api.grpc.services.config_service import ConfigurationServiceServicer
from unified_oss.api.grpc.services.security_service import (
    SecurityServiceServicer,
    AuthorizationManager,
)
from unified_oss.api.grpc.services.accounting_service import AccountingServiceServicer

__all__ = [
    # Server
    "GRPCServer",
    "ServerConfig",
    "ServerState",
    "ServiceRegistry",
    "create_and_run_server",
    # Services
    "AlarmServiceServicer",
    "PerformanceServiceServicer",
    "ConfigurationServiceServicer",
    "SecurityServiceServicer",
    "AuthorizationManager",
    "AccountingServiceServicer",
]

__version__ = "1.0.0"
