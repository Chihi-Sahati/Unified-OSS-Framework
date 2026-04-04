"""
gRPC Server Module for Unified OSS Framework.

This module provides the core gRPC server implementation with async support,
reflection, health checking, TLS/mTLS support, and graceful shutdown.

Features:
    - Async gRPC server using grpcio aio
    - gRPC reflection support for service discovery
    - Health checking via gRPC health protocol
    - TLS/mTLS support for secure communications
    - Graceful shutdown with configurable timeout
    - Service registry for dynamic service registration

Example:
    >>> from unified_oss.api.grpc.server import GRPCServer
    >>> server = GRPCServer(port=50051)
    >>> await server.start()
    >>> # ... server is running ...
    >>> await server.stop()
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
    Type,
    TypeVar,
    Union,
)

# gRPC imports
try:
    import grpc
    from grpc import aio
    from grpc_reflection.v1alpha import reflection
    from grpc_health.v1 import health, health_pb2, health_pb2_grpc
    GRPC_AVAILABLE = True
except ImportError:
    GRPC_AVAILABLE = False
    grpc = None
    aio = None

logger = logging.getLogger(__name__)

# Type aliases
ServicerType = Any
ServiceAdderType = Callable[[Any, aio.Server], None]
T = TypeVar("T")


class ServerState(Enum):
    """Enumeration of gRPC server states.
    
    Attributes:
        INITIALIZED: Server has been initialized but not started.
        STARTING: Server is in the process of starting.
        RUNNING: Server is running and accepting connections.
        STOPPING: Server is in the process of shutting down.
        STOPPED: Server has been stopped.
        ERROR: Server encountered an error.
    """
    INITIALIZED = "initialized"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"


class HealthStatus(Enum):
    """Health check status values.
    
    Attributes:
        UNKNOWN: Health status is unknown.
        SERVING: Service is healthy and serving.
        NOT_SERVING: Service is not serving.
        SERVICE_UNKNOWN: Service is unknown.
    """
    UNKNOWN = health_pb2.HealthCheckResponse.UNKNOWN if GRPC_AVAILABLE else 0
    SERVING = health_pb2.HealthCheckResponse.SERVING if GRPC_AVAILABLE else 1
    NOT_SERVING = health_pb2.HealthCheckResponse.NOT_SERVING if GRPC_AVAILABLE else 2
    SERVICE_UNKNOWN = health_pb2.HealthCheckResponse.SERVICE_UNKNOWN if GRPC_AVAILABLE else 3


@dataclass
class ServerConfig:
    """Configuration for the gRPC server.
    
    Attributes:
        host: Server host address.
        port: Server port number.
        max_workers: Maximum worker threads.
        max_message_length: Maximum message size in bytes.
        max_receive_message_length: Maximum receive message size.
        max_send_message_length: Maximum send message size.
        keepalive_time_ms: Keepalive time in milliseconds.
        keepalive_timeout_ms: Keepalive timeout in milliseconds.
        keepalive_permit_without_calls: Allow keepalive without calls.
        http2_max_ping_strikes: Maximum HTTP/2 ping strikes.
        http2_min_recv_ping_interval_without_calls_ms: Minimum ping interval.
        graceful_shutdown_timeout_seconds: Graceful shutdown timeout.
        enable_reflection: Enable gRPC reflection.
        enable_health_check: Enable health checking.
        cert_file: Path to TLS certificate file.
        key_file: Path to TLS private key file.
        ca_file: Path to CA certificate file for mTLS.
        require_client_cert: Require client certificate (mTLS).
    """
    host: str = "0.0.0.0"
    port: int = 50051
    max_workers: int = 10
    max_message_length: int = 16 * 1024 * 1024  # 16 MB
    max_receive_message_length: int = 16 * 1024 * 1024
    max_send_message_length: int = 16 * 1024 * 1024
    keepalive_time_ms: int = 30000
    keepalive_timeout_ms: int = 10000
    keepalive_permit_without_calls: bool = False
    http2_max_ping_strikes: int = 2
    http2_min_recv_ping_interval_without_calls_ms: int = 300000
    graceful_shutdown_timeout_seconds: int = 30
    enable_reflection: bool = True
    enable_health_check: bool = True
    cert_file: Optional[str] = None
    key_file: Optional[str] = None
    ca_file: Optional[str] = None
    require_client_cert: bool = False

    @property
    def address(self) -> str:
        """Get the server address string.
        
        Returns:
            Server address in host:port format.
        """
        return f"{self.host}:{self.port}"

    @property
    def is_tls_enabled(self) -> bool:
        """Check if TLS is enabled.
        
        Returns:
            True if both cert_file and key_file are set.
        """
        return self.cert_file is not None and self.key_file is not None

    @property
    def is_mtls_enabled(self) -> bool:
        """Check if mTLS is enabled.
        
        Returns:
            True if TLS is enabled with client cert requirement.
        """
        return self.is_tls_enabled and self.require_client_cert and self.ca_file is not None


@dataclass
class ServiceRegistration:
    """Registration information for a gRPC service.
    
    Attributes:
        service_name: Fully qualified service name.
        servicer: The servicer instance.
        adder: Function to add servicer to server.
        description: Human-readable service description.
        registered_at: Registration timestamp.
        health_status: Current health status.
    """
    service_name: str
    servicer: ServicerType
    adder: ServiceAdderType
    description: str = ""
    registered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    health_status: HealthStatus = HealthStatus.SERVING


class ServiceRegistry:
    """Registry for gRPC services.
    
    Provides centralized management of service registrations,
    health status tracking, and service discovery.
    
    Attributes:
        services: Dictionary of registered services.
    
    Example:
        >>> registry = ServiceRegistry()
        >>> registry.register(
        ...     service_name="unified_oss.v1.AlarmService",
        ...     servicer=alarm_servicer,
        ...     adder=add_AlarmServiceServicer_to_server
        ... )
    """

    def __init__(self) -> None:
        """Initialize the service registry."""
        self._services: Dict[str, ServiceRegistration] = {}
        self._lock = asyncio.Lock()
        logger.info("ServiceRegistry initialized")

    @property
    def services(self) -> Dict[str, ServiceRegistration]:
        """Get all registered services.
        
        Returns:
            Dictionary of service name to registration.
        """
        return self._services.copy()

    @property
    def service_names(self) -> List[str]:
        """Get all registered service names.
        
        Returns:
            List of service names.
        """
        return list(self._services.keys())

    def register(
        self,
        service_name: str,
        servicer: ServicerType,
        adder: ServiceAdderType,
        description: str = "",
    ) -> ServiceRegistration:
        """Register a gRPC service.
        
        Args:
            service_name: Fully qualified service name.
            servicer: The servicer instance.
            adder: Function to add servicer to server.
            description: Human-readable service description.
            
        Returns:
            The created service registration.
            
        Raises:
            ValueError: If service_name is already registered.
        """
        if service_name in self._services:
            raise ValueError(f"Service '{service_name}' is already registered")

        registration = ServiceRegistration(
            service_name=service_name,
            servicer=servicer,
            adder=adder,
            description=description,
            health_status=HealthStatus.SERVING,
        )

        self._services[service_name] = registration
        logger.info(f"Registered service: {service_name}")
        return registration

    def unregister(self, service_name: str) -> bool:
        """Unregister a gRPC service.
        
        Args:
            service_name: Service name to unregister.
            
        Returns:
            True if service was unregistered, False if not found.
        """
        if service_name in self._services:
            del self._services[service_name]
            logger.info(f"Unregistered service: {service_name}")
            return True
        return False

    def get_service(self, service_name: str) -> Optional[ServiceRegistration]:
        """Get a service registration by name.
        
        Args:
            service_name: Service name to look up.
            
        Returns:
            Service registration or None if not found.
        """
        return self._services.get(service_name)

    def update_health_status(
        self,
        service_name: str,
        status: HealthStatus,
    ) -> bool:
        """Update health status for a service.
        
        Args:
            service_name: Service name to update.
            status: New health status.
            
        Returns:
            True if status was updated, False if service not found.
        """
        registration = self._services.get(service_name)
        if registration:
            registration.health_status = status
            logger.debug(f"Updated health status for {service_name}: {status.name}")
            return True
        return False

    def get_all_health_status(self) -> Dict[str, HealthStatus]:
        """Get health status for all services.
        
        Returns:
            Dictionary of service name to health status.
        """
        return {
            name: reg.health_status
            for name, reg in self._services.items()
        }

    def clear(self) -> None:
        """Clear all service registrations."""
        self._services.clear()
        logger.info("Cleared all service registrations")


class GRPCServer:
    """Async gRPC server with reflection and health checking.
    
    Provides a production-ready gRPC server implementation with:
    - Async support using grpcio aio
    - gRPC reflection for service discovery
    - Health checking via gRPC health protocol
    - TLS/mTLS support for secure communications
    - Graceful shutdown with configurable timeout
    - Signal handling for SIGTERM/SIGINT
    
    Attributes:
        config: Server configuration.
        registry: Service registry.
        state: Current server state.
        server: The underlying aio server.
    
    Example:
        >>> config = ServerConfig(port=50051, enable_reflection=True)
        >>> server = GRPCServer(config=config)
        >>> server.register_service(
        ...     service_name="unified_oss.v1.AlarmService",
        ...     servicer=AlarmServiceServicer(),
        ...     adder=add_AlarmServiceServicer_to_server
        ... )
        >>> await server.start()
        >>> # Server is running...
        >>> await server.stop()
    """

    def __init__(
        self,
        config: Optional[ServerConfig] = None,
        registry: Optional[ServiceRegistry] = None,
    ) -> None:
        """Initialize the gRPC server.
        
        Args:
            config: Server configuration. Uses defaults if not provided.
            registry: Service registry. Creates new instance if not provided.
        """
        if not GRPC_AVAILABLE:
            raise RuntimeError(
                "gRPC is not available. Install grpcio, grpcio-tools, "
                "grpcio-reflection, and grpcio-health-checking packages."
            )

        self.config = config or ServerConfig()
        self.registry = registry or ServiceRegistry()
        self._server: Optional[aio.Server] = None
        self._health_servicer: Optional[health.HealthServicer] = None
        self._state = ServerState.INITIALIZED
        self._shutdown_event = asyncio.Event()
        self._startup_complete = asyncio.Event()

        # Setup signal handlers
        self._setup_signal_handlers()

        logger.info(
            f"GRPCServer initialized on {self.config.address} "
            f"(TLS: {self.config.is_tls_enabled}, "
            f"mTLS: {self.config.is_mtls_enabled})"
        )

    @property
    def state(self) -> ServerState:
        """Get the current server state.
        
        Returns:
            Current server state enum value.
        """
        return self._state

    @property
    def is_running(self) -> bool:
        """Check if the server is running.
        
        Returns:
            True if server is in RUNNING state.
        """
        return self._state == ServerState.RUNNING

    def _setup_signal_handlers(self) -> None:
        """Setup signal handlers for graceful shutdown."""
        loop = asyncio.get_event_loop()
        
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(
                    sig,
                    lambda s=sig: asyncio.create_task(self._handle_signal(s))
                )
            except NotImplementedError:
                # Windows doesn't support add_signal_handler
                signal.signal(sig, self._sync_handle_signal)

    def _sync_handle_signal(self, signum: int, frame: Any) -> None:
        """Handle signal synchronously (for Windows compatibility).
        
        Args:
            signum: Signal number.
            frame: Current stack frame.
        """
        logger.info(f"Received signal {signum}, initiating shutdown")
        asyncio.create_task(self.stop())

    async def _handle_signal(self, signum: signal.Signals) -> None:
        """Handle signal asynchronously.
        
        Args:
            signum: Signal enum value.
        """
        logger.info(f"Received signal {signum.name}, initiating shutdown")
        await self.stop()

    def _create_server_options(self) -> List[Tuple[str, Any]]:
        """Create gRPC server options.
        
        Returns:
            List of option tuples for server configuration.
        """
        options = [
            ("grpc.max_receive_message_length", self.config.max_receive_message_length),
            ("grpc.max_send_message_length", self.config.max_send_message_length),
            ("grpc.keepalive_time_ms", self.config.keepalive_time_ms),
            ("grpc.keepalive_timeout_ms", self.config.keepalive_timeout_ms),
            ("grpc.keepalive_permit_without_calls", self.config.keepalive_permit_without_calls),
            ("grpc.http2.max_ping_strikes", self.config.http2_max_ping_strikes),
            (
                "grpc.http2.min_recv_ping_interval_without_calls_ms",
                self.config.http2_min_recv_ping_interval_without_calls_ms,
            ),
        ]
        return options

    def _create_server_credentials(self) -> Optional[aio.ServerCredentials]:
        """Create server credentials for TLS/mTLS.
        
        Returns:
            ServerCredentials if TLS is enabled, None otherwise.
        """
        if not self.config.is_tls_enabled:
            return None

        # Load certificate and key
        with open(self.config.cert_file, "rb") as f:
            certificate_chain = f.read()
        with open(self.config.key_file, "rb") as f:
            private_key = f.read()

        if self.config.is_mtls_enabled:
            # mTLS: require and verify client certificate
            with open(self.config.ca_file, "rb") as f:
                root_certificates = f.read()

            return aio.ssl_server_credentials(
                (private_key, certificate_chain),
                root_certificates=root_certificates,
                require_client_auth=True,
            )
        else:
            # TLS only
            return aio.ssl_server_credentials(
                (private_key, certificate_chain)
            )

    def register_service(
        self,
        service_name: str,
        servicer: ServicerType,
        adder: ServiceAdderType,
        description: str = "",
    ) -> ServiceRegistration:
        """Register a gRPC service with the server.
        
        Args:
            service_name: Fully qualified service name.
            servicer: The servicer instance.
            adder: Function to add servicer to server.
            description: Human-readable service description.
            
        Returns:
            The created service registration.
            
        Raises:
            RuntimeError: If server is already running.
            ValueError: If service_name is already registered.
        """
        if self._state == ServerState.RUNNING:
            raise RuntimeError("Cannot register service while server is running")

        return self.registry.register(
            service_name=service_name,
            servicer=servicer,
            adder=adder,
            description=description,
        )

    async def start(self) -> None:
        """Start the gRPC server.
        
        Creates the server, registers all services, configures TLS,
        and starts listening for connections.
        
        Raises:
            RuntimeError: If server fails to start.
        """
        if self._state == ServerState.RUNNING:
            logger.warning("Server is already running")
            return

        try:
            self._state = ServerState.STARTING
            logger.info("Starting gRPC server...")

            # Create the server
            self._server = aio.server(options=self._create_server_options())

            # Register services from registry
            for registration in self.registry.services.values():
                registration.adder(registration.servicer, self._server)
                logger.debug(f"Added service: {registration.service_name}")

            # Setup health checking
            if self.config.enable_health_check:
                self._setup_health_check()

            # Setup reflection
            if self.config.enable_reflection:
                self._setup_reflection()

            # Configure credentials
            credentials = self._create_server_credentials()

            # Add insecure or secure port
            if credentials:
                self._server.add_secure_port(self.config.address, credentials)
                logger.info(f"TLS enabled on {self.config.address}")
            else:
                self._server.add_insecure_port(self.config.address)
                logger.info(f"Server listening on {self.config.address} (insecure)")

            # Start the server
            await self._server.start()
            self._state = ServerState.RUNNING
            self._startup_complete.set()

            logger.info(
                f"gRPC server started successfully on {self.config.address} "
                f"with {len(self.registry.services)} service(s)"
            )

        except Exception as e:
            self._state = ServerState.ERROR
            logger.error(f"Failed to start gRPC server: {e}")
            raise RuntimeError(f"Failed to start gRPC server: {e}") from e

    def _setup_health_check(self) -> None:
        """Setup gRPC health checking service."""
        if not GRPC_AVAILABLE:
            return

        self._health_servicer = health.HealthServicer()
        health_pb2_grpc.add_HealthServicer_to_server(
            self._health_servicer, self._server
        )

        # Set health status for all services
        for service_name in self.registry.service_names:
            self._health_servicer.set(
                service_name,
                health_pb2.HealthCheckResponse.SERVING,
            )

        # Set overall server health
        self._health_servicer.set(
            "",
            health_pb2.HealthCheckResponse.SERVING,
        )

        logger.info("Health checking service enabled")

    def _setup_reflection(self) -> None:
        """Setup gRPC reflection service."""
        if not GRPC_AVAILABLE:
            return

        # Get all service names including reflection and health
        service_names = list(self.registry.service_names)

        # Add reflection service
        reflection.enable_server_reflection(service_names, self._server)
        logger.info("Reflection service enabled")

    async def stop(self, grace: Optional[float] = None) -> None:
        """Stop the gRPC server gracefully.
        
        Args:
            grace: Grace period in seconds for pending RPCs to complete.
                   Uses config value if not provided.
        """
        if self._state not in (ServerState.RUNNING, ServerState.STARTING):
            logger.warning("Server is not running")
            return

        try:
            self._state = ServerState.STOPPING
            grace_period = grace or self.config.graceful_shutdown_timeout_seconds

            logger.info(
                f"Stopping gRPC server with {grace_period}s grace period..."
            )

            # Set health status to not serving
            if self._health_servicer:
                for service_name in self.registry.service_names:
                    self._health_servicer.set(
                        service_name,
                        health_pb2.HealthCheckResponse.NOT_SERVING,
                    )
                self._health_servicer.set(
                    "",
                    health_pb2.HealthCheckResponse.NOT_SERVING,
                )

            # Stop the server
            if self._server:
                await self._server.stop(grace_period)

            self._state = ServerState.STOPPED
            self._shutdown_event.set()

            logger.info("gRPC server stopped successfully")

        except Exception as e:
            self._state = ServerState.ERROR
            logger.error(f"Error stopping gRPC server: {e}")

    async def wait_for_termination(self, timeout: Optional[float] = None) -> bool:
        """Wait for server termination.
        
        Args:
            timeout: Maximum time to wait in seconds.
            
        Returns:
            True if server terminated, False if timeout expired.
        """
        try:
            await asyncio.wait_for(
                self._shutdown_event.wait(),
                timeout=timeout
            )
            return True
        except asyncio.TimeoutError:
            return False

    async def wait_for_startup(self, timeout: float = 10.0) -> bool:
        """Wait for server startup to complete.
        
        Args:
            timeout: Maximum time to wait in seconds.
            
        Returns:
            True if startup completed, False if timeout expired.
        """
        try:
            await asyncio.wait_for(
                self._startup_complete.wait(),
                timeout=timeout
            )
            return True
        except asyncio.TimeoutError:
            return False

    def set_service_health(
        self,
        service_name: str,
        status: HealthStatus,
    ) -> bool:
        """Set health status for a service.
        
        Args:
            service_name: Service name to update.
            status: New health status.
            
        Returns:
            True if status was updated, False if service not found.
        """
        if not self._health_servicer:
            logger.warning("Health checking not enabled")
            return False

        grpc_status = {
            HealthStatus.UNKNOWN: health_pb2.HealthCheckResponse.UNKNOWN,
            HealthStatus.SERVING: health_pb2.HealthCheckResponse.SERVING,
            HealthStatus.NOT_SERVING: health_pb2.HealthCheckResponse.NOT_SERVING,
        }.get(status, health_pb2.HealthCheckResponse.UNKNOWN)

        self._health_servicer.set(service_name, grpc_status)
        return self.registry.update_health_status(service_name, status)

    def get_stats(self) -> Dict[str, Any]:
        """Get server statistics.
        
        Returns:
            Dictionary containing server statistics.
        """
        return {
            "state": self._state.value,
            "address": self.config.address,
            "tls_enabled": self.config.is_tls_enabled,
            "mtls_enabled": self.config.is_mtls_enabled,
            "services_count": len(self.registry.services),
            "services": self.registry.service_names,
            "health_status": {
                name: status.name
                for name, status in self.registry.get_all_health_status().items()
            },
            "uptime_seconds": self._get_uptime_seconds(),
        }

    def _get_uptime_seconds(self) -> Optional[float]:
        """Calculate server uptime in seconds.
        
        Returns:
            Uptime in seconds or None if not running.
        """
        # This is a simplified implementation
        # In production, you'd track actual start time
        if self._state == ServerState.RUNNING:
            return 0.0  # Placeholder
        return None


async def create_and_run_server(
    config: Optional[ServerConfig] = None,
    services: Optional[List[Dict[str, Any]]] = None,
) -> GRPCServer:
    """Create and start a gRPC server with the given configuration.
    
    Convenience function for quickly creating and starting a server.
    
    Args:
        config: Server configuration.
        services: List of service registration dictionaries with keys:
                  - service_name: str
                  - servicer: servicer instance
                  - adder: adder function
                  - description: optional description
    
    Returns:
        The started GRPCServer instance.
        
    Example:
        >>> server = await create_and_run_server(
        ...     config=ServerConfig(port=50051),
        ...     services=[{
        ...         "service_name": "unified_oss.v1.AlarmService",
        ...         "servicer": AlarmServiceServicer(),
        ...         "adder": add_AlarmServiceServicer_to_server
        ...     }]
        ... )
    """
    server = GRPCServer(config=config)

    if services:
        for svc in services:
            server.register_service(
                service_name=svc["service_name"],
                servicer=svc["servicer"],
                adder=svc["adder"],
                description=svc.get("description", ""),
            )

    await server.start()
    return server
