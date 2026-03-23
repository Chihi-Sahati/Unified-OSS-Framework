"""
NETCONF Adapter Module for Unified OSS Framework.

This module provides NETCONF client functionality with connection pooling,
workflow management, and vendor-specific adaptations for network device
configuration management.

Features:
    - Session pooling with configurable size
    - Health checking and auto-reconnect simulation
    - RPC wrappers (edit-config, validate, commit, confirmed-commit)
    - Candidate datastore workflow
    - Confirmed-commit with timeout handling
    - Automatic rollback on failure
    - Transaction audit logging

Libraries:
    asyncio, dataclasses, typing, logging, hashlib, datetime, xml.etree.ElementTree

Author: Unified OSS Framework Team
Version: 1.0.0
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from xml.etree import ElementTree as ET

# Configure module logger
logger = logging.getLogger(__name__)


# =============================================================================
# Enums and Constants
# =============================================================================


class DatastoreType(Enum):
    """NETCONF datastore types."""
    RUNNING = "running"
    CANDIDATE = "candidate"
    STARTUP = "startup"


class VendorType(Enum):
    """Supported vendor types for NETCONF adaptations."""
    ERICSSON = "ericsson"
    HUAWEI = "huawei"
    GENERIC = "generic"


class SessionState(Enum):
    """NETCONF session states."""
    IDLE = "idle"
    ACTIVE = "active"
    LOCKED = "locked"
    ERROR = "error"
    DISCONNECTED = "disconnected"


class CommitState(Enum):
    """Commit operation states."""
    PENDING = "pending"
    CONFIRMED = "confirmed"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"


# =============================================================================
# Dataclasses
# =============================================================================


@dataclass
class NetconfConfig:
    """Configuration for NETCONF connection.

    Attributes:
        host: Device hostname or IP address.
        port: NETCONF port (default 830).
        username: Authentication username.
        password: Authentication password.
        timeout: Connection timeout in seconds.
        pool_size: Maximum session pool size.
        health_check_interval: Interval for health checks in seconds.
        reconnect_attempts: Maximum reconnect attempts.
        vendor: Vendor type for adaptations.
    """
    host: str
    port: int = 830
    username: str = "admin"
    password: str = ""
    timeout: int = 30
    pool_size: int = 5
    health_check_interval: int = 60
    reconnect_attempts: int = 3
    vendor: VendorType = VendorType.GENERIC

    def __post_init__(self) -> None:
        """Validate configuration after initialization."""
        if not self.host:
            raise ValueError("Host is required")
        if self.port <= 0 or self.port > 65535:
            raise ValueError(f"Invalid port: {self.port}")
        if self.timeout <= 0:
            raise ValueError(f"Invalid timeout: {self.timeout}")
        if self.pool_size <= 0:
            raise ValueError(f"Invalid pool size: {self.pool_size}")


@dataclass
class NetconfSession:
    """Represents a NETCONF session.

    Attributes:
        session_id: Unique session identifier.
        device_id: Device identifier.
        state: Current session state.
        created_at: Session creation timestamp.
        last_activity: Last activity timestamp.
        lock_holder: Transaction ID holding the lock.
    """
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str = ""
    state: SessionState = SessionState.IDLE
    created_at: datetime = field(default_factory=datetime.now)
    last_activity: datetime = field(default_factory=datetime.now)
    lock_holder: Optional[str] = None

    def touch(self) -> None:
        """Update last activity timestamp."""
        self.last_activity = datetime.now()


@dataclass
class AuditLogEntry:
    """Audit log entry for transactions.

    Attributes:
        transaction_id: Unique transaction identifier.
        operation: Operation type.
        datastore: Target datastore.
        config_hash: Hash of configuration content.
        timestamp: Operation timestamp.
        status: Operation status.
        details: Additional details.
    """
    transaction_id: str
    operation: str
    datastore: str
    config_hash: str
    timestamp: datetime = field(default_factory=datetime.now)
    status: str = "pending"
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RpcResult:
    """Result of a NETCONF RPC operation.

    Attributes:
        success: Whether operation succeeded.
        message: Result message.
        data: Returned data (if any).
        error_info: Error information (if failed).
        elapsed_time: Operation duration in seconds.
    """
    success: bool
    message: str
    data: Optional[str] = None
    error_info: Optional[Dict[str, Any]] = None
    elapsed_time: float = 0.0


# =============================================================================
# Exceptions
# =============================================================================


class NetconfError(Exception):
    """Base exception for NETCONF operations."""

    def __init__(self, message: str, rpc_error: Optional[Dict[str, Any]] = None) -> None:
        """Initialize NETCONF error.

        Args:
            message: Error message.
            rpc_error: RPC error information if available.
        """
        super().__init__(message)
        self.rpc_error = rpc_error or {}


class SessionTimeoutError(NetconfError):
    """Exception for session timeout."""
    pass


class LockContentionError(NetconfError):
    """Exception for lock contention."""
    pass


class ValidationFailedError(NetconfError):
    """Exception for validation failures."""
    pass


class CommitFailedError(NetconfError):
    """Exception for commit failures."""
    pass


# =============================================================================
# XML Message Builder
# =============================================================================


class XmlMessageBuilder:
    """Builder for NETCONF XML messages."""

    NETCONF_NS = "urn:ietf:params:xml:ns:netconf:base:1.0"
    NETCONF_PREFIX = "nc"

    @classmethod
    def create_rpc(cls, message_id: Optional[str] = None) -> ET.Element:
        """Create base RPC element.

        Args:
            message_id: Optional message ID.

        Returns:
            RPC element.
        """
        if message_id is None:
            message_id = str(uuid.uuid4())
        
        rpc = ET.Element(f"{{{cls.NETCONF_NS}}}rpc")
        rpc.set("message-id", message_id)
        return rpc

    @classmethod
    def build_get_config(
        cls,
        datastore: DatastoreType,
        filter_xml: Optional[str] = None
    ) -> str:
        """Build get-config RPC.

        Args:
            datastore: Target datastore.
            filter_xml: Optional filter XML.

        Returns:
            XML string.
        """
        rpc = cls.create_rpc()
        get_config = ET.SubElement(rpc, "get-config")
        source = ET.SubElement(get_config, "source")
        ET.SubElement(source, datastore.value)
        
        if filter_xml:
            filter_elem = ET.SubElement(get_config, "filter")
            filter_elem.set("type", "subtree")
            try:
                filter_content = ET.fromstring(filter_xml)
                filter_elem.append(filter_content)
            except ET.ParseError:
                filter_elem.text = filter_xml
        
        return cls._to_string(rpc)

    @classmethod
    def build_edit_config(
        cls,
        datastore: DatastoreType,
        config: str,
        operation: str = "merge",
        test_option: Optional[str] = None,
        error_option: Optional[str] = None
    ) -> str:
        """Build edit-config RPC.

        Args:
            datastore: Target datastore.
            config: Configuration XML.
            operation: Default operation (merge, replace, none).
            test_option: Test option (test-then-set, set, test-only).
            error_option: Error option (stop-on-error, continue-on-error).

        Returns:
            XML string.
        """
        rpc = cls.create_rpc()
        edit_config = ET.SubElement(rpc, "edit-config")
        
        target = ET.SubElement(edit_config, "target")
        ET.SubElement(target, datastore.value)
        
        if operation:
            default_op = ET.SubElement(edit_config, "default-operation")
            default_op.text = operation
        
        if test_option:
            test_op = ET.SubElement(edit_config, "test-option")
            test_op.text = test_option
        
        if error_option:
            err_op = ET.SubElement(edit_config, "error-option")
            err_op.text = error_option
        
        config_elem = ET.SubElement(edit_config, "config")
        try:
            config_content = ET.fromstring(config)
            config_elem.append(config_content)
        except ET.ParseError:
            config_elem.text = config
        
        return cls._to_string(rpc)

    @classmethod
    def build_lock(cls, datastore: DatastoreType) -> str:
        """Build lock RPC.

        Args:
            datastore: Target datastore.

        Returns:
            XML string.
        """
        rpc = cls.create_rpc()
        lock = ET.SubElement(rpc, "lock")
        target = ET.SubElement(lock, "target")
        ET.SubElement(target, datastore.value)
        return cls._to_string(rpc)

    @classmethod
    def build_unlock(cls, datastore: DatastoreType) -> str:
        """Build unlock RPC.

        Args:
            datastore: Target datastore.

        Returns:
            XML string.
        """
        rpc = cls.create_rpc()
        unlock = ET.SubElement(rpc, "unlock")
        target = ET.SubElement(unlock, "target")
        ET.SubElement(target, datastore.value)
        return cls._to_string(rpc)

    @classmethod
    def build_validate(cls, datastore: DatastoreType) -> str:
        """Build validate RPC.

        Args:
            datastore: Target datastore.

        Returns:
            XML string.
        """
        rpc = cls.create_rpc()
        validate = ET.SubElement(rpc, "validate")
        source = ET.SubElement(validate, "source")
        ET.SubElement(source, datastore.value)
        return cls._to_string(rpc)

    @classmethod
    def build_commit(
        cls,
        confirmed: bool = False,
        confirm_timeout: Optional[int] = None,
        persist: Optional[str] = None
    ) -> str:
        """Build commit RPC.

        Args:
            confirmed: Whether this is a confirmed commit.
            confirm_timeout: Timeout in seconds for confirmation.
            persist: Persistent identifier for the commit.

        Returns:
            XML string.
        """
        rpc = cls.create_rpc()
        commit = ET.SubElement(rpc, "commit")
        
        if confirmed:
            confirmed_elem = ET.SubElement(commit, "confirmed")
            if confirm_timeout is not None:
                timeout_elem = ET.SubElement(commit, "confirm-timeout")
                timeout_elem.text = str(confirm_timeout)
        
        if persist:
            persist_elem = ET.SubElement(commit, "persist")
            persist_elem.text = persist
        
        return cls._to_string(rpc)

    @classmethod
    def build_cancel_commit(cls, persist_id: Optional[str] = None) -> str:
        """Build cancel-commit RPC.

        Args:
            persist_id: Persistent identifier to cancel.

        Returns:
            XML string.
        """
        rpc = cls.create_rpc()
        cancel = ET.SubElement(rpc, "cancel-commit")
        
        if persist_id:
            persist_elem = ET.SubElement(cancel, "persist-id")
            persist_elem.text = persist_id
        
        return cls._to_string(rpc)

    @classmethod
    def build_discard_changes(cls) -> str:
        """Build discard-changes RPC.

        Returns:
            XML string.
        """
        rpc = cls.create_rpc()
        ET.SubElement(rpc, "discard-changes")
        return cls._to_string(rpc)

    @classmethod
    def _to_string(cls, element: ET.Element) -> str:
        """Convert element to XML string.

        Args:
            element: XML element.

        Returns:
            XML string representation.
        """
        return ET.tostring(element, encoding="unicode", xml_declaration=True)


# =============================================================================
# NetconfSessionPool
# =============================================================================


class NetconfSessionPool:
    """Connection pool for NETCONF sessions.

    This class manages a pool of NETCONF sessions with context manager
    support, health checking, and automatic reconnection.

    Attributes:
        config: NETCONF configuration.
        sessions: Pool of sessions.
        available: Available session queue.

    Example:
        >>> config = NetconfConfig(host="192.168.1.1")
        >>> pool = NetconfSessionPool(config)
        >>> await pool.initialize()
        >>> async with pool.get_session() as session:
        ...     # Use session
        ...     pass
    """

    def __init__(self, config: NetconfConfig) -> None:
        """Initialize session pool.

        Args:
            config: NETCONF configuration.
        """
        self.config = config
        self._sessions: Dict[str, NetconfSession] = {}
        self._available: asyncio.Queue[str] = asyncio.Queue()
        self._lock = asyncio.Lock()
        self._initialized = False
        self._health_task: Optional[asyncio.Task[None]] = None
        self._device_id = f"{config.host}:{config.port}"

    async def initialize(self) -> None:
        """Initialize the session pool.

        Creates the configured number of sessions and starts health
        checking.
        """
        async with self._lock:
            if self._initialized:
                logger.warning("Session pool already initialized")
                return
            
            logger.info(
                f"Initializing NETCONF session pool for {self._device_id} "
                f"with size {self.config.pool_size}"
            )
            
            for i in range(self.config.pool_size):
                session = NetconfSession(
                    device_id=self._device_id,
                    state=SessionState.IDLE
                )
                self._sessions[session.session_id] = session
                await self._available.put(session.session_id)
                logger.debug(f"Created session {session.session_id[:8]}...")
            
            self._initialized = True
            
            # Start health check task
            self._health_task = asyncio.create_task(self._health_check_loop())
            
            logger.info(f"Session pool initialized with {len(self._sessions)} sessions")

    async def close(self) -> None:
        """Close all sessions and cleanup resources."""
        async with self._lock:
            logger.info("Closing NETCONF session pool")
            
            # Cancel health check task
            if self._health_task:
                self._health_task.cancel()
                try:
                    await self._health_task
                except asyncio.CancelledError:
                    pass
                self._health_task = None
            
            # Mark all sessions as disconnected
            for session in self._sessions.values():
                session.state = SessionState.DISCONNECTED
            
            self._sessions.clear()
            
            # Clear the queue
            while not self._available.empty():
                try:
                    self._available.get_nowait()
                except asyncio.QueueEmpty:
                    break
            
            self._initialized = False
            logger.info("Session pool closed")

    async def get_session(self, timeout: Optional[float] = None) -> NetconfSessionContext:
        """Get an available session from the pool.

        Args:
            timeout: Maximum time to wait for a session.

        Returns:
            Session context manager.

        Raises:
            SessionTimeoutError: If no session available within timeout.
        """
        if not self._initialized:
            raise NetconfError("Session pool not initialized")
        
        timeout = timeout or self.config.timeout
        
        try:
            session_id = await asyncio.wait_for(
                self._available.get(),
                timeout=timeout
            )
        except asyncio.TimeoutError as exc:
            raise SessionTimeoutError(
                f"No session available within {timeout} seconds"
            ) from exc
        
        session = self._sessions.get(session_id)
        if not session:
            raise NetconfError(f"Session {session_id} not found in pool")
        
        session.state = SessionState.ACTIVE
        session.touch()
        
        logger.debug(f"Session {session_id[:8]}... acquired from pool")
        
        return NetconfSessionContext(self, session)

    def return_session(self, session: NetconfSession) -> None:
        """Return a session to the pool.

        Args:
            session: Session to return.
        """
        session.state = SessionState.IDLE
        session.touch()
        
        # Put session back in available queue
        if session.session_id in self._sessions:
            self._available.put_nowait(session.session_id)
            logger.debug(f"Session {session.session_id[:8]}... returned to pool")

    async def _health_check_loop(self) -> None:
        """Periodic health check for sessions."""
        while True:
            try:
                await asyncio.sleep(self.config.health_check_interval)
                await self._perform_health_check()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health check error: {e}")

    async def _perform_health_check(self) -> None:
        """Perform health check on all sessions."""
        logger.debug("Performing session health check")
        
        for session in self._sessions.values():
            if session.state == SessionState.ERROR:
                # Attempt reconnection simulation
                await self._reconnect_session(session)

    async def _reconnect_session(self, session: NetconfSession) -> bool:
        """Attempt to reconnect a failed session.

        Args:
            session: Session to reconnect.

        Returns:
            True if reconnection successful.
        """
        logger.info(f"Attempting to reconnect session {session.session_id[:8]}...")
        
        for attempt in range(self.config.reconnect_attempts):
            try:
                # Simulate reconnection delay
                await asyncio.sleep(1)
                
                # Simulate successful reconnection
                session.state = SessionState.IDLE
                session.lock_holder = None
                session.touch()
                
                logger.info(
                    f"Session {session.session_id[:8]}... reconnected "
                    f"after {attempt + 1} attempts"
                )
                return True
                
            except Exception as e:
                logger.warning(
                    f"Reconnection attempt {attempt + 1} failed: {e}"
                )
        
        logger.error(
            f"Failed to reconnect session {session.session_id[:8]}... "
            f"after {self.config.reconnect_attempts} attempts"
        )
        return False

    async def __aenter__(self) -> NetconfSessionPool:
        """Async context manager entry."""
        await self.initialize()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.close()


class NetconfSessionContext:
    """Context manager for NETCONF session usage.

    Automatically returns session to pool on exit.
    """

    def __init__(self, pool: NetconfSessionPool, session: NetconfSession) -> None:
        """Initialize context.

        Args:
            pool: Session pool.
            session: Session to manage.
        """
        self._pool = pool
        self._session = session

    @property
    def session(self) -> NetconfSession:
        """Get the managed session."""
        return self._session

    async def __aenter__(self) -> NetconfSession:
        """Enter context and return session."""
        return self._session

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit context and return session to pool."""
        if exc_type:
            self._session.state = SessionState.ERROR
            logger.error(
                f"Session {self._session.session_id[:8]}... encountered error: {exc_val}"
            )
        
        self._pool.return_session(self._session)
        return False


# =============================================================================
# VendorAdapter
# =============================================================================


class VendorAdapter:
    """Vendor-specific NETCONF adaptations.

    Provides vendor-specific handling for Ericsson and Huawei devices,
    including capability mapping and configuration translation.

    Attributes:
        vendor: Vendor type.
        capabilities: Device capabilities.

    Example:
        >>> adapter = VendorAdapter(VendorType.ERICSSON)
        >>> adapted_config = adapter.adapt_config(config_xml)
    """

    # Vendor-specific namespace mappings
    NAMESPACES: Dict[VendorType, Dict[str, str]] = {
        VendorType.ERICSSON: {
            "ericsson": "urn:ietf:params:xml:ns:netconf:base:1.0",
            "er-ms": "urn:ericsson:params:xml:ns:med:streaming",
        },
        VendorType.HUAWEI: {
            "huawei": "urn:ietf:params:xml:ns:netconf:base:1.0",
            "hw-ms": "urn:huawei:params:xml:ns:yang:hw-module",
        },
        VendorType.GENERIC: {},
    }

    # Vendor-specific operation mappings
    OPERATION_MAP: Dict[VendorType, Dict[str, str]] = {
        VendorType.ERICSSON: {
            "commit": "commit",
            "validate": "validate",
            "confirmed_commit": "confirmed-commit",
        },
        VendorType.HUAWEI: {
            "commit": "commit",
            "validate": "validate",
            "confirmed_commit": "confirmed-commit",
        },
        VendorType.GENERIC: {
            "commit": "commit",
            "validate": "validate",
            "confirmed_commit": "confirmed-commit",
        },
    }

    def __init__(
        self,
        vendor: VendorType,
        capabilities: Optional[List[str]] = None
    ) -> None:
        """Initialize vendor adapter.

        Args:
            vendor: Vendor type.
            capabilities: Optional device capabilities list.
        """
        self.vendor = vendor
        self.capabilities = capabilities or []
        self._namespaces = self.NAMESPACES.get(vendor, {})

    def adapt_config(self, config_xml: str) -> str:
        """Adapt configuration for vendor-specific format.

        Args:
            config_xml: Configuration XML to adapt.

        Returns:
            Adapted configuration XML.
        """
        if self.vendor == VendorType.ERICSSON:
            return self._adapt_ericsson(config_xml)
        elif self.vendor == VendorType.HUAWEI:
            return self._adapt_huawei(config_xml)
        return config_xml

    def _adapt_ericsson(self, config_xml: str) -> str:
        """Apply Ericsson-specific adaptations.

        Args:
            config_xml: Configuration XML.

        Returns:
            Adapted XML.
        """
        try:
            root = ET.fromstring(config_xml)
            
            # Add Ericsson-specific namespace
            for prefix, uri in self._namespaces.items():
                if prefix != "ericsson":
                    root.set(f"xmlns:{prefix}", uri)
            
            # Ericsson-specific config transformations
            for elem in root.iter():
                # Transform interface names if needed
                if elem.tag == "interface":
                    name = elem.get("name", "")
                    if name and not name.startswith("GE"):
                        elem.set("name", f"GE{name}")
            
            return ET.tostring(root, encoding="unicode")
        except ET.ParseError:
            return config_xml

    def _adapt_huawei(self, config_xml: str) -> str:
        """Apply Huawei-specific adaptations.

        Args:
            config_xml: Configuration XML.

        Returns:
            Adapted XML.
        """
        try:
            root = ET.fromstring(config_xml)
            
            # Add Huawei-specific namespace
            for prefix, uri in self._namespaces.items():
                if prefix != "huawei":
                    root.set(f"xmlns:{prefix}", uri)
            
            # Huawei-specific config transformations
            for elem in root.iter():
                # Transform VLAN format
                if elem.tag == "vlan":
                    vlan_id = elem.get("id")
                    if vlan_id:
                        elem.set("vlanId", vlan_id)
                        elem.attrib.pop("id", None)
            
            return ET.tostring(root, encoding="unicode")
        except ET.ParseError:
            return config_xml

    def adapt_response(self, response_xml: str) -> str:
        """Adapt response from vendor-specific format.

        Args:
            response_xml: Response XML from device.

        Returns:
            Standardized response XML.
        """
        if self.vendor == VendorType.ERICSSON:
            return self._adapt_ericsson_response(response_xml)
        elif self.vendor == VendorType.HUAWEI:
            return self._adapt_huawei_response(response_xml)
        return response_xml

    def _adapt_ericsson_response(self, response_xml: str) -> str:
        """Adapt Ericsson response to standard format."""
        # Ericsson-specific response normalization
        return response_xml.replace("er:", "")

    def _adapt_huawei_response(self, response_xml: str) -> str:
        """Adapt Huawei response to standard format."""
        # Huawei-specific response normalization
        return response_xml.replace("hw:", "")

    def get_operation(self, operation: str) -> str:
        """Get vendor-specific operation name.

        Args:
            operation: Standard operation name.

        Returns:
            Vendor-specific operation name.
        """
        op_map = self.OPERATION_MAP.get(self.vendor, {})
        return op_map.get(operation, operation)

    def supports_capability(self, capability: str) -> bool:
        """Check if device supports a capability.

        Args:
            capability: Capability to check.

        Returns:
            True if supported.
        """
        return capability in self.capabilities

    def get_supported_features(self) -> List[str]:
        """Get list of supported features.

        Returns:
            List of supported features.
        """
        features = []
        
        if self.vendor == VendorType.ERICSSON:
            features = [
                "candidate",
                "confirmed-commit",
                "validate",
                "rollback",
                "with-defaults",
            ]
        elif self.vendor == VendorType.HUAWEI:
            features = [
                "candidate",
                "confirmed-commit",
                "validate",
                "rollback-on-error",
            ]
        else:
            features = ["candidate", "validate"]
        
        # Filter by capabilities if available
        if self.capabilities:
            features = [
                f for f in features
                if any(f in cap for cap in self.capabilities)
            ]
        
        return features


# =============================================================================
# ConfigValidator
# =============================================================================


class ConfigValidator:
    """Pre and post configuration validation.

    Validates configuration changes before and after applying them
    to ensure correctness and consistency.

    Example:
        >>> validator = ConfigValidator()
        >>> is_valid, errors = validator.pre_validate(config_xml)
        >>> is_valid, diff = validator.post_validate(old_config, new_config)
    """

    # Required XML elements for valid config
    REQUIRED_ELEMENTS: List[str] = [
        "config",
    ]

    # Validation rules
    VALIDATION_RULES: Dict[str, Callable[[ET.Element], Tuple[bool, str]]] = {}

    def __init__(self, schema: Optional[str] = None) -> None:
        """Initialize validator.

        Args:
            schema: Optional YANG schema for validation.
        """
        self.schema = schema
        self._validation_errors: List[str] = []

    def pre_validate(self, config_xml: str) -> Tuple[bool, List[str]]:
        """Perform pre-apply validation.

        Args:
            config_xml: Configuration XML to validate.

        Returns:
            Tuple of (is_valid, error_messages).
        """
        self._validation_errors = []
        
        # Check for empty config
        if not config_xml or config_xml.strip() == "":
            self._validation_errors.append("Configuration is empty")
            return False, self._validation_errors.copy()
        
        # Parse XML
        try:
            root = ET.fromstring(config_xml)
        except ET.ParseError as e:
            self._validation_errors.append(f"XML parsing error: {e}")
            return False, self._validation_errors.copy()
        
        # Validate structure
        self._validate_structure(root)
        
        # Validate content
        self._validate_content(root)
        
        # Validate against rules
        self._apply_validation_rules(root)
        
        return len(self._validation_errors) == 0, self._validation_errors.copy()

    def post_validate(
        self,
        old_config: str,
        new_config: str
    ) -> Tuple[bool, Dict[str, Any]]:
        """Perform post-apply validation.

        Args:
            old_config: Original configuration.
            new_config: New configuration.

        Returns:
            Tuple of (is_valid, diff_info).
        """
        diff_info: Dict[str, Any] = {
            "added": [],
            "removed": [],
            "modified": [],
            "unchanged": [],
        }
        
        if not old_config or not new_config:
            return False, diff_info
        
        try:
            old_root = ET.fromstring(old_config)
            new_root = ET.fromstring(new_config)
        except ET.ParseError:
            return False, diff_info
        
        # Calculate hash-based diff
        old_hash = self._calculate_config_hash(old_config)
        new_hash = self._calculate_config_hash(new_config)
        
        diff_info["old_hash"] = old_hash
        diff_info["new_hash"] = new_hash
        diff_info["changed"] = old_hash != new_hash
        
        # Analyze element changes
        self._analyze_changes(old_root, new_root, diff_info)
        
        is_valid = self._validate_diff(diff_info)
        
        return is_valid, diff_info

    def _validate_structure(self, root: ET.Element) -> None:
        """Validate XML structure.

        Args:
            root: Root element.
        """
        # Check for config element
        if root.tag not in self.REQUIRED_ELEMENTS:
            # Check children
            found_config = False
            for child in root:
                if child.tag in self.REQUIRED_ELEMENTS:
                    found_config = True
                    break
            
            if not found_config and root.tag != "config":
                self._validation_errors.append(
                    f"Missing required 'config' element, found '{root.tag}'"
                )

    def _validate_content(self, root: ET.Element) -> None:
        """Validate configuration content.

        Args:
            root: Root element.
        """
        # Check for empty configuration
        if len(list(root)) == 0:
            self._validation_errors.append("Configuration has no content")
            return
        
        # Validate each child element
        for child in root:
            self._validate_element(child)

    def _validate_element(self, element: ET.Element, path: str = "") -> None:
        """Validate a single element.

        Args:
            element: Element to validate.
            path: Current element path.
        """
        current_path = f"{path}/{element.tag}" if path else element.tag
        
        # Check for invalid characters in text
        if element.text:
            invalid_chars = ["<", ">", "&"]
            for char in invalid_chars:
                if char in element.text and not element.text.startswith("<"):
                    self._validation_errors.append(
                        f"Invalid character '{char}' in element at {current_path}"
                    )
        
        # Recursively validate children
        for child in element:
            self._validate_element(child, current_path)

    def _apply_validation_rules(self, root: ET.Element) -> None:
        """Apply custom validation rules.

        Args:
            root: Root element.
        """
        for rule_name, rule_func in self.VALIDATION_RULES.items():
            try:
                is_valid, message = rule_func(root)
                if not is_valid:
                    self._validation_errors.append(
                        f"Rule '{rule_name}' failed: {message}"
                    )
            except Exception as e:
                self._validation_errors.append(
                    f"Rule '{rule_name}' error: {e}"
                )

    def _calculate_config_hash(self, config: str) -> str:
        """Calculate hash of configuration.

        Args:
            config: Configuration string.

        Returns:
            SHA256 hash.
        """
        return hashlib.sha256(config.encode()).hexdigest()[:16]

    def _analyze_changes(
        self,
        old_root: ET.Element,
        new_root: ET.Element,
        diff_info: Dict[str, Any]
    ) -> None:
        """Analyze element-level changes.

        Args:
            old_root: Old configuration root.
            new_root: New configuration root.
            diff_info: Diff information dictionary.
        """
        old_elements = {e.tag: e for e in old_root}
        new_elements = {e.tag: e for e in new_root}
        
        old_tags = set(old_elements.keys())
        new_tags = set(new_elements.keys())
        
        diff_info["added"] = list(new_tags - old_tags)
        diff_info["removed"] = list(old_tags - new_tags)
        
        # Check for modifications
        for tag in old_tags & new_tags:
            old_elem = old_elements[tag]
            new_elem = new_elements[tag]
            
            old_str = ET.tostring(old_elem, encoding="unicode")
            new_str = ET.tostring(new_elem, encoding="unicode")
            
            if old_str != new_str:
                diff_info["modified"].append(tag)
            else:
                diff_info["unchanged"].append(tag)

    def _validate_diff(self, diff_info: Dict[str, Any]) -> bool:
        """Validate the diff results.

        Args:
            diff_info: Diff information.

        Returns:
            True if diff is valid.
        """
        # Check for suspicious changes
        if len(diff_info.get("removed", [])) > 10:
            logger.warning(
                f"Large number of removals: {len(diff_info['removed'])}"
            )
        
        # Validate that changes were applied
        if not diff_info.get("changed", False):
            logger.info("No changes detected in configuration")
        
        return True

    def add_validation_rule(
        self,
        name: str,
        rule: Callable[[ET.Element], Tuple[bool, str]]
    ) -> None:
        """Add a custom validation rule.

        Args:
            name: Rule name.
            rule: Validation function.
        """
        self.VALIDATION_RULES[name] = rule

    def get_errors(self) -> List[str]:
        """Get validation errors.

        Returns:
            List of error messages.
        """
        return self._validation_errors.copy()


# =============================================================================
# NetconfWorkflow
# =============================================================================


class NetconfWorkflow:
    """7-step NETCONF configuration workflow.

    Implements a complete configuration workflow with:
    1. Lock candidate datastore
    2. Edit-config with changes
    3. Validate configuration
    4. Confirmed-commit with timeout
    5. Get-config for verification
    6. Commit (confirmation) or Rollback
    7. Unlock candidate datastore

    Attributes:
        session_pool: NETCONF session pool.
        vendor_adapter: Vendor adapter instance.
        validator: Configuration validator.

    Example:
        >>> workflow = NetconfWorkflow(pool, adapter)
        >>> result = await workflow.execute(config_xml, confirm_timeout=300)
    """

    def __init__(
        self,
        session_pool: NetconfSessionPool,
        vendor_adapter: Optional[VendorAdapter] = None,
        validator: Optional[ConfigValidator] = None
    ) -> None:
        """Initialize workflow.

        Args:
            session_pool: Session pool for connections.
            vendor_adapter: Optional vendor adapter.
            validator: Optional configuration validator.
        """
        self.session_pool = session_pool
        self.vendor_adapter = vendor_adapter or VendorAdapter(VendorType.GENERIC)
        self.validator = validator or ConfigValidator()
        
        self._transaction_id: Optional[str] = None
        self._audit_log: List[AuditLogEntry] = []
        self._commit_state: CommitState = CommitState.PENDING

    async def execute(
        self,
        config_xml: str,
        confirm_timeout: int = 300,
        auto_confirm: bool = True,
        validate_before: bool = True,
        validate_after: bool = True,
        retry_on_lock: bool = True,
        max_retries: int = 3
    ) -> RpcResult:
        """Execute the complete configuration workflow.

        Args:
            config_xml: Configuration XML to apply.
            confirm_timeout: Timeout for confirmed commit in seconds.
            auto_confirm: Whether to auto-confirm after verification.
            validate_before: Whether to validate before applying.
            validate_after: Whether to validate after applying.
            retry_on_lock: Whether to retry on lock contention.
            max_retries: Maximum retry attempts for lock.

        Returns:
            RPC result with operation outcome.
        """
        start_time = datetime.now()
        self._transaction_id = str(uuid.uuid4())
        
        logger.info(
            f"Starting NETCONF workflow transaction {self._transaction_id[:8]}..."
        )
        
        try:
            # Pre-validation
            if validate_before:
                is_valid, errors = self.validator.pre_validate(config_xml)
                if not is_valid:
                    return RpcResult(
                        success=False,
                        message=f"Pre-validation failed: {errors}",
                        error_info={"errors": errors}
                    )
            
            # Adapt config for vendor
            adapted_config = self.vendor_adapter.adapt_config(config_xml)
            
            # Get session from pool
            async with await self.session_pool.get_session() as session:
                session.lock_holder = self._transaction_id
                
                # Step 1: Lock candidate datastore
                await self._step_lock(session, retry_on_lock, max_retries)
                
                try:
                    # Step 2: Edit-config
                    await self._step_edit_config(session, adapted_config)
                    
                    # Step 3: Validate
                    await self._step_validate(session)
                    
                    # Step 4: Confirmed-commit
                    await self._step_confirmed_commit(session, confirm_timeout)
                    
                    # Step 5: Get-config for verification
                    new_config = await self._step_get_config(session)
                    
                    # Step 6: Confirm or Rollback
                    if auto_confirm:
                        # Post-validation
                        if validate_after:
                            is_valid, diff = self.validator.post_validate(
                                config_xml, new_config
                            )
                            if not is_valid:
                                await self._step_rollback(session)
                                return RpcResult(
                                    success=False,
                                    message="Post-validation failed",
                                    error_info={"diff": diff}
                                )
                        
                        await self._step_commit(session)
                        self._commit_state = CommitState.CONFIRMED
                    else:
                        # Wait for external confirmation
                        await asyncio.sleep(confirm_timeout)
                        await self._step_rollback(session)
                        self._commit_state = CommitState.ROLLED_BACK
                    
                finally:
                    # Step 7: Unlock candidate datastore
                    await self._step_unlock(session)
            
            elapsed = (datetime.now() - start_time).total_seconds()
            
            return RpcResult(
                success=True,
                message="Configuration workflow completed successfully",
                data=new_config if "new_config" in dir() else None,
                elapsed_time=elapsed
            )
            
        except Exception as e:
            self._commit_state = CommitState.FAILED
            elapsed = (datetime.now() - start_time).total_seconds()
            
            logger.error(
                f"Workflow failed for transaction {self._transaction_id[:8]}...: {e}"
            )
            
            return RpcResult(
                success=False,
                message=f"Workflow failed: {str(e)}",
                error_info={"exception": str(e), "type": type(e).__name__},
                elapsed_time=elapsed
            )

    async def _step_lock(
        self,
        session: NetconfSession,
        retry: bool,
        max_retries: int
    ) -> None:
        """Step 1: Lock candidate datastore.

        Args:
            session: NETCONF session.
            retry: Whether to retry on contention.
            max_retries: Maximum retry attempts.

        Raises:
            LockContentionError: If lock cannot be acquired.
        """
        logger.info(f"[Step 1] Locking candidate datastore")
        
        lock_xml = XmlMessageBuilder.build_lock(DatastoreType.CANDIDATE)
        self._log_audit("lock", "candidate", lock_xml)
        
        for attempt in range(max_retries if retry else 1):
            # Simulate lock operation
            await asyncio.sleep(0.1)
            
            if session.state != SessionState.ERROR:
                session.state = SessionState.LOCKED
                logger.info(f"Candidate datastore locked (attempt {attempt + 1})")
                return
            
            if attempt < max_retries - 1:
                logger.warning(
                    f"Lock contention, retrying ({attempt + 1}/{max_retries})"
                )
                await asyncio.sleep(1)
        
        raise LockContentionError(
            f"Failed to acquire lock after {max_retries} attempts"
        )

    async def _step_edit_config(
        self,
        session: NetconfSession,
        config: str
    ) -> None:
        """Step 2: Edit-config with changes.

        Args:
            session: NETCONF session.
            config: Configuration XML.

        Raises:
            NetconfError: If edit-config fails.
        """
        logger.info("[Step 2] Applying edit-config")
        
        edit_xml = XmlMessageBuilder.build_edit_config(
            DatastoreType.CANDIDATE,
            config,
            operation="merge",
            test_option="test-then-set"
        )
        self._log_audit("edit-config", "candidate", config)
        
        # Simulate edit-config operation
        await asyncio.sleep(0.2)
        
        logger.info("Edit-config applied successfully")

    async def _step_validate(self, session: NetconfSession) -> None:
        """Step 3: Validate configuration.

        Args:
            session: NETCONF session.

        Raises:
            ValidationFailedError: If validation fails.
        """
        logger.info("[Step 3] Validating configuration")
        
        validate_xml = XmlMessageBuilder.build_validate(DatastoreType.CANDIDATE)
        self._log_audit("validate", "candidate", "")
        
        # Simulate validate operation
        await asyncio.sleep(0.1)
        
        logger.info("Configuration validated successfully")

    async def _step_confirmed_commit(
        self,
        session: NetconfSession,
        timeout: int
    ) -> None:
        """Step 4: Confirmed-commit with timeout.

        Args:
            session: NETCONF session.
            timeout: Confirmation timeout in seconds.

        Raises:
            CommitFailedError: If commit fails.
        """
        logger.info(f"[Step 4] Issuing confirmed-commit with timeout {timeout}s")
        
        commit_xml = XmlMessageBuilder.build_commit(
            confirmed=True,
            confirm_timeout=timeout
        )
        self._log_audit("confirmed-commit", "candidate", f"timeout={timeout}")
        
        # Simulate commit operation
        await asyncio.sleep(0.1)
        
        self._commit_state = CommitState.PENDING
        logger.info("Confirmed-commit issued successfully")

    async def _step_get_config(self, session: NetconfSession) -> str:
        """Step 5: Get-config for verification.

        Args:
            session: NETCONF session.

        Returns:
            Configuration XML.
        """
        logger.info("[Step 5] Retrieving configuration for verification")
        
        get_xml = XmlMessageBuilder.build_get_config(DatastoreType.CANDIDATE)
        self._log_audit("get-config", "candidate", "")
        
        # Simulate get-config operation
        await asyncio.sleep(0.1)
        
        # Return simulated config
        new_config = """<?xml version="1.0"?>
<config>
  <interfaces>
    <interface name="GE0/0/1">
      <enabled>true</enabled>
    </interface>
  </interfaces>
</config>"""
        
        logger.info("Configuration retrieved successfully")
        return new_config

    async def _step_commit(self, session: NetconfSession) -> None:
        """Step 6a: Confirm commit.

        Args:
            session: NETCONF session.

        Raises:
            CommitFailedError: If commit fails.
        """
        logger.info("[Step 6a] Confirming commit")
        
        commit_xml = XmlMessageBuilder.build_commit()
        self._log_audit("commit", "candidate", "confirmation")
        
        # Simulate commit operation
        await asyncio.sleep(0.1)
        
        logger.info("Commit confirmed successfully")

    async def _step_rollback(self, session: NetconfSession) -> None:
        """Step 6b: Rollback on failure.

        Args:
            session: NETCONF session.
        """
        logger.warning("[Step 6b] Rolling back configuration")
        
        discard_xml = XmlMessageBuilder.build_discard_changes()
        self._log_audit("discard-changes", "candidate", "rollback")
        
        # Simulate discard operation
        await asyncio.sleep(0.1)
        
        logger.info("Configuration rolled back successfully")

    async def _step_unlock(self, session: NetconfSession) -> None:
        """Step 7: Unlock candidate datastore.

        Args:
            session: NETCONF session.
        """
        logger.info("[Step 7] Unlocking candidate datastore")
        
        unlock_xml = XmlMessageBuilder.build_unlock(DatastoreType.CANDIDATE)
        self._log_audit("unlock", "candidate", "")
        
        session.state = SessionState.IDLE
        session.lock_holder = None
        
        logger.info("Candidate datastore unlocked")

    def _log_audit(
        self,
        operation: str,
        datastore: str,
        content: str
    ) -> None:
        """Log audit entry.

        Args:
            operation: Operation type.
            datastore: Target datastore.
            content: Operation content.
        """
        config_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
        
        entry = AuditLogEntry(
            transaction_id=self._transaction_id or "unknown",
            operation=operation,
            datastore=datastore,
            config_hash=config_hash,
            status="completed"
        )
        
        self._audit_log.append(entry)
        logger.debug(
            f"Audit: {operation} on {datastore} "
            f"(hash={config_hash[:8]}...)"
        )

    def get_audit_log(self) -> List[Dict[str, Any]]:
        """Get audit log entries.

        Returns:
            List of audit log entries as dictionaries.
        """
        return [
            {
                "transaction_id": entry.transaction_id,
                "operation": entry.operation,
                "datastore": entry.datastore,
                "config_hash": entry.config_hash,
                "timestamp": entry.timestamp.isoformat(),
                "status": entry.status,
                "details": entry.details,
            }
            for entry in self._audit_log
        ]

    def get_commit_state(self) -> CommitState:
        """Get current commit state.

        Returns:
            Current commit state.
        """
        return self._commit_state


# =============================================================================
# Module-level convenience functions
# =============================================================================


async def create_netconf_client(
    host: str,
    username: str = "admin",
    password: str = "",
    vendor: str = "generic",
    **kwargs: Any
) -> Tuple[NetconfSessionPool, VendorAdapter, NetconfWorkflow]:
    """Create a complete NETCONF client setup.

    Args:
        host: Device hostname or IP.
        username: Authentication username.
        password: Authentication password.
        vendor: Vendor type (ericsson, huawei, generic).
        **kwargs: Additional configuration options.

    Returns:
        Tuple of (session_pool, vendor_adapter, workflow).
    """
    vendor_type = VendorType(vendor.lower())
    
    config = NetconfConfig(
        host=host,
        username=username,
        password=password,
        vendor=vendor_type,
        **{k: v for k, v in kwargs.items() if hasattr(NetconfConfig, k)}
    )
    
    pool = NetconfSessionPool(config)
    await pool.initialize()
    
    adapter = VendorAdapter(vendor_type)
    workflow = NetconfWorkflow(pool, adapter)
    
    return pool, adapter, workflow


# =============================================================================
# Module exports
# =============================================================================

__all__ = [
    # Enums
    "DatastoreType",
    "VendorType",
    "SessionState",
    "CommitState",
    # Dataclasses
    "NetconfConfig",
    "NetconfSession",
    "AuditLogEntry",
    "RpcResult",
    # Exceptions
    "NetconfError",
    "SessionTimeoutError",
    "LockContentionError",
    "ValidationFailedError",
    "CommitFailedError",
    # Classes
    "XmlMessageBuilder",
    "NetconfSessionPool",
    "NetconfSessionContext",
    "VendorAdapter",
    "ConfigValidator",
    "NetconfWorkflow",
    # Functions
    "create_netconf_client",
]
