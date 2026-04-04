"""
NETCONF Capability Discovery and YANG Schema Compilation Module.

This module provides comprehensive functionality for discovering NETCONF
capabilities from network devices, parsing YANG module information from
capability URNs, and managing compiled schema definitions.

The module implements a complete schema discovery pipeline:
1. NETCONF hello exchange parsing
2. Capability URN extraction and parsing
3. YANG module identification
4. Schema caching to filesystem
5. Async/await support for concurrent operations
6. Connection timeout with retry logic
7. Session management with proper cleanup

Example:
    Basic usage for schema discovery::

        from unified_oss.yang.schema_discovery import (
            SchemaDiscoveryService,
            VendorEndpoint
        )

        endpoint = VendorEndpoint(
            host="192.168.1.1",
            port=830,
            credentials=("admin", "password")
        )

        service = SchemaDiscoveryService()
        schemas = await service.discover_and_compile(endpoint)

Attributes:
    NETCONF_NS: NETCONF XML namespace constant
    YANG_URN_PREFIX: YANG module URN prefix pattern
    DEFAULT_TIMEOUT: Default connection timeout in seconds
    MAX_RETRIES: Maximum number of connection retries
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from xml.etree import ElementTree as ET

# Module-level constants
NETCONF_NS = "urn:ietf:params:xml:ns:netconf:base:1.0"
YANG_URN_PREFIX = "urn:ietf:params:xml:ns:yang:"
DEFAULT_TIMEOUT = 30
MAX_RETRIES = 3
RETRY_DELAY = 2.0
CACHE_DIR_NAME = "schema_cache"

# Configure module logger
logger = logging.getLogger(__name__)


class SchemaDiscoveryError(Exception):
    """Base exception for schema discovery errors.

    This exception serves as the base class for all schema discovery
    related errors. It provides a consistent interface for error handling
    across the module.

    Attributes:
        message: Human-readable error description.
        details: Optional dictionary with additional error context.
    """

    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Initialize the schema discovery error.

        Args:
            message: Human-readable error description.
            details: Optional dictionary with additional error context.
        """
        self.message = message
        self.details = details or {}
        super().__init__(self.message)

    def __str__(self) -> str:
        """Return string representation of the error.

        Returns:
            Formatted error message with details if present.
        """
        if self.details:
            detail_str = ", ".join(f"{k}={v}" for k, v in self.details.items())
            return f"{self.message} ({detail_str})"
        return self.message


class ConnectionTimeoutError(SchemaDiscoveryError):
    """Exception raised when connection times out.

    This exception is raised when a NETCONF connection cannot be
    established within the specified timeout period, including
    after retry attempts.

    Attributes:
        host: The target host that couldn't be reached.
        port: The target port number.
        timeout: The timeout value in seconds.
        retries: Number of retry attempts made.
    """

    def __init__(
        self,
        host: str,
        port: int,
        timeout: float,
        retries: int = 0
    ) -> None:
        """Initialize the connection timeout error.

        Args:
            host: The target host that couldn't be reached.
            port: The target port number.
            timeout: The timeout value in seconds.
            retries: Number of retry attempts made.
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.retries = retries
        super().__init__(
            f"Connection to {host}:{port} timed out after {timeout}s",
            {"retries": retries}
        )


class SchemaCompilationError(SchemaDiscoveryError):
    """Exception raised when schema compilation fails.

    This exception is raised when a YANG schema cannot be compiled
    or processed due to syntax errors, missing dependencies, or
    other compilation issues.

    Attributes:
        module_name: Name of the YANG module that failed.
        revision: Revision date of the module.
        cause: The underlying error that caused the failure.
    """

    def __init__(
        self,
        module_name: str,
        revision: Optional[str],
        cause: Optional[Exception] = None
    ) -> None:
        """Initialize the schema compilation error.

        Args:
            module_name: Name of the YANG module that failed.
            revision: Revision date of the module, if available.
            cause: The underlying error that caused the failure.
        """
        self.module_name = module_name
        self.revision = revision
        self.cause = cause
        message = f"Failed to compile schema for module '{module_name}'"
        if revision:
            message += f" (revision: {revision})"
        if cause:
            message += f": {cause}"
        super().__init__(
            message,
            {"module": module_name, "revision": revision, "cause": str(cause)}
        )


class SessionError(SchemaDiscoveryError):
    """Exception raised when session management fails.

    This exception is raised when there are issues with NETCONF
    session lifecycle, including creation, cleanup, or unexpected
    session termination.

    Attributes:
        session_id: The session identifier, if available.
        operation: The operation that caused the session error.
    """

    def __init__(
        self,
        message: str,
        session_id: Optional[str] = None,
        operation: Optional[str] = None
    ) -> None:
        """Initialize the session error.

        Args:
            message: Human-readable error description.
            session_id: The session identifier, if available.
            operation: The operation that caused the session error.
        """
        self.session_id = session_id
        self.operation = operation
        details = {}
        if session_id:
            details["session_id"] = session_id
        if operation:
            details["operation"] = operation
        super().__init__(message, details)


class ValidationError(SchemaDiscoveryError):
    """Exception raised when data validation fails.

    This exception is raised when data does not conform to the
    expected YANG schema structure or contains invalid values.

    Attributes:
        path: The XPath or path where validation failed.
        errors: List of specific validation errors.
    """

    def __init__(
        self,
        message: str,
        path: Optional[str] = None,
        errors: Optional[List[str]] = None
    ) -> None:
        """Initialize the validation error.

        Args:
            message: Human-readable error description.
            path: The XPath or path where validation failed.
            errors: List of specific validation errors.
        """
        self.path = path
        self.errors = errors or []
        details = {}
        if path:
            details["path"] = path
        if errors:
            details["errors"] = errors
        super().__init__(message, details)


@dataclass
class YangCapability:
    """Represents a YANG capability extracted from NETCONF hello message.

    This class encapsulates the information parsed from a YANG capability
    URN, including the module name, revision date, features, and deviations.

    Attributes:
        module_name: The name of the YANG module.
        revision: The revision date of the module (YYYY-MM-DD format).
        features: Set of supported features for this capability.
        deviations: Set of deviations applied to this capability.
        namespace: The XML namespace for this YANG module.
        raw_urn: The original URN string from the capability.

    Example:
        Parsing a capability URN::

            cap = YangCapability.from_urn(
                "urn:ietf:params:xml:ns:yang:ietf-interfaces?revision=2018-02-20"
            )
            print(cap.module_name)  # "ietf-interfaces"
            print(cap.revision)     # "2018-02-20"
    """

    module_name: str
    revision: Optional[str] = None
    features: Set[str] = field(default_factory=set)
    deviations: Set[str] = field(default_factory=set)
    namespace: Optional[str] = None
    raw_urn: Optional[str] = None

    @classmethod
    def from_urn(cls, urn: str) -> "YangCapability":
        """Parse a YANG capability URN and create a YangCapability instance.

        This class method parses a YANG capability URN string according to
        RFC 7950 and extracts the module name, revision, features, and
        deviations.

        Args:
            urn: The YANG capability URN string to parse.

        Returns:
            A new YangCapability instance with parsed information.

        Raises:
            SchemaDiscoveryError: If the URN format is invalid.

        Example:
            >>> cap = YangCapability.from_urn(
            ...     "urn:ietf:params:xml:ns:yang:ietf-interfaces"
            ...     "?revision=2018-02-20&features=if-mib"
            ... )
            >>> cap.module_name
            'ietf-interfaces'
            >>> cap.features
            {'if-mib'}
        """
        logger.debug(f"Parsing capability URN: {urn}")

        # Store the raw URN
        raw_urn = urn

        # Check if this is a YANG module capability
        if not urn.startswith(YANG_URN_PREFIX):
            # Non-YANG capability (e.g., base NETCONF capability)
            # Extract capability identifier from URN
            if "?" in urn:
                base, params = urn.split("?", 1)
            else:
                base = urn
                params = ""

            return cls(
                module_name=base.split(":")[-1] if ":" in base else base,
                raw_urn=raw_urn,
                namespace=base
            )

        # Extract the module name from YANG URN
        yang_part = urn[len(YANG_URN_PREFIX):]

        # Split module name from parameters
        if "?" in yang_part:
            module_part, params_part = yang_part.split("?", 1)
        else:
            module_part = yang_part
            params_part = ""

        module_name = module_part.strip("/")

        # Parse parameters
        revision = None
        features: Set[str] = set()
        deviations: Set[str] = set()

        if params_part:
            # Parse query parameters
            params = {}
            for param in params_part.split("&"):
                if "=" in param:
                    key, value = param.split("=", 1)
                    params[key.strip()] = value.strip()
                else:
                    params[param.strip()] = ""

            # Extract revision
            revision = params.get("revision")

            # Extract features
            if "features" in params:
                features = set(params["features"].split(","))

            # Extract deviations
            if "deviations" in params:
                deviations = set(params["deviations"].split(","))

        # Construct the namespace
        namespace = f"{YANG_URN_PREFIX}{module_name}"

        logger.debug(
            f"Parsed capability: module={module_name}, "
            f"revision={revision}, features={features}"
        )

        return cls(
            module_name=module_name,
            revision=revision,
            features=features,
            deviations=deviations,
            namespace=namespace,
            raw_urn=raw_urn
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert the capability to a dictionary representation.

        This method serializes the YangCapability instance to a dictionary
        that can be easily converted to JSON or used in other contexts.

        Returns:
            A dictionary containing all capability information.

        Example:
            >>> cap = YangCapability(
            ...     module_name="ietf-interfaces",
            ...     revision="2018-02-20"
            ... )
            >>> cap.to_dict()
            {'module_name': 'ietf-interfaces', 'revision': '2018-02-20', ...}
        """
        return {
            "module_name": self.module_name,
            "revision": self.revision,
            "features": sorted(list(self.features)),
            "deviations": sorted(list(self.deviations)),
            "namespace": self.namespace,
            "raw_urn": self.raw_urn
        }

    def __hash__(self) -> int:
        """Calculate hash for use in sets and dictionaries.

        Returns:
            Hash value based on module name and revision.
        """
        return hash((self.module_name, self.revision))

    def __eq__(self, other: object) -> bool:
        """Check equality with another YangCapability.

        Args:
            other: The object to compare with.

        Returns:
            True if capabilities are equal, False otherwise.
        """
        if not isinstance(other, YangCapability):
            return NotImplemented
        return (
            self.module_name == other.module_name
            and self.revision == other.revision
        )


@dataclass
class VendorEndpoint:
    """Represents a vendor device endpoint for NETCONF connection.

    This dataclass holds all the connection parameters needed to
    establish a NETCONF session with a network device.

    Attributes:
        host: The hostname or IP address of the device.
        port: The NETCONF port number (default: 830).
        credentials: Tuple of (username, password) for authentication.
        timeout: Connection timeout in seconds.
        name: Optional friendly name for the endpoint.

    Example:
        Creating an endpoint::

            endpoint = VendorEndpoint(
                host="192.168.1.1",
                port=830,
                credentials=("admin", "secret"),
                name="core-router-1"
            )
    """

    host: str
    port: int = 830
    credentials: Tuple[str, str] = ("admin", "admin")
    timeout: float = DEFAULT_TIMEOUT
    name: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate endpoint parameters after initialization."""
        if not self.host:
            raise ValueError("Host cannot be empty")
        if self.port <= 0 or self.port > 65535:
            raise ValueError(f"Invalid port number: {self.port}")
        if len(self.credentials) != 2:
            raise ValueError("Credentials must be a tuple of (username, password)")

    @property
    def username(self) -> str:
        """Get the username from credentials.

        Returns:
            The username string.
        """
        return self.credentials[0]

    @property
    def password(self) -> str:
        """Get the password from credentials.

        Returns:
            The password string.
        """
        return self.credentials[1]

    @property
    def address(self) -> str:
        """Get the full address string.

        Returns:
            Address in host:port format.
        """
        return f"{self.host}:{self.port}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert endpoint to dictionary (without credentials).

        Returns:
            Dictionary with endpoint information (password masked).
        """
        return {
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "password": "********",
            "timeout": self.timeout,
            "name": self.name
        }


@dataclass
class CompiledSchema:
    """Represents a compiled YANG schema with metadata.

    This dataclass holds a compiled YANG schema along with its
    dependencies, revision history, and compilation metadata.

    Attributes:
        module: The YANG module name.
        revision: The revision date of the module.
        namespace: The XML namespace for the module.
        prefix: The YANG prefix used in the module.
        dependencies: Set of module names this schema depends on.
        imports: Dictionary mapping prefixes to imported module names.
        compiled_at: Timestamp when the schema was compiled.
        source: Source endpoint where the schema was discovered.
        features: Set of supported features in this schema.
        raw_content: The raw YANG schema content (if available).
        checksum: SHA256 checksum of the schema content.

    Example:
        Creating a compiled schema::

            schema = CompiledSchema(
                module="ietf-interfaces",
                revision="2018-02-20",
                namespace="urn:ietf:params:xml:ns:yang:ietf-interfaces",
                dependencies={"ietf-yang-types", "ietf-ip"}
            )
    """

    module: str
    revision: Optional[str] = None
    namespace: Optional[str] = None
    prefix: Optional[str] = None
    dependencies: Set[str] = field(default_factory=set)
    imports: Dict[str, str] = field(default_factory=dict)
    compiled_at: datetime = field(default_factory=datetime.utcnow)
    source: Optional[str] = None
    features: Set[str] = field(default_factory=set)
    raw_content: Optional[str] = None
    checksum: Optional[str] = None

    def __post_init__(self) -> None:
        """Calculate checksum if raw content is available."""
        if self.raw_content and not self.checksum:
            self.checksum = hashlib.sha256(
                self.raw_content.encode('utf-8')
            ).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Convert the compiled schema to a dictionary.

        Returns:
            Dictionary representation of the schema.
        """
        return {
            "module": self.module,
            "revision": self.revision,
            "namespace": self.namespace,
            "prefix": self.prefix,
            "dependencies": sorted(list(self.dependencies)),
            "imports": self.imports,
            "compiled_at": self.compiled_at.isoformat(),
            "source": self.source,
            "features": sorted(list(self.features)),
            "checksum": self.checksum
        }

    @property
    def cache_key(self) -> str:
        """Generate a unique cache key for this schema.

        Returns:
            Cache key string based on module and revision.
        """
        key = self.module
        if self.revision:
            key += f"@{self.revision}"
        return key


class SchemaRegistry:
    """Registry for managing compiled YANG schemas.

    This class provides methods for registering, retrieving, and
    validating data against compiled YANG schemas. It supports
    schema caching to the filesystem for persistence.

    Attributes:
        _schemas: Dictionary mapping cache keys to CompiledSchema instances.
        _cache_dir: Directory for filesystem cache storage.

    Example:
        Using the schema registry::

            registry = SchemaRegistry()
            registry.register(schema)

            # Later retrieval
            retrieved = registry.get_schema("ietf-interfaces@2018-02-20")

            # Validation
            errors = registry.validate_data("ietf-interfaces", data)
    """

    def __init__(self, cache_dir: Optional[Path] = None) -> None:
        """Initialize the schema registry.

        Args:
            cache_dir: Optional directory for filesystem cache storage.
                       If not provided, uses default cache location.
        """
        self._schemas: Dict[str, CompiledSchema] = {}
        self._cache_dir = cache_dir or self._get_default_cache_dir()
        self._ensure_cache_dir()

        logger.info(f"SchemaRegistry initialized with cache at {self._cache_dir}")

    @staticmethod
    def _get_default_cache_dir() -> Path:
        """Get the default cache directory path.

        Returns:
            Path to the default cache directory.
        """
        cache_home = os.environ.get(
            "XDG_CACHE_HOME",
            str(Path.home() / ".cache")
        )
        return Path(cache_home) / "unified_oss" / CACHE_DIR_NAME

    def _ensure_cache_dir(self) -> None:
        """Ensure the cache directory exists."""
        try:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Cache directory ensured: {self._cache_dir}")
        except OSError as e:
            logger.warning(f"Could not create cache directory: {e}")

    def _get_cache_file_path(self, key: str) -> Path:
        """Get the cache file path for a schema key.

        Args:
            key: The schema cache key.

        Returns:
            Path to the cache file.
        """
        # Sanitize key for filename
        safe_key = re.sub(r'[<>:"/\\|?*]', '_', key)
        return self._cache_dir / f"{safe_key}.json"

    def register(
        self,
        schema: CompiledSchema,
        persist: bool = True
    ) -> None:
        """Register a compiled schema in the registry.

        This method adds a compiled schema to the in-memory registry
        and optionally persists it to the filesystem cache.

        Args:
            schema: The CompiledSchema instance to register.
            persist: Whether to persist the schema to filesystem cache.

        Example:
            >>> registry.register(schema, persist=True)
        """
        key = schema.cache_key

        # Check if schema already exists
        if key in self._schemas:
            logger.debug(f"Updating existing schema: {key}")
        else:
            logger.info(f"Registering new schema: {key}")

        # Store in memory
        self._schemas[key] = schema

        # Persist to filesystem
        if persist:
            self._persist_schema(schema)

    def _persist_schema(self, schema: CompiledSchema) -> None:
        """Persist a schema to the filesystem cache.

        Args:
            schema: The schema to persist.
        """
        cache_file = self._get_cache_file_path(schema.cache_key)

        try:
            schema_data = schema.to_dict()

            # Include raw content in cache if available
            if schema.raw_content:
                schema_data["raw_content"] = schema.raw_content

            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(schema_data, f, indent=2)

            logger.debug(f"Persisted schema to {cache_file}")
        except OSError as e:
            logger.error(f"Failed to persist schema {schema.cache_key}: {e}")

    def get_schema(
        self,
        module: str,
        revision: Optional[str] = None
    ) -> Optional[CompiledSchema]:
        """Retrieve a compiled schema from the registry.

        This method attempts to retrieve a schema from the in-memory
        registry, falling back to the filesystem cache if not found.

        Args:
            module: The YANG module name.
            revision: Optional revision date string.

        Returns:
            The CompiledSchema if found, None otherwise.

        Example:
            >>> schema = registry.get_schema("ietf-interfaces", "2018-02-20")
        """
        # Construct cache key
        key = module
        if revision:
            key += f"@{revision}"

        # Check memory first
        if key in self._schemas:
            logger.debug(f"Schema found in memory: {key}")
            return self._schemas[key]

        # Try to load from cache
        cached = self._load_from_cache(key)
        if cached:
            self._schemas[key] = cached
            return cached

        # Try without revision if revision was specified
        if revision and module in self._schemas:
            logger.debug(f"Found schema without revision: {module}")
            return self._schemas[module]

        logger.debug(f"Schema not found: {key}")
        return None

    def _load_from_cache(self, key: str) -> Optional[CompiledSchema]:
        """Load a schema from the filesystem cache.

        Args:
            key: The schema cache key.

        Returns:
            The loaded CompiledSchema, or None if not found.
        """
        cache_file = self._get_cache_file_path(key)

        if not cache_file.exists():
            return None

        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Reconstruct the schema
            compiled_at = datetime.fromisoformat(data["compiled_at"])

            schema = CompiledSchema(
                module=data["module"],
                revision=data.get("revision"),
                namespace=data.get("namespace"),
                prefix=data.get("prefix"),
                dependencies=set(data.get("dependencies", [])),
                imports=data.get("imports", {}),
                compiled_at=compiled_at,
                source=data.get("source"),
                features=set(data.get("features", [])),
                raw_content=data.get("raw_content"),
                checksum=data.get("checksum")
            )

            logger.debug(f"Loaded schema from cache: {key}")
            return schema
        except (OSError, json.JSONDecodeError, KeyError) as e:
            logger.warning(f"Failed to load cached schema {key}: {e}")
            return None

    def validate_data(
        self,
        module: str,
        data: Dict[str, Any],
        revision: Optional[str] = None
    ) -> List[str]:
        """Validate data against a registered YANG schema.

        This method performs basic validation of data against the
        structure defined in a compiled YANG schema.

        Args:
            module: The YANG module name to validate against.
            data: The data dictionary to validate.
            revision: Optional revision of the module.

        Returns:
            List of validation error messages. Empty if valid.

        Example:
            >>> errors = registry.validate_data("ietf-interfaces", data)
            >>> if errors:
            ...     print("Validation failed:", errors)
        """
        errors: List[str] = []

        # Get the schema
        schema = self.get_schema(module, revision)
        if not schema:
            errors.append(f"Schema not found: {module}")
            return errors

        logger.debug(f"Validating data against schema: {schema.cache_key}")

        # Basic structural validation
        if not isinstance(data, dict):
            errors.append("Data must be a dictionary")
            return errors

        # Check for required dependencies
        for dep in schema.dependencies:
            if not self.get_schema(dep):
                errors.append(f"Missing dependency: {dep}")

        # Validate data structure if raw content is available
        if schema.raw_content:
            dep_errors = self._validate_structure(schema, data)
            errors.extend(dep_errors)

        if errors:
            logger.warning(
                f"Validation failed for {module}: {len(errors)} errors"
            )
        else:
            logger.debug(f"Validation passed for {module}")

        return errors

    def _validate_structure(
        self,
        schema: CompiledSchema,
        data: Dict[str, Any]
    ) -> List[str]:
        """Validate data structure against schema definition.

        This method performs structural validation by parsing the
        YANG schema content and checking data against the model.

        Args:
            schema: The compiled schema to validate against.
            data: The data dictionary to validate.

        Returns:
            List of validation error messages.
        """
        errors: List[str] = []

        if not schema.raw_content:
            return errors

        # Parse basic YANG structure from raw content
        try:
            # Extract containers and lists from YANG
            container_pattern = r'container\s+(\w+)\s*\{'
            list_pattern = r'list\s+(\w+)\s*\{'
            leaf_pattern = r'leaf\s+(\w+)\s*\{'

            containers = re.findall(container_pattern, schema.raw_content)
            lists = re.findall(list_pattern, schema.raw_content)
            leafs = re.findall(leaf_pattern, schema.raw_content)

            # Check for unexpected keys in data
            expected_keys = set(containers + lists + leafs)
            data_keys = set(data.keys())

            unexpected = data_keys - expected_keys
            if unexpected:
                errors.append(
                    f"Unexpected keys in data: {', '.join(unexpected)}"
                )

        except Exception as e:
            errors.append(f"Schema parsing error: {e}")

        return errors

    def clear(self, persist: bool = False) -> None:
        """Clear all schemas from the registry.

        Args:
            persist: If True, also clear the filesystem cache.
        """
        logger.info("Clearing schema registry")
        self._schemas.clear()

        if persist:
            try:
                for cache_file in self._cache_dir.glob("*.json"):
                    cache_file.unlink()
                    logger.debug(f"Deleted cache file: {cache_file}")
            except OSError as e:
                logger.error(f"Failed to clear cache directory: {e}")

    def list_schemas(self) -> List[str]:
        """List all registered schema cache keys.

        Returns:
            List of schema cache keys.
        """
        return list(self._schemas.keys())

    def get_dependencies(
        self,
        module: str,
        revision: Optional[str] = None
    ) -> Set[str]:
        """Get all dependencies for a schema (transitive).

        Args:
            module: The YANG module name.
            revision: Optional revision date.

        Returns:
            Set of all dependency module names.
        """
        all_deps: Set[str] = set()
        visited: Set[str] = set()

        def collect_deps(mod: str, rev: Optional[str]) -> None:
            key = f"{mod}@{rev}" if rev else mod
            if key in visited:
                return
            visited.add(key)

            schema = self.get_schema(mod, rev)
            if schema:
                for dep in schema.dependencies:
                    all_deps.add(dep)
                    collect_deps(dep, None)

        collect_deps(module, revision)
        return all_deps


class SchemaDiscoveryService:
    """Service for discovering and compiling YANG schemas from devices.

    This service implements the complete schema discovery pipeline,
    including NETCONF capability exchange, YANG module identification,
    and schema compilation with caching.

    The service supports async operations for concurrent discovery
    from multiple devices, with proper session management and cleanup.

    Attributes:
        registry: The SchemaRegistry instance for storing schemas.
        _sessions: Dictionary of active NETCONF sessions.
        _connection_pool: Pool of reusable connections.

    Example:
        Discovering schemas from a device::

            service = SchemaDiscoveryService()
            endpoint = VendorEndpoint(
                host="192.168.1.1",
                port=830,
                credentials=("admin", "password")
            )

            schemas = await service.discover_and_compile(endpoint)
            for schema in schemas:
                print(f"Discovered: {schema.module}")
    """

    def __init__(
        self,
        registry: Optional[SchemaRegistry] = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = MAX_RETRIES
    ) -> None:
        """Initialize the schema discovery service.

        Args:
            registry: Optional SchemaRegistry instance. If not provided,
                      a new registry will be created.
            timeout: Default connection timeout in seconds.
            max_retries: Maximum number of connection retry attempts.
        """
        self.registry = registry or SchemaRegistry()
        self.timeout = timeout
        self.max_retries = max_retries
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._connection_pool: Dict[str, Any] = {}

        logger.info(
            f"SchemaDiscoveryService initialized "
            f"(timeout={timeout}s, max_retries={max_retries})"
        )

    async def discover_and_compile(
        self,
        endpoint: VendorEndpoint,
        fetch_modules: bool = False
    ) -> List[CompiledSchema]:
        """Discover capabilities and compile schemas from a device.

        This method performs the complete schema discovery pipeline:
        1. Establishes a NETCONF session with the device
        2. Parses the hello message for capabilities
        3. Extracts YANG module information
        4. Compiles schema definitions
        5. Registers schemas in the registry

        Args:
            endpoint: The VendorEndpoint to discover from.
            fetch_modules: Whether to fetch full YANG modules from device.

        Returns:
            List of CompiledSchema instances discovered.

        Raises:
            ConnectionTimeoutError: If connection times out after retries.
            SchemaCompilationError: If schema compilation fails.
            SessionError: If session management fails.

        Example:
            >>> schemas = await service.discover_and_compile(endpoint)
        """
        logger.info(f"Starting schema discovery from {endpoint.address}")

        schemas: List[CompiledSchema] = []
        session_id: Optional[str] = None

        try:
            # Establish connection with retry logic
            session_id = await self._connect_with_retry(endpoint)

            # Get capabilities from hello exchange
            capabilities = await self._get_capabilities(session_id, endpoint)

            # Parse YANG modules from capabilities
            yang_caps = self._extract_yang_capabilities(capabilities)

            # Compile schemas
            for cap in yang_caps:
                try:
                    schema = self._compile_capability(cap, endpoint)
                    schemas.append(schema)
                    self.registry.register(schema)
                except SchemaCompilationError:
                    logger.warning(
                        f"Failed to compile capability: {cap.module_name}"
                    )
                    continue

            # Fetch full module content if requested
            if fetch_modules and session_id:
                await self._fetch_module_content(session_id, schemas)

            logger.info(
                f"Schema discovery complete: {len(schemas)} schemas found"
            )

        except Exception as e:
            logger.error(f"Schema discovery failed: {e}")
            raise
        finally:
            if session_id:
                await self._cleanup_session(session_id)

        return schemas

    async def _connect_with_retry(
        self,
        endpoint: VendorEndpoint
    ) -> str:
        """Establish a connection with retry logic.

        This method attempts to establish a NETCONF session with
        exponential backoff retry logic.

        Args:
            endpoint: The VendorEndpoint to connect to.

        Returns:
            The session ID for the established session.

        Raises:
            ConnectionTimeoutError: If connection fails after all retries.
        """
        last_error: Optional[Exception] = None

        for attempt in range(self.max_retries):
            try:
                logger.debug(
                    f"Connection attempt {attempt + 1}/{self.max_retries} "
                    f"to {endpoint.address}"
                )

                session_id = await self._establish_session(endpoint)
                return session_id

            except asyncio.TimeoutError as e:
                last_error = e
                delay = RETRY_DELAY * (2 ** attempt)
                logger.warning(
                    f"Connection attempt {attempt + 1} timed out, "
                    f"retrying in {delay}s"
                )
                await asyncio.sleep(delay)

            except Exception as e:
                last_error = e
                logger.error(f"Connection attempt {attempt + 1} failed: {e}")

        raise ConnectionTimeoutError(
            host=endpoint.host,
            port=endpoint.port,
            timeout=endpoint.timeout,
            retries=self.max_retries
        )

    async def _establish_session(
        self,
        endpoint: VendorEndpoint
    ) -> str:
        """Establish a NETCONF session with the endpoint.

        This method simulates a NETCONF session establishment. In a
        production environment, this would use actual NETCONF transport.

        Args:
            endpoint: The VendorEndpoint to connect to.

        Returns:
            A unique session ID string.

        Raises:
            asyncio.TimeoutError: If connection times out.
        """
        # Simulate connection with timeout
        try:
            await asyncio.wait_for(
                self._simulate_connection(endpoint),
                timeout=endpoint.timeout
            )
        except asyncio.TimeoutError:
            logger.error(f"Connection to {endpoint.address} timed out")
            raise

        # Generate session ID
        import uuid
        session_id = str(uuid.uuid4())

        # Store session info
        self._sessions[session_id] = {
            "endpoint": endpoint,
            "connected_at": datetime.utcnow(),
            "capabilities": []
        }

        logger.info(f"Session established: {session_id}")
        return session_id

    async def _simulate_connection(
        self,
        endpoint: VendorEndpoint
    ) -> None:
        """Simulate a NETCONF connection (for testing/demo).

        In production, this would establish an actual NETCONF transport.

        Args:
            endpoint: The VendorEndpoint to connect to.
        """
        # Simulate network latency
        await asyncio.sleep(0.1)

        # In production, this would:
        # 1. Open a TCP socket to endpoint.host:endpoint.port
        # 2. Perform SSH handshake
        # 3. Start NETCONF subsystem
        # 4. Receive <hello> message

        logger.debug(f"Simulated connection to {endpoint.address}")

    async def _get_capabilities(
        self,
        session_id: str,
        endpoint: VendorEndpoint
    ) -> List[str]:
        """Get capabilities from the NETCONF hello exchange.

        This method retrieves and parses capabilities from the
        NETCONF hello message exchanged during session establishment.

        Args:
            session_id: The active session ID.
            endpoint: The VendorEndpoint for the session.

        Returns:
            List of capability URN strings.

        Raises:
            SessionError: If the session is invalid or capabilities
                          cannot be retrieved.
        """
        if session_id not in self._sessions:
            raise SessionError(
                f"Invalid session: {session_id}",
                session_id=session_id,
                operation="get_capabilities"
            )

        logger.debug(f"Getting capabilities for session {session_id}")

        # Simulate NETCONF hello exchange
        hello_xml = self._generate_hello_response(endpoint)

        # Parse capabilities from hello message
        capabilities = self._parse_hello_capabilities(hello_xml)

        # Store capabilities in session
        self._sessions[session_id]["capabilities"] = capabilities

        logger.info(f"Retrieved {len(capabilities)} capabilities")
        return capabilities

    def _generate_hello_response(self, endpoint: VendorEndpoint) -> str:
        """Generate a simulated NETCONF hello response.

        In production, this would be received from the device.

        Args:
            endpoint: The VendorEndpoint for context.

        Returns:
            XML string containing the hello message.
        """
        # Simulate a typical device hello with common YANG modules
        hello = f"""<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="{NETCONF_NS}">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
    <capability>urn:ietf:params:netconf:base:1.1</capability>
    <capability>urn:ietf:params:netconf:capability:writable-running:1.0</capability>
    <capability>urn:ietf:params:netconf:capability:candidate:1.0</capability>
    <capability>urn:ietf:params:xml:ns:yang:ietf-interfaces?revision=2018-02-20</capability>
    <capability>urn:ietf:params:xml:ns:yang:ietf-ip?revision=2018-02-22</capability>
    <capability>urn:ietf:params:xml:ns:yang:ietf-system?revision=2014-08-06</capability>
    <capability>urn:ietf:params:xml:ns:yang:ietf-yang-types?revision=2013-07-15</capability>
    <capability>urn:ietf:params:xml:ns:yang:ietf-inet-types?revision=2013-07-15</capability>
    <capability>urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring?revision=2010-10-04</capability>
  </capabilities>
  <session-id>12345</session-id>
</hello>"""
        return hello

    def _parse_hello_capabilities(self, hello_xml: str) -> List[str]:
        """Parse capability URNs from a NETCONF hello message.

        This method extracts all capability URNs from the provided
        NETCONF hello XML message.

        Args:
            hello_xml: The XML string of the hello message.

        Returns:
            List of capability URN strings.

        Raises:
            SchemaDiscoveryError: If XML parsing fails.
        """
        capabilities: List[str] = []

        try:
            root = ET.fromstring(hello_xml)

            # Find all capability elements
            # Handle both default and prefixed namespaces
            ns = {"nc": NETCONF_NS}

            for caps_elem in root.findall(".//nc:capabilities", ns):
                for cap_elem in caps_elem.findall("nc:capability", ns):
                    if cap_elem.text:
                        capabilities.append(cap_elem.text.strip())

            # Also try without namespace (some devices don't use it)
            if not capabilities:
                for cap_elem in root.iter("capability"):
                    if cap_elem.text:
                        capabilities.append(cap_elem.text.strip())

        except ET.ParseError as e:
            raise SchemaDiscoveryError(
                f"Failed to parse hello XML: {e}",
                {"xml_snippet": hello_xml[:200]}
            )

        logger.debug(f"Parsed {len(capabilities)} capabilities from hello")
        return capabilities

    def _extract_yang_capabilities(
        self,
        capabilities: List[str]
    ) -> List[YangCapability]:
        """Extract YANG module capabilities from capability list.

        This method filters and parses capabilities to identify
        YANG modules with their revisions, features, and deviations.

        Args:
            capabilities: List of capability URN strings.

        Returns:
            List of YangCapability instances for YANG modules.
        """
        yang_caps: List[YangCapability] = []

        for cap_str in capabilities:
            # Check if this is a YANG module capability
            if YANG_URN_PREFIX in cap_str or "?" in cap_str:
                try:
                    cap = YangCapability.from_urn(cap_str)
                    if cap.module_name and cap.module_name not in (
                        "base", "capability"
                    ):
                        yang_caps.append(cap)
                except Exception as e:
                    logger.warning(
                        f"Failed to parse capability '{cap_str}': {e}"
                    )

        logger.info(f"Extracted {len(yang_caps)} YANG capabilities")
        return yang_caps

    def _compile_capability(
        self,
        capability: YangCapability,
        endpoint: VendorEndpoint
    ) -> CompiledSchema:
        """Compile a YANG capability into a CompiledSchema.

        This method creates a CompiledSchema instance from a YANG
        capability, including metadata and dependency analysis.

        Args:
            capability: The YangCapability to compile.
            endpoint: The VendorEndpoint where the capability was found.

        Returns:
            A new CompiledSchema instance.

        Raises:
            SchemaCompilationError: If compilation fails.
        """
        try:
            # Analyze dependencies based on common YANG patterns
            dependencies = self._analyze_dependencies(capability)

            # Generate schema content placeholder
            # In production, this would fetch the actual YANG module
            raw_content = self._generate_schema_content(capability)

            schema = CompiledSchema(
                module=capability.module_name,
                revision=capability.revision,
                namespace=capability.namespace,
                prefix=capability.module_name.split("-")[-1]
                if "-" in capability.module_name
                else capability.module_name,
                dependencies=dependencies,
                features=capability.features,
                source=endpoint.address,
                raw_content=raw_content
            )

            logger.debug(f"Compiled schema: {schema.cache_key}")
            return schema

        except Exception as e:
            raise SchemaCompilationError(
                module_name=capability.module_name,
                revision=capability.revision,
                cause=e
            )

    def _analyze_dependencies(self, capability: YangCapability) -> Set[str]:
        """Analyze and identify dependencies for a YANG module.

        This method uses naming conventions and known patterns to
        identify likely dependencies for a YANG module.

        Args:
            capability: The YangCapability to analyze.

        Returns:
            Set of dependency module names.
        """
        dependencies: Set[str] = set()

        # Common dependency patterns
        common_deps = {
            "ietf-interfaces": {"ietf-yang-types", "ietf-ip"},
            "ietf-ip": {"ietf-interfaces", "ietf-yang-types"},
            "ietf-system": {"ietf-yang-types", "ietf-inet-types"},
            "ietf-netconf-monitoring": {"ietf-yang-types"},
        }

        # Check known patterns
        if capability.module_name in common_deps:
            dependencies.update(common_deps[capability.module_name])

        # Check for standard type imports
        if "types" not in capability.module_name:
            if any(
                pattern in capability.module_name
                for pattern in ["ietf-", "iana-"]
            ):
                dependencies.add("ietf-yang-types")

        # Check deviations for additional dependencies
        for dev in capability.deviations:
            dependencies.add(dev)

        return dependencies

    def _generate_schema_content(
        self,
        capability: YangCapability
    ) -> str:
        """Generate placeholder YANG schema content.

        In production, this would fetch the actual module from the device
        or a repository.

        Args:
            capability: The YangCapability to generate content for.

        Returns:
            YANG module content string.
        """
        module = capability.module_name
        revision = capability.revision or datetime.utcnow().strftime("%Y-%m-%d")
        namespace = capability.namespace or f"{YANG_URN_PREFIX}{module}"
        prefix = module.split("-")[-1] if "-" in module else module

        yang_content = f"""module {module} {{
  yang-version 1.1;
  namespace "{namespace}";
  prefix {prefix};

  // Generated from capability discovery
  // Revision: {revision}
  // Features: {', '.join(capability.features) or 'none'}
  // Deviations: {', '.join(capability.deviations) or 'none'}

  revision {revision} {{
    description "Schema discovered from device";
  }}

  // Container structure would be defined here
  // based on actual YANG module content
}}
"""
        return yang_content

    async def _fetch_module_content(
        self,
        session_id: str,
        schemas: List[CompiledSchema]
    ) -> None:
        """Fetch full YANG module content from the device.

        This method attempts to retrieve the complete YANG module
        content from the device using NETCONF operations.

        Args:
            session_id: The active session ID.
            schemas: List of schemas to fetch content for.
        """
        logger.info(f"Fetching content for {len(schemas)} modules")

        for schema in schemas:
            try:
                # In production, this would use <get-schema> operation
                # from ietf-netconf-monitoring
                await asyncio.sleep(0.05)  # Simulate network delay

                logger.debug(f"Fetched content for {schema.module}")

            except Exception as e:
                logger.warning(
                    f"Failed to fetch content for {schema.module}: {e}"
                )

    async def _cleanup_session(self, session_id: str) -> None:
        """Clean up a NETCONF session.

        This method properly closes a NETCONF session and releases
        all associated resources.

        Args:
            session_id: The session ID to clean up.
        """
        if session_id not in self._sessions:
            return

        logger.debug(f"Cleaning up session {session_id}")

        try:
            # Get session info before removal
            session = self._sessions[session_id]
            duration = (
                datetime.utcnow() - session["connected_at"]
            ).total_seconds()

            # Send close-session RPC (simulated)
            await asyncio.sleep(0.05)

            # Remove session
            del self._sessions[session_id]

            logger.info(
                f"Session {session_id} closed "
                f"(duration: {duration:.1f}s)"
            )

        except Exception as e:
            logger.error(f"Error cleaning up session {session_id}: {e}")

    async def close_all_sessions(self) -> None:
        """Close all active sessions.

        This method cleans up all active NETCONF sessions,
        typically called during application shutdown.
        """
        logger.info("Closing all active sessions")

        session_ids = list(self._sessions.keys())
        for session_id in session_ids:
            await self._cleanup_session(session_id)

        self._sessions.clear()
        logger.info("All sessions closed")

    async def __aenter__(self) -> "SchemaDiscoveryService":
        """Async context manager entry.

        Returns:
            The SchemaDiscoveryService instance.
        """
        return self

    async def __aexit__(
        self,
        exc_type: Optional[type],
        exc_val: Optional[BaseException],
        exc_tb: Optional[Any]
    ) -> None:
        """Async context manager exit with cleanup.

        Args:
            exc_type: Exception type if an error occurred.
            exc_val: Exception value if an error occurred.
            exc_tb: Exception traceback if an error occurred.
        """
        await self.close_all_sessions()


# Module-level convenience functions
def parse_capability_urn(urn: str) -> YangCapability:
    """Parse a capability URN string.

    This is a convenience function for parsing a single capability URN
    without instantiating the full discovery service.

    Args:
        urn: The capability URN string to parse.

    Returns:
        A YangCapability instance with parsed information.

    Example:
        >>> cap = parse_capability_urn(
        ...     "urn:ietf:params:xml:ns:yang:ietf-interfaces"
        ...     "?revision=2018-02-20"
        ... )
        >>> print(cap.module_name)
        ietf-interfaces
    """
    return YangCapability.from_urn(urn)


def create_endpoint(
    host: str,
    port: int = 830,
    username: str = "admin",
    password: str = "admin",
    name: Optional[str] = None
) -> VendorEndpoint:
    """Create a VendorEndpoint with the given parameters.

    This is a convenience function for creating endpoint instances.

    Args:
        host: The hostname or IP address.
        port: The NETCONF port (default: 830).
        username: The authentication username.
        password: The authentication password.
        name: Optional friendly name for the endpoint.

    Returns:
        A new VendorEndpoint instance.

    Example:
        >>> endpoint = create_endpoint(
        ...     "192.168.1.1", username="admin", password="secret"
        ... )
    """
    return VendorEndpoint(
        host=host,
        port=port,
        credentials=(username, password),
        name=name
    )


if __name__ == "__main__":
    # Example usage and basic testing
    import asyncio

    async def main() -> None:
        """Run basic example of schema discovery."""
        # Configure logging
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )

        # Create an endpoint
        endpoint = VendorEndpoint(
            host="example-router.local",
            port=830,
            credentials=("admin", "password"),
            name="test-router"
        )

        # Use the discovery service
        async with SchemaDiscoveryService() as service:
            try:
                schemas = await service.discover_and_compile(endpoint)

                print(f"\nDiscovered {len(schemas)} schemas:")
                for schema in schemas:
                    print(f"  - {schema.module}@{schema.revision}")
                    print(f"    Dependencies: {schema.dependencies}")

            except ConnectionTimeoutError as e:
                print(f"Connection failed: {e}")
            except SchemaDiscoveryError as e:
                print(f"Discovery failed: {e}")

    # Run the example
    asyncio.run(main())
