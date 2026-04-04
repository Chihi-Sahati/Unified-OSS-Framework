"""
Database Adapter Module for PostgreSQL/TimescaleDB/Redis Data Persistence.

This module provides comprehensive database operations including connection pooling,
TimescaleDB hypertable management, Redis caching, and tamper-evident audit logging.

Supports:
    - Async PostgreSQL/TimescaleDB operations
    - Redis-based caching with TTL
    - Cryptographic audit trail
    - Transaction management with rollback
    - Query optimization with indexed lookups
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import (
    Any,
    AsyncGenerator,
    Awaitable,
    Callable,
    Dict,
    Generic,
    List,
    Optional,
    Protocol,
    Set,
    Tuple,
    TypeVar,
    Union,
)

# Configure module logger
logger = logging.getLogger(__name__)

# Type aliases for clarity
ConnectionType = TypeVar("ConnectionType")
QueryResult = Dict[str, Any]
QueryParams = Union[Tuple[Any, ...], Dict[str, Any]]
T = TypeVar("T")


class DatabaseError(Exception):
    """Base exception for database operations."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Initialize database error.

        Args:
            message: Error message.
            details: Additional error details.
        """
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ConnectionError(DatabaseError):
    """Exception raised for connection failures."""

    pass


class ConstraintViolationError(DatabaseError):
    """Exception raised for constraint violations."""

    def __init__(
        self,
        message: str,
        constraint_name: Optional[str] = None,
        table_name: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initialize constraint violation error.

        Args:
            message: Error message.
            constraint_name: Name of the violated constraint.
            table_name: Name of the affected table.
            details: Additional error details.
        """
        super().__init__(message, details)
        self.constraint_name = constraint_name
        self.table_name = table_name


class DeadlockError(DatabaseError):
    """Exception raised for transaction deadlocks."""

    def __init__(
        self, message: str, retry_count: int = 0, details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Initialize deadlock error.

        Args:
            message: Error message.
            retry_count: Number of retry attempts made.
            details: Additional error details.
        """
        super().__init__(message, details)
        self.retry_count = retry_count


class QueryTimeoutError(DatabaseError):
    """Exception raised when query execution times out."""

    pass


class DatabaseType(Enum):
    """Supported database types."""

    POSTGRESQL = "postgresql"
    TIMESCALEDB = "timescaledb"
    REDIS = "redis"


@dataclass
class ConnectionConfig:
    """Configuration for database connections.

    Attributes:
        host: Database host address.
        port: Database port number.
        database: Database name.
        username: Authentication username.
        password: Authentication password.
        min_connections: Minimum connections in pool.
        max_connections: Maximum connections in pool.
        connection_timeout: Connection timeout in seconds.
        idle_timeout: Idle connection timeout in seconds.
        ssl_enabled: Whether SSL is enabled.
        ssl_cert_path: Path to SSL certificate.
    """

    host: str = "localhost"
    port: int = 5432
    database: str = "oss_db"
    username: str = "postgres"
    password: str = ""
    min_connections: int = 5
    max_connections: int = 20
    connection_timeout: float = 30.0
    idle_timeout: float = 300.0
    ssl_enabled: bool = False
    ssl_cert_path: Optional[str] = None

    def to_connection_string(self) -> str:
        """Generate PostgreSQL connection string.

        Returns:
            Connection string for asyncpg.
        """
        base = f"postgresql://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}"
        if self.ssl_enabled:
            base += f"?sslmode=require&sslrootcert={self.ssl_cert_path}"
        return base


@dataclass
class QueryStats:
    """Statistics for query execution.

    Attributes:
        query_count: Total number of queries executed.
        total_time: Total execution time in seconds.
        avg_time: Average execution time in seconds.
        slow_queries: Count of slow queries.
        errors: Count of query errors.
    """

    query_count: int = 0
    total_time: float = 0.0
    avg_time: float = 0.0
    slow_queries: int = 0
    errors: int = 0

    def record_query(self, execution_time: float, is_slow: bool = False, is_error: bool = False) -> None:
        """Record a query execution.

        Args:
            execution_time: Time taken to execute the query.
            is_slow: Whether the query was slow.
            is_error: Whether the query resulted in an error.
        """
        self.query_count += 1
        self.total_time += execution_time
        self.avg_time = self.total_time / self.query_count
        if is_slow:
            self.slow_queries += 1
        if is_error:
            self.errors += 1


@dataclass
class ConnectionPool:
    """Simulated connection pool for database connections.

    Attributes:
        config: Connection configuration.
        connections: List of active connections.
        available: Set of available connection indices.
        stats: Pool statistics.
    """

    config: ConnectionConfig
    connections: List[Any] = field(default_factory=list)
    available: Set[int] = field(default_factory=set)
    stats: QueryStats = field(default_factory=QueryStats)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _initialized: bool = False

    async def initialize(self) -> None:
        """Initialize the connection pool."""
        async with self._lock:
            if self._initialized:
                return

            logger.info(
                f"Initializing connection pool with {self.config.min_connections} connections"
            )

            # Simulate connection creation
            for i in range(self.config.min_connections):
                conn = await self._create_connection(i)
                self.connections.append(conn)
                self.available.add(i)

            self._initialized = True
            logger.info(f"Connection pool initialized with {len(self.connections)} connections")

    async def _create_connection(self, index: int) -> Dict[str, Any]:
        """Create a new database connection.

        Args:
            index: Connection index.

        Returns:
            Connection object.
        """
        await asyncio.sleep(0.01)  # Simulate connection latency
        return {
            "id": index,
            "created_at": datetime.now(timezone.utc),
            "last_used": datetime.now(timezone.utc),
            "transaction_active": False,
            "prepared_statements": {},
        }

    async def acquire(self, timeout: float = 10.0) -> Tuple[int, Dict[str, Any]]:
        """Acquire a connection from the pool.

        Args:
            timeout: Maximum time to wait for a connection.

        Returns:
            Tuple of connection index and connection object.

        Raises:
            ConnectionError: If no connection is available within timeout.
        """
        async with self._lock:
            if not self._initialized:
                await self.initialize()

            start_time = time.monotonic()
            while not self.available:
                if time.monotonic() - start_time > timeout:
                    raise ConnectionError(
                        "Connection pool exhausted",
                        details={"timeout": timeout, "pool_size": len(self.connections)},
                    )
                await asyncio.sleep(0.1)

            # Create new connection if needed
            if not self.available and len(self.connections) < self.config.max_connections:
                index = len(self.connections)
                conn = await self._create_connection(index)
                self.connections.append(conn)
                self.available.add(index)

            index = self.available.pop()
            self.connections[index]["last_used"] = datetime.now(timezone.utc)
            return index, self.connections[index]

    async def release(self, index: int) -> None:
        """Release a connection back to the pool.

        Args:
            index: Connection index to release.
        """
        async with self._lock:
            if 0 <= index < len(self.connections):
                self.connections[index]["last_used"] = datetime.now(timezone.utc)
                self.available.add(index)

    async def close(self) -> None:
        """Close all connections in the pool."""
        async with self._lock:
            logger.info(f"Closing connection pool with {len(self.connections)} connections")
            self.connections.clear()
            self.available.clear()
            self._initialized = False


class DatabaseConnectionPool:
    """Async connection management for PostgreSQL/TimescaleDB.

    This class provides connection pooling, transaction management,
    and query execution with automatic retry on failures.

    Attributes:
        config: Database connection configuration.
        pool: Underlying connection pool.
        database_type: Type of database being used.
    """

    def __init__(
        self,
        config: ConnectionConfig,
        database_type: DatabaseType = DatabaseType.POSTGRESQL,
    ) -> None:
        """Initialize the database connection pool.

        Args:
            config: Database connection configuration.
            database_type: Type of database (PostgreSQL or TimescaleDB).
        """
        self.config = config
        self.database_type = database_type
        self._pool = ConnectionPool(config)
        self._transaction_depth = 0
        self._query_stats = QueryStats()

    async def initialize(self) -> None:
        """Initialize the connection pool."""
        await self._pool.initialize()
        logger.info(f"DatabaseConnectionPool initialized for {self.database_type.value}")

    async def close(self) -> None:
        """Close all connections in the pool."""
        await self._pool.close()
        logger.info("DatabaseConnectionPool closed")

    async def execute(
        self,
        query: str,
        params: Optional[QueryParams] = None,
        timeout: float = 30.0,
    ) -> QueryResult:
        """Execute a query with parameters.

        Args:
            query: SQL query to execute.
            params: Query parameters.
            timeout: Query execution timeout.

        Returns:
            Query result dictionary.

        Raises:
            QueryTimeoutError: If query execution times out.
            DatabaseError: If query execution fails.
        """
        start_time = time.monotonic()
        index, conn = await self._pool.acquire()

        try:
            # Simulate query execution
            await asyncio.sleep(0.005)  # Simulate query latency

            execution_time = time.monotonic() - start_time
            is_slow = execution_time > 1.0

            self._query_stats.record_query(execution_time, is_slow=is_slow)

            if is_slow:
                logger.warning(f"Slow query detected: {execution_time:.3f}s - {query[:100]}")

            return {
                "success": True,
                "rowcount": 1,
                "rows": [],
                "execution_time": execution_time,
            }

        except Exception as e:
            self._query_stats.record_query(time.monotonic() - start_time, is_error=True)
            raise DatabaseError(f"Query execution failed: {str(e)}", details={"query": query})
        finally:
            await self._pool.release(index)

    async def execute_many(
        self,
        query: str,
        params_list: List[QueryParams],
        timeout: float = 60.0,
    ) -> List[QueryResult]:
        """Execute a query multiple times with different parameters.

        Args:
            query: SQL query to execute.
            params_list: List of parameter sets.
            timeout: Total execution timeout.

        Returns:
            List of query results.
        """
        results = []
        for params in params_list:
            result = await self.execute(query, params, timeout / len(params_list))
            results.append(result)
        return results

    async def fetch_one(
        self,
        query: str,
        params: Optional[QueryParams] = None,
        timeout: float = 30.0,
    ) -> Optional[QueryResult]:
        """Execute a query and fetch a single row.

        Args:
            query: SQL query to execute.
            params: Query parameters.
            timeout: Query execution timeout.

        Returns:
            Single row result or None.
        """
        result = await self.execute(query, params, timeout)
        rows = result.get("rows", [])
        return rows[0] if rows else None

    async def fetch_all(
        self,
        query: str,
        params: Optional[QueryParams] = None,
        timeout: float = 30.0,
    ) -> List[QueryResult]:
        """Execute a query and fetch all rows.

        Args:
            query: SQL query to execute.
            params: Query parameters.
            timeout: Query execution timeout.

        Returns:
            List of row results.
        """
        result = await self.execute(query, params, timeout)
        return result.get("rows", [])

    async def transaction(
        self,
        callback: Callable[[DatabaseConnectionPool], Awaitable[T]],
        isolation_level: str = "READ COMMITTED",
        retry_on_deadlock: bool = True,
        max_retries: int = 3,
    ) -> T:
        """Execute operations within a transaction.

        Args:
            callback: Async function to execute within transaction.
            isolation_level: Transaction isolation level.
            retry_on_deadlock: Whether to retry on deadlock.
            max_retries: Maximum number of retry attempts.

        Returns:
            Result of the callback function.

        Raises:
            DeadlockError: If deadlock persists after retries.
            DatabaseError: If transaction fails.
        """
        retry_count = 0

        while retry_count <= max_retries:
            try:
                index, conn = await self._pool.acquire()
                conn["transaction_active"] = True

                try:
                    # Simulate BEGIN TRANSACTION
                    await self.execute(f"BEGIN ISOLATION LEVEL {isolation_level}")

                    result = await callback(self)

                    # Simulate COMMIT
                    await self.execute("COMMIT")

                    return result

                except Exception as e:
                    # Simulate ROLLBACK
                    await self.execute("ROLLBACK")
                    raise

            except DeadlockError:
                if not retry_on_deadlock or retry_count >= max_retries:
                    raise DeadlockError(
                        "Transaction deadlock after retries",
                        retry_count=retry_count,
                    )
                retry_count += 1
                await asyncio.sleep(0.1 * retry_count)  # Exponential backoff
                logger.warning(f"Deadlock detected, retry {retry_count}/{max_retries}")

            finally:
                conn["transaction_active"] = False
                await self._pool.release(index)

        raise DeadlockError("Unexpected deadlock state", retry_count=retry_count)

    def build_upsert_query(
        self,
        table: str,
        data: Dict[str, Any],
        conflict_columns: List[str],
        update_columns: Optional[List[str]] = None,
        returning: Optional[List[str]] = None,
    ) -> Tuple[str, List[Any]]:
        """Build an UPSERT query with conflict resolution.

        Args:
            table: Target table name.
            data: Column values to insert/update.
            conflict_columns: Columns for conflict detection.
            update_columns: Columns to update on conflict (default: all except conflict).
            returning: Columns to return.

        Returns:
            Tuple of query string and parameters.
        """
        columns = list(data.keys())
        placeholders = [f"${i + 1}" for i in range(len(columns))]
        values = list(data.values())

        if update_columns is None:
            update_columns = [c for c in columns if c not in conflict_columns]

        update_clause = ", ".join(f"{c} = EXCLUDED.{c}" for c in update_columns)
        conflict_clause = ", ".join(conflict_columns)

        query = f"""
            INSERT INTO {table} ({', '.join(columns)})
            VALUES ({', '.join(placeholders)})
            ON CONFLICT ({conflict_clause})
            DO UPDATE SET {update_clause}
        """

        if returning:
            query += f" RETURNING {', '.join(returning)}"

        return query.strip(), values

    def build_select_query(
        self,
        table: str,
        columns: Optional[List[str]] = None,
        where: Optional[Dict[str, Any]] = None,
        order_by: Optional[List[Tuple[str, str]]] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> Tuple[str, List[Any]]:
        """Build a SELECT query with optional filtering.

        Args:
            table: Source table name.
            columns: Columns to select (default: all).
            where: WHERE clause conditions.
            order_by: ORDER BY columns with direction.
            limit: Maximum rows to return.
            offset: Number of rows to skip.

        Returns:
            Tuple of query string and parameters.
        """
        col_clause = ", ".join(columns) if columns else "*"
        query = f"SELECT {col_clause} FROM {table}"
        params: List[Any] = []

        if where:
            conditions = []
            for i, (col, val) in enumerate(where.items(), start=1):
                conditions.append(f"{col} = ${i}")
                params.append(val)
            query += f" WHERE {' AND '.join(conditions)}"

        if order_by:
            order_clause = ", ".join(f"{col} {direction}" for col, direction in order_by)
            query += f" ORDER BY {order_clause}"

        if limit is not None:
            query += f" LIMIT {limit}"

        if offset is not None:
            query += f" OFFSET {offset}"

        return query, params

    @property
    def stats(self) -> QueryStats:
        """Get query statistics."""
        return self._query_stats


@dataclass
class HypertableConfig:
    """Configuration for TimescaleDB hypertables.

    Attributes:
        table_name: Name of the hypertable.
        time_column: Name of the time column.
        chunk_time_interval: Time interval for each chunk.
        compression_enabled: Whether compression is enabled.
        compression_after: Compress chunks older than this interval.
        retention_period: Retention period for data.
    """

    table_name: str
    time_column: str = "time"
    chunk_time_interval: timedelta = timedelta(days=1)
    compression_enabled: bool = True
    compression_after: Optional[timedelta] = timedelta(days=7)
    retention_period: Optional[timedelta] = timedelta(days=365)


class TimescaleDBWriter:
    """Writer for TimescaleDB hypertable operations.

    This class provides specialized operations for time-series data
    including hypertable creation, compression, and batch inserts.

    Attributes:
        connection_pool: Database connection pool.
        hypertable_configs: Registered hypertable configurations.
    """

    def __init__(self, connection_pool: DatabaseConnectionPool) -> None:
        """Initialize the TimescaleDB writer.

        Args:
            connection_pool: Database connection pool.
        """
        self._pool = connection_pool
        self._hypertable_configs: Dict[str, HypertableConfig] = {}
        self._compression_jobs: Dict[str, List[Dict[str, Any]]] = {}

        # Default hypertable configurations
        self._register_default_hypertables()

    def _register_default_hypertables(self) -> None:
        """Register default hypertable configurations."""
        default_configs = {
            "metrics": HypertableConfig(
                table_name="metrics",
                time_column="time",
                chunk_time_interval=timedelta(hours=6),
                compression_enabled=True,
                compression_after=timedelta(days=3),
                retention_period=timedelta(days=90),
            ),
            "alarm_history": HypertableConfig(
                table_name="alarm_history",
                time_column="created_at",
                chunk_time_interval=timedelta(days=1),
                compression_enabled=True,
                compression_after=timedelta(days=7),
            ),
        }

        for name, config in default_configs.items():
            self._hypertable_configs[name] = config

    def register_hypertable(self, config: HypertableConfig) -> None:
        """Register a hypertable configuration.

        Args:
            config: Hypertable configuration.
        """
        self._hypertable_configs[config.table_name] = config
        logger.info(f"Registered hypertable: {config.table_name}")

    async def create_hypertable(
        self,
        table_name: str,
        time_column: Optional[str] = None,
        chunk_time_interval: Optional[timedelta] = None,
        if_not_exists: bool = True,
    ) -> QueryResult:
        """Create a hypertable from an existing table.

        Args:
            table_name: Name of the table to convert.
            time_column: Name of the time column.
            chunk_time_interval: Time interval for chunks.
            if_not_exists: Whether to skip if hypertable exists.

        Returns:
            Query result.
        """
        config = self._hypertable_configs.get(table_name)
        time_col = time_column or (config.time_column if config else "time")
        chunk_interval = chunk_time_interval or (
            config.chunk_time_interval if config else timedelta(days=1)
        )

        if_not_exists_clause = "IF NOT EXISTS" if if_not_exists else ""

        query = f"""
            SELECT create_hypertable(
                '{table_name}',
                '{time_col}',
                chunk_time_interval => INTERVAL '{chunk_interval}',
                if_not_exists => {str(if_not_exists).upper()}
            );
        """

        logger.info(f"Creating hypertable: {table_name}")
        result = await self._pool.execute(query)

        # Configure compression if enabled
        if config and config.compression_enabled:
            await self._configure_compression(table_name, config)

        return result

    async def _configure_compression(self, table_name: str, config: HypertableConfig) -> None:
        """Configure compression for a hypertable.

        Args:
            table_name: Name of the hypertable.
            config: Hypertable configuration.
        """
        if not config.compression_after:
            return

        query = f"""
            ALTER TABLE {table_name} SET (
                timescaledb.compress,
                timescaledb.compress_segmentby = 'id',
                timescaledb.compress_orderby = '{config.time_column}'
            );
        """

        await self._pool.execute(query)
        logger.info(f"Compression configured for: {table_name}")

    async def insert_metric(
        self,
        metric_name: str,
        value: float,
        timestamp: Optional[datetime] = None,
        tags: Optional[Dict[str, str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> QueryResult:
        """Insert a single metric data point.

        Args:
            metric_name: Name of the metric.
            value: Metric value.
            timestamp: Timestamp for the metric.
            tags: Metric tags.
            metadata: Additional metadata.

        Returns:
            Query result.
        """
        ts = timestamp or datetime.now(timezone.utc)
        tags_json = json.dumps(tags or {})
        metadata_json = json.dumps(metadata or {})

        query, params = self._pool.build_upsert_query(
            "metrics",
            {
                "name": metric_name,
                "value": value,
                "time": ts,
                "tags": tags_json,
                "metadata": metadata_json,
                "updated_at": datetime.now(timezone.utc),
            },
            conflict_columns=["name", "time"],
            returning=["id"],
        )

        return await self._pool.execute(query, tuple(params))

    async def insert_metrics_batch(
        self,
        metrics: List[Dict[str, Any]],
        batch_size: int = 1000,
    ) -> List[QueryResult]:
        """Insert multiple metrics in batches.

        Args:
            metrics: List of metric dictionaries.
            batch_size: Number of metrics per batch.

        Returns:
            List of query results.
        """
        results = []

        for i in range(0, len(metrics), batch_size):
            batch = metrics[i : i + batch_size]
            params_list = []

            for metric in batch:
                ts = metric.get("timestamp", datetime.now(timezone.utc))
                params = (
                    metric.get("name"),
                    metric.get("value"),
                    ts,
                    json.dumps(metric.get("tags", {})),
                    json.dumps(metric.get("metadata", {})),
                )
                params_list.append(params)

            query = """
                INSERT INTO metrics (name, value, time, tags, metadata)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (name, time) DO UPDATE SET
                    value = EXCLUDED.value,
                    tags = EXCLUDED.tags,
                    metadata = EXCLUDED.metadata
            """

            batch_results = await self._pool.execute_many(query, params_list)
            results.extend(batch_results)

        logger.info(f"Inserted {len(metrics)} metrics in {len(results)} batches")
        return results

    async def run_compression_job(
        self,
        table_name: str,
        older_than: Optional[timedelta] = None,
    ) -> QueryResult:
        """Run a compression job for a hypertable.

        Args:
            table_name: Name of the hypertable.
            older_than: Compress chunks older than this.

        Returns:
            Query result.
        """
        config = self._hypertable_configs.get(table_name)
        compress_after = older_than or (config.compression_after if config else timedelta(days=7))

        query = f"""
            SELECT compress_chunk(c.chunk_name)
            FROM show_chunks('{table_name}') AS c(chunk_name)
            WHERE c.is_compressed = false
            AND c.range_end < NOW() - INTERVAL '{compress_after}';
        """

        result = await self._pool.execute(query)

        # Track compression job
        if table_name not in self._compression_jobs:
            self._compression_jobs[table_name] = []

        self._compression_jobs[table_name].append({
            "executed_at": datetime.now(timezone.utc),
            "older_than": str(compress_after),
            "status": "completed",
        })

        logger.info(f"Compression job completed for: {table_name}")
        return result

    async def query_metrics(
        self,
        metric_name: str,
        start_time: datetime,
        end_time: datetime,
        tags: Optional[Dict[str, str]] = None,
        aggregation: str = "avg",
        interval: Optional[timedelta] = None,
    ) -> List[QueryResult]:
        """Query aggregated metrics over a time range.

        Args:
            metric_name: Name of the metric.
            start_time: Query start time.
            end_time: Query end time.
            tags: Filter by tags.
            aggregation: Aggregation function (avg, sum, min, max).
            interval: Time bucket interval.

        Returns:
            List of aggregated metric results.
        """
        interval_str = f"INTERVAL '{interval}'" if interval else None
        time_bucket = f"time_bucket({interval_str}, time)" if interval else "time"

        query = f"""
            SELECT
                {time_bucket} AS bucket,
                {aggregation}(value) AS value,
                COUNT(*) AS sample_count
            FROM metrics
            WHERE name = $1
            AND time >= $2
            AND time <= $3
        """

        params: List[Any] = [metric_name, start_time, end_time]

        if tags:
            for key, value in tags.items():
                param_idx = len(params) + 1
                query += f" AND tags->>'{key}' = ${param_idx}"
                params.append(value)

        if interval:
            query += f" GROUP BY bucket ORDER BY bucket"
        else:
            query += " ORDER BY time"

        return await self._pool.fetch_all(query, tuple(params))

    async def delete_old_chunks(
        self,
        table_name: str,
        older_than: Optional[timedelta] = None,
    ) -> QueryResult:
        """Delete old chunks from a hypertable.

        Args:
            table_name: Name of the hypertable.
            older_than: Delete chunks older than this.

        Returns:
            Query result.
        """
        config = self._hypertable_configs.get(table_name)
        retention = older_than or (config.retention_period if config else timedelta(days=365))

        query = f"""
            SELECT drop_chunks(
                '{table_name}',
                older_than => NOW() - INTERVAL '{retention}'
            );
        """

        result = await self._pool.execute(query)
        logger.info(f"Dropped old chunks from {table_name}, older than {retention}")
        return result

    @property
    def compression_history(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get compression job history."""
        return self._compression_jobs.copy()


@dataclass
class CacheEntry:
    """Represents a cached item with TTL.

    Attributes:
        key: Cache key.
        value: Cached value.
        created_at: Creation timestamp.
        expires_at: Expiration timestamp.
        ttl_seconds: Time to live in seconds.
        hits: Number of cache hits.
    """

    key: str
    value: Any
    created_at: datetime
    expires_at: Optional[datetime] = None
    ttl_seconds: Optional[int] = None
    hits: int = 0

    def is_expired(self) -> bool:
        """Check if the cache entry is expired.

        Returns:
            True if expired, False otherwise.
        """
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        """Convert cache entry to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "key": self.key,
            "value": self.value,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "ttl_seconds": self.ttl_seconds,
            "hits": self.hits,
        }


class RedisCache:
    """Redis-style caching for active alarms and latest KPIs.

    This class provides TTL-based caching simulation with support
    for various data types including alarms, metrics, and configurations.

    Attributes:
        default_ttl: Default TTL for cache entries in seconds.
        max_memory: Maximum memory usage in bytes (simulation).
    """

    def __init__(
        self,
        default_ttl: int = 3600,
        max_memory: int = 100 * 1024 * 1024,  # 100 MB
    ) -> None:
        """Initialize the Redis cache.

        Args:
            default_ttl: Default TTL for cache entries.
            max_memory: Maximum memory usage in bytes.
        """
        self.default_ttl = default_ttl
        self.max_memory = max_memory
        self._cache: Dict[str, CacheEntry] = {}
        self._lock = asyncio.Lock()
        self._stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "memory_used": 0,
        }

    async def get(self, key: str) -> Optional[Any]:
        """Get a value from the cache.

        Args:
            key: Cache key.

        Returns:
            Cached value or None if not found/expired.
        """
        async with self._lock:
            entry = self._cache.get(key)

            if entry is None:
                self._stats["misses"] += 1
                return None

            if entry.is_expired():
                del self._cache[key]
                self._stats["misses"] += 1
                self._stats["evictions"] += 1
                return None

            entry.hits += 1
            self._stats["hits"] += 1
            return entry.value

    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
    ) -> bool:
        """Set a value in the cache.

        Args:
            key: Cache key.
            value: Value to cache.
            ttl: Time to live in seconds.

        Returns:
            True if successful.
        """
        async with self._lock:
            ttl_seconds = ttl or self.default_ttl
            now = datetime.now(timezone.utc)
            expires_at = now + timedelta(seconds=ttl_seconds)

            entry = CacheEntry(
                key=key,
                value=value,
                created_at=now,
                expires_at=expires_at,
                ttl_seconds=ttl_seconds,
            )

            self._cache[key] = entry
            self._update_memory_usage()
            return True

    async def delete(self, key: str) -> bool:
        """Delete a value from the cache.

        Args:
            key: Cache key.

        Returns:
            True if deleted, False if not found.
        """
        async with self._lock:
            if key in self._cache:
                del self._cache[key]
                self._update_memory_usage()
                return True
            return False

    async def exists(self, key: str) -> bool:
        """Check if a key exists in the cache.

        Args:
            key: Cache key.

        Returns:
            True if exists and not expired.
        """
        value = await self.get(key)
        return value is not None

    async def expire(self, key: str, ttl: int) -> bool:
        """Set expiration on a key.

        Args:
            key: Cache key.
            ttl: New TTL in seconds.

        Returns:
            True if successful.
        """
        async with self._lock:
            entry = self._cache.get(key)
            if entry is None or entry.is_expired():
                return False

            entry.ttl_seconds = ttl
            entry.expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)
            return True

    async def incr(self, key: str, amount: int = 1) -> int:
        """Increment a counter in the cache.

        Args:
            key: Cache key.
            amount: Amount to increment.

        Returns:
            New value after increment.
        """
        async with self._lock:
            entry = self._cache.get(key)
            current = entry.value if entry and not entry.is_expired() else 0
            new_value = int(current) + amount
            await self.set(key, new_value)
            return new_value

    async def set_alarm(self, alarm_id: str, alarm_data: Dict[str, Any]) -> bool:
        """Cache an active alarm.

        Args:
            alarm_id: Alarm identifier.
            alarm_data: Alarm data dictionary.

        Returns:
            True if successful.
        """
        key = f"alarm:{alarm_id}"
        return await self.set(key, alarm_data, ttl=300)  # 5-minute TTL

    async def get_alarm(self, alarm_id: str) -> Optional[Dict[str, Any]]:
        """Get a cached alarm.

        Args:
            alarm_id: Alarm identifier.

        Returns:
            Alarm data or None.
        """
        key = f"alarm:{alarm_id}"
        return await self.get(key)

    async def get_active_alarms(self) -> List[Dict[str, Any]]:
        """Get all active alarms from cache.

        Returns:
            List of active alarm dictionaries.
        """
        async with self._lock:
            alarms = []
            expired_keys = []

            for key, entry in self._cache.items():
                if key.startswith("alarm:"):
                    if entry.is_expired():
                        expired_keys.append(key)
                    else:
                        alarms.append(entry.value)

            # Clean up expired entries
            for key in expired_keys:
                del self._cache[key]
                self._stats["evictions"] += 1

            return alarms

    async def set_kpi(self, kpi_name: str, kpi_value: Any) -> bool:
        """Cache a KPI value.

        Args:
            kpi_name: KPI name.
            kpi_value: KPI value.

        Returns:
            True if successful.
        """
        key = f"kpi:{kpi_name}"
        return await self.set(key, kpi_value, ttl=60)  # 1-minute TTL

    async def get_kpi(self, kpi_name: str) -> Optional[Any]:
        """Get a cached KPI value.

        Args:
            kpi_name: KPI name.

        Returns:
            KPI value or None.
        """
        key = f"kpi:{kpi_name}"
        return await self.get(key)

    async def set_config(self, config_key: str, config_value: Any) -> bool:
        """Cache a configuration value.

        Args:
            config_key: Configuration key.
            config_value: Configuration value.

        Returns:
            True if successful.
        """
        key = f"config:{config_key}"
        return await self.set(key, config_value, ttl=3600)  # 1-hour TTL

    async def get_config(self, config_key: str) -> Optional[Any]:
        """Get a cached configuration value.

        Args:
            config_key: Configuration key.

        Returns:
            Configuration value or None.
        """
        key = f"config:{config_key}"
        return await self.get(key)

    async def clear_pattern(self, pattern: str) -> int:
        """Clear all keys matching a pattern.

        Args:
            pattern: Key pattern (supports * wildcard).

        Returns:
            Number of keys cleared.
        """
        async with self._lock:
            import fnmatch

            keys_to_delete = []
            for key in self._cache.keys():
                if fnmatch.fnmatch(key, pattern):
                    keys_to_delete.append(key)

            for key in keys_to_delete:
                del self._cache[key]

            self._update_memory_usage()
            return len(keys_to_delete)

    def _update_memory_usage(self) -> None:
        """Update memory usage statistics."""
        total_size = 0
        for entry in self._cache.values():
            # Rough estimate of memory usage
            total_size += len(str(entry.value)) + 100  # Entry overhead
        self._stats["memory_used"] = total_size

    async def cleanup_expired(self) -> int:
        """Remove all expired entries from cache.

        Returns:
            Number of entries removed.
        """
        async with self._lock:
            expired_keys = [
                key for key, entry in self._cache.items() if entry.is_expired()
            ]

            for key in expired_keys:
                del self._cache[key]
                self._stats["evictions"] += 1

            self._update_memory_usage()
            return len(expired_keys)

    @property
    def stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        total_requests = self._stats["hits"] + self._stats["misses"]
        hit_rate = self._stats["hits"] / total_requests if total_requests > 0 else 0

        return {
            **self._stats,
            "total_requests": total_requests,
            "hit_rate": hit_rate,
            "entry_count": len(self._cache),
        }


@dataclass
class AuditEntry:
    """Represents an audit log entry.

    Attributes:
        id: Unique identifier.
        timestamp: Entry timestamp.
        action: Action performed.
        entity_type: Type of entity.
        entity_id: Entity identifier.
        user_id: User who performed the action.
        old_value: Previous value (for updates).
        new_value: New value.
        metadata: Additional metadata.
        previous_hash: Hash of previous entry for chain validation.
        current_hash: Hash of this entry.
    """

    id: Optional[int] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    action: str = ""
    entity_type: str = ""
    entity_id: str = ""
    user_id: Optional[str] = None
    old_value: Optional[Dict[str, Any]] = None
    new_value: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None
    previous_hash: Optional[str] = None
    current_hash: Optional[str] = None

    def compute_hash(self) -> str:
        """Compute cryptographic hash for tamper detection.

        Returns:
            SHA-256 hash of the entry.
        """
        data = {
            "timestamp": self.timestamp.isoformat(),
            "action": self.action,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "user_id": self.user_id,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "metadata": self.metadata,
            "previous_hash": self.previous_hash,
        }
        content = json.dumps(data, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "action": self.action,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "user_id": self.user_id,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "metadata": self.metadata,
            "previous_hash": self.previous_hash,
            "current_hash": self.current_hash,
        }


class AuditLogger:
    """Tamper-evident audit logging system.

    This class provides cryptographic audit logging with chain
    validation for detecting tampering with audit records.

    Attributes:
        connection_pool: Database connection pool.
        last_hash: Hash of the last audit entry.
    """

    def __init__(self, connection_pool: DatabaseConnectionPool) -> None:
        """Initialize the audit logger.

        Args:
            connection_pool: Database connection pool.
        """
        self._pool = connection_pool
        self._last_hash: Optional[str] = None
        self._lock = asyncio.Lock()
        self._pending_entries: List[AuditEntry] = []

    async def initialize(self) -> None:
        """Initialize the audit logger and get last hash."""
        query = """
            SELECT current_hash FROM audit_log
            ORDER BY log_id DESC LIMIT 1
        """
        result = await self._pool.fetch_one(query)
        if result:
            self._last_hash = result.get("current_hash")
        logger.info(f"AuditLogger initialized, last_hash: {self._last_hash}")

    async def log_action(
        self,
        action: str,
        entity_type: str,
        entity_id: str,
        user_id: Optional[str] = None,
        old_value: Optional[Dict[str, Any]] = None,
        new_value: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEntry:
        """Log an action to the audit trail.

        Args:
            action: Action performed (CREATE, UPDATE, DELETE, etc.).
            entity_type: Type of entity affected.
            entity_id: Identifier of the entity.
            user_id: User who performed the action.
            old_value: Previous state (for updates).
            new_value: New state.
            metadata: Additional context.

        Returns:
            Created audit entry.
        """
        async with self._lock:
            entry = AuditEntry(
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                user_id=user_id,
                old_value=old_value,
                new_value=new_value,
                metadata=metadata,
                previous_hash=self._last_hash,
            )

            # Compute hash for this entry
            entry.current_hash = entry.compute_hash()

            # Persist to database
            await self._persist_entry(entry)

            # Update last hash
            self._last_hash = entry.current_hash

            logger.debug(
                f"Audit log: {action} on {entity_type}:{entity_id} by {user_id}"
            )
            return entry

    async def _persist_entry(self, entry: AuditEntry) -> None:
        """Persist an audit entry to the database.

        Args:
            entry: Audit entry to persist.
        """
        # Map AuditEntry fields to audit_log table columns
        # Audit logs are append-only, so we use INSERT instead of UPSERT
        query = """
            INSERT INTO audit_log (
                event_timestamp,
                event_type,
                actor_user_id,
                target_resource,
                target_resource_type,
                action_performed,
                action_status,
                previous_value,
                new_value,
                previous_hash,
                current_hash,
                chain_validated
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            RETURNING log_id
        """
        params = (
            entry.timestamp,
            self._map_action_to_event_type(entry.action),
            entry.user_id,
            entry.entity_id,
            entry.entity_type,
            entry.action,
            "SUCCESS",  # action_status
            json.dumps(entry.old_value) if entry.old_value else None,
            json.dumps(entry.new_value) if entry.new_value else None,
            entry.previous_hash,
            entry.current_hash,
            False,  # chain_validated - newly created entries need validation
        )

        result = await self._pool.execute(query, params)
        entry.id = result.get("log_id")

    def _map_action_to_event_type(self, action: str) -> str:
        """Map action string to security_event_type enum value.

        Args:
            action: The action string (e.g., 'CREATE', 'UPDATE', 'DELETE').

        Returns:
            Corresponding security event type.
        """
        action_upper = action.upper()
        action_mapping = {
            "CREATE": "CONFIGURATION_CHANGE",
            "UPDATE": "CONFIGURATION_CHANGE",
            "DELETE": "CONFIGURATION_CHANGE",
            "CONFIG_UPDATE": "CONFIGURATION_CHANGE",
            "LOGIN": "USER_LOGIN",
            "LOGOUT": "USER_LOGOUT",
            "SECURITY_USER_LOGIN": "USER_LOGIN",
            "SECURITY_USER_LOGOUT": "USER_LOGOUT",
            "SECURITY_INCIDENT": "SECURITY_INCIDENT",
            "ALARM_ACKNOWLEDGE": "ALARM_MANAGEMENT",
            "ALARM_CLEAR": "ALARM_MANAGEMENT",
            "ALARM_ESCALATE": "ALARM_MANAGEMENT",
            "EXPORT": "EXPORT_OPERATION",
            "API_CALL": "API_CALL",
        }
        return action_mapping.get(action_upper, "DATA_ACCESS")

    async def log_alarm_action(
        self,
        action: str,
        alarm_id: str,
        alarm_data: Dict[str, Any],
        user_id: Optional[str] = None,
        changes: Optional[Dict[str, Any]] = None,
    ) -> AuditEntry:
        """Log an alarm-related action.

        Args:
            action: Action performed.
            alarm_id: Alarm identifier.
            alarm_data: Alarm data.
            user_id: User who performed the action.
            changes: Changes made.

        Returns:
            Created audit entry.
        """
        return await self.log_action(
            action=action,
            entity_type="alarm",
            entity_id=alarm_id,
            user_id=user_id,
            new_value=alarm_data,
            metadata={"changes": changes},
        )

    async def log_config_change(
        self,
        config_key: str,
        old_value: Any,
        new_value: Any,
        user_id: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> AuditEntry:
        """Log a configuration change.

        Args:
            config_key: Configuration key.
            old_value: Previous value.
            new_value: New value.
            user_id: User who made the change.
            reason: Reason for the change.

        Returns:
            Created audit entry.
        """
        return await self.log_action(
            action="CONFIG_UPDATE",
            entity_type="configuration",
            entity_id=config_key,
            user_id=user_id,
            old_value={"value": old_value},
            new_value={"value": new_value},
            metadata={"reason": reason},
        )

    async def log_security_event(
        self,
        event_type: str,
        details: Dict[str, Any],
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        severity: str = "INFO",
    ) -> AuditEntry:
        """Log a security-related event.

        Args:
            event_type: Type of security event.
            details: Event details.
            user_id: Associated user.
            ip_address: Source IP address.
            severity: Event severity.

        Returns:
            Created audit entry.
        """
        return await self.log_action(
            action=f"SECURITY_{event_type}",
            entity_type="security_event",
            entity_id=details.get("event_id", ""),
            user_id=user_id,
            new_value=details,
            metadata={
                "ip_address": ip_address,
                "severity": severity,
            },
        )

    async def validate_chain(self, limit: int = 1000) -> Tuple[bool, List[Dict[str, Any]]]:
        """Validate the integrity of the audit chain.

        Args:
            limit: Maximum number of entries to validate.

        Returns:
            Tuple of (is_valid, list of violations).
        """
        violations = []
        query = """
            SELECT * FROM audit_log
            ORDER BY log_id ASC
            LIMIT $1
        """

        entries = await self._pool.fetch_all(query, (limit,))
        previous_hash = None

        for entry_data in entries:
            entry = AuditEntry(
                id=entry_data.get("log_id"),
                timestamp=datetime.fromisoformat(entry_data["event_timestamp"]),
                action=entry_data.get("action_performed"),
                entity_type=entry_data.get("target_resource_type"),
                entity_id=entry_data.get("target_resource"),
                user_id=entry_data.get("actor_user_id"),
                old_value=json.loads(entry_data["previous_value"]) if entry_data.get("previous_value") else None,
                new_value=json.loads(entry_data["new_value"]) if entry_data.get("new_value") else None,
                metadata=None,  # metadata not stored in audit_log table
                previous_hash=entry_data.get("previous_hash"),
                current_hash=entry_data.get("current_hash"),
            )

            # Verify hash chain
            if entry.previous_hash != previous_hash:
                violations.append({
                    "entry_id": entry.id,
                    "violation": "broken_chain",
                    "expected_previous": previous_hash,
                    "actual_previous": entry.previous_hash,
                })

            # Verify entry hash
            computed_hash = entry.compute_hash()
            if computed_hash != entry.current_hash:
                violations.append({
                    "entry_id": entry.id,
                    "violation": "tampered_hash",
                    "stored_hash": entry.current_hash,
                    "computed_hash": computed_hash,
                })

            previous_hash = entry.current_hash

        is_valid = len(violations) == 0
        return is_valid, violations

    async def query_audit_trail(
        self,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditEntry]:
        """Query the audit trail with filters.

        Args:
            entity_type: Filter by entity type.
            entity_id: Filter by entity ID.
            user_id: Filter by user ID.
            action: Filter by action.
            start_time: Filter by start time.
            end_time: Filter by end time.
            limit: Maximum results.
            offset: Result offset.

        Returns:
            List of matching audit entries.
        """
        conditions = []
        params: List[Any] = []
        param_idx = 1

        if entity_type:
            conditions.append(f"target_resource_type = ${param_idx}")
            params.append(entity_type)
            param_idx += 1

        if entity_id:
            conditions.append(f"target_resource = ${param_idx}")
            params.append(entity_id)
            param_idx += 1

        if user_id:
            conditions.append(f"actor_user_id = ${param_idx}")
            params.append(user_id)
            param_idx += 1

        if action:
            conditions.append(f"action_performed = ${param_idx}")
            params.append(action)
            param_idx += 1

        if start_time:
            conditions.append(f"event_timestamp >= ${param_idx}")
            params.append(start_time)
            param_idx += 1

        if end_time:
            conditions.append(f"event_timestamp <= ${param_idx}")
            params.append(end_time)
            param_idx += 1

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        query = f"""
            SELECT * FROM audit_log
            WHERE {where_clause}
            ORDER BY event_timestamp DESC
            LIMIT ${param_idx} OFFSET ${param_idx + 1}
        """
        params.extend([limit, offset])

        results = await self._pool.fetch_all(query, tuple(params))

        entries = []
        for row in results:
            entry = AuditEntry(
                id=row.get("log_id"),
                timestamp=datetime.fromisoformat(row["event_timestamp"]),
                action=row.get("action_performed"),
                entity_type=row.get("target_resource_type"),
                entity_id=row.get("target_resource"),
                user_id=row.get("actor_user_id"),
                old_value=json.loads(row["previous_value"]) if row.get("previous_value") else None,
                new_value=json.loads(row["new_value"]) if row.get("new_value") else None,
                metadata=None,  # metadata not stored in audit_log table
                previous_hash=row.get("previous_hash"),
                current_hash=row.get("current_hash"),
            )
            entries.append(entry)

        return entries

    async def export_audit_trail(
        self,
        start_time: datetime,
        end_time: datetime,
        format: str = "json",
    ) -> str:
        """Export audit trail for a time range.

        Args:
            start_time: Export start time.
            end_time: Export end time.
            format: Export format (json or csv).

        Returns:
            Exported data as string.
        """
        entries = await self.query_audit_trail(
            start_time=start_time,
            end_time=end_time,
            limit=10000,
        )

        if format == "json":
            return json.dumps(
                [entry.to_dict() for entry in entries],
                indent=2,
            )
        elif format == "csv":
            import csv
            import io

            output = io.StringIO()
            writer = csv.DictWriter(
                output,
                fieldnames=[
                    "id", "timestamp", "action", "entity_type",
                    "entity_id", "user_id", "previous_hash", "current_hash"
                ],
            )
            writer.writeheader()
            for entry in entries:
                writer.writerow({
                    "id": entry.id,
                    "timestamp": entry.timestamp.isoformat(),
                    "action": entry.action,
                    "entity_type": entry.entity_type,
                    "entity_id": entry.entity_id,
                    "user_id": entry.user_id,
                    "previous_hash": entry.previous_hash,
                    "current_hash": entry.current_hash,
                })
            return output.getvalue()
        else:
            raise ValueError(f"Unsupported export format: {format}")


class DatabaseAdapter:
    """Main database adapter coordinating all database operations.

    This class provides a unified interface for database operations
    including connection management, TimescaleDB writes, caching,
    and audit logging.

    Attributes:
        config: Database configuration.
        connection_pool: Connection pool instance.
        timescale_writer: TimescaleDB writer instance.
        cache: Redis cache instance.
        audit_logger: Audit logger instance.
    """

    def __init__(self, config: Optional[ConnectionConfig] = None) -> None:
        """Initialize the database adapter.

        Args:
            config: Database connection configuration.
        """
        self.config = config or ConnectionConfig()
        self.connection_pool = DatabaseConnectionPool(self.config)
        self.timescale_writer = TimescaleDBWriter(self.connection_pool)
        self.cache = RedisCache()
        self.audit_logger = AuditLogger(self.connection_pool)
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize all database components."""
        if self._initialized:
            return

        logger.info("Initializing DatabaseAdapter...")

        await self.connection_pool.initialize()
        await self.audit_logger.initialize()

        self._initialized = True
        logger.info("DatabaseAdapter initialized successfully")

    async def close(self) -> None:
        """Close all database connections."""
        logger.info("Closing DatabaseAdapter...")
        await self.connection_pool.close()
        self._initialized = False
        logger.info("DatabaseAdapter closed")

    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on all components.

        Returns:
            Health check results.
        """
        results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "healthy",
            "components": {},
        }

        # Check connection pool
        try:
            await self.connection_pool.execute("SELECT 1")
            results["components"]["connection_pool"] = {
                "status": "healthy",
                "stats": self.connection_pool.stats.__dict__,
            }
        except Exception as e:
            results["components"]["connection_pool"] = {
                "status": "unhealthy",
                "error": str(e),
            }
            results["status"] = "degraded"

        # Check cache
        cache_stats = self.cache.stats
        results["components"]["cache"] = {
            "status": "healthy",
            "stats": cache_stats,
        }

        # Check audit logger
        results["components"]["audit_logger"] = {
            "status": "healthy",
            "last_hash": self.audit_logger._last_hash,
        }

        return results

    async def __aenter__(self) -> DatabaseAdapter:
        """Async context manager entry."""
        await self.initialize()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.close()


# Module-level convenience functions
async def create_adapter(
    host: str = "localhost",
    port: int = 5432,
    database: str = "oss_db",
    username: str = "postgres",
    password: str = "",
) -> DatabaseAdapter:
    """Create and initialize a database adapter.

    Args:
        host: Database host.
        port: Database port.
        database: Database name.
        username: Database username.
        password: Database password.

    Returns:
        Initialized database adapter.
    """
    config = ConnectionConfig(
        host=host,
        port=port,
        database=database,
        username=username,
        password=password,
    )
    adapter = DatabaseAdapter(config)
    await adapter.initialize()
    return adapter


__all__ = [
    # Main classes
    "DatabaseAdapter",
    "DatabaseConnectionPool",
    "TimescaleDBWriter",
    "RedisCache",
    "AuditLogger",
    # Configuration classes
    "ConnectionConfig",
    "HypertableConfig",
    "CacheEntry",
    "AuditEntry",
    # Exceptions
    "DatabaseError",
    "ConnectionError",
    "ConstraintViolationError",
    "DeadlockError",
    "QueryTimeoutError",
    # Enums
    "DatabaseType",
    # Utility functions
    "create_adapter",
]
