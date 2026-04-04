"""
Kafka Streams Topology Module.

This module provides stream processing capabilities for real-time data transformation
in the unified OSS framework. It handles message consumption from raw vendor topics,
processing, and routing to unified output topics.

The module supports:
- Multi-vendor alarm, PM, and config data processing
- Message type detection and routing
- Dead-letter queue for error handling
- Backpressure management
- Message batching and offset management
"""

import asyncio
import json
import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import (
    Any,
    AsyncIterator,
    Callable,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

# Configure module logger
logger = logging.getLogger(__name__)


class MessageType(Enum):
    """Enumeration of supported message types."""
    ALARM = "alarm"
    PM = "pm"
    CONFIG = "config"
    UNKNOWN = "unknown"


class VendorType(Enum):
    """Enumeration of supported vendor types."""
    ERICSSON = "ericsson"
    HUAWEI = "huawei"
    UNKNOWN = "unknown"


@dataclass
class KafkaConfig:
    """Configuration for Kafka connection and processing.
    
    Attributes:
        bootstrap_servers: Comma-separated list of Kafka broker addresses.
        consumer_group_id: Consumer group identifier for offset management.
        auto_offset_reset: Offset reset policy ('earliest' or 'latest').
        enable_auto_commit: Whether to auto-commit consumer offsets.
        session_timeout_ms: Consumer session timeout in milliseconds.
        max_poll_records: Maximum records per poll operation.
        batch_size: Number of messages to process in a batch.
        batch_timeout_ms: Maximum wait time for batch accumulation.
        producer_acks: Producer acknowledgment setting ('0', '1', 'all').
        producer_timeout_ms: Producer acknowledgment timeout.
        max_retries: Maximum retry attempts for failed operations.
        retry_backoff_ms: Backoff time between retries in milliseconds.
    """
    bootstrap_servers: str = "localhost:9092"
    consumer_group_id: str = "unified-oss-streams"
    auto_offset_reset: str = "earliest"
    enable_auto_commit: bool = False
    session_timeout_ms: int = 30000
    max_poll_records: int = 500
    batch_size: int = 100
    batch_timeout_ms: int = 5000
    producer_acks: str = "all"
    producer_timeout_ms: int = 30000
    max_retries: int = 3
    retry_backoff_ms: int = 1000


@dataclass
class Message:
    """Represents a Kafka message with metadata.
    
    Attributes:
        topic: Source topic name.
        partition: Topic partition number.
        offset: Message offset within partition.
        key: Message key (optional).
        value: Message value/payload.
        headers: Message headers as key-value pairs.
        timestamp: Message timestamp in milliseconds.
        message_type: Detected message type.
        vendor: Detected vendor type.
        error: Processing error if any.
    """
    topic: str
    partition: int
    offset: int
    key: Optional[bytes] = None
    value: Optional[bytes] = None
    headers: Dict[str, bytes] = field(default_factory=dict)
    timestamp: int = 0
    message_type: MessageType = MessageType.UNKNOWN
    vendor: VendorType = VendorType.UNKNOWN
    error: Optional[str] = None

    def __post_init__(self) -> None:
        """Initialize derived fields after construction."""
        if not self.timestamp:
            self.timestamp = int(datetime.now(timezone.utc).timestamp() * 1000)

    def deserialize_value(self) -> Optional[Dict[str, Any]]:
        """Deserialize message value to dictionary.
        
        Attempts JSON parsing first, then falls back to XML parsing.
        
        Returns:
            Parsed dictionary or None if parsing fails.
        """
        if not self.value:
            return None
        
        try:
            decoded = self.value.decode("utf-8")
            
            # Try JSON parsing
            try:
                return json.loads(decoded)
            except json.JSONDecodeError:
                pass
            
            # Try XML parsing
            try:
                root = ET.fromstring(decoded)
                return self._xml_to_dict(root)
            except ET.ParseError:
                pass
            
            logger.warning(
                f"Failed to parse message value from topic {self.topic}",
                extra={"partition": self.partition, "offset": self.offset}
            )
            return None
        except UnicodeDecodeError as e:
            self.error = f"Unicode decode error: {e}"
            logger.error(f"Unicode decode error: {e}")
            return None

    def _xml_to_dict(self, element: ET.Element) -> Dict[str, Any]:
        """Convert XML element to dictionary recursively.
        
        Args:
            element: XML element to convert.
            
        Returns:
            Dictionary representation of XML element.
        """
        result: Dict[str, Any] = {}
        
        if element.attrib:
            result["@attributes"] = dict(element.attrib)
        
        if element.text and element.text.strip():
            result["#text"] = element.text.strip()
        
        for child in element:
            child_dict = self._xml_to_dict(child)
            if child.tag in result:
                if not isinstance(result[child.tag], list):
                    result[child.tag] = [result[child.tag]]
                result[child.tag].append(child_dict)
            else:
                result[child.tag] = child_dict
        
        return result


@dataclass
class BatchResult:
    """Result of processing a batch of messages.
    
    Attributes:
        processed_count: Number of successfully processed messages.
        failed_count: Number of failed messages.
        sent_to_dlq: Number of messages sent to dead-letter queue.
        processing_time_ms: Total processing time in milliseconds.
        errors: List of error messages encountered.
    """
    processed_count: int = 0
    failed_count: int = 0
    sent_to_dlq: int = 0
    processing_time_ms: int = 0
    errors: List[str] = field(default_factory=list)


class TopicManager:
    """Manages Kafka topic creation and configuration.
    
    Provides utilities for topic management including creation,
    configuration, and metadata retrieval.
    
    Attributes:
        config: Kafka configuration instance.
        topics: Set of managed topic names.
    """

    # Topic definitions
    RAW_TOPICS: Dict[str, Tuple[MessageType, VendorType]] = {
        "raw-alarms-ericsson": (MessageType.ALARM, VendorType.ERICSSON),
        "raw-alarms-huawei": (MessageType.ALARM, VendorType.HUAWEI),
        "raw-pm-ericsson": (MessageType.PM, VendorType.ERICSSON),
        "raw-pm-huawei": (MessageType.PM, VendorType.HUAWEI),
        "raw-config-ericsson": (MessageType.CONFIG, VendorType.ERICSSON),
        "raw-config-huawei": (MessageType.CONFIG, VendorType.HUAWEI),
    }

    UNIFIED_TOPICS: Dict[str, MessageType] = {
        "unified-alarms": MessageType.ALARM,
        "unified-pm": MessageType.PM,
        "unified-config": MessageType.CONFIG,
    }

    DEAD_LETTER_TOPIC: str = "dead-letter-queue"

    def __init__(self, config: KafkaConfig) -> None:
        """Initialize TopicManager.
        
        Args:
            config: Kafka configuration instance.
        """
        self.config = config
        self.topics: Set[str] = set()
        self._topic_configs: Dict[str, Dict[str, Any]] = {}
        logger.info("TopicManager initialized")

    def get_raw_topics(self) -> List[str]:
        """Get list of all raw input topics.
        
        Returns:
            List of raw topic names.
        """
        return list(self.RAW_TOPICS.keys())

    def get_unified_topics(self) -> List[str]:
        """Get list of all unified output topics.
        
        Returns:
            List of unified topic names.
        """
        return list(self.UNIFIED_TOPICS.keys())

    def get_all_topics(self) -> List[str]:
        """Get list of all managed topics.
        
        Returns:
            List of all topic names including dead-letter queue.
        """
        all_topics = list(self.RAW_TOPICS.keys()) + list(self.UNIFIED_TOPICS.keys())
        all_topics.append(self.DEAD_LETTER_TOPIC)
        return all_topics

    def get_topic_info(self, topic: str) -> Tuple[MessageType, VendorType]:
        """Get message type and vendor for a raw topic.
        
        Args:
            topic: Topic name to query.
            
        Returns:
            Tuple of (message_type, vendor) or (UNKNOWN, UNKNOWN) if not found.
        """
        if topic in self.RAW_TOPICS:
            return self.RAW_TOPICS[topic]
        return (MessageType.UNKNOWN, VendorType.UNKNOWN)

    def get_unified_topic_for_type(self, message_type: MessageType) -> Optional[str]:
        """Get unified output topic for a message type.
        
        Args:
            message_type: Message type to look up.
            
        Returns:
            Unified topic name or None if not found.
        """
        for topic, mtype in self.UNIFIED_TOPICS.items():
            if mtype == message_type:
                return topic
        return None

    def create_topic_config(
        self,
        topic: str,
        partitions: int = 3,
        replication_factor: int = 1,
        retention_ms: int = 604800000,  # 7 days
        compression_type: str = "gzip"
    ) -> Dict[str, Any]:
        """Create topic configuration dictionary.
        
        Args:
            topic: Topic name.
            partitions: Number of partitions.
            replication_factor: Replication factor.
            retention_ms: Message retention time in milliseconds.
            compression_type: Compression type for the topic.
            
        Returns:
            Topic configuration dictionary.
        """
        config = {
            "topic": topic,
            "num_partitions": partitions,
            "replication_factor": replication_factor,
            "configs": {
                "retention.ms": str(retention_ms),
                "compression.type": compression_type,
                "cleanup.policy": "delete",
            }
        }
        self._topic_configs[topic] = config
        self.topics.add(topic)
        return config

    async def ensure_topics_exist(self) -> bool:
        """Ensure all required topics exist, creating if necessary.
        
        Simulates topic creation for the aiokafka-style interface.
        
        Returns:
            True if all topics exist or were created successfully.
        """
        logger.info("Ensuring all required topics exist...")
        
        for topic in self.get_all_topics():
            if topic == self.DEAD_LETTER_TOPIC:
                config = self.create_topic_config(
                    topic,
                    partitions=1,
                    retention_ms=86400000,  # 1 day for DLQ
                )
            else:
                config = self.create_topic_config(topic)
            
            logger.debug(f"Topic configuration: {config}")
            # Simulate async topic creation
            await asyncio.sleep(0.01)
        
        logger.info(f"All {len(self.topics)} topics ready")
        return True

    def get_topic_metadata(self, topic: str) -> Optional[Dict[str, Any]]:
        """Get metadata for a specific topic.
        
        Args:
            topic: Topic name to query.
            
        Returns:
            Topic metadata dictionary or None if not found.
        """
        return self._topic_configs.get(topic)


class KafkaConsumerWrapper:
    """Async wrapper for Kafka message consumption.
    
    Provides an aiokafka-style interface for consuming messages from
    multiple topics with support for batching and offset management.
    
    Attributes:
        config: Kafka configuration instance.
        topics: List of topics to consume from.
        topic_manager: TopicManager instance for topic metadata.
    """

    def __init__(
        self,
        config: KafkaConfig,
        topics: List[str],
        topic_manager: TopicManager
    ) -> None:
        """Initialize KafkaConsumerWrapper.
        
        Args:
            config: Kafka configuration instance.
            topics: List of topics to consume from.
            topic_manager: TopicManager instance.
        """
        self.config = config
        self.topics = topics
        self.topic_manager = topic_manager
        self._connected = False
        self._paused = False
        self._offsets: Dict[str, Dict[int, int]] = {}
        self._pending_commits: Dict[str, Dict[int, int]] = {}
        self._message_queue: asyncio.Queue[Message] = asyncio.Queue()
        self._consumer_task: Optional[asyncio.Task[None]] = None
        logger.info(f"KafkaConsumerWrapper initialized for topics: {topics}")

    async def start(self) -> None:
        """Start the consumer and connect to Kafka brokers.
        
        Raises:
            ConnectionError: If connection to Kafka fails after retries.
        """
        logger.info("Starting Kafka consumer...")
        
        for attempt in range(self.config.max_retries):
            try:
                # Simulate connection establishment
                await asyncio.sleep(0.1)
                self._connected = True
                
                # Initialize offsets for all topic partitions
                for topic in self.topics:
                    self._offsets[topic] = {0: 0, 1: 0, 2: 0}
                    self._pending_commits[topic] = {}
                
                logger.info("Kafka consumer started successfully")
                return
            except Exception as e:
                logger.warning(
                    f"Connection attempt {attempt + 1} failed: {e}",
                    extra={"retry_backoff_ms": self.config.retry_backoff_ms}
                )
                if attempt < self.config.max_retries - 1:
                    await asyncio.sleep(self.config.retry_backoff_ms / 1000)
        
        raise ConnectionError("Failed to connect to Kafka after max retries")

    async def stop(self) -> None:
        """Stop the consumer and release resources."""
        logger.info("Stopping Kafka consumer...")
        
        if self._consumer_task:
            self._consumer_task.cancel()
            try:
                await self._consumer_task
            except asyncio.CancelledError:
                pass
        
        # Commit any pending offsets
        await self.commit()
        
        self._connected = False
        logger.info("Kafka consumer stopped")

    async def __aenter__(self) -> "KafkaConsumerWrapper":
        """Async context manager entry."""
        await self.start()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.stop()

    def pause(self, topic: Optional[str] = None) -> None:
        """Pause consumption for backpressure handling.
        
        Args:
            topic: Specific topic to pause, or None to pause all.
        """
        self._paused = True
        logger.debug(f"Consumer paused (topic={topic})")

    def resume(self, topic: Optional[str] = None) -> None:
        """Resume consumption after pause.
        
        Args:
            topic: Specific topic to resume, or None to resume all.
        """
        self._paused = False
        logger.debug(f"Consumer resumed (topic={topic})")

    async def getone(self) -> Optional[Message]:
        """Get a single message from the consumer.
        
        Returns:
            Next available message or None if no messages available.
        """
        if not self._connected or self._paused:
            return None
        
        # Simulate message consumption
        await asyncio.sleep(0.001)
        
        # Generate simulated message
        import random
        if self.topics and random.random() < 0.1:  # 10% chance of message
            topic = random.choice(self.topics)
            partition = random.randint(0, 2)
            offset = self._offsets[topic][partition]
            self._offsets[topic][partition] = offset + 1
            
            message_type, vendor = self.topic_manager.get_topic_info(topic)
            
            return Message(
                topic=topic,
                partition=partition,
                offset=offset,
                message_type=message_type,
                vendor=vendor,
            )
        
        return None

    async def getmany(
        self,
        max_records: Optional[int] = None,
        timeout_ms: Optional[int] = None
    ) -> AsyncIterator[Message]:
        """Get multiple messages in a batch.
        
        Args:
            max_records: Maximum number of records to return.
            timeout_ms: Maximum wait time for batch accumulation.
            
        Yields:
            Messages from the consumer batch.
        """
        max_records = max_records or self.config.max_poll_records
        timeout_ms = timeout_ms or self.config.batch_timeout_ms
        
        batch: List[Message] = []
        start_time = asyncio.get_event_loop().time()
        
        while len(batch) < max_records:
            if self._paused:
                await asyncio.sleep(0.1)
                continue
            
            elapsed_ms = int((asyncio.get_event_loop().time() - start_time) * 1000)
            if elapsed_ms >= timeout_ms:
                break
            
            message = await self.getone()
            if message:
                batch.append(message)
            else:
                await asyncio.sleep(0.01)
        
        for message in batch:
            yield message

    async def commit(self, offsets: Optional[Dict[str, Dict[int, int]]] = None) -> None:
        """Commit consumer offsets.
        
        Args:
            offsets: Specific offsets to commit, or None for pending commits.
        """
        if offsets:
            self._pending_commits.update(offsets)
        
        if self._pending_commits:
            logger.debug(f"Committing offsets: {self._pending_commits}")
            # Simulate offset commit
            await asyncio.sleep(0.01)
            self._pending_commits.clear()

    async def seek_to_beginning(self, topic: Optional[str] = None) -> None:
        """Reset consumer offsets to beginning.
        
        Args:
            topic: Specific topic to reset, or None for all topics.
        """
        topics_to_reset = [topic] if topic else self.topics
        for t in topics_to_reset:
            if t in self._offsets:
                for partition in self._offsets[t]:
                    self._offsets[t][partition] = 0
        logger.info(f"Reset offsets to beginning for topics: {topics_to_reset}")

    async def seek_to_end(self, topic: Optional[str] = None) -> None:
        """Reset consumer offsets to end.
        
        Args:
            topic: Specific topic to reset, or None for all topics.
        """
        topics_to_reset = [topic] if topic else self.topics
        for t in topics_to_reset:
            if t in self._offsets:
                for partition in self._offsets[t]:
                    # Set to high value to simulate end
                    self._offsets[t][partition] = 999999999
        logger.info(f"Reset offsets to end for topics: {topics_to_reset}")

    @property
    def assignment(self) -> List[Tuple[str, int]]:
        """Get current partition assignment.
        
        Returns:
            List of (topic, partition) tuples.
        """
        assignment: List[Tuple[str, int]] = []
        for topic in self.topics:
            for partition in self._offsets.get(topic, {}).keys():
                assignment.append((topic, partition))
        return assignment

    def highwater(self, topic: str, partition: int) -> int:
        """Get highwater offset for a partition.
        
        Args:
            topic: Topic name.
            partition: Partition number.
            
        Returns:
            Highwater offset (last committed offset + 1).
        """
        return self._offsets.get(topic, {}).get(partition, 0)

    def position(self, topic: str, partition: int) -> int:
        """Get current consumer position for a partition.
        
        Args:
            topic: Topic name.
            partition: Partition number.
            
        Returns:
            Current consumer position.
        """
        return self._offsets.get(topic, {}).get(partition, 0)


class KafkaProducerWrapper:
    """Async wrapper for Kafka message production.
    
    Provides an aiokafka-style interface for producing messages to
    Kafka topics with support for batching and acknowledgment handling.
    
    Attributes:
        config: Kafka configuration instance.
        topic_manager: TopicManager instance for topic metadata.
    """

    def __init__(self, config: KafkaConfig, topic_manager: TopicManager) -> None:
        """Initialize KafkaProducerWrapper.
        
        Args:
            config: Kafka configuration instance.
            topic_manager: TopicManager instance.
        """
        self.config = config
        self.topic_manager = topic_manager
        self._connected = False
        self._pending_acks: Dict[int, asyncio.Future[None]] = {}
        self._sequence_id = 0
        self._batch_buffer: Dict[str, List[Dict[str, Any]]] = {}
        logger.info("KafkaProducerWrapper initialized")

    async def start(self) -> None:
        """Start the producer and connect to Kafka brokers.
        
        Raises:
            ConnectionError: If connection to Kafka fails after retries.
        """
        logger.info("Starting Kafka producer...")
        
        for attempt in range(self.config.max_retries):
            try:
                # Simulate connection establishment
                await asyncio.sleep(0.1)
                self._connected = True
                logger.info("Kafka producer started successfully")
                return
            except Exception as e:
                logger.warning(
                    f"Connection attempt {attempt + 1} failed: {e}",
                    extra={"retry_backoff_ms": self.config.retry_backoff_ms}
                )
                if attempt < self.config.max_retries - 1:
                    await asyncio.sleep(self.config.retry_backoff_ms / 1000)
        
        raise ConnectionError("Failed to connect to Kafka after max retries")

    async def stop(self) -> None:
        """Stop the producer and flush pending messages."""
        logger.info("Stopping Kafka producer...")
        
        # Wait for pending acknowledgments with timeout
        if self._pending_acks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*self._pending_acks.values(), return_exceptions=True),
                    timeout=5.0
                )
            except asyncio.TimeoutError:
                logger.warning("Timeout waiting for pending acknowledgments")
        
        # Flush any remaining batch buffer
        await self.flush()
        
        self._connected = False
        logger.info("Kafka producer stopped")

    async def __aenter__(self) -> "KafkaProducerWrapper":
        """Async context manager entry."""
        await self.start()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.stop()

    def _get_sequence_id(self) -> int:
        """Generate unique sequence ID for message tracking.
        
        Returns:
            Unique sequence ID.
        """
        self._sequence_id += 1
        return self._sequence_id

    async def send(
        self,
        topic: str,
        value: Union[bytes, str, Dict[str, Any], None] = None,
        key: Optional[Union[bytes, str]] = None,
        partition: Optional[int] = None,
        timestamp_ms: Optional[int] = None,
        headers: Optional[Dict[str, bytes]] = None
    ) -> asyncio.Future[None]:
        """Send a message to a Kafka topic.
        
        Args:
            topic: Target topic name.
            value: Message value (will be serialized if not bytes).
            key: Message key (optional).
            partition: Target partition (optional, auto-selected if None).
            timestamp_ms: Message timestamp (optional).
            headers: Message headers (optional).
            
        Returns:
            Future that resolves when message is acknowledged.
            
        Raises:
            RuntimeError: If producer is not connected.
        """
        if not self._connected:
            raise RuntimeError("Producer is not connected")
        
        # Serialize value
        if value is None:
            serialized_value: Optional[bytes] = None
        elif isinstance(value, bytes):
            serialized_value = value
        elif isinstance(value, str):
            serialized_value = value.encode("utf-8")
        elif isinstance(value, dict):
            serialized_value = json.dumps(value).encode("utf-8")
        else:
            serialized_value = str(value).encode("utf-8")
        
        # Serialize key
        serialized_key: Optional[bytes] = None
        if key is not None:
            if isinstance(key, bytes):
                serialized_key = key
            else:
                serialized_key = key.encode("utf-8")
        
        # Simulate message send
        seq_id = self._get_sequence_id()
        future: asyncio.Future[None] = asyncio.get_event_loop().create_future()
        self._pending_acks[seq_id] = future
        
        logger.debug(
            f"Sending message to topic {topic}",
            extra={
                "partition": partition,
                "key": key,
                "sequence_id": seq_id
            }
        )
        
        # Simulate async acknowledgment
        async def simulate_ack() -> None:
            await asyncio.sleep(0.01)  # Simulate network latency
            if seq_id in self._pending_acks:
                if not future.done():
                    future.set_result(None)
                del self._pending_acks[seq_id]
        
        asyncio.create_task(simulate_ack())
        
        return future

    async def send_and_wait(
        self,
        topic: str,
        value: Union[bytes, str, Dict[str, Any], None] = None,
        key: Optional[Union[bytes, str]] = None,
        partition: Optional[int] = None,
        timestamp_ms: Optional[int] = None,
        headers: Optional[Dict[str, bytes]] = None
    ) -> None:
        """Send a message and wait for acknowledgment.
        
        Args:
            topic: Target topic name.
            value: Message value.
            key: Message key (optional).
            partition: Target partition (optional).
            timestamp_ms: Message timestamp (optional).
            headers: Message headers (optional).
            
        Raises:
            asyncio.TimeoutError: If acknowledgment times out.
        """
        future = await self.send(
            topic, value, key, partition, timestamp_ms, headers
        )
        
        try:
            await asyncio.wait_for(future, timeout=self.config.producer_timeout_ms / 1000)
        except asyncio.TimeoutError:
            logger.error(f"Producer acknowledgment timeout for topic {topic}")
            raise

    async def send_batch(
        self,
        topic: str,
        messages: List[Dict[str, Any]]
    ) -> List[asyncio.Future[None]]:
        """Send multiple messages as a batch.
        
        Args:
            topic: Target topic name.
            messages: List of message dictionaries with 'value', 'key', etc.
            
        Returns:
            List of futures for each message acknowledgment.
        """
        futures: List[asyncio.Future[None]] = []
        
        for msg in messages:
            future = await self.send(
                topic=topic,
                value=msg.get("value"),
                key=msg.get("key"),
                partition=msg.get("partition"),
                timestamp_ms=msg.get("timestamp_ms"),
                headers=msg.get("headers")
            )
            futures.append(future)
        
        logger.debug(f"Sent batch of {len(messages)} messages to topic {topic}")
        return futures

    async def flush(self, timeout: Optional[float] = None) -> None:
        """Flush all pending messages.
        
        Args:
            timeout: Maximum time to wait for flush completion.
        """
        timeout = timeout or 30.0
        
        if self._pending_acks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*self._pending_acks.values(), return_exceptions=True),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                logger.warning(f"Flush timeout with {len(self._pending_acks)} pending acks")
        
        # Clear batch buffer
        self._batch_buffer.clear()
        logger.debug("Producer flush completed")

    async def create_partitions(
        self,
        topic: str,
        new_partition_count: int
    ) -> None:
        """Create additional partitions for a topic.
        
        Args:
            topic: Topic name.
            new_partition_count: New total partition count.
        """
        logger.info(f"Creating partitions for topic {topic}: {new_partition_count}")
        # Simulate partition creation
        await asyncio.sleep(0.01)


class StreamProcessor:
    """Processes and routes Kafka messages.
    
    Handles message parsing, type detection, transformation, and routing
    to appropriate output topics including dead-letter queue for errors.
    
    Attributes:
        config: Kafka configuration instance.
        topic_manager: TopicManager instance.
        consumer: KafkaConsumerWrapper instance.
        producer: KafkaProducerWrapper instance.
    """

    def __init__(
        self,
        config: KafkaConfig,
        topic_manager: TopicManager,
        consumer: KafkaConsumerWrapper,
        producer: KafkaProducerWrapper
    ) -> None:
        """Initialize StreamProcessor.
        
        Args:
            config: Kafka configuration instance.
            topic_manager: TopicManager instance.
            consumer: Kafka consumer wrapper.
            producer: Kafka producer wrapper.
        """
        self.config = config
        self.topic_manager = topic_manager
        self.consumer = consumer
        self.producer = producer
        self._running = False
        self._processors: Dict[MessageType, Callable[[Message], Dict[str, Any]]] = {}
        self._error_count = 0
        self._processed_count = 0
        logger.info("StreamProcessor initialized")

    def register_processor(
        self,
        message_type: MessageType,
        processor: Callable[[Message], Dict[str, Any]]
    ) -> None:
        """Register a custom processor for a message type.
        
        Args:
            message_type: Message type to handle.
            processor: Callable that processes messages and returns transformed data.
        """
        self._processors[message_type] = processor
        logger.info(f"Registered processor for message type: {message_type.value}")

    def detect_message_type(self, message: Message) -> MessageType:
        """Detect message type from topic name or content.
        
        Args:
            message: Message to analyze.
            
        Returns:
            Detected message type.
        """
        # First, check if type was already detected from topic
        if message.message_type != MessageType.UNKNOWN:
            return message.message_type
        
        # Try to detect from topic name
        topic_lower = message.topic.lower()
        if "alarm" in topic_lower:
            return MessageType.ALARM
        elif "pm" in topic_lower:
            return MessageType.PM
        elif "config" in topic_lower:
            return MessageType.CONFIG
        
        # Try to detect from content
        data = message.deserialize_value()
        if data:
            if "alarm" in str(data).lower():
                return MessageType.ALARM
            elif any(key in data for key in ["counter", "measurement", "metric"]):
                return MessageType.PM
            elif any(key in data for key in ["config", "configuration", "settings"]):
                return MessageType.CONFIG
        
        return MessageType.UNKNOWN

    def detect_vendor(self, message: Message) -> VendorType:
        """Detect vendor from topic name or content.
        
        Args:
            message: Message to analyze.
            
        Returns:
            Detected vendor type.
        """
        # First, check if vendor was already detected from topic
        if message.vendor != VendorType.UNKNOWN:
            return message.vendor
        
        # Try to detect from topic name
        topic_lower = message.topic.lower()
        if "ericsson" in topic_lower:
            return VendorType.ERICSSON
        elif "huawei" in topic_lower:
            return VendorType.HUAWEI
        
        # Try to detect from content
        data = message.deserialize_value()
        if data:
            content_str = str(data).lower()
            if "ericsson" in content_str:
                return VendorType.ERICSSON
            elif "huawei" in content_str:
                return VendorType.HUAWEI
        
        return VendorType.UNKNOWN

    def transform_message(self, message: Message) -> Dict[str, Any]:
        """Transform a raw message to unified format.
        
        Args:
            message: Raw message to transform.
            
        Returns:
            Transformed message as dictionary.
        """
        data = message.deserialize_value()
        
        # Base transformation
        transformed: Dict[str, Any] = {
            "source_topic": message.topic,
            "source_partition": message.partition,
            "source_offset": message.offset,
            "message_type": message.message_type.value,
            "vendor": message.vendor.value,
            "processed_at": datetime.now(timezone.utc).isoformat(),
            "original_data": data,
        }
        
        # Apply type-specific transformation
        if message.message_type in self._processors:
            try:
                type_specific = self._processors[message.message_type](message)
                transformed.update(type_specific)
            except Exception as e:
                logger.error(f"Processor error: {e}")
                transformed["processor_error"] = str(e)
        
        return transformed

    async def process_message(self, message: Message) -> Tuple[bool, Optional[str]]:
        """Process a single message through the pipeline.
        
        Args:
            message: Message to process.
            
        Returns:
            Tuple of (success, error_message).
        """
        try:
            # Detect message type and vendor
            message.message_type = self.detect_message_type(message)
            message.vendor = self.detect_vendor(message)
            
            # Check for parsing errors
            if message.error:
                return (False, message.error)
            
            # Transform message
            transformed = self.transform_message(message)
            
            # Determine output topic
            output_topic = self.topic_manager.get_unified_topic_for_type(
                message.message_type
            )
            
            if output_topic:
                # Send to unified topic
                await self.producer.send_and_wait(output_topic, transformed)
                self._processed_count += 1
                logger.debug(
                    f"Processed message: {message.topic}[{message.partition}:{message.offset}] "
                    f"-> {output_topic}"
                )
                return (True, None)
            else:
                # Unknown message type - send to DLQ
                await self.send_to_dlq(message, "Unknown message type")
                return (False, "Unknown message type")
                
        except Exception as e:
            error_msg = f"Processing error: {e}"
            logger.error(error_msg, exc_info=True)
            await self.send_to_dlq(message, error_msg)
            return (False, error_msg)

    async def process_batch(
        self,
        messages: List[Message],
        commit_callback: Optional[Callable[[Dict[str, Dict[int, int]]], None]] = None
    ) -> BatchResult:
        """Process a batch of messages.
        
        Args:
            messages: List of messages to process.
            commit_callback: Optional callback for offset commits.
            
        Returns:
            BatchResult with processing statistics.
        """
        start_time = asyncio.get_event_loop().time()
        result = BatchResult()
        offsets_to_commit: Dict[str, Dict[int, int]] = {}
        
        for message in messages:
            success, error = await self.process_message(message)
            
            if success:
                result.processed_count += 1
            else:
                result.failed_count += 1
                if error:
                    result.errors.append(error)
            
            # Track offsets for commit
            if message.topic not in offsets_to_commit:
                offsets_to_commit[message.topic] = {}
            offsets_to_commit[message.topic][message.partition] = message.offset
        
        # Commit offsets
        if commit_callback:
            commit_callback(offsets_to_commit)
        
        result.processing_time_ms = int(
            (asyncio.get_event_loop().time() - start_time) * 1000
        )
        
        return result

    async def send_to_dlq(self, message: Message, error: str) -> None:
        """Send a failed message to dead-letter queue.
        
        Args:
            message: Failed message to send.
            error: Error description.
        """
        dlq_message = {
            "original_topic": message.topic,
            "original_partition": message.partition,
            "original_offset": message.offset,
            "original_key": message.key.decode("utf-8") if message.key else None,
            "original_value": message.value.decode("utf-8") if message.value else None,
            "error": error,
            "failed_at": datetime.now(timezone.utc).isoformat(),
            "message_type": message.message_type.value,
            "vendor": message.vendor.value,
        }
        
        try:
            await self.producer.send_and_wait(
                self.topic_manager.DEAD_LETTER_TOPIC,
                dlq_message,
                key=message.key
            )
            self._error_count += 1
            logger.warning(
                f"Sent message to DLQ: {message.topic}[{message.partition}:{message.offset}] "
                f"Error: {error}"
            )
        except Exception as e:
            logger.error(f"Failed to send to DLQ: {e}")

    async def handle_backpressure(self) -> None:
        """Handle backpressure by pausing consumer."""
        logger.warning("Backpressure detected - pausing consumer")
        self.consumer.pause()
        
        # Wait for producer to catch up
        while len(self.producer._pending_acks) > self.config.batch_size * 2:
            await asyncio.sleep(0.1)
        
        self.consumer.resume()
        logger.info("Backpressure resolved - resuming consumer")

    async def run(self) -> None:
        """Run the stream processor main loop."""
        self._running = True
        logger.info("Stream processor started")
        
        try:
            while self._running:
                # Check for backpressure
                if len(self.producer._pending_acks) > self.config.batch_size * 3:
                    await self.handle_backpressure()
                    continue
                
                # Process messages in batches
                messages: List[Message] = []
                async for message in self.consumer.getmany(
                    max_records=self.config.batch_size,
                    timeout_ms=self.config.batch_timeout_ms
                ):
                    messages.append(message)
                
                if messages:
                    result = await self.process_batch(messages)
                    logger.debug(
                        f"Batch processed: {result.processed_count} success, "
                        f"{result.failed_count} failed, "
                        f"{result.processing_time_ms}ms"
                    )
                else:
                    await asyncio.sleep(0.1)  # Small sleep if no messages
                    
        except asyncio.CancelledError:
            logger.info("Stream processor cancelled")
        except Exception as e:
            logger.error(f"Stream processor error: {e}", exc_info=True)
            raise
        finally:
            self._running = False
            logger.info("Stream processor stopped")

    def stop(self) -> None:
        """Stop the stream processor."""
        self._running = False
        logger.info("Stream processor stop requested")

    @property
    def statistics(self) -> Dict[str, int]:
        """Get processor statistics.
        
        Returns:
            Dictionary with processed and error counts.
        """
        return {
            "processed_count": self._processed_count,
            "error_count": self._error_count,
        }


async def create_stream_topology(
    config: Optional[KafkaConfig] = None,
    custom_processors: Optional[Dict[MessageType, Callable[[Message], Dict[str, Any]]]] = None
) -> Tuple[TopicManager, KafkaConsumerWrapper, KafkaProducerWrapper, StreamProcessor]:
    """Create and initialize the complete stream processing topology.
    
    Factory function that creates all components needed for stream processing.
    
    Args:
        config: Kafka configuration (uses defaults if None).
        custom_processors: Optional custom processors by message type.
        
    Returns:
        Tuple of (topic_manager, consumer, producer, processor).
    """
    config = config or KafkaConfig()
    
    # Create topic manager and ensure topics exist
    topic_manager = TopicManager(config)
    await topic_manager.ensure_topics_exist()
    
    # Create consumer for raw topics
    consumer = KafkaConsumerWrapper(
        config=config,
        topics=topic_manager.get_raw_topics(),
        topic_manager=topic_manager
    )
    
    # Create producer
    producer = KafkaProducerWrapper(config=config, topic_manager=topic_manager)
    
    # Create stream processor
    processor = StreamProcessor(
        config=config,
        topic_manager=topic_manager,
        consumer=consumer,
        producer=producer
    )
    
    # Register custom processors
    if custom_processors:
        for msg_type, proc in custom_processors.items():
            processor.register_processor(msg_type, proc)
    
    return (topic_manager, consumer, producer, processor)


async def main() -> None:
    """Main entry point for the stream processor."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    topic_manager, consumer, producer, processor = await create_stream_topology()
    
    async with consumer, producer:
        await processor.run()


if __name__ == "__main__":
    asyncio.run(main())
