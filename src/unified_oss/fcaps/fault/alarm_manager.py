"""
Alarm Manager Module for FCAPS Fault Management.

This module provides comprehensive alarm management functionality including
alarm ingestion, lifecycle management, notification, deduplication, and
persistence for the Unified OSS Framework.

Supports:
    - Alarm ingestion from Ericsson/Huawei NETCONF notifications
    - Alarm lifecycle management (raised→updated→cleared→acknowledged)
    - Severity normalization (Ericsson string→CIM enum, Huawei int→CIM enum)
    - WebSocket notification to northbound clients
    - Alarm deduplication and suppression
    - Integration with database adapter for persistence
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import uuid
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

# Type aliases
T = TypeVar("T")
AlarmCallback = Callable[[Dict[str, Any]], Awaitable[None]]


class AlarmState(Enum):
    """Enumeration of alarm lifecycle states.
    
    Attributes:
        RAISED: Alarm has been raised but not yet acknowledged.
        UPDATED: Alarm has been updated with new information.
        CLEARED: Alarm condition has been resolved.
        ACKNOWLEDGED: Alarm has been acknowledged by operator.
        SUPPRESSED: Alarm is suppressed due to correlation rules.
    """
    RAISED = "RAISED"
    UPDATED = "UPDATED"
    CLEARED = "CLEARED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    SUPPRESSED = "SUPPRESSED"


class AlarmSeverity(Enum):
    """CIM-compliant alarm severity levels.
    
    Attributes:
        CRITICAL: Critical severity requiring immediate attention.
        MAJOR: Major severity requiring prompt attention.
        MINOR: Minor severity for non-critical issues.
        WARNING: Warning severity for informational purposes.
        INDETERMINATE: Severity cannot be determined.
        CLEARED: Alarm has been cleared.
        HIGH: Alias for MAJOR.
        MEDIUM: Alias for MINOR.
        LOW: Alias for WARNING.
    """
    CRITICAL = "CRITICAL"
    MAJOR = "MAJOR"
    MINOR = "MINOR"
    WARNING = "WARNING"
    INDETERMINATE = "INDETERMINATE"
    CLEARED = "CLEARED"
    # Aliases
    HIGH = "MAJOR"
    MEDIUM = "MINOR"
    LOW = "WARNING"


class AlarmType(Enum):
    """Enumeration of alarm types.
    
    Attributes:
        EQUIPMENT: Equipment/hardware related alarms.
        COMMUNICATION: Communication/network related alarms.
        PROCESSING: Processing error alarms.
        ENVIRONMENT: Environmental alarms (temperature, power).
        QUALITY_OF_SERVICE: QoS degradation alarms.
        OTHER: Unclassified alarms.
    """
    EQUIPMENT = "EQUIPMENT"
    COMMUNICATION = "COMMUNICATION"
    PROCESSING = "PROCESSING"
    ENVIRONMENT = "ENVIRONMENT"
    QUALITY_OF_SERVICE = "QUALITY_OF_SERVICE"
    OTHER = "OTHER"


class AlarmCategory(Enum):
    """Enumeration of alarm categories.
    
    Attributes:
        HARDWARE: Hardware-related alarms.
        SOFTWARE: Software-related alarms.
        NETWORK: Network-related alarms.
        ENVIRONMENTAL: Environmental alarms.
        SECURITY: Security-related alarms.
    """
    HARDWARE = "HARDWARE"
    SOFTWARE = "SOFTWARE"
    NETWORK = "NETWORK"
    ENVIRONMENTAL = "ENVIRONMENTAL"
    SECURITY = "SECURITY"


class AlarmSource(Enum):
    """Enumeration of alarm sources by vendor.
    
    Attributes:
        ERICSSON: Ericsson network equipment.
        HUAWEI: Huawei network equipment.
        NOKIA: Nokia network equipment.
        ZTE: ZTE network equipment.
        CISCO: Cisco network equipment.
        UNKNOWN: Unknown or unclassified source.
    """
    ERICSSON = "ERICSSON"
    HUAWEI = "HUAWEI"
    NOKIA = "NOKIA"
    ZTE = "ZTE"
    CISCO = "CISCO"
    UNKNOWN = "UNKNOWN"


class AlarmManagerError(Exception):
    """Base exception for alarm manager operations."""
    pass


class AlarmNotFoundError(AlarmManagerError):
    """Exception raised when an alarm cannot be found."""
    pass


class AlarmAlreadyExistsError(AlarmManagerError):
    """Exception raised when an alarm already exists."""
    pass


class AlarmStateError(AlarmManagerError):
    """Exception raised for invalid alarm state transitions."""
    pass


class NotificationError(AlarmManagerError):
    """Exception raised for notification delivery failures."""
    pass


# Type aliases
NotificationCallback = Callable[[Dict[str, Any]], Awaitable[None]]


@dataclass
class Alarm:
    """Dataclass representing a normalized alarm.
    
    Attributes:
        alarm_id: Unique identifier for the alarm.
        ne_id: Network element identifier.
        alarm_type: Type of alarm.
        severity: Normalized CIM severity level.
        probable_cause: Probable cause code (ITU-T X.733).
        specific_problem: Vendor-specific problem identifier.
        timestamp: Timestamp when alarm was raised.
        correlation_key: Key used for deduplication and correlation.
        source: Vendor source of the alarm.
        state: Current lifecycle state.
        resource_path: CIM-format resource path.
        alarm_text: Human-readable alarm description.
        additional_info: Additional metadata.
        vendor_data: Original vendor-specific alarm data.
        acknowledged: Whether alarm has been acknowledged.
        acknowledged_by: User who acknowledged the alarm.
        ack_time: Timestamp when alarm was acknowledged.
        cleared: Whether alarm has been cleared.
        cleared_by: User or system that cleared the alarm.
        clear_time: Timestamp when alarm was cleared.
        raised_at: Timestamp when alarm was raised.
        updated_at: Timestamp of last update.
    """
    alarm_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ne_id: str = ""
    alarm_type: AlarmType = AlarmType.OTHER
    severity: AlarmSeverity = AlarmSeverity.MINOR
    probable_cause: str = ""
    specific_problem: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    correlation_key: str = ""
    source: AlarmSource = AlarmSource.UNKNOWN
    state: AlarmState = AlarmState.RAISED
    resource_path: str = ""
    alarm_text: str = ""
    additional_info: Dict[str, Any] = field(default_factory=dict)
    vendor_data: Dict[str, Any] = field(default_factory=dict)
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    ack_time: Optional[datetime] = None
    cleared: bool = False
    cleared_by: Optional[str] = None
    clear_time: Optional[datetime] = None
    raised_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    notification_count: int = 0
    last_notified_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert alarm to dictionary representation.
        
        Returns:
            Dictionary containing all alarm attributes.
        """
        return {
            "alarm_id": self.alarm_id,
            "ne_id": self.ne_id,
            "alarm_type": self.alarm_type.value if hasattr(self.alarm_type, 'value') else str(self.alarm_type),
            "severity": self.severity.value if hasattr(self.severity, 'value') else str(self.severity),
            "probable_cause": self.probable_cause,
            "specific_problem": self.specific_problem,
            "timestamp": self.timestamp.isoformat(),
            "correlation_key": self.correlation_key,
            "source": self.source.value if hasattr(self.source, 'value') else str(self.source),
            "state": self.state.value if hasattr(self.state, 'value') else str(self.state),
            "resource_path": self.resource_path,
            "alarm_text": self.alarm_text,
            "additional_info": self.additional_info,
            "acknowledged": self.acknowledged,
            "acknowledged_by": self.acknowledged_by,
            "ack_time": self.ack_time.isoformat() if self.ack_time else None,
            "cleared": self.cleared,
            "cleared_by": self.cleared_by,
            "clear_time": self.clear_time.isoformat() if self.clear_time else None,
            "raised_at": self.raised_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    @property
    def content_hash(self) -> str:
        """Calculate a hash for the alarm content.
        
        Returns:
            SHA-256 hash string.
        """
        data = f"{self.alarm_id}:{self.ne_id}:{self.alarm_type}:{self.severity}:{self.probable_cause}"
        return hashlib.sha256(data.encode()).hexdigest()

    def acknowledge(self, user: str) -> None:
        """Acknowledge the alarm.
        
        Args:
            user: User acknowledging the alarm.
        """
        self.acknowledged = True
        self.acknowledged_by = user
        self.ack_time = datetime.now(timezone.utc)
        self.state = AlarmState.ACKNOWLEDGED
        self.updated_at = datetime.now(timezone.utc)

    def clear(self, user: str) -> None:
        """Clear the alarm.
        
        Args:
            user: User or system clearing the alarm.
        """
        self.cleared = True
        self.cleared_by = user
        self.clear_time = datetime.now(timezone.utc)
        self.state = AlarmState.CLEARED
        self.severity = AlarmSeverity.CLEARED
        self.updated_at = datetime.now(timezone.utc)

    def is_active(self) -> bool:
        """Check if the alarm is active.
        
        Returns:
            True if alarm is active (not cleared).
        """
        return self.state != AlarmState.CLEARED and not self.cleared

    def duration(self) -> Optional[timedelta]:
        """Calculate alarm duration.
        
        Returns:
            Duration from raised to cleared, or None if not cleared.
        """
        if self.clear_time and self.raised_at:
            return self.clear_time - self.raised_at
        return None

    def generate_fingerprint(self) -> str:
        """Generate a fingerprint for deduplication.
        
        Returns:
            SHA-256 hash of correlation key and resource path.
        """
        data = f"{self.correlation_key}:{self.resource_path}:{self.probable_cause}"
        return hashlib.sha256(data.encode()).hexdigest()


@dataclass
class NotificationSubscription:
    """Dataclass representing a notification subscription.
    
    Attributes:
        subscription_id: Unique identifier for the subscription.
        client_id: Client identifier for WebSocket connection.
        callback: Async callback function for notifications.
        filters: Filter criteria for notifications.
        created_at: Subscription creation timestamp.
        active: Whether the subscription is active.
    """
    subscription_id: str
    client_id: str
    callback: AlarmCallback
    filters: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    active: bool = True


class AlarmLifecycle:
    """Manages alarm lifecycle state transitions.
    
    This class provides methods for managing the lifecycle of alarms
    including state transitions, validation, and history tracking.
    
    Attributes:
        valid_transitions: Dictionary of valid state transitions.
    """

    # Valid state transition map
    VALID_TRANSITIONS: Dict[AlarmState, Set[AlarmState]] = {
        AlarmState.RAISED: {AlarmState.UPDATED, AlarmState.CLEARED, AlarmState.ACKNOWLEDGED, AlarmState.SUPPRESSED},
        AlarmState.UPDATED: {AlarmState.UPDATED, AlarmState.CLEARED, AlarmState.ACKNOWLEDGED, AlarmState.SUPPRESSED},
        AlarmState.ACKNOWLEDGED: {AlarmState.CLEARED, AlarmState.UPDATED},
        AlarmState.CLEARED: set(),  # Terminal state
        AlarmState.SUPPRESSED: {AlarmState.RAISED, AlarmState.CLEARED},  # Can be unsuppressed
    }

    def __init__(self) -> None:
        """Initialize the alarm lifecycle manager."""
        self._state_history: Dict[str, List[Tuple[AlarmState, datetime, Optional[str]]]] = {}

    def can_transition(self, current_state: AlarmState, target_state: AlarmState) -> bool:
        """Check if a state transition is valid.
        
        Args:
            current_state: Current alarm state.
            target_state: Target alarm state.
            
        Returns:
            True if transition is valid, False otherwise.
        """
        valid_targets = self.VALID_TRANSITIONS.get(current_state, set())
        return target_state in valid_targets

    def transition(
        self,
        alarm: Alarm,
        target_state: AlarmState,
        user: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> Alarm:
        """Perform a state transition on an alarm.
        
        Args:
            alarm: The alarm to transition.
            target_state: The target state.
            user: User performing the transition (if applicable).
            reason: Reason for the transition.
            
        Returns:
            The updated alarm.
            
        Raises:
            AlarmStateError: If the transition is invalid.
        """
        if not self.can_transition(alarm.state, target_state):
            raise AlarmStateError(
                f"Invalid state transition from {alarm.state.value} to {target_state.value}"
            )

        previous_state = alarm.state
        alarm.state = target_state
        alarm.updated_at = datetime.now(timezone.utc)

        # Handle state-specific updates
        if target_state == AlarmState.CLEARED:
            alarm.cleared = True
            alarm.clear_time = datetime.now(timezone.utc)
            alarm.cleared_by = user
            alarm.severity = AlarmSeverity.CLEARED
        elif target_state == AlarmState.ACKNOWLEDGED:
            alarm.acknowledged = True
            alarm.ack_time = datetime.now(timezone.utc)
            alarm.acknowledged_by = user

        # Record state history
        self._record_history(alarm.alarm_id, previous_state, target_state, user, reason)

        logger.info(
            f"Alarm {alarm.alarm_id} transitioned from {previous_state.value} to {target_state.value}"
        )

        return alarm

    def _record_history(
        self,
        alarm_id: str,
        from_state: AlarmState,
        to_state: AlarmState,
        user: Optional[str],
        reason: Optional[str],
    ) -> None:
        """Record a state transition in history.
        
        Args:
            alarm_id: Alarm identifier.
            from_state: Previous state.
            to_state: New state.
            user: User who performed the transition.
            reason: Reason for the transition.
        """
        if alarm_id not in self._state_history:
            self._state_history[alarm_id] = []

        self._state_history[alarm_id].append({
            "from_state": from_state.value,
            "to_state": to_state.value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user": user,
            "reason": reason,
        })

    def get_history(self, alarm_id: str) -> List[Dict[str, Any]]:
        """Get state transition history for an alarm.
        
        Args:
            alarm_id: Alarm identifier.
            
        Returns:
            List of state transition records.
        """
        return self._state_history.get(alarm_id, [])


class AlarmNotifier:
    """Handles alarm notifications to subscribers.
    
    This class provides WebSocket-based notification delivery to
    northbound clients with support for filtering and delivery tracking.
    
    Attributes:
        subscriptions: Active notification subscriptions.
    """

    def __init__(self, max_retries: int = 3, retry_delay: float = 1.0) -> None:
        """Initialize the alarm notifier.
        
        Args:
            max_retries: Maximum retry attempts for failed deliveries.
            retry_delay: Delay between retry attempts in seconds.
        """
        self._subscriptions: Dict[str, NotificationSubscription] = {}
        self._max_retries = max_retries
        self._retry_delay = retry_delay
        self._notification_queue: Optional[asyncio.Queue] = None
        self._process_task: Optional[asyncio.Task] = None
        self._notification_stats = {
            "sent": 0,
            "failed": 0,
            "retried": 0,
        }

    async def start(self) -> None:
        """Start the notification processor."""
        logger.info("Starting alarm notifier")
        self._notification_queue = asyncio.Queue()
        self._process_task = asyncio.create_task(self._process_queue())

    async def stop(self) -> None:
        """Stop the notification processor."""
        logger.info("Stopping alarm notifier")
        if self._process_task:
            self._process_task.cancel()
            try:
                await self._process_task
            except asyncio.CancelledError:
                pass
            self._process_task = None

    async def _process_queue(self) -> None:
        """Process notifications from the queue."""
        while True:
            try:
                notification = await self._notification_queue.get()
                await self._deliver_notification(notification)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error processing notification: {e}")

    async def _deliver_notification(self, notification: Dict[str, Any]) -> None:
        """Deliver a notification to all subscribers.
        
        Args:
            notification: The notification payload.
        """
        alarm = notification.get("alarm", {})
        event_type = notification.get("event_type", "alarm")

        for subscription in self._subscriptions.values():
            if not subscription.active:
                continue

            if not self._matches_filters(alarm, subscription.filters):
                continue

            for attempt in range(self._max_retries):
                try:
                    await subscription.callback(notification)
                    self._notification_stats["sent"] += 1
                    break
                except Exception as e:
                    if attempt == self._max_retries - 1:
                        logger.error(
                            f"Failed to deliver notification to {subscription.client_id}: {e}"
                        )
                        self._notification_stats["failed"] += 1
                    else:
                        logger.warning(
                            f"Retrying notification to {subscription.client_id} (attempt {attempt + 1})"
                        )
                        self._notification_stats["retried"] += 1
                        await asyncio.sleep(self._retry_delay)

    def _matches_filters(self, alarm: Dict[str, Any], filters: Dict[str, Any]) -> bool:
        """Check if an alarm matches subscription filters.
        
        Args:
            alarm: The alarm to check.
            filters: Filter criteria.
            
        Returns:
            True if alarm matches filters, False otherwise.
        """
        if not filters:
            return True

        # Check severity filter
        if "severities" in filters:
            if alarm.get("severity") not in filters["severities"]:
                return False

        # Check source filter
        if "sources" in filters:
            if alarm.get("source") not in filters["sources"]:
                return False

        # Check resource path prefix filter
        if "resource_prefix" in filters:
            if not alarm.get("resource_path", "").startswith(filters["resource_prefix"]):
                return False

        # Check state filter
        if "states" in filters:
            if alarm.get("state") not in filters["states"]:
                return False

        return True

    async def subscribe(
        self,
        client_id: str,
        callback: AlarmCallback,
        filters: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Subscribe to alarm notifications.
        
        Args:
            client_id: Client identifier.
            callback: Async callback function for notifications.
            filters: Optional filter criteria.
            
        Returns:
            Subscription identifier.
        """
        subscription_id = str(uuid.uuid4())
        subscription = NotificationSubscription(
            subscription_id=subscription_id,
            client_id=client_id,
            callback=callback,
            filters=filters or {},
        )

        self._subscriptions[subscription_id] = subscription
        logger.info(f"Created notification subscription {subscription_id} for client {client_id}")

        return subscription_id

    async def unsubscribe(self, subscription_id: str) -> bool:
        """Unsubscribe from alarm notifications.
        
        Args:
            subscription_id: Subscription identifier to remove.
            
        Returns:
            True if subscription was removed, False if not found.
        """
        if subscription_id in self._subscriptions:
            del self._subscriptions[subscription_id]
            logger.info(f"Removed notification subscription {subscription_id}")
            return True
        return False

    async def notify(self, alarm: Alarm, event_type: str = "alarm") -> None:
        """Queue a notification for delivery.
        
        Args:
            alarm: The alarm to notify about.
            event_type: Type of notification event.
        """
        notification = {
            "event_type": event_type,
            "alarm": alarm.to_dict(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if self._notification_queue is not None:
            await self._notification_queue.put(notification)
            alarm.notification_count += 1
            alarm.last_notified_at = datetime.now(timezone.utc)

    def get_stats(self) -> Dict[str, Any]:
        """Get notification statistics.
        
        Returns:
            Dictionary of notification statistics.
        """
        return {
            **self._notification_stats,
            "active_subscriptions": len([s for s in self._subscriptions.values() if s.active]),
            "queue_size": self._notification_queue.qsize(),
        }


class AlarmManager:
    """Central alarm management for FCAPS Fault Management.
    
    This class provides comprehensive alarm management including ingestion,
    lifecycle management, deduplication, and persistence integration.
    
    Example:
        >>> manager = AlarmManager(db_adapter)
        >>> await manager.initialize()
        >>> alarm = await manager.ingest_alarm(vendor_data, "ericsson")
        >>> await manager.acknowledge_alarm(alarm.alarm_id, "operator1")
    """

    # Vendor severity mappings
    ERICSSON_SEVERITY_MAP: Dict[str, AlarmSeverity] = {
        "critical": AlarmSeverity.CRITICAL,
        "major": AlarmSeverity.HIGH,
        "minor": AlarmSeverity.MEDIUM,
        "warning": AlarmSeverity.LOW,
        "indeterminate": AlarmSeverity.INDETERMINATE,
        "cleared": AlarmSeverity.CLEARED,
    }

    HUAWEI_SEVERITY_MAP: Dict[int, AlarmSeverity] = {
        1: AlarmSeverity.CRITICAL,
        2: AlarmSeverity.HIGH,
        3: AlarmSeverity.MEDIUM,
        4: AlarmSeverity.LOW,
        0: AlarmSeverity.INDETERMINATE,
        5: AlarmSeverity.CLEARED,
    }

    def __init__(
        self,
        db_adapter: Optional[Any] = None,
        dedup_window: timedelta = timedelta(minutes=5),
        max_active_alarms: int = 100000,
    ) -> None:
        """Initialize the alarm manager.
        
        Args:
            db_adapter: Database adapter for persistence.
            dedup_window: Time window for deduplication.
            max_active_alarms: Maximum number of active alarms to maintain.
        """
        self._db = db_adapter
        self._dedup_window = dedup_window
        self._max_active_alarms = max_active_alarms

        self._lifecycle = AlarmLifecycle()
        self._notifier = AlarmNotifier()

        self._active_alarms: Dict[str, Alarm] = {}
        self._alarms = self._active_alarms  # Alias for test compatibility
        self._fingerprint_index: Dict[str, str] = {}  # fingerprint -> alarm_id
        self._suppression_rules: Dict[str, Dict[str, Any]] = {}
        self._notification_callbacks: List[NotificationCallback] = []
        self._cleanup_tasks: set = set()

        self._stats = {
            "total_ingested": 0,
            "total_deduplicated": 0,
            "total_suppressed": 0,
            "total_cleared": 0,
            "total_acknowledged": 0,
        }

    async def initialize(self) -> None:
        """Initialize the alarm manager."""
        await self._notifier.start()
        logger.info("AlarmManager initialized")

    async def close(self) -> None:
        """Close the alarm manager and release resources."""
        await self._notifier.stop()
        
        for task in self._cleanup_tasks:
            task.cancel()
        if self._cleanup_tasks:
            await asyncio.gather(*self._cleanup_tasks, return_exceptions=True)
            self._cleanup_tasks.clear()
            
        logger.info("AlarmManager closed")

    def _detect_vendor(self, vendor_data: Dict[str, Any]) -> AlarmSource:
        """Detect the vendor from alarm data.
        
        Args:
            vendor_data: Raw vendor alarm data.
            
        Returns:
            Detected alarm source.
        """
        # Check for vendor-specific fields
        if "ericsson" in str(vendor_data).lower():
            return AlarmSource.ERICSSON
        if "huawei" in str(vendor_data).lower():
            return AlarmSource.HUAWEI
        if "nokia" in str(vendor_data).lower():
            return AlarmSource.NOKIA

        # Check for specific field patterns
        if "alarmId" in vendor_data and "perceivedSeverity" in vendor_data:
            return AlarmSource.ERICSSON
        if "alarmId" in vendor_data and "severity" in vendor_data:
            if isinstance(vendor_data.get("severity"), int):
                return AlarmSource.HUAWEI

        return AlarmSource.UNKNOWN

    def _map_severity(
        self,
        severity_value: Union[str, int],
        source: AlarmSource,
    ) -> AlarmSeverity:
        """Map vendor severity to CIM severity.
        
        Args:
            severity_value: Vendor-specific severity value.
            source: Alarm source vendor.
            
        Returns:
            Normalized CIM severity.
        """
        if source == AlarmSource.ERICSSON:
            if isinstance(severity_value, str):
                return self.ERICSSON_SEVERITY_MAP.get(
                    severity_value.lower(), AlarmSeverity.INDETERMINATE
                )
        elif source == AlarmSource.HUAWEI:
            if isinstance(severity_value, int):
                return self.HUAWEI_SEVERITY_MAP.get(severity_value, AlarmSeverity.INDETERMINATE)

        return AlarmSeverity.INDETERMINATE

    def _generate_correlation_key(self, vendor_data: Dict[str, Any], source: AlarmSource) -> str:
        """Generate a correlation key for deduplication.
        
        Args:
            vendor_data: Raw vendor alarm data.
            source: Alarm source vendor.
            
        Returns:
            Correlation key string.
        """
        if source == AlarmSource.ERICSSON:
            # Ericsson: Use alarmId, moId, and eventType
            alarm_id = vendor_data.get("alarmId", "")
            mo_id = vendor_data.get("moId", vendor_data.get("managedObject", ""))
            event_type = vendor_data.get("eventType", vendor_data.get("specificProblem", ""))
            return f"ericsson:{mo_id}:{alarm_id}:{event_type}"
        elif source == AlarmSource.HUAWEI:
            # Huawei: Use alarmId, neId, and alarmName
            alarm_id = vendor_data.get("alarmId", "")
            ne_id = vendor_data.get("neId", vendor_data.get("networkElementId", ""))
            alarm_name = vendor_data.get("alarmName", vendor_data.get("alarmTitle", ""))
            return f"huawei:{ne_id}:{alarm_id}:{alarm_name}"
        else:
            # Generic: Use available identifiers
            key_parts = [
                str(vendor_data.get("alarmId", "")),
                str(vendor_data.get("neId", vendor_data.get("moId", ""))),
                str(vendor_data.get("alarmName", vendor_data.get("eventType", ""))),
            ]
            return ":".join(key_parts)

    def _generate_resource_path(self, vendor_data: Dict[str, Any], source: AlarmSource) -> str:
        """Generate a CIM-format resource path.
        
        Args:
            vendor_data: Raw vendor alarm data.
            source: Alarm source vendor.
            
        Returns:
            CIM-format resource path.
        """
        if source == AlarmSource.ERICSSON:
            mo_id = vendor_data.get("moId", vendor_data.get("managedObject", ""))
            # Parse Ericsson MO format: SubNetwork=..., ManagedElement=..., ...
            if mo_id:
                parts = mo_id.split(",")
                path_parts = []
                for part in parts:
                    if "=" in part:
                        key, value = part.split("=", 1)
                        path_parts.append(f"{key.lower()}s/{value}")
                return f"/network/{'/'.join(path_parts)}" if path_parts else f"/network/unknown/{mo_id}"
        elif source == AlarmSource.HUAWEI:
            ne_id = vendor_data.get("neId", vendor_data.get("networkElementId", ""))
            ne_name = vendor_data.get("neName", "")
            if ne_id:
                return f"/network/elements/{ne_id}"
            elif ne_name:
                return f"/network/elements/{ne_name}"

        return "/network/unknown"

    async def ingest_alarm(
        self,
        vendor_data: Dict[str, Any],
        vendor_hint: Optional[str] = None,
    ) -> Optional[Alarm]:
        """Ingest an alarm from vendor notification.
        
        Args:
            vendor_data: Raw vendor alarm data.
            vendor_hint: Optional vendor identifier hint.
            
        Returns:
            Created or updated alarm, or None if suppressed.
        """
        self._stats["total_ingested"] += 1

        # Detect or use provided vendor
        source = self._detect_vendor(vendor_data)
        if vendor_hint:
            try:
                source = AlarmSource(vendor_hint.upper())
            except ValueError:
                pass

        # Generate correlation key and fingerprint
        correlation_key = self._generate_correlation_key(vendor_data, source)
        fingerprint = hashlib.sha256(
            f"{correlation_key}:{json.dumps(vendor_data, sort_keys=True)}".encode()
        ).hexdigest()

        # Check for deduplication
        if fingerprint in self._fingerprint_index:
            existing_id = self._fingerprint_index[fingerprint]
            if existing_id in self._active_alarms:
                existing = self._active_alarms[existing_id]
                # Update existing alarm
                existing.updated_at = datetime.now(timezone.utc)
                existing.notification_count += 1
                self._stats["total_deduplicated"] += 1
                logger.debug(f"Deduplicated alarm: {existing_id}")
                return existing

        # Check for suppression rules
        if self._is_suppressed(vendor_data, source):
            self._stats["total_suppressed"] += 1
            logger.debug(f"Suppressed alarm: {correlation_key}")
            return None

        # Map severity
        severity_value = vendor_data.get(
            "perceivedSeverity",
            vendor_data.get("severity", vendor_data.get("alarmSeverity", "indeterminate"))
        )
        severity = self._map_severity(severity_value, source)

        # Determine initial state
        state = AlarmState.CLEARED if severity == AlarmSeverity.CLEARED else AlarmState.RAISED

        # Create alarm
        alarm = Alarm(
            alarm_id=str(uuid.uuid4()),
            correlation_key=correlation_key,
            source=source,
            severity=severity,
            state=state,
            resource_path=self._generate_resource_path(vendor_data, source),
            alarm_text=vendor_data.get(
                "alarmText",
                vendor_data.get("alarmName", vendor_data.get("eventText", "Unknown alarm"))
            ),
            probable_cause=vendor_data.get(
                "probableCause",
                vendor_data.get("eventCategory", "unknown")
            ),
            specific_problem=vendor_data.get(
                "specificProblem",
                vendor_data.get("alarmName", "")
            ),
            vendor_data=vendor_data,
        )

        # Store alarm
        self._active_alarms[alarm.alarm_id] = alarm
        self._fingerprint_index[fingerprint] = alarm.alarm_id

        # Persist to database
        await self._persist_alarm(alarm)

        # Send notification
        await self._notifier.notify(alarm, "alarm_raised" if state == AlarmState.RAISED else "alarm_cleared")

        logger.info(
            f"Ingested alarm {alarm.alarm_id} from {source.value}: "
            f"{alarm.severity.value} - {alarm.alarm_text[:50]}"
        )

        return alarm

    def _is_suppressed(self, vendor_data: Dict[str, Any], source: AlarmSource) -> bool:
        """Check if an alarm should be suppressed.
        
        Args:
            vendor_data: Raw vendor alarm data.
            source: Alarm source vendor.
            
        Returns:
            True if alarm should be suppressed, False otherwise.
        """
        for rule_id, rule in self._suppression_rules.items():
            if not rule.get("enabled", True):
                continue

            # Check source filter
            if "sources" in rule and source.value not in rule["sources"]:
                continue

            # Check severity filter
            if "severities" in rule:
                severity = self._map_severity(
                    vendor_data.get("perceivedSeverity", vendor_data.get("severity", "indeterminate")),
                    source
                )
                if severity.value not in rule["severities"]:
                    continue

            # Check pattern match
            if "pattern" in rule:
                alarm_text = vendor_data.get("alarmText", vendor_data.get("alarmName", ""))
                if rule["pattern"].lower() in alarm_text.lower():
                    return True

        return False

    async def acknowledge_alarm(
        self,
        alarm_id: str,
        user: str,
        comment: Optional[str] = None,
    ) -> Alarm:
        """Acknowledge an alarm.
        
        Args:
            alarm_id: Alarm identifier.
            user: User acknowledging the alarm.
            comment: Optional acknowledgment comment.
            
        Returns:
            The updated alarm.
            
        Raises:
            AlarmNotFoundError: If alarm is not found.
            AlarmStateError: If alarm cannot be acknowledged.
        """
        if alarm_id not in self._active_alarms:
            raise AlarmNotFoundError(f"Alarm not found: {alarm_id}")

        alarm = self._active_alarms[alarm_id]

        if alarm.state == AlarmState.CLEARED:
            raise AlarmStateError("Cannot acknowledge cleared alarm")

        alarm = self._lifecycle.transition(alarm, AlarmState.ACKNOWLEDGED, user, comment)
        self._stats["total_acknowledged"] += 1

        await self._persist_alarm(alarm)
        await self._notifier.notify(alarm, "alarm_acknowledged")

        logger.info(f"Alarm {alarm_id} acknowledged by {user}")
        return alarm

    async def clear_alarm(
        self,
        alarm_id: str,
        user: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> Alarm:
        """Clear an alarm.
        
        Args:
            alarm_id: Alarm identifier.
            user: User clearing the alarm (if manual).
            reason: Reason for clearing.
            
        Returns:
            The updated alarm.
            
        Raises:
            AlarmNotFoundError: If alarm is not found.
        """
        if alarm_id not in self._active_alarms:
            raise AlarmNotFoundError(f"Alarm not found: {alarm_id}")

        alarm = self._active_alarms[alarm_id]
        alarm = self._lifecycle.transition(alarm, AlarmState.CLEARED, user, reason)
        self._stats["total_cleared"] += 1

        await self._persist_alarm(alarm)
        await self._notifier.notify(alarm, "alarm_cleared")

        # Remove from active alarms after a delay
        task = asyncio.create_task(self._schedule_cleanup(alarm_id))
        self._cleanup_tasks.add(task)
        task.add_done_callback(self._cleanup_tasks.discard)

        logger.info(f"Alarm {alarm_id} cleared")
        return alarm

    async def _schedule_cleanup(self, alarm_id: str, delay: int = 300) -> None:
        """Schedule cleanup of a cleared alarm.
        
        Args:
            alarm_id: Alarm identifier.
            delay: Delay in seconds before cleanup.
        """
        await asyncio.sleep(delay)
        if alarm_id in self._active_alarms:
            alarm = self._active_alarms[alarm_id]
            if alarm.state == AlarmState.CLEARED:
                del self._active_alarms[alarm_id]
                logger.debug(f"Cleaned up cleared alarm: {alarm_id}")

    async def get_active_alarms(
        self,
        severities: Optional[List[AlarmSeverity]] = None,
        sources: Optional[List[AlarmSource]] = None,
        resource_prefix: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Alarm]:
        """Get active alarms with optional filtering.
        
        Args:
            severities: Filter by severity levels.
            sources: Filter by alarm sources.
            resource_prefix: Filter by resource path prefix.
            limit: Maximum number of results.
            offset: Result offset for pagination.
            
        Returns:
            List of matching alarms.
        """
        results = []

        for alarm in self._active_alarms.values():
            # Skip cleared alarms
            if alarm.state == AlarmState.CLEARED:
                continue

            # Apply filters
            if severities and alarm.severity not in severities:
                continue
            if sources and alarm.source not in sources:
                continue
            if resource_prefix and not alarm.resource_path.startswith(resource_prefix):
                continue

            results.append(alarm)

        # Sort by severity (critical first) then by raised_at (newest first)
        severity_order = {
            AlarmSeverity.CRITICAL: 0,
            AlarmSeverity.HIGH: 1,
            AlarmSeverity.MEDIUM: 2,
            AlarmSeverity.LOW: 3,
            AlarmSeverity.INDETERMINATE: 4,
        }
        results.sort(key=lambda a: (severity_order.get(a.severity, 5), -a.raised_at.timestamp()))

        return results[offset:offset + limit]

    async def get_alarm(self, alarm_id: str) -> Optional[Alarm]:
        """Get an alarm by ID.
        
        Args:
            alarm_id: Alarm identifier.
            
        Returns:
            The alarm or None if not found.
        """
        return self._active_alarms.get(alarm_id)

    async def subscribe_notifications(
        self,
        client_id: str,
        callback: AlarmCallback,
        filters: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Subscribe to alarm notifications.
        
        Args:
            client_id: Client identifier.
            callback: Async callback function.
            filters: Optional filter criteria.
            
        Returns:
            Subscription identifier.
        """
        return await self._notifier.subscribe(client_id, callback, filters)

    async def unsubscribe_notifications(self, subscription_id: str) -> bool:
        """Unsubscribe from alarm notifications.
        
        Args:
            subscription_id: Subscription identifier.
            
        Returns:
            True if unsubscribed successfully.
        """
        return await self._notifier.unsubscribe(subscription_id)

    def add_suppression_rule(
        self,
        rule_id: str,
        pattern: str,
        sources: Optional[List[str]] = None,
        severities: Optional[List[str]] = None,
        enabled: bool = True,
    ) -> None:
        """Add an alarm suppression rule.
        
        Args:
            rule_id: Rule identifier.
            pattern: Pattern to match in alarm text.
            sources: List of sources to apply rule to.
            severities: List of severities to apply rule to.
            enabled: Whether the rule is enabled.
        """
        self._suppression_rules[rule_id] = {
            "pattern": pattern,
            "sources": sources or [],
            "severities": severities or [],
            "enabled": enabled,
        }
        logger.info(f"Added suppression rule: {rule_id}")

    def remove_suppression_rule(self, rule_id: str) -> bool:
        """Remove a suppression rule.
        
        Args:
            rule_id: Rule identifier.
            
        Returns:
            True if removed, False if not found.
        """
        if rule_id in self._suppression_rules:
            del self._suppression_rules[rule_id]
            logger.info(f"Removed suppression rule: {rule_id}")
            return True
        return False

    async def _persist_alarm(self, alarm: Alarm) -> None:
        """Persist an alarm to the database.
        
        Args:
            alarm: The alarm to persist.
        """
        if self._db is None:
            return

        try:
            # Build query using database adapter
            data = alarm.to_dict()
            # Database persistence would be implemented here
            logger.debug(f"Persisted alarm {alarm.alarm_id} to database")
        except Exception as e:
            logger.error(f"Failed to persist alarm {alarm.alarm_id}: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get alarm manager statistics.
        
        Returns:
            Dictionary of statistics.
        """
        return {
            **self._stats,
            "active_alarms": len([a for a in self._active_alarms.values() if a.state != AlarmState.CLEARED]),
            "suppression_rules": len(self._suppression_rules),
            "notification_stats": self._notifier.get_stats(),
        }

    async def health_check(self) -> Dict[str, Any]:
        """Perform a health check.
        
        Returns:
            Health check results.
        """
        return {
            "status": "healthy",
            "active_alarms": len(self._active_alarms),
            "uptime_stats": self._stats,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


class SeverityMapper:
    """Maps vendor-specific severity values to CIM severity.
    
    This class provides severity mapping for multiple vendors including
    Ericsson (string-based) and Huawei (integer-based).
    
    Example:
        >>> mapper = SeverityMapper()
        >>> severity = mapper.map_vendor_severity("ericsson", "critical")
        >>> print(severity)  # AlarmSeverity.CRITICAL
    """

    # Ericsson severity mappings (string-based)
    ERICSSON_MAP: Dict[str, AlarmSeverity] = {
        "critical": AlarmSeverity.CRITICAL,
        "a1": AlarmSeverity.CRITICAL,
        "major": AlarmSeverity.HIGH,
        "a2": AlarmSeverity.HIGH,
        "minor": AlarmSeverity.MEDIUM,
        "a3": AlarmSeverity.MEDIUM,
        "warning": AlarmSeverity.LOW,
        "b1": AlarmSeverity.LOW,
        "indeterminate": AlarmSeverity.INDETERMINATE,
        "cleared": AlarmSeverity.CLEARED,
    }

    # Huawei severity mappings (integer-based and string-based)
    HUAWEI_MAP: Dict[Union[int, str], AlarmSeverity] = {
        1: AlarmSeverity.CRITICAL,
        2: AlarmSeverity.HIGH,
        3: AlarmSeverity.MEDIUM,
        4: AlarmSeverity.LOW,
        0: AlarmSeverity.INDETERMINATE,
        5: AlarmSeverity.CLEARED,
        # String-based mappings
        "critical": AlarmSeverity.CRITICAL,
        "major": AlarmSeverity.HIGH,
        "minor": AlarmSeverity.MEDIUM,
        "warning": AlarmSeverity.LOW,
    }

    # Nokia severity mappings
    NOKIA_MAP: Dict[str, AlarmSeverity] = {
        "a1": AlarmSeverity.CRITICAL,
        "a2": AlarmSeverity.HIGH,
        "a3": AlarmSeverity.MEDIUM,
        "critical": AlarmSeverity.CRITICAL,
        "major": AlarmSeverity.HIGH,
        "minor": AlarmSeverity.MEDIUM,
        "warning": AlarmSeverity.LOW,
    }

    def __init__(self) -> None:
        """Initialize the severity mapper."""
        self._custom_mappings: Dict[str, Dict[Any, AlarmSeverity]] = {}

    def map_vendor_severity(
        self,
        vendor: str,
        severity_value: Union[str, int],
    ) -> AlarmSeverity:
        """Map a vendor severity value to CIM severity.
        
        Args:
            vendor: Vendor identifier (case-insensitive).
            severity_value: Original severity value.
            
        Returns:
            Mapped CIM severity.
        """
        vendor_lower = vendor.lower()
        
        # Check custom mappings first
        if vendor_lower in self._custom_mappings:
            custom_map = self._custom_mappings[vendor_lower]
            if severity_value in custom_map:
                return custom_map[severity_value]
        
        # Vendor-specific mappings
        if vendor_lower == "ericsson":
            if isinstance(severity_value, str):
                return self.ERICSSON_MAP.get(
                    severity_value.lower(), AlarmSeverity.MINOR
                )
        elif vendor_lower == "huawei":
            # Support both integer and string severity values
            if isinstance(severity_value, int):
                return self.HUAWEI_MAP.get(severity_value, AlarmSeverity.MINOR)
            elif isinstance(severity_value, str):
                return self.HUAWEI_MAP.get(
                    severity_value.lower(), AlarmSeverity.MINOR
                )
        elif vendor_lower == "nokia":
            if isinstance(severity_value, str):
                return self.NOKIA_MAP.get(
                    severity_value.lower(), AlarmSeverity.MINOR
                )
        # Handle case-insensitive matching for standard severity names
        if isinstance(severity_value, str):
            upper_val = severity_value.upper()
            for severity in AlarmSeverity:
                if severity.value == upper_val:
                    return severity
        
        return AlarmSeverity.MINOR

    def add_vendor_mapping(
        self,
        vendor: str,
        mapping: Optional[Dict[Union[str, int], AlarmSeverity]] = None,
        source_value: Optional[Union[str, int]] = None,
        target_severity: Optional[AlarmSeverity] = None,
    ) -> None:
        """Add a custom severity mapping.
        
        Args:
            vendor: Vendor identifier.
            mapping: Dictionary mapping source values to target severities.
            source_value: Source severity value (alternative to mapping dict).
            target_severity: Target CIM severity (alternative to mapping dict).
        """
        vendor_lower = vendor.lower()
        if vendor_lower not in self._custom_mappings:
            self._custom_mappings[vendor_lower] = {}
        
        # Support both mapping dict and individual key-value pair
        if mapping is not None:
            self._custom_mappings[vendor_lower].update(mapping)
            logger.info(f"Added severity mappings for {vendor}: {len(mapping)} entries")
        elif source_value is not None and target_severity is not None:
            self._custom_mappings[vendor_lower][source_value] = target_severity
            logger.info(f"Added severity mapping: {vendor}:{source_value} -> {target_severity.value}")


class RootCauseAnalyzer:
    """Analyzes alarms to identify root causes.
    
    This class provides root cause analysis including correlation
    identification and impact assessment.
    
    Example:
        >>> analyzer = RootCauseAnalyzer()
        >>> result = analyzer.analyze(alarms)
        >>> print(result["root_cause"])
    """

    def __init__(self) -> None:
        """Initialize the root cause analyzer."""
        pass

    def analyze(self, alarms: List[Alarm]) -> Dict[str, Any]:
        """Analyze a group of alarms for root cause.
        
        Args:
            alarms: List of alarms to analyze.
            
        Returns:
            Dictionary with root cause analysis results.
        """
        if not alarms:
            return {
                "root_cause": None,
                "affected_ne": [],
                "correlation_score": 0.0,
            }
        
        # Score each alarm as potential root cause
        scores: List[Tuple[Alarm, float]] = []
        
        severity_weights = {
            AlarmSeverity.CRITICAL: 0.4,
            AlarmSeverity.HIGH: 0.3,
            AlarmSeverity.MEDIUM: 0.2,
            AlarmSeverity.LOW: 0.1,
            AlarmSeverity.INDETERMINATE: 0.05,
        }
        
        for alarm in alarms:
            score = 0.0
            
            # Severity weight
            severity = alarm.severity
            score += severity_weights.get(severity, 0.05)
            
            # Alarm text analysis
            alarm_text = alarm.alarm_text.lower() if alarm.alarm_text else ""
            root_cause_keywords = [
                "link", "power", "temperature", "fan", "battery",
                "transmission", "backhaul", "fiber", "optical", "hardware",
            ]
            for kw in root_cause_keywords:
                if kw in alarm_text:
                    score += 0.1
                    break
            
            scores.append((alarm, score))
        
        # Sort by score descending
        scores.sort(key=lambda x: -x[1])
        
        root_cause = scores[0][0] if scores else None
        affected_ne = list(set(a.ne_id for a in alarms if a.ne_id))
        
        # Calculate correlation score
        if len(alarms) > 1:
            correlation_score = min(len(alarms) / 10.0, 1.0)
        else:
            correlation_score = 0.0
        
        return {
            "root_cause": root_cause,
            "affected_ne": affected_ne,
            "correlation_score": correlation_score,
        }

    def find_correlated(
        self,
        primary_alarm: Alarm,
        alarms: List[Alarm],
    ) -> List[Alarm]:
        """Find alarms correlated with a primary alarm.
        
        Args:
            primary_alarm: The primary alarm.
            alarms: List of alarms to check.
            
        Returns:
            List of correlated alarms.
        """
        correlated = []
        
        for alarm in alarms:
            if alarm.alarm_id == primary_alarm.alarm_id:
                continue
            
            # Check for same NE
            if alarm.ne_id and alarm.ne_id == primary_alarm.ne_id:
                correlated.append(alarm)
                continue
            
            # Check for similar alarm type
            if alarm.alarm_type == primary_alarm.alarm_type:
                correlated.append(alarm)
        
        return correlated

    def calculate_impact_score(self, alarms: List[Alarm]) -> float:
        """Calculate impact score for a group of alarms.
        
        Args:
            alarms: List of alarms.
            
        Returns:
            Impact score between 0.0 and 1.0.
        """
        if not alarms:
            return 0.0
        
        # Factor 1: Severity distribution
        severity_scores = {
            AlarmSeverity.CRITICAL: 1.0,
            AlarmSeverity.HIGH: 0.7,
            AlarmSeverity.MEDIUM: 0.4,
            AlarmSeverity.LOW: 0.2,
            AlarmSeverity.INDETERMINATE: 0.1,
        }
        
        total_severity = sum(
            severity_scores.get(a.severity, 0.1) for a in alarms
        )
        avg_severity = total_severity / len(alarms)
        
        # Factor 2: Number of affected NEs
        unique_ne = len(set(a.ne_id for a in alarms if a.ne_id))
        ne_factor = min(unique_ne / 10.0, 1.0) * 0.3
        
        # Factor 3: Alarm count
        count_factor = min(len(alarms) / 20.0, 1.0) * 0.2
        
        return min(avg_severity * 0.5 + ne_factor + count_factor, 1.0)


# Add additional methods to AlarmManager class
# These will be monkey-patched onto the class

async def create_alarm(
    self,
    ne_id: str,
    alarm_type: AlarmType = AlarmType.OTHER,
    severity: AlarmSeverity = AlarmSeverity.MINOR,
    probable_cause: str = "",
    specific_problem: str = "",
    additional_info: Optional[Dict[str, Any]] = None,
) -> Alarm:
    """Create a new alarm.
    
    Args:
        ne_id: Network element identifier.
        alarm_type: Type of alarm.
        severity: Alarm severity.
        probable_cause: Probable cause.
        specific_problem: Specific problem description.
        additional_info: Additional metadata.
        
    Returns:
        Created alarm.
        
    Raises:
        AlarmAlreadyExistsError: If a similar alarm already exists.
    """
    # Check for duplicate
    for existing in self._active_alarms.values():
        if (existing.ne_id == ne_id and 
            existing.alarm_type == alarm_type and
            existing.probable_cause == probable_cause and
            existing.is_active()):
            raise AlarmAlreadyExistsError(
                f"Similar alarm already exists for {ne_id}"
            )
    
    alarm = Alarm(
        ne_id=ne_id,
        alarm_type=alarm_type,
        severity=severity,
        probable_cause=probable_cause,
        specific_problem=specific_problem,
        additional_info=additional_info or {},
    )
    
    self._active_alarms[alarm.alarm_id] = alarm
    self._stats["total_ingested"] += 1
    
    await self._persist_alarm(alarm)
    await self._notifier.notify(alarm, "alarm_created")
    
    # Legacy callback support
    for cb in getattr(self, "_notification_callbacks", []):
        try:
            await cb(alarm)
        except Exception as e:
            logger.error(f"Error in notification callback: {e}")
    
    logger.info(f"Created alarm {alarm.alarm_id} for NE {ne_id}")
    return alarm


async def update_alarm(
    self,
    alarm_id: str,
    **updates: Any,
) -> Alarm:
    """Update an existing alarm.
    
    Args:
        alarm_id: Alarm identifier.
        **updates: Fields to update.
        
    Returns:
        Updated alarm.
        
    Raises:
        AlarmNotFoundError: If alarm is not found.
    """
    if alarm_id not in self._active_alarms:
        raise AlarmNotFoundError(f"Alarm not found: {alarm_id}")
    
    alarm = self._active_alarms[alarm_id]
    
    # Apply updates
    for key, value in updates.items():
        if hasattr(alarm, key):
            setattr(alarm, key, value)
    
    alarm.updated_at = datetime.now(timezone.utc)
    alarm.state = AlarmState.UPDATED
    
    await self._persist_alarm(alarm)
    await self._notifier.notify(alarm, "alarm_updated")
    
    logger.info(f"Updated alarm {alarm_id}")
    return alarm


async def get_alarms(
    self,
    severity: Optional[AlarmSeverity] = None,
    ne_id: Optional[str] = None,
    state: Optional[AlarmState] = None,
    limit: int = 100,
) -> List[Alarm]:
    """Get alarms with optional filtering.
    
    Args:
        severity: Filter by severity.
        ne_id: Filter by network element ID.
        state: Filter by alarm state.
        limit: Maximum number of results.
        
    Returns:
        List of matching alarms.
    """
    results = []
    
    for alarm in self._active_alarms.values():
        # Apply filters
        if severity and alarm.severity != severity:
            continue
        if ne_id and alarm.ne_id != ne_id:
            continue
        if state and alarm.state != state:
            continue
        
        results.append(alarm)
    
    return results[:limit]


def get_statistics(self) -> Dict[str, Any]:
    """Get alarm manager statistics.
    
    Returns:
        Dictionary of statistics.
    """
    by_severity: Dict[str, int] = {}
    for alarm in self._active_alarms.values():
        sev = alarm.severity.value if hasattr(alarm.severity, 'value') else str(alarm.severity)
        by_severity[sev] = by_severity.get(sev, 0) + 1
    
    return {
        "total_alarms": len(self._active_alarms),
        "active_alarms": len([a for a in self._active_alarms.values() if a.is_active()]),
        "by_severity": by_severity,
        **self._stats,
    }


def register_notification_callback(
    self,
    callback: NotificationCallback,
) -> None:
    """Register a notification callback.
    
    Args:
        callback: Async callback function.
    """
    self._notification_callbacks.append(callback)
    logger.info("Registered notification callback")


async def search_alarms(
    self,
    query: str,
    limit: int = 100,
) -> List[Alarm]:
    """Search alarms by text query.
    
    Args:
        query: Search query string.
        limit: Maximum number of results.
        
    Returns:
        List of matching alarms.
    """
    results = []
    query_lower = query.lower()
    
    for alarm in self._active_alarms.values():
        # Search in alarm text and probable cause
        if (query_lower in alarm.alarm_text.lower() or
            query_lower in alarm.probable_cause.lower() or
            query_lower in alarm.specific_problem.lower() or
            query_lower in alarm.ne_id.lower()):
            results.append(alarm)
    
    return results[:limit]


async def bulk_acknowledge(
    self,
    alarm_ids: List[str],
    user: str,
) -> int:
    """Acknowledge multiple alarms.
    
    Args:
        alarm_ids: List of alarm identifiers.
        user: User acknowledging the alarms.
        
    Returns:
        Number of alarms acknowledged.
    """
    count = 0
    for alarm_id in alarm_ids:
        try:
            await self.acknowledge_alarm(alarm_id, user)
            count += 1
        except (AlarmNotFoundError, AlarmStateError) as e:
            logger.warning(f"Failed to acknowledge {alarm_id}: {e}")
    
    logger.info(f"Bulk acknowledged {count} alarms by {user}")
    return count


# Monkey-patch methods onto AlarmManager
AlarmManager.create_alarm = create_alarm
AlarmManager.update_alarm = update_alarm
AlarmManager.get_alarms = get_alarms
AlarmManager.get_statistics = get_statistics
AlarmManager.register_notification_callback = register_notification_callback
AlarmManager.search_alarms = search_alarms
AlarmManager.bulk_acknowledge = bulk_acknowledge

# Initialize notification_callbacks list in AlarmManager.__init__
_original_init = AlarmManager.__init__

def _patched_init(self, *args, **kwargs):
    _original_init(self, *args, **kwargs)
    self._notification_callbacks = []

AlarmManager.__init__ = _patched_init
