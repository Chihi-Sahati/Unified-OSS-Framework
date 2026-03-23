"""
Alarm Service gRPC Implementation for Unified OSS Framework.

This module provides the gRPC service implementation for fault management
operations, integrating with the fcaps.fault module for alarm management.

Features:
    - Alarm retrieval with filtering and pagination
    - Alarm acknowledgment with related alarm handling
    - Alarm clearing with reason tracking
    - Real-time alarm subscription via server streaming
    - Integration with AlarmManager from fcaps.fault module

Example:
    >>> from unified_oss.api.grpc.services.alarm_service import AlarmServiceServicer
    >>> from unified_oss.fcaps.fault.alarm_manager import AlarmManager
    >>> alarm_manager = AlarmManager()
    >>> servicer = AlarmServiceServicer(alarm_manager)
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import (
    Any,
    AsyncGenerator,
    Dict,
    List,
    Optional,
    Set,
    TYPE_CHECKING,
)

# gRPC imports
try:
    import grpc
    from grpc import aio
    GRPC_AVAILABLE = True
except ImportError:
    GRPC_AVAILABLE = False
    grpc = None
    aio = None

# Import from fcaps module
from unified_oss.fcaps.fault.alarm_manager import (
    Alarm,
    AlarmManager,
    AlarmSeverity,
    AlarmSource,
    AlarmState,
    AlarmNotFoundError,
    AlarmStateError,
)

# Configure module logger
logger = logging.getLogger(__name__)


def severity_to_enum(severity_value: str) -> int:
    """Convert severity string to proto enum value.
    
    Args:
        severity_value: Severity string from Alarm model.
        
    Returns:
        Integer value for proto Severity enum.
    """
    mapping = {
        "CRITICAL": 1,
        "HIGH": 2,  # Major
        "MEDIUM": 3,  # Minor
        "LOW": 4,  # Warning
        "INDETERMINATE": 5,  # Informational
        "CLEARED": 6,
    }
    return mapping.get(severity_value.upper(), 0)


def state_to_enum(state_value: str) -> int:
    """Convert state string to proto enum value.
    
    Args:
        state_value: State string from Alarm model.
        
    Returns:
        Integer value for proto AlarmState enum.
    """
    mapping = {
        "RAISED": 1,
        "UPDATED": 2,
        "CLEARED": 3,
        "ACKNOWLEDGED": 4,
        "SUPPRESSED": 5,
    }
    return mapping.get(state_value.upper(), 0)


def vendor_to_enum(vendor_value: str) -> int:
    """Convert vendor string to proto enum value.
    
    Args:
        vendor_value: Vendor string from Alarm model.
        
    Returns:
        Integer value for proto Vendor enum.
    """
    mapping = {
        "ERICSSON": 1,
        "HUAWEI": 2,
        "NOKIA": 3,
        "CISCO": 4,
        "ZTE": 5,
    }
    return mapping.get(vendor_value.upper(), 0)


@dataclass
class AlarmSubscription:
    """Represents an active alarm subscription.
    
    Attributes:
        subscription_id: Unique subscription identifier.
        client_id: Client identifier.
        severities: Filter by severities.
        sources: Filter by sources.
        resource_prefix: Filter by resource path prefix.
        include_cleared: Include cleared alarms.
        queue: Async queue for notifications.
        active: Whether subscription is active.
    """
    subscription_id: str
    client_id: str
    severities: List[int]
    sources: List[int]
    resource_prefix: str
    include_cleared: bool
    queue: asyncio.Queue
    active: bool = True


class AlarmServiceServicer:
    """gRPC servicer for AlarmService operations.
    
    Provides fault management operations including alarm retrieval,
    acknowledgment, clearing, and real-time subscriptions.
    
    Attributes:
        alarm_manager: AlarmManager instance from fcaps.fault module.
        subscriptions: Active alarm subscriptions.
    
    Example:
        >>> alarm_manager = AlarmManager()
        >>> servicer = AlarmServiceServicer(alarm_manager)
        >>> # Register with gRPC server
        >>> add_AlarmServiceServicer_to_server(servicer, server)
    """

    def __init__(
        self,
        alarm_manager: AlarmManager,
        subscription_queue_size: int = 1000,
    ) -> None:
        """Initialize the AlarmService servicer.
        
        Args:
            alarm_manager: AlarmManager instance for alarm operations.
            subscription_queue_size: Maximum queue size for subscriptions.
        """
        self._alarm_manager = alarm_manager
        self._subscription_queue_size = subscription_queue_size
        self._subscriptions: Dict[str, AlarmSubscription] = {}
        self._lock = asyncio.Lock()

        # Register callback with alarm manager
        asyncio.create_task(self._setup_notification_callback())

        logger.info("AlarmServiceServicer initialized")

    async def _setup_notification_callback(self) -> None:
        """Setup notification callback with alarm manager."""
        # Subscribe to alarm manager notifications
        self._subscription_id = await self._alarm_manager.subscribe_notifications(
            client_id="grpc-alarm-service",
            callback=self._handle_alarm_notification,
        )
        logger.debug(f"Registered notification callback: {self._subscription_id}")

    async def _handle_alarm_notification(self, notification: Dict[str, Any]) -> None:
        """Handle alarm notification from AlarmManager.
        
        Args:
            notification: Notification dictionary from AlarmManager.
        """
        alarm_dict = notification.get("alarm", {})
        event_type = notification.get("event_type", "alarm")

        # Forward to all matching subscriptions
        async with self._lock:
            for sub in self._subscriptions.values():
                if not sub.active:
                    continue

                # Check filters
                if not self._matches_subscription(alarm_dict, sub):
                    continue

                try:
                    # Non-blocking put with timeout
                    await asyncio.wait_for(
                        sub.queue.put(notification),
                        timeout=1.0
                    )
                except asyncio.TimeoutError:
                    logger.warning(
                        f"Subscription {sub.subscription_id} queue full, "
                        "dropping notification"
                    )

    def _matches_subscription(
        self,
        alarm_dict: Dict[str, Any],
        subscription: AlarmSubscription,
    ) -> bool:
        """Check if an alarm matches subscription filters.
        
        Args:
            alarm_dict: Alarm dictionary to check.
            subscription: Subscription to match against.
            
        Returns:
            True if alarm matches subscription criteria.
        """
        # Check severity filter
        if subscription.severities:
            severity = severity_to_enum(alarm_dict.get("severity", ""))
            if severity not in subscription.severities:
                return False

        # Check source filter
        if subscription.sources:
            source = vendor_to_enum(alarm_dict.get("source", ""))
            if source not in subscription.sources:
                return False

        # Check resource prefix filter
        if subscription.resource_prefix:
            resource_path = alarm_dict.get("resource_path", "")
            if not resource_path.startswith(subscription.resource_prefix):
                return False

        # Check include_cleared filter
        if not subscription.include_cleared:
            state = alarm_dict.get("state", "")
            if state == "CLEARED":
                return False

        return True

    async def GetAlarms(
        self,
        request: Any,
        context: Any,
    ) -> Any:
        """Get alarms with optional filtering.
        
        Retrieves alarms from the alarm manager with support for
        filtering by severity, source, state, and resource path.
        
        Args:
            request: GetAlarmsRequest with filter parameters.
            context: gRPC context.
            
        Returns:
            GetAlarmsResponse with matching alarms.
        """
        try:
            # Extract filter parameters
            severities = []
            if hasattr(request, "severities") and request.severities:
                for s in request.severities:
                    if s == 1:
                        severities.append(AlarmSeverity.CRITICAL)
                    elif s == 2:
                        severities.append(AlarmSeverity.HIGH)
                    elif s == 3:
                        severities.append(AlarmSeverity.MEDIUM)
                    elif s == 4:
                        severities.append(AlarmSeverity.LOW)
                    elif s == 5:
                        severities.append(AlarmSeverity.INDETERMINATE)
                    elif s == 6:
                        severities.append(AlarmSeverity.CLEARED)

            sources = []
            if hasattr(request, "sources") and request.sources:
                for s in request.sources:
                    if s == 1:
                        sources.append(AlarmSource.ERICSSON)
                    elif s == 2:
                        sources.append(AlarmSource.HUAWEI)
                    elif s == 3:
                        sources.append(AlarmSource.NOKIA)
                    elif s == 4:
                        sources.append(AlarmSource.CISCO)
                    elif s == 5:
                        sources.append(AlarmSource.ZTE)

            states = []
            if hasattr(request, "states") and request.states:
                for s in request.states:
                    if s == 1:
                        states.append(AlarmState.RAISED)
                    elif s == 2:
                        states.append(AlarmState.UPDATED)
                    elif s == 3:
                        states.append(AlarmState.CLEARED)
                    elif s == 4:
                        states.append(AlarmState.ACKNOWLEDGED)
                    elif s == 5:
                        states.append(AlarmState.SUPPRESSED)

            resource_prefix = ""
            if hasattr(request, "resource_prefix"):
                resource_prefix = request.resource_prefix

            pagination = getattr(request, "pagination", None)
            page_size = 100
            if pagination and hasattr(pagination, "page_size"):
                page_size = pagination.page_size or 100

            # Get alarms from manager
            alarms = await self._alarm_manager.get_active_alarms(
                severities=severities if severities else None,
                sources=sources if sources else None,
                resource_prefix=resource_prefix if resource_prefix else None,
                limit=page_size,
            )

            # Filter by state if specified
            if states:
                alarms = [a for a in alarms if a.state in states]

            # Build response
            alarm_messages = []
            severity_counts: Dict[str, int] = {}

            for alarm in alarms:
                alarm_messages.append(self._alarm_to_proto(alarm))
                sev_name = alarm.severity.value
                severity_counts[sev_name] = severity_counts.get(sev_name, 0) + 1

            logger.info(
                f"GetAlarms returned {len(alarm_messages)} alarms "
                f"(filters: severities={len(severities)}, sources={len(sources)})"
            )

            # Create response
            response = self._create_get_alarms_response(
                alarm_messages, severity_counts
            )
            return response

        except Exception as e:
            logger.error(f"GetAlarms error: {e}")
            await context.abort(
                grpc.StatusCode.INTERNAL if GRPC_AVAILABLE else 13,
                f"Failed to get alarms: {str(e)}"
            )

    def _alarm_to_proto(self, alarm: Alarm) -> Dict[str, Any]:
        """Convert Alarm model to proto-compatible dictionary.
        
        Args:
            alarm: Alarm model instance.
            
        Returns:
            Dictionary with proto-compatible fields.
        """
        return {
            "alarm_id": alarm.alarm_id,
            "correlation_key": alarm.correlation_key,
            "source": vendor_to_enum(alarm.source.value),
            "severity": severity_to_enum(alarm.severity.value),
            "state": state_to_enum(alarm.state.value),
            "resource_path": alarm.resource_path,
            "alarm_text": alarm.alarm_text,
            "probable_cause": alarm.probable_cause,
            "specific_problem": alarm.specific_problem,
            "raised_at": alarm.raised_at,
            "updated_at": alarm.updated_at,
            "cleared_at": alarm.cleared_at,
            "acknowledged_at": alarm.acknowledged_at,
            "acknowledged_by": alarm.acknowledged_by or "",
            "notification_count": alarm.notification_count,
            "additional_info": alarm.additional_info,
            "vendor_data": alarm.vendor_data,
        }

    def _create_get_alarms_response(
        self,
        alarms: List[Dict[str, Any]],
        severity_counts: Dict[str, int],
    ) -> Dict[str, Any]:
        """Create GetAlarmsResponse dictionary.
        
        Args:
            alarms: List of alarm dictionaries.
            severity_counts: Dictionary of severity counts.
            
        Returns:
            Response dictionary.
        """
        return {
            "alarms": alarms,
            "pagination": {
                "next_page_token": "",
                "total_count": len(alarms),
                "has_more": False,
            },
            "total_count": len(alarms),
            "severity_counts": severity_counts,
        }

    async def AcknowledgeAlarm(
        self,
        request: Any,
        context: Any,
    ) -> Any:
        """Acknowledge an alarm.
        
        Acknowledges one or more alarms by ID, optionally including
        related alarms based on correlation keys.
        
        Args:
            request: AcknowledgeAlarmRequest with alarm_id and user.
            context: gRPC context.
            
        Returns:
            AcknowledgeAlarmResponse with updated alarm.
        """
        try:
            alarm_id = getattr(request, "alarm_id", "")
            user = getattr(request, "user", "")
            comment = getattr(request, "comment", "")
            acknowledge_related = getattr(request, "acknowledge_related", False)

            if not alarm_id:
                await context.abort(
                    grpc.StatusCode.INVALID_ARGUMENT if GRPC_AVAILABLE else 3,
                    "alarm_id is required"
                )

            if not user:
                await context.abort(
                    grpc.StatusCode.INVALID_ARGUMENT if GRPC_AVAILABLE else 3,
                    "user is required"
                )

            # Acknowledge the alarm
            try:
                alarm = await self._alarm_manager.acknowledge_alarm(
                    alarm_id=alarm_id,
                    user=user,
                    comment=comment,
                )
            except AlarmNotFoundError:
                await context.abort(
                    grpc.StatusCode.NOT_FOUND if GRPC_AVAILABLE else 5,
                    f"Alarm not found: {alarm_id}"
                )
            except AlarmStateError as e:
                await context.abort(
                    grpc.StatusCode.FAILED_PRECONDITION if GRPC_AVAILABLE else 9,
                    str(e)
                )

            # Find related alarms if requested
            related_ids: List[str] = []
            if acknowledge_related:
                # Get alarms with same correlation key
                all_alarms = await self._alarm_manager.get_active_alarms()
                for a in all_alarms:
                    if (a.correlation_key == alarm.correlation_key and
                        a.alarm_id != alarm_id and
                        a.state != AlarmState.ACKNOWLEDGED):
                        try:
                            await self._alarm_manager.acknowledge_alarm(
                                alarm_id=a.alarm_id,
                                user=user,
                                comment=comment,
                            )
                            related_ids.append(a.alarm_id)
                        except Exception as e:
                            logger.warning(
                                f"Failed to acknowledge related alarm {a.alarm_id}: {e}"
                            )

            logger.info(
                f"Alarm {alarm_id} acknowledged by {user}"
                f"{' with ' + str(len(related_ids)) + ' related' if related_ids else ''}"
            )

            return {
                "alarm": self._alarm_to_proto(alarm),
                "success": True,
                "related_alarm_ids": related_ids,
                "acknowledged_at": datetime.now(timezone.utc),
            }

        except Exception as e:
            logger.error(f"AcknowledgeAlarm error: {e}")
            if GRPC_AVAILABLE:
                await context.abort(
                    grpc.StatusCode.INTERNAL,
                    f"Failed to acknowledge alarm: {str(e)}"
                )

    async def ClearAlarm(
        self,
        request: Any,
        context: Any,
    ) -> Any:
        """Clear an alarm.
        
        Clears an alarm by ID with optional reason tracking.
        
        Args:
            request: ClearAlarmRequest with alarm_id and user.
            context: gRPC context.
            
        Returns:
            ClearAlarmResponse with updated alarm.
        """
        try:
            alarm_id = getattr(request, "alarm_id", "")
            user = getattr(request, "user", "")
            reason = getattr(request, "reason", "")

            if not alarm_id:
                await context.abort(
                    grpc.StatusCode.INVALID_ARGUMENT if GRPC_AVAILABLE else 3,
                    "alarm_id is required"
                )

            # Clear the alarm
            try:
                alarm = await self._alarm_manager.clear_alarm(
                    alarm_id=alarm_id,
                    user=user if user else None,
                    reason=reason if reason else None,
                )
            except AlarmNotFoundError:
                await context.abort(
                    grpc.StatusCode.NOT_FOUND if GRPC_AVAILABLE else 5,
                    f"Alarm not found: {alarm_id}"
                )

            logger.info(f"Alarm {alarm_id} cleared by {user or 'system'}")

            return {
                "alarm": self._alarm_to_proto(alarm),
                "success": True,
                "cleared_at": datetime.now(timezone.utc),
            }

        except Exception as e:
            logger.error(f"ClearAlarm error: {e}")
            if GRPC_AVAILABLE:
                await context.abort(
                    grpc.StatusCode.INTERNAL,
                    f"Failed to clear alarm: {str(e)}"
                )

    async def SubscribeAlarms(
        self,
        request: Any,
        context: Any,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Subscribe to alarm notifications.
        
        Creates a server-streaming subscription for real-time alarm
        notifications based on filter criteria.
        
        Args:
            request: SubscribeAlarmsRequest with filter parameters.
            context: gRPC context.
            
        Yields:
            AlarmNotification messages for matching alarms.
        """
        # Create subscription
        subscription_id = str(uuid.uuid4())
        client_id = f"client-{subscription_id[:8]}"

        # Extract filters
        severities = list(getattr(request, "severities", []))
        sources = list(getattr(request, "sources", []))
        resource_prefix = getattr(request, "resource_prefix", "")
        include_cleared = getattr(request, "include_cleared", False)

        # Create subscription object
        subscription = AlarmSubscription(
            subscription_id=subscription_id,
            client_id=client_id,
            severities=severities,
            sources=sources,
            resource_prefix=resource_prefix,
            include_cleared=include_cleared,
            queue=asyncio.Queue(maxsize=self._subscription_queue_size),
        )

        # Register subscription
        async with self._lock:
            self._subscriptions[subscription_id] = subscription

        logger.info(
            f"Created alarm subscription {subscription_id} "
            f"(severities={severities}, sources={sources})"
        )

        try:
            # Send initial connection notification
            yield {
                "subscription_id": subscription_id,
                "event_type": "subscription_started",
                "alarm": None,
                "event_time": datetime.now(timezone.utc),
            }

            # Stream notifications
            while subscription.active and context.is_active():
                try:
                    # Wait for notification with timeout
                    notification = await asyncio.wait_for(
                        subscription.queue.get(),
                        timeout=30.0  # Heartbeat interval
                    )

                    # Send notification
                    alarm_dict = notification.get("alarm", {})
                    yield {
                        "subscription_id": subscription_id,
                        "event_type": notification.get("event_type", "alarm"),
                        "alarm": alarm_dict,
                        "event_time": datetime.now(timezone.utc),
                    }

                except asyncio.TimeoutError:
                    # Send heartbeat
                    yield {
                        "subscription_id": subscription_id,
                        "event_type": "heartbeat",
                        "alarm": None,
                        "event_time": datetime.now(timezone.utc),
                    }

        except Exception as e:
            logger.error(f"SubscribeAlarms error for {subscription_id}: {e}")

        finally:
            # Cleanup subscription
            async with self._lock:
                if subscription_id in self._subscriptions:
                    del self._subscriptions[subscription_id]

            logger.info(f"Closed alarm subscription {subscription_id}")

    def get_subscription_count(self) -> int:
        """Get the number of active subscriptions.
        
        Returns:
            Number of active subscriptions.
        """
        return sum(1 for s in self._subscriptions.values() if s.active)

    def get_stats(self) -> Dict[str, Any]:
        """Get service statistics.
        
        Returns:
            Dictionary with service statistics.
        """
        alarm_stats = self._alarm_manager.get_stats()
        return {
            "active_subscriptions": self.get_subscription_count(),
            "total_subscriptions_created": len(self._subscriptions),
            "alarm_manager_stats": alarm_stats,
        }
