"""
Performance Service gRPC Implementation for Unified OSS Framework.

This module provides the gRPC service implementation for performance
monitoring and KPI management, integrating with the fcaps.performance module.

Features:
    - KPI catalog retrieval and querying
    - Metrics retrieval with aggregation support
    - Real-time KPI subscription via server streaming
    - Threshold breach detection and reporting
    - Integration with KPIManager from fcaps.performance module

Example:
    >>> from unified_oss.api.grpc.services.performance_service import PerformanceServiceServicer
    >>> from unified_oss.fcaps.performance.kpi_manager import KPIManager
    >>> kpi_manager = KPIManager()
    >>> servicer = PerformanceServiceServicer(kpi_manager)
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import (
    Any,
    AsyncGenerator,
    Callable,
    Dict,
    List,
    Optional,
    Tuple,
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
from unified_oss.fcaps.performance.kpi_manager import (
    KPIManager,
    KPIDefinition,
    KPIResult,
    KPICategory,
    KPIAggregation,
    SubscriptionStatus,
)

# Configure module logger
logger = logging.getLogger(__name__)


def category_to_enum(category: str) -> int:
    """Convert category string to proto enum value.
    
    Args:
        category: Category string from KPI model.
        
    Returns:
        Integer value for proto KPICategory enum.
    """
    mapping = {
        "AVAILABILITY": 1,
        "QUALITY": 2,
        "CAPACITY": 3,
        "MOBILITY": 4,
        "THROUGHPUT": 5,
        "RETAINABILITY": 6,
    }
    return mapping.get(category.upper(), 0)


def aggregation_to_enum(aggregation: str) -> int:
    """Convert aggregation string to proto enum value.
    
    Args:
        aggregation: Aggregation string.
        
    Returns:
        Integer value for proto KPIAggregation enum.
    """
    mapping = {
        "raw": 1,
        "avg": 2,
        "sum": 3,
        "min": 4,
        "max": 5,
        "p95": 6,
        "p99": 7,
    }
    return mapping.get(aggregation.lower(), 0)


@dataclass
class KPIStreamSubscription:
    """Represents an active KPI stream subscription.
    
    Attributes:
        subscription_id: Unique subscription identifier.
        kpi_ids: KPI IDs to subscribe to.
        ne_ids: Network element IDs to filter.
        threshold_min: Minimum threshold for alerts.
        threshold_max: Maximum threshold for alerts.
        queue: Async queue for notifications.
        active: Whether subscription is active.
        interval: Update interval in seconds.
    """
    subscription_id: str
    kpi_ids: List[str]
    ne_ids: List[str]
    threshold_min: Optional[float]
    threshold_max: Optional[float]
    queue: asyncio.Queue
    active: bool = True
    interval: int = 60


@dataclass
class ThresholdBreachRecord:
    """Record of a threshold breach event.
    
    Attributes:
        kpi_id: KPI identifier.
        ne_id: Network element identifier.
        current_value: Current KPI value.
        threshold_value: Threshold that was breached.
        threshold_type: Type of threshold (warning, critical).
        breach_direction: Direction of breach (above, below).
        breach_time: When the breach occurred.
        duration_seconds: Duration of the breach.
    """
    kpi_id: str
    ne_id: str
    current_value: float
    threshold_value: float
    threshold_type: str
    breach_direction: str
    breach_time: datetime
    duration_seconds: int = 0


class PerformanceServiceServicer:
    """gRPC servicer for PerformanceService operations.
    
    Provides performance monitoring operations including KPI retrieval,
    metrics querying, and real-time subscriptions.
    
    Attributes:
        kpi_manager: KPIManager instance from fcaps.performance module.
        subscriptions: Active KPI stream subscriptions.
        breach_history: History of threshold breaches.
    
    Example:
        >>> kpi_manager = KPIManager()
        >>> servicer = PerformanceServiceServicer(kpi_manager)
        >>> # Register with gRPC server
        >>> add_PerformanceServiceServicer_to_server(servicer, server)
    """

    def __init__(
        self,
        kpi_manager: KPIManager,
        subscription_queue_size: int = 1000,
        max_breach_history: int = 10000,
    ) -> None:
        """Initialize the PerformanceService servicer.
        
        Args:
            kpi_manager: KPIManager instance for KPI operations.
            subscription_queue_size: Maximum queue size for subscriptions.
            max_breach_history: Maximum number of breach records to retain.
        """
        self._kpi_manager = kpi_manager
        self._subscription_queue_size = subscription_queue_size
        self._max_breach_history = max_breach_history
        self._subscriptions: Dict[str, KPIStreamSubscription] = {}
        self._breach_history: List[ThresholdBreachRecord] = []
        self._subscription_tasks: Dict[str, asyncio.Task] = {}
        self._lock = asyncio.Lock()

        logger.info("PerformanceServiceServicer initialized")

    async def GetKPIs(
        self,
        request: Any,
        context: Any,
    ) -> Any:
        """Retrieve KPI definitions and current values.
        
        Gets KPI definitions from the catalog along with their current
        computed values for specified network elements.
        
        Args:
            request: GetKPIsRequest with kpi_ids and filters.
            context: gRPC context.
            
        Returns:
            GetKPIsResponse with KPI definitions and results.
        """
        try:
            # Extract parameters
            kpi_ids = list(getattr(request, "kpi_ids", []))
            ne_ids = list(getattr(request, "ne_ids", []))
            category = getattr(request, "category", 0)
            include_definitions = getattr(request, "include_definitions", True)

            # Convert category enum to KPICategory
            category_enum = None
            if category:
                category_map = {
                    1: KPICategory.AVAILABILITY,
                    2: KPICategory.QUALITY,
                    3: KPICategory.CAPACITY,
                    4: KPICategory.MOBILITY,
                    5: KPICategory.THROUGHPUT,
                    6: KPICategory.RETAINABILITY,
                }
                category_enum = category_map.get(category)

            # Get KPI definitions
            definitions = []
            if include_definitions:
                if kpi_ids:
                    for kpi_id in kpi_ids:
                        defn = self._kpi_manager.catalog.get_kpi(kpi_id)
                        if defn:
                            definitions.append(defn)
                elif category_enum:
                    definitions = self._kpi_manager.catalog.get_kpis_by_category(
                        category_enum
                    )
                else:
                    definitions = self._kpi_manager.catalog.get_all_kpis()

            # Get current KPI values
            results = []
            kpis_to_query = kpi_ids if kpi_ids else [d.kpi_id for d in definitions]
            ne_list = ne_ids if ne_ids else [None]

            for kpi_id in kpis_to_query:
                for ne_id in ne_list:
                    result = await self._kpi_manager.get_kpi(kpi_id, ne_id)
                    if result:
                        results.append(result)

            logger.info(
                f"GetKPIs returned {len(definitions)} definitions, "
                f"{len(results)} results"
            )

            # Build response
            return {
                "definitions": [self._definition_to_dict(d) for d in definitions],
                "results": [self._result_to_dict(r) for r in results],
                "vendor_mappings": self._get_vendor_mappings(),
            }

        except Exception as e:
            logger.error(f"GetKPIs error: {e}")
            if GRPC_AVAILABLE:
                await context.abort(
                    grpc.StatusCode.INTERNAL,
                    f"Failed to get KPIs: {str(e)}"
                )

    def _definition_to_dict(self, definition: KPIDefinition) -> Dict[str, Any]:
        """Convert KPIDefinition to proto-compatible dictionary.
        
        Args:
            definition: KPIDefinition instance.
            
        Returns:
            Dictionary with proto-compatible fields.
        """
        return {
            "kpi_id": definition.kpi_id,
            "name": definition.name,
            "description": definition.description,
            "category": category_to_enum(definition.category.value),
            "unit": definition.unit,
            "formula": definition.formula,
            "tags": definition.tags,
            "thresholds": definition.thresholds,
            "created_at": definition.created_at,
            "updated_at": definition.updated_at,
        }

    def _result_to_dict(self, result: KPIResult) -> Dict[str, Any]:
        """Convert KPIResult to proto-compatible dictionary.
        
        Args:
            result: KPIResult instance.
            
        Returns:
            Dictionary with proto-compatible fields.
        """
        return {
            "kpi_id": result.kpi_id,
            "value": result.value,
            "unit": result.unit,
            "timestamp": result.timestamp,
            "ne_id": result.ne_id or "",
            "quality_flag": result.quality_flag,
            "raw_counters": result.raw_counters,
            "metadata": result.metadata,
        }

    def _get_vendor_mappings(self) -> Dict[str, str]:
        """Get vendor counter mappings for KPIs.
        
        Returns:
            Dictionary mapping counter names to vendors.
        """
        mappings = {}
        for kpi in self._kpi_manager.catalog.get_all_kpis():
            for vendor, counters in kpi.vendor_mappings.items():
                for counter_name in counters.keys():
                    key = f"{kpi.kpi_id}:{counter_name}"
                    mappings[key] = vendor
        return mappings

    async def GetMetrics(
        self,
        request: Any,
        context: Any,
    ) -> Any:
        """Retrieve metrics with aggregation support.
        
        Gets metrics for specified KPIs and network elements with
        optional time range filtering and aggregation.
        
        Args:
            request: GetMetricsRequest with metric names and filters.
            context: gRPC context.
            
        Returns:
            GetMetricsResponse with metrics and aggregated results.
        """
        try:
            # Extract parameters
            metric_names = list(getattr(request, "metric_names", []))
            ne_ids = list(getattr(request, "ne_ids", []))
            aggregation = getattr(request, "aggregation", 0)
            label_filters = dict(getattr(request, "label_filters", {}))

            # Extract time range
            time_range = getattr(request, "time_range", None)
            start_time = None
            end_time = None
            if time_range:
                start_time = getattr(time_range, "start_time", None)
                end_time = getattr(time_range, "end_time", None)

            # Convert aggregation enum
            agg_enum = KPIAggregation.RAW
            if aggregation:
                agg_map = {
                    1: KPIAggregation.RAW,
                    2: KPIAggregation.AVG,
                    3: KPIAggregation.SUM,
                    4: KPIAggregation.MIN,
                    5: KPIAggregation.MAX,
                    6: KPIAggregation.PERCENTILE_95,
                    7: KPIAggregation.PERCENTILE_99,
                }
                agg_enum = agg_map.get(aggregation, KPIAggregation.RAW)

            # Get metrics
            metrics = []
            aggregated_results = {}

            kpi_ids = metric_names if metric_names else []
            if not kpi_ids:
                kpi_ids = [d.kpi_id for d in self._kpi_manager.catalog.get_all_kpis()]

            for kpi_id in kpi_ids:
                ne_list = ne_ids if ne_ids else [None]
                for ne_id in ne_list:
                    if start_time and end_time:
                        # Historical query
                        history = await self._kpi_manager.get_kpi_history(
                            kpi_id=kpi_id,
                            start_time=start_time,
                            end_time=end_time,
                            ne_id=ne_id,
                            aggregation=agg_enum,
                        )
                        for result in history:
                            metrics.append(self._result_to_metric(result))
                    else:
                        # Current value
                        result = await self._kpi_manager.get_kpi(kpi_id, ne_id)
                        if result:
                            metrics.append(self._result_to_metric(result))
                            aggregated_results[kpi_id] = result

            logger.info(
                f"GetMetrics returned {len(metrics)} metrics "
                f"(aggregation={agg_enum.value})"
            )

            return {
                "metrics": metrics,
                "pagination": {
                    "next_page_token": "",
                    "total_count": len(metrics),
                    "has_more": False,
                },
                "aggregated_results": {
                    k: self._result_to_dict(v)
                    for k, v in aggregated_results.items()
                },
            }

        except Exception as e:
            logger.error(f"GetMetrics error: {e}")
            if GRPC_AVAILABLE:
                await context.abort(
                    grpc.StatusCode.INTERNAL,
                    f"Failed to get metrics: {str(e)}"
                )

    def _result_to_metric(self, result: KPIResult) -> Dict[str, Any]:
        """Convert KPIResult to metric dictionary.
        
        Args:
            result: KPIResult instance.
            
        Returns:
            Dictionary with metric fields.
        """
        return {
            "metric_id": str(uuid.uuid4()),
            "name": result.kpi_id,
            "ne_id": result.ne_id or "",
            "value": result.value or 0.0,
            "unit": result.unit,
            "timestamp": result.timestamp,
            "labels": {},
            "dimensions": result.raw_counters,
        }

    async def SubscribeKPIs(
        self,
        request: Any,
        context: Any,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Subscribe to KPI notifications.
        
        Creates a server-streaming subscription for real-time KPI
        updates with optional threshold monitoring.
        
        Args:
            request: SubscribeKPIsRequest with KPI IDs and thresholds.
            context: gRPC context.
            
        Yields:
            KPINotification messages for KPI updates.
        """
        # Create subscription
        subscription_id = str(uuid.uuid4())

        # Extract parameters
        kpi_ids = list(getattr(request, "kpi_ids", []))
        ne_ids = list(getattr(request, "ne_ids", []))
        interval = getattr(request, "interval", None)
        threshold_min = getattr(request, "threshold_min", None)
        threshold_max = getattr(request, "threshold_max", None)

        # Handle interval
        interval_seconds = 60
        if interval and hasattr(interval, "seconds"):
            interval_seconds = interval.seconds

        # Create subscription object
        subscription = KPIStreamSubscription(
            subscription_id=subscription_id,
            kpi_ids=kpi_ids,
            ne_ids=ne_ids,
            threshold_min=threshold_min,
            threshold_max=threshold_max,
            queue=asyncio.Queue(maxsize=self._subscription_queue_size),
            interval=interval_seconds,
        )

        # Register subscription
        async with self._lock:
            self._subscriptions[subscription_id] = subscription

        # Start update task
        task = asyncio.create_task(
            self._subscription_update_loop(subscription_id)
        )
        self._subscription_tasks[subscription_id] = task

        logger.info(
            f"Created KPI subscription {subscription_id} "
            f"(kpis={kpi_ids}, interval={interval_seconds}s)"
        )

        try:
            # Send initial connection notification
            yield {
                "subscription_id": subscription_id,
                "result": None,
                "event_type": "subscription_started",
                "threshold_breach": False,
                "breach_direction": "",
                "event_time": datetime.now(timezone.utc),
            }

            # Stream notifications
            while subscription.active and context.is_active():
                try:
                    notification = await asyncio.wait_for(
                        subscription.queue.get(),
                        timeout=30.0
                    )

                    yield notification

                except asyncio.TimeoutError:
                    # Send heartbeat
                    yield {
                        "subscription_id": subscription_id,
                        "result": None,
                        "event_type": "heartbeat",
                        "threshold_breach": False,
                        "breach_direction": "",
                        "event_time": datetime.now(timezone.utc),
                    }

        except Exception as e:
            logger.error(f"SubscribeKPIs error for {subscription_id}: {e}")

        finally:
            # Cleanup subscription
            subscription.active = False
            task = self._subscription_tasks.pop(subscription_id, None)
            if task:
                task.cancel()

            async with self._lock:
                self._subscriptions.pop(subscription_id, None)

            logger.info(f"Closed KPI subscription {subscription_id}")

    async def _subscription_update_loop(self, subscription_id: str) -> None:
        """Run the update loop for a KPI subscription.
        
        Args:
            subscription_id: Subscription identifier.
        """
        subscription = self._subscriptions.get(subscription_id)
        if not subscription:
            return

        while subscription.active:
            try:
                # Fetch KPI values
                for kpi_id in subscription.kpi_ids:
                    ne_list = subscription.ne_ids if subscription.ne_ids else [None]
                    for ne_id in ne_list:
                        result = await self._kpi_manager.get_kpi(kpi_id, ne_id)
                        if not result:
                            continue

                        # Check thresholds
                        threshold_breach = False
                        breach_direction = ""

                        if result.value is not None:
                            if subscription.threshold_min is not None:
                                if result.value < subscription.threshold_min:
                                    threshold_breach = True
                                    breach_direction = "below"
                                    self._record_breach(
                                        kpi_id, ne_id, result.value,
                                        subscription.threshold_min, "warning", "below"
                                    )

                            if subscription.threshold_max is not None:
                                if result.value > subscription.threshold_max:
                                    threshold_breach = True
                                    breach_direction = "above"
                                    self._record_breach(
                                        kpi_id, ne_id, result.value,
                                        subscription.threshold_max, "critical", "above"
                                    )

                        # Queue notification
                        notification = {
                            "subscription_id": subscription_id,
                            "result": self._result_to_dict(result),
                            "event_type": "kpi_update",
                            "threshold_breach": threshold_breach,
                            "breach_direction": breach_direction,
                            "event_time": datetime.now(timezone.utc),
                        }

                        try:
                            await asyncio.wait_for(
                                subscription.queue.put(notification),
                                timeout=1.0
                            )
                        except asyncio.TimeoutError:
                            logger.warning(
                                f"Subscription {subscription_id} queue full"
                            )

                await asyncio.sleep(subscription.interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Update loop error for {subscription_id}: {e}")
                await asyncio.sleep(5)

    def _record_breach(
        self,
        kpi_id: str,
        ne_id: Optional[str],
        current_value: float,
        threshold_value: float,
        threshold_type: str,
        breach_direction: str,
    ) -> None:
        """Record a threshold breach event.
        
        Args:
            kpi_id: KPI identifier.
            ne_id: Network element identifier.
            current_value: Current KPI value.
            threshold_value: Threshold value.
            threshold_type: Type of threshold.
            breach_direction: Direction of breach.
        """
        breach = ThresholdBreachRecord(
            kpi_id=kpi_id,
            ne_id=ne_id or "",
            current_value=current_value,
            threshold_value=threshold_value,
            threshold_type=threshold_type,
            breach_direction=breach_direction,
            breach_time=datetime.now(timezone.utc),
        )

        self._breach_history.append(breach)

        # Trim history
        if len(self._breach_history) > self._max_breach_history:
            self._breach_history = self._breach_history[-self._max_breach_history:]

        logger.info(
            f"Threshold breach recorded: {kpi_id}={current_value} "
            f"({breach_direction} {threshold_value})"
        )

    async def GetThresholdBreaches(
        self,
        request: Any,
        context: Any,
    ) -> Any:
        """Retrieve threshold breach history.
        
        Gets historical threshold breach records with optional filtering.
        
        Args:
            request: GetThresholdBreachesRequest with filters.
            context: gRPC context.
            
        Returns:
            GetThresholdBreachesResponse with breach records.
        """
        try:
            # Extract parameters
            kpi_ids = list(getattr(request, "kpi_ids", []))
            ne_ids = list(getattr(request, "ne_ids", []))
            threshold_types = list(getattr(request, "threshold_types", []))
            active_only = getattr(request, "active_only", False)

            # Extract time range
            time_range = getattr(request, "time_range", None)
            start_time = None
            end_time = None
            if time_range:
                start_time = getattr(time_range, "start_time", None)
                end_time = getattr(time_range, "end_time", None)

            # Filter breaches
            breaches = list(self._breach_history)

            if kpi_ids:
                breaches = [b for b in breaches if b.kpi_id in kpi_ids]
            if ne_ids:
                breaches = [b for b in breaches if b.ne_id in ne_ids]
            if threshold_types:
                breaches = [b for b in breaches if b.threshold_type in threshold_types]
            if start_time:
                breaches = [b for b in breaches if b.breach_time >= start_time]
            if end_time:
                breaches = [b for b in breaches if b.breach_time <= end_time]

            # Count by KPI
            breaches_by_kpi: Dict[str, int] = {}
            for breach in breaches:
                breaches_by_kpi[breach.kpi_id] = breaches_by_kpi.get(breach.kpi_id, 0) + 1

            logger.info(f"GetThresholdBreaches returned {len(breaches)} breaches")

            return {
                "breaches": [self._breach_to_dict(b) for b in breaches],
                "pagination": {
                    "next_page_token": "",
                    "total_count": len(breaches),
                    "has_more": False,
                },
                "total_breaches": len(breaches),
                "breaches_by_kpi": breaches_by_kpi,
            }

        except Exception as e:
            logger.error(f"GetThresholdBreaches error: {e}")
            if GRPC_AVAILABLE:
                await context.abort(
                    grpc.StatusCode.INTERNAL,
                    f"Failed to get threshold breaches: {str(e)}"
                )

    def _breach_to_dict(self, breach: ThresholdBreachRecord) -> Dict[str, Any]:
        """Convert ThresholdBreachRecord to dictionary.
        
        Args:
            breach: ThresholdBreachRecord instance.
            
        Returns:
            Dictionary with breach fields.
        """
        return {
            "kpi_id": breach.kpi_id,
            "ne_id": breach.ne_id,
            "current_value": breach.current_value,
            "threshold_value": breach.threshold_value,
            "threshold_type": breach.threshold_type,
            "breach_direction": breach.breach_direction,
            "breach_time": breach.breach_time,
            "duration_seconds": breach.duration_seconds,
        }

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
        return {
            "active_subscriptions": self.get_subscription_count(),
            "total_subscriptions_created": len(self._subscriptions),
            "total_breach_records": len(self._breach_history),
            "kpi_catalog_size": len(self._kpi_manager.catalog.get_all_kpis()),
        }
