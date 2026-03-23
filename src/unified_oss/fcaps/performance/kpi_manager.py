"""
KPI Manager Module for Performance Management.

This module provides comprehensive KPI (Key Performance Indicator) management
capabilities including catalog management, real-time subscriptions, multi-vendor
counter mapping, and dashboard data aggregation.

Supports:
    - KPI catalog with predefined telecommunications KPIs
    - Real-time KPI subscription and notification
    - Multi-vendor counter mapping (Ericsson, Huawei, Nokia, etc.)
    - Historical KPI retrieval with aggregation
    - Dashboard-ready data aggregation

Example:
    >>> from unified_oss.fcaps.performance.kpi_manager import KPIManager
    >>> manager = KPIManager(db_pool, cache)
    >>> kpi_value = await manager.get_kpi("rrc_success_rate", ne_id="ENB001")
"""

from __future__ import annotations

import asyncio
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

from unified_oss.core.constants import (
    VENDOR_ERICSSON,
    VENDOR_HUAWEI,
    VENDOR_NOKIA,
    KPI_CATEGORY_AVAILABILITY,
    KPI_CATEGORY_QUALITY,
    KPI_CATEGORY_CAPACITY,
    KPI_CATEGORY_MOBILITY,
    KPI_CATEGORY_THROUGHPUT,
)

# Configure module logger
logger = logging.getLogger(__name__)

# Type aliases
T = TypeVar("T")
KPIValue = Union[float, int, None]
SubscriberCallback = Callable[[str, "KPIResult"], Awaitable[None]]


class KPICategory(Enum):
    """KPI category enumeration.
    
    Attributes:
        AVAILABILITY: Availability-related KPIs (uptime, reachability).
        QUALITY: Quality-related KPIs (success rates, error rates).
        CAPACITY: Capacity-related KPIs (utilization, load).
        MOBILITY: Mobility-related KPIs (handover success, mobility).
        THROUGHPUT: Throughput-related KPIs (data rates, bandwidth).
        RETAINABILITY: Retainability-related KPIs (drop rates, session stability).
    """
    
    AVAILABILITY = "AVAILABILITY"
    QUALITY = "QUALITY"
    CAPACITY = "CAPACITY"
    MOBILITY = "MOBILITY"
    THROUGHPUT = "THROUGHPUT"
    RETAINABILITY = "RETAINABILITY"


class KPIAggregation(Enum):
    """KPI aggregation methods.
    
    Attributes:
        RAW: No aggregation, raw values.
        AVG: Average over time period.
        SUM: Sum over time period.
        MIN: Minimum value in period.
        MAX: Maximum value in period.
        PERCENTILE_95: 95th percentile.
        PERCENTILE_99: 99th percentile.
    """
    
    RAW = "raw"
    AVG = "avg"
    SUM = "sum"
    MIN = "min"
    MAX = "max"
    PERCENTILE_95 = "p95"
    PERCENTILE_99 = "p99"


class SubscriptionStatus(Enum):
    """KPI subscription status.
    
    Attributes:
        ACTIVE: Subscription is active and receiving updates.
        PAUSED: Subscription is temporarily paused.
        EXPIRED: Subscription has expired.
        CANCELLED: Subscription was cancelled by user.
    """
    
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"


# Alias for backward compatibility
KPIStatus = SubscriptionStatus


@dataclass
class KPIDefinition:
    """Definition of a KPI in the catalog.
    
    Attributes:
        kpi_id: Unique identifier for the KPI.
        name: Human-readable KPI name.
        description: Detailed description of the KPI.
        category: KPI category (availability, quality, etc.).
        unit: Unit of measurement (percentage, count, mbps, etc.).
        formula: Formula for computing the KPI from counters.
        vendor_mappings: Mapping of vendor-specific counters.
        thresholds: Default threshold values (warning, critical).
        tags: Additional metadata tags.
    """
    
    kpi_id: str
    name: str
    description: str
    category: KPICategory
    unit: str
    formula: str
    vendor_mappings: Dict[str, Dict[str, str]] = field(default_factory=dict)
    thresholds: Dict[str, float] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    @property
    def kpi_name(self) -> str:
        """Alias for kpi_id for backward compatibility."""
        return self.kpi_id
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert KPI definition to dictionary.
        
        Returns:
            Dictionary representation of the KPI definition.
        """
        return {
            "kpi_id": self.kpi_id,
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "unit": self.unit,
            "formula": self.formula,
            "vendor_mappings": self.vendor_mappings,
            "thresholds": self.thresholds,
            "tags": self.tags,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass
class KPIResult:
    """Result of a KPI computation.
    
    Attributes:
        kpi_id: KPI identifier.
        value: Computed KPI value.
        unit: Unit of measurement.
        timestamp: Timestamp of the computation.
        ne_id: Network element identifier.
        quality_flag: Data quality indicator.
        raw_counters: Raw counter values used for computation.
        metadata: Additional metadata.
    """
    
    kpi_id: str
    value: KPIValue
    unit: str
    timestamp: datetime
    ne_id: Optional[str] = None
    quality_flag: str = "NORMAL"
    raw_counters: Dict[str, float] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert KPI result to dictionary.
        
        Returns:
            Dictionary representation of the KPI result.
        """
        return {
            "kpi_id": self.kpi_id,
            "value": self.value,
            "unit": self.unit,
            "timestamp": self.timestamp.isoformat(),
            "ne_id": self.ne_id,
            "quality_flag": self.quality_flag,
            "raw_counters": self.raw_counters,
            "metadata": self.metadata,
        }


@dataclass
class DashboardData:
    """Aggregated data for dashboard display.
    
    Attributes:
        dashboard_id: Unique dashboard identifier.
        title: Dashboard title.
        widgets: List of widget configurations.
        kpi_data: Aggregated KPI data by widget.
        last_updated: Last update timestamp.
        refresh_interval: Auto-refresh interval in seconds.
    """
    
    dashboard_id: str
    title: str
    widgets: List[Dict[str, Any]] = field(default_factory=list)
    kpi_data: Dict[str, List[KPIResult]] = field(default_factory=dict)
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    refresh_interval: int = 60
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert dashboard data to dictionary.
        
        Returns:
            Dictionary representation of the dashboard data.
        """
        return {
            "dashboard_id": self.dashboard_id,
            "title": self.title,
            "widgets": self.widgets,
            "kpi_data": {
                k: [v.to_dict() for v in vals] for k, vals in self.kpi_data.items()
            },
            "last_updated": self.last_updated.isoformat(),
            "refresh_interval": self.refresh_interval,
        }


class KPICatalog:
    """Catalog of predefined KPIs for telecommunications networks.
    
    This class manages the KPI catalog including:
    - Standard telecommunications KPIs (RRC success, HO success, throughput)
    - Vendor-specific counter mappings
    - KPI definitions and formulas
    - Default threshold configurations
    
    Attributes:
        kpis: Dictionary of KPI definitions indexed by KPI ID.
        vendor_mappings: Vendor-specific counter name mappings.
    """
    
    def __init__(self) -> None:
        """Initialize the KPI catalog with predefined KPIs."""
        self._kpis: Dict[str, KPIDefinition] = {}
        self._vendor_counter_mappings: Dict[str, Dict[str, str]] = {}
        self._initialized = False
        
        # Initialize predefined KPIs
        self._initialize_predefined_kpis()
    
    def _initialize_predefined_kpis(self) -> None:
        """Initialize predefined telecommunications KPIs."""
        
        # RRC Connection Success Rate
        self.add_kpi(KPIDefinition(
            kpi_id="rrc_success_rate",
            name="rrc_success_rate",
            description="Percentage of successful RRC connection establishments",
            category=KPICategory.MOBILITY,
            unit="%",
            formula="(rrc_conn_successes / rrc_conn_attempts) * 100",
            vendor_mappings={
                VENDOR_ERICSSON: {
                    "rrc_conn_successes": "pmRrcConnEstabSuccess",
                    "rrc_conn_attempts": "pmRrcConnEstabAtt",
                },
                VENDOR_HUAWEI: {
                    "rrc_conn_successes": "VS.RRC.ConnEstab.Success",
                    "rrc_conn_attempts": "VS.RRC.ConnEstab.Att",
                },
                VENDOR_NOKIA: {
                    "rrc_conn_successes": "RRC_CONN_ESTAB_SUCCESS",
                    "rrc_conn_attempts": "RRC_CONN_ESTAB_ATT",
                },
            },
            thresholds={"warning": 95.0, "critical": 90.0},
            tags=["lte", "5g", "rrc", "mobility"],
        ))
        
        # RRC Connection Drop Rate
        self.add_kpi(KPIDefinition(
            kpi_id="rrc_drop_rate",
            name="RRC Connection Drop Rate",
            description="Percentage of RRC connections that were dropped",
            category=KPICategory.QUALITY,
            unit="%",
            formula="(rrc_conn_drops / rrc_conn_successes) * 100",
            vendor_mappings={
                VENDOR_ERICSSON: {
                    "rrc_conn_drops": "pmRrcConnEstabFail",
                    "rrc_conn_successes": "pmRrcConnEstabSuccess",
                },
                VENDOR_HUAWEI: {
                    "rrc_conn_drops": "VS.RRC.ConnEstab.Fail",
                    "rrc_conn_successes": "VS.RRC.ConnEstab.Success",
                },
                VENDOR_NOKIA: {
                    "rrc_conn_drops": "RRC_CONN_ESTAB_FAIL",
                    "rrc_conn_successes": "RRC_CONN_ESTAB_SUCCESS",
                },
            },
            thresholds={"warning": 2.0, "critical": 5.0},
            tags=["lte", "5g", "rrc", "quality"],
        ))
        
        # Handover Success Rate
        self.add_kpi(KPIDefinition(
            kpi_id="ho_success_rate",
            name="ho_success_rate",
            description="Percentage of successful handovers",
            category=KPICategory.MOBILITY,
            unit="%",
            formula="(ho_successes / ho_attempts) * 100",
            vendor_mappings={
                VENDOR_ERICSSON: {
                    "ho_successes": "pmHoSuccess",
                    "ho_attempts": "pmHoAtt",
                },
                VENDOR_HUAWEI: {
                    "ho_successes": "VS.HO.Success",
                    "ho_attempts": "VS.HO.Att",
                },
                VENDOR_NOKIA: {
                    "ho_successes": "HO_SUCCESS",
                    "ho_attempts": "HO_ATT",
                },
            },
            thresholds={"warning": 95.0, "critical": 90.0},
            tags=["lte", "5g", "handover", "mobility"],
        ))
        
        # E-RAB Setup Success Rate
        self.add_kpi(KPIDefinition(
            kpi_id="erab_success_rate",
            name="E-RAB Setup Success Rate",
            description="Percentage of successful E-RAB setups",
            category=KPICategory.QUALITY,
            unit="%",
            formula="(erab_setup_success / erab_setup_attempts) * 100",
            vendor_mappings={
                VENDOR_ERICSSON: {
                    "erab_setup_success": "pmErabEstabSuccess",
                    "erab_setup_attempts": "pmErabEstabAtt",
                },
                VENDOR_HUAWEI: {
                    "erab_setup_success": "VS.ERAB.Setup.Success",
                    "erab_setup_attempts": "VS.ERAB.Setup.Att",
                },
                VENDOR_NOKIA: {
                    "erab_setup_success": "ERAB_SETUP_SUCCESS",
                    "erab_setup_attempts": "ERAB_SETUP_ATT",
                },
            },
            thresholds={"warning": 95.0, "critical": 90.0},
            tags=["lte", "erab", "quality"],
        ))
        
        # Cell Availability
        self.add_kpi(KPIDefinition(
            kpi_id="cell_availability",
            name="Cell Availability",
            description="Percentage of time the cell was available",
            category=KPICategory.AVAILABILITY,
            unit="%",
            formula="(cell_available_time / total_time) * 100",
            vendor_mappings={
                VENDOR_ERICSSON: {
                    "cell_available_time": "pmCellAvailTime",
                    "total_time": "pmCellTotalTime",
                },
                VENDOR_HUAWEI: {
                    "cell_available_time": "VS.Cell.AvailTime",
                    "total_time": "VS.Cell.TotalTime",
                },
                VENDOR_NOKIA: {
                    "cell_available_time": "CELL_AVAIL_TIME",
                    "total_time": "CELL_TOTAL_TIME",
                },
            },
            thresholds={"warning": 99.0, "critical": 95.0},
            tags=["lte", "5g", "availability"],
        ))
        
        # Downlink Throughput
        self.add_kpi(KPIDefinition(
            kpi_id="dl_throughput",
            name="Downlink Throughput",
            description="Average downlink throughput per user",
            category=KPICategory.THROUGHPUT,
            unit="Mbps",
            formula="dl_bytes / (active_users * measurement_period) / 1000000",
            vendor_mappings={
                VENDOR_ERICSSON: {
                    "dl_bytes": "pmDlBytes",
                    "active_users": "pmActiveUsers",
                    "measurement_period": "900",
                },
                VENDOR_HUAWEI: {
                    "dl_bytes": "VS.DL.Bytes",
                    "active_users": "VS.Active.Users",
                    "measurement_period": "900",
                },
                VENDOR_NOKIA: {
                    "dl_bytes": "DL_BYTES",
                    "active_users": "ACTIVE_USERS",
                    "measurement_period": "900",
                },
            },
            thresholds={"warning": 50.0, "critical": 20.0},
            tags=["lte", "5g", "throughput", "downlink"],
        ))
        
        # Uplink Throughput
        self.add_kpi(KPIDefinition(
            kpi_id="ul_throughput",
            name="Uplink Throughput",
            description="Average uplink throughput per user",
            category=KPICategory.THROUGHPUT,
            unit="Mbps",
            formula="ul_bytes / (active_users * measurement_period) / 1000000",
            vendor_mappings={
                VENDOR_ERICSSON: {
                    "ul_bytes": "pmUlBytes",
                    "active_users": "pmActiveUsers",
                    "measurement_period": "900",
                },
                VENDOR_HUAWEI: {
                    "ul_bytes": "VS.UL.Bytes",
                    "active_users": "VS.Active.Users",
                    "measurement_period": "900",
                },
                VENDOR_NOKIA: {
                    "ul_bytes": "UL_BYTES",
                    "active_users": "ACTIVE_USERS",
                    "measurement_period": "900",
                },
            },
            thresholds={"warning": 20.0, "critical": 10.0},
            tags=["lte", "5g", "throughput", "uplink"],
        ))
        
        # PRB Utilization
        self.add_kpi(KPIDefinition(
            kpi_id="prb_utilization",
            name="PRB Utilization",
            description="Percentage of PRBs utilized",
            category=KPICategory.CAPACITY,
            unit="%",
            formula="(used_prb / total_prb) * 100",
            vendor_mappings={
                VENDOR_ERICSSON: {
                    "used_prb": "pmUsedPrb",
                    "total_prb": "pmTotalPrb",
                },
                VENDOR_HUAWEI: {
                    "used_prb": "VS.PRB.Used",
                    "total_prb": "VS.PRB.Total",
                },
                VENDOR_NOKIA: {
                    "used_prb": "USED_PRB",
                    "total_prb": "TOTAL_PRB",
                },
            },
            thresholds={"warning": 70.0, "critical": 85.0},
            tags=["lte", "5g", "capacity", "prb"],
        ))
        
        # CPU Utilization
        self.add_kpi(KPIDefinition(
            kpi_id="cpu_utilization",
            name="CPU Utilization",
            description="Percentage of CPU utilization",
            category=KPICategory.CAPACITY,
            unit="%",
            formula="cpu_usage",
            vendor_mappings={
                VENDOR_ERICSSON: {
                    "cpu_usage": "pmCpuUsage",
                },
                VENDOR_HUAWEI: {
                    "cpu_usage": "VS.CPU.Usage",
                },
                VENDOR_NOKIA: {
                    "cpu_usage": "CPU_USAGE",
                },
            },
            thresholds={"warning": 70.0, "critical": 85.0},
            tags=["system", "capacity", "cpu"],
        ))
        
        # Memory Utilization
        self.add_kpi(KPIDefinition(
            kpi_id="memory_utilization",
            name="Memory Utilization",
            description="Percentage of memory utilization",
            category=KPICategory.CAPACITY,
            unit="%",
            formula="memory_usage",
            vendor_mappings={
                VENDOR_ERICSSON: {
                    "memory_usage": "pmMemoryUsage",
                },
                VENDOR_HUAWEI: {
                    "memory_usage": "VS.Memory.Usage",
                },
                VENDOR_NOKIA: {
                    "memory_usage": "MEMORY_USAGE",
                },
            },
            thresholds={"warning": 70.0, "critical": 85.0},
            tags=["system", "capacity", "memory"],
        ))
        
        # 5G NR-specific KPIs
        self.add_kpi(KPIDefinition(
            kpi_id="nr_ran_success_rate",
            name="NR RAN Connection Success Rate",
            description="Percentage of successful NR RAN connections",
            category=KPICategory.MOBILITY,
            unit="%",
            formula="(nr_conn_success / nr_conn_attempts) * 100",
            vendor_mappings={
                VENDOR_ERICSSON: {
                    "nr_conn_success": "pmNrRanConnEstabSuccess",
                    "nr_conn_attempts": "pmNrRanConnEstabAtt",
                },
                VENDOR_HUAWEI: {
                    "nr_conn_success": "VS.NR.ConnEstab.Success",
                    "nr_conn_attempts": "VS.NR.ConnEstab.Att",
                },
            },
            thresholds={"warning": 95.0, "critical": 90.0},
            tags=["5g", "nr", "mobility"],
        ))
        
        # VoLTE Success Rate
        self.add_kpi(KPIDefinition(
            kpi_id="volte_success_rate",
            name="VoLTE Call Success Rate",
            description="Percentage of successful VoLTE calls",
            category=KPICategory.QUALITY,
            unit="%",
            formula="(volte_call_success / volte_call_attempts) * 100",
            vendor_mappings={
                VENDOR_ERICSSON: {
                    "volte_call_success": "pmVolteCallSuccess",
                    "volte_call_attempts": "pmVolteCallAtt",
                },
                VENDOR_HUAWEI: {
                    "volte_call_success": "VS.VoLTE.Call.Success",
                    "volte_call_attempts": "VS.VoLTE.Call.Att",
                },
            },
            thresholds={"warning": 95.0, "critical": 90.0},
            tags=["lte", "volte", "quality"],
        ))
        
        self._initialized = True
        logger.info(f"KPI catalog initialized with {len(self._kpis)} KPIs")
    
    def add_kpi(self, kpi: KPIDefinition) -> None:
        """Add a KPI definition to the catalog.
        
        Args:
            kpi: KPI definition to add.
        """
        self._kpis[kpi.kpi_id] = kpi
        logger.debug(f"Added KPI to catalog: {kpi.kpi_id}")
    
    def get_kpi(self, kpi_id: str) -> Optional[KPIDefinition]:
        """Get a KPI definition by ID.
        
        Args:
            kpi_id: KPI identifier.
            
        Returns:
            KPI definition or None if not found.
        """
        return self._kpis.get(kpi_id)
    
    def get_all_kpis(self) -> List[KPIDefinition]:
        """Get all KPI definitions.
        
        Returns:
            List of all KPI definitions.
        """
        return list(self._kpis.values())
    
    def get_kpis_by_category(self, category: KPICategory) -> List[KPIDefinition]:
        """Get KPIs filtered by category.
        
        Args:
            category: KPI category to filter by.
            
        Returns:
            List of KPI definitions in the category.
        """
        return [kpi for kpi in self._kpis.values() if kpi.category == category]
    
    def get_kpis_by_tag(self, tag: str) -> List[KPIDefinition]:
        """Get KPIs filtered by tag.
        
        Args:
            tag: Tag to filter by.
            
        Returns:
            List of KPI definitions with the tag.
        """
        return [kpi for kpi in self._kpis.values() if tag in kpi.tags]
    
    def get_vendor_counter_mapping(
        self, kpi_id: str, vendor: str
    ) -> Optional[Dict[str, str]]:
        """Get vendor-specific counter mapping for a KPI.
        
        Args:
            kpi_id: KPI identifier.
            vendor: Vendor name.
            
        Returns:
            Dictionary of counter name mappings or None.
        """
        kpi = self._kpis.get(kpi_id)
        if kpi:
            return kpi.vendor_mappings.get(vendor)
        return None
    
    def search_kpis(self, query: str) -> List[KPIDefinition]:
        """Search KPIs by name or description.
        
        Args:
            query: Search query string.
            
        Returns:
            List of matching KPI definitions.
        """
        query_lower = query.lower()
        results = []
        for kpi in self._kpis.values():
            if (query_lower in kpi.name.lower() or
                query_lower in kpi.description.lower() or
                query_lower in kpi.kpi_id.lower()):
                results.append(kpi)
        return results
    
    def list_all(self) -> List[KPIDefinition]:
        """List all KPI definitions.
        
        Returns:
            List of all KPI definitions.
        """
        return list(self._kpis.values())


@dataclass
class KPISubscription:
    """Subscription for real-time KPI updates.
    
    Attributes:
        subscription_id: Unique subscription identifier.
        kpi_ids: List of KPI IDs to subscribe to.
        kpi_name: Primary KPI name (alias for first kpi_id).
        ne_ids: Optional list of network element IDs to filter.
        callback: Async callback function for notifications.
        interval: Update interval in seconds.
        status: Current subscription status.
        created_at: Subscription creation timestamp.
        expires_at: Optional expiration timestamp.
        filters: Additional filter criteria.
        last_notification: Last notification timestamp.
        notification_count: Number of notifications sent.
    """
    
    subscription_id: str
    kpi_ids: List[str]
    callback: Optional[SubscriberCallback] = None
    ne_ids: Optional[List[str]] = None
    interval: int = 60
    status: SubscriptionStatus = SubscriptionStatus.ACTIVE
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    filters: Dict[str, Any] = field(default_factory=dict)
    last_notification: Optional[datetime] = None
    notification_count: int = 0
    
    @property
    def kpi_name(self) -> Optional[str]:
        """Get the primary KPI name (first in the list)."""
        return self.kpi_ids[0] if self.kpi_ids else None
    
    def is_expired(self) -> bool:
        """Check if subscription is expired.
        
        Returns:
            True if expired, False otherwise.
        """
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at
    
    def should_notify(self) -> bool:
        """Check if subscription should receive notification.
        
        Returns:
            True if notification should be sent.
        """
        if self.status != SubscriptionStatus.ACTIVE:
            return False
        if self.is_expired():
            return False
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert subscription to dictionary.
        
        Returns:
            Dictionary representation.
        """
        return {
            "subscription_id": self.subscription_id,
            "kpi_ids": self.kpi_ids,
            "ne_ids": self.ne_ids,
            "interval": self.interval,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "filters": self.filters,
            "last_notification": self.last_notification.isoformat() if self.last_notification else None,
            "notification_count": self.notification_count,
        }


class KPIManager:
    """Main KPI management class for performance monitoring.
    
    This class provides comprehensive KPI management including:
    - KPI retrieval and computation
    - Real-time KPI subscriptions
    - Historical KPI data retrieval
    - Dashboard data aggregation
    - Integration with database and cache
    
    Attributes:
        catalog: KPI catalog with predefined KPIs.
        subscriptions: Active KPI subscriptions.
        db_pool: Database connection pool for TimescaleDB.
        cache: Redis cache for KPI values.
    """
    
    def __init__(
        self,
        db_pool: Optional[Any] = None,
        cache: Optional[Any] = None,
    ) -> None:
        """Initialize the KPI manager.
        
        Args:
            db_pool: Database connection pool.
            cache: Redis cache instance.
        """
        self.catalog = KPICatalog()
        self._subscriptions: Dict[str, KPISubscription] = {}
        self._db_pool = db_pool
        self._cache = cache
        self._computation_lock = asyncio.Lock()
        self._subscription_tasks: Dict[str, asyncio.Task] = {}
        
        logger.info("KPIManager initialized")
    
    async def get_kpi(
        self,
        kpi_id: Optional[str] = None,
        ne_id: Optional[str] = None,
        counters: Optional[Dict[str, float]] = None,
        timestamp: Optional[datetime] = None,
        use_cache: bool = True,
        # Support for kpi_name parameter alias
        kpi_name: Optional[str] = None,
        **kwargs,
    ) -> Optional[KPIResult]:
        """Get current KPI value.
        
        Args:
            kpi_id: KPI identifier (optional if kpi_name is provided).
            ne_id: Optional network element ID.
            counters: Optional counter values to use for computation.
            timestamp: Optional timestamp for historical data.
            use_cache: Whether to use cached values.
            kpi_name: Alias for kpi_id (takes precedence if both provided).
            **kwargs: Additional keyword arguments for flexibility.
            
        Returns:
            KPI result or None if not found.
        """
        # Support kpi_name as alias for kpi_id
        if kpi_name is not None:
            kpi_id = kpi_name
        
        # Ensure we have a kpi_id
        if kpi_id is None:
            logger.warning("No KPI identifier provided")
            return None
        
        # Check cache first if enabled
        if use_cache and self._cache and timestamp is None and counters is None:
            cache_key = f"kpi:{kpi_id}:{ne_id or 'global'}"
            cached = await self._cache.get(cache_key)
            if cached:
                logger.debug(f"KPI {kpi_id} retrieved from cache")
                return KPIResult(**cached)
        
        # Get KPI definition
        kpi_def = self.catalog.get_kpi(kpi_id)
        if kpi_def is None:
            logger.warning(f"KPI not found: {kpi_id}")
            return None
        
        # Compute KPI value
        result = await self.compute_kpi(kpi_id, ne_id, timestamp, counters)
        
        # Cache the result
        if use_cache and self._cache and result and counters is None:
            cache_key = f"kpi:{kpi_id}:{ne_id or 'global'}"
            await self._cache.set(cache_key, result.to_dict(), ttl=60)
        
        return result
    
    async def compute_kpi(
        self,
        kpi_id: Optional[str] = None,
        ne_id: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        counters: Optional[Dict[str, float]] = None,
        # Support for kpi_name parameter alias
        kpi_name: Optional[str] = None,
        **kwargs,
    ) -> Optional[KPIResult]:
        """Compute KPI value from raw counters.
        
        Args:
            kpi_id: KPI identifier (optional if kpi_name is provided).
            ne_id: Optional network element ID.
            timestamp: Optional timestamp for historical computation.
            counters: Optional counter values to use directly.
            kpi_name: Alias for kpi_id (takes precedence if both provided).
            **kwargs: Additional keyword arguments for flexibility.
            
        Returns:
            Computed KPI result or None.
        """
        # Support kpi_name as alias for kpi_id
        if kpi_name is not None:
            kpi_id = kpi_name
        
        # Ensure we have a kpi_id
        if kpi_id is None:
            logger.warning("No KPI identifier provided for computation")
            return None
        
        async with self._computation_lock:
            kpi_def = self.catalog.get_kpi(kpi_id)
            if kpi_def is None:
                return None
            
            # Use provided counters or fetch from database
            if counters is not None:
                raw_counters = counters
            else:
                # Get raw counters from database
                raw_counters = await self._fetch_counters(kpi_def, ne_id, timestamp)
            
            if not raw_counters:
                return KPIResult(
                    kpi_id=kpi_id,
                    value=None,
                    unit=kpi_def.unit,
                    timestamp=timestamp or datetime.now(timezone.utc),
                    ne_id=ne_id,
                    quality_flag="NO_DATA",
                )
            
            # Evaluate formula
            try:
                value = self._evaluate_formula(kpi_def.formula, raw_counters)
                quality_flag = "NORMAL" if value is not None else "NO_DATA"
            except ZeroDivisionError:
                value = None
                quality_flag = "ZERO_DENOMINATOR"
            except Exception as e:
                logger.error(f"Formula evaluation error for {kpi_id}: {e}")
                value = None
                quality_flag = "COMPUTATION_ERROR"
            
            return KPIResult(
                kpi_id=kpi_id,
                value=value,
                unit=kpi_def.unit,
                timestamp=timestamp or datetime.now(timezone.utc),
                ne_id=ne_id,
                quality_flag=quality_flag,
                raw_counters=raw_counters,
            )
    
    async def _fetch_counters(
        self,
        kpi_def: KPIDefinition,
        ne_id: Optional[str],
        timestamp: Optional[datetime],
    ) -> Dict[str, float]:
        """Fetch raw counters from database.
        
        Args:
            kpi_def: KPI definition.
            ne_id: Network element ID.
            timestamp: Optional timestamp.
            
        Returns:
            Dictionary of counter values.
        """
        if self._db_pool is None:
            # Return simulated data for testing
            return self._get_simulated_counters(kpi_def)
        
        try:
            # Build query for counter data
            ts = timestamp or datetime.now(timezone.utc)
            query = """
                SELECT counter_name, counter_value
                FROM pm_counters
                WHERE kpi_id = $1
                AND timestamp >= $2 - INTERVAL '15 minutes'
                AND timestamp <= $2
            """
            params = [kpi_def.kpi_id, ts]
            
            if ne_id:
                query += " AND ne_id = $3"
                params.append(ne_id)
            
            rows = await self._db_pool.fetch_all(query, tuple(params))
            
            counters = {}
            for row in rows:
                counters[row["counter_name"]] = float(row["counter_value"])
            
            return counters
            
        except Exception as e:
            logger.error(f"Failed to fetch counters for {kpi_def.kpi_id}: {e}")
            return {}
    
    def _get_simulated_counters(self, kpi_def: KPIDefinition) -> Dict[str, float]:
        """Get simulated counter values for testing.
        
        Args:
            kpi_def: KPI definition.
            
        Returns:
            Simulated counter values.
        """
        import random
        
        counters = {}
        for var in kpi_def.vendor_mappings.get(VENDOR_ERICSSON, {}).keys():
            if "success" in var.lower():
                counters[var] = random.randint(900, 1000)
            elif "attempt" in var.lower() or "att" in var.lower():
                counters[var] = random.randint(950, 1000)
            elif "bytes" in var.lower():
                counters[var] = random.randint(1000000, 10000000)
            elif "user" in var.lower():
                counters[var] = random.randint(10, 100)
            else:
                counters[var] = random.randint(50, 100)
        
        return counters
    
    def _evaluate_formula(
        self,
        formula: str,
        counters: Dict[str, float],
    ) -> Optional[float]:
        """Evaluate KPI formula with counter values.
        
        Args:
            formula: Formula string.
            counters: Counter values.
            
        Returns:
            Computed value or None.
        """
        # Simple formula evaluation
        # Replace variable names with values
        expr = formula
        
        # Handle percentage calculation
        if "*" in formula and "100" in formula:
            # Success rate formula: (success / attempts) * 100
            if "/" in formula:
                for var, val in counters.items():
                    expr = expr.replace(var, str(val))
                
                # Check for division by zero
                if "/ 0" in expr or "/0" in expr:
                    raise ZeroDivisionError("Division by zero in formula")
                
                try:
                    result = eval(expr)
                    return round(float(result), 2)
                except Exception:
                    return None
        
        # Direct value (gauge metrics)
        for var, val in counters.items():
            if var in formula:
                return val
        
        return None
    
    async def subscribe_kpi(
        self,
        kpi_ids: Optional[List[str]] = None,
        callback: Optional[SubscriberCallback] = None,
        ne_ids: Optional[List[str]] = None,
        interval: int = 60,
        expires_in: Optional[int] = None,
        filters: Optional[Dict[str, Any]] = None,
        # Alternative signature support
        kpi_name: Optional[str] = None,
        ne_id: Optional[str] = None,
        interval_seconds: Optional[int] = None,
        **kwargs,
    ) -> KPISubscription:
        """Subscribe to real-time KPI updates.
        
        Supports two signatures:
        1. subscribe_kpi(kpi_ids: List[str], callback, ne_ids, interval, ...)
        2. subscribe_kpi(kpi_name: str, ne_id: str, callback, interval_seconds: int)
        
        Args:
            kpi_ids: List of KPI IDs to subscribe to.
            callback: Async callback function for notifications.
            ne_ids: Optional list of network element IDs.
            interval: Update interval in seconds.
            expires_in: Optional expiration time in seconds.
            filters: Additional filter criteria.
            kpi_name: Single KPI name (alternative signature).
            ne_id: Single network element ID (alternative signature).
            interval_seconds: Interval in seconds (alternative signature).
            
        Returns:
            Created subscription.
        """
        # Handle alternative signature
        if kpi_ids is None and kpi_name is not None:
            kpi_ids = [kpi_name]
        if ne_ids is None and ne_id is not None:
            ne_ids = [ne_id]
        if interval_seconds is not None:
            interval = interval_seconds
        
        # Ensure we have required parameters
        if kpi_ids is None:
            raise ValueError("kpi_ids or kpi_name is required")
        if callback is None:
            raise ValueError("callback is required")
        
        subscription_id = str(uuid.uuid4())
        
        expires_at = None
        if expires_in:
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        
        subscription = KPISubscription(
            subscription_id=subscription_id,
            kpi_ids=kpi_ids,
            callback=callback,
            ne_ids=ne_ids,
            interval=interval,
            expires_at=expires_at,
            filters=filters or {},
        )
        
        self._subscriptions[subscription_id] = subscription
        
        # Start subscription task
        task = asyncio.create_task(
            self._subscription_loop(subscription_id)
        )
        self._subscription_tasks[subscription_id] = task
        
        logger.info(f"Created KPI subscription: {subscription_id}")
        return subscription
    
    async def _subscription_loop(self, subscription_id: str) -> None:
        """Run subscription notification loop.
        
        Args:
            subscription_id: Subscription identifier.
        """
        subscription = self._subscriptions.get(subscription_id)
        if subscription is None:
            return
        
        try:
            while subscription.should_notify():
                # Fetch KPI values
                for kpi_id in subscription.kpi_ids:
                    ne_ids = subscription.ne_ids or [None]
                    for ne_id in ne_ids:
                        result = await self.get_kpi(kpi_id, ne_id)
                        
                        if result and subscription.callback:
                            try:
                                await subscription.callback(kpi_id, result)
                            except Exception as e:
                                logger.error(
                                    f"Subscription callback error: {e}"
                                )
                
                subscription.last_notification = datetime.now(timezone.utc)
                subscription.notification_count += 1
                
                await asyncio.sleep(subscription.interval)
                
        except asyncio.CancelledError:
            logger.debug(f"Subscription cancelled: {subscription_id}")
        except Exception as e:
            logger.error(f"Subscription loop error: {e}")
    
    async def unsubscribe(self, subscription_id: str) -> bool:
        """Cancel a KPI subscription.
        
        Args:
            subscription_id: Subscription identifier.
            
        Returns:
            True if successfully cancelled.
        """
        subscription = self._subscriptions.get(subscription_id)
        if subscription is None:
            return False
        
        subscription.status = SubscriptionStatus.CANCELLED
        
        # Cancel the task
        task = self._subscription_tasks.get(subscription_id)
        if task:
            task.cancel()
            del self._subscription_tasks[subscription_id]
        
        logger.info(f"Cancelled subscription: {subscription_id}")
        return True
    
    async def get_kpi_history(
        self,
        kpi_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        ne_id: Optional[str] = None,
        aggregation: KPIAggregation = KPIAggregation.AVG,
        interval: Optional[timedelta] = None,
        # Alternative signature support
        kpi_name: Optional[str] = None,
        **kwargs,
    ) -> List[KPIResult]:
        """Get historical KPI values.
        
        Supports two signatures:
        1. get_kpi_history(kpi_id, start_time, end_time, ne_id, ...)
        2. get_kpi_history(kpi_name, ne_id, start_time, end_time)
        
        Args:
            kpi_id: KPI identifier (optional if kpi_name is provided).
            start_time: Query start time.
            end_time: Query end time.
            ne_id: Optional network element ID.
            aggregation: Aggregation method.
            interval: Aggregation interval.
            kpi_name: Alternative KPI name parameter (takes precedence if both provided).
            
        Returns:
            List of KPI results.
        """
        # Support kpi_name as alias for kpi_id
        if kpi_name is not None:
            kpi_id = kpi_name
        
        # Ensure we have a kpi_id
        if kpi_id is None:
            logger.warning("No KPI identifier provided for history query")
            return []
        
        kpi_def = self.catalog.get_kpi(kpi_id)
        if kpi_def is None:
            return []
        
        if self._db_pool is None:
            # Return simulated historical data
            return self._get_simulated_history(
                kpi_def, start_time, end_time, ne_id
            )
        
        try:
            interval_str = ""
            if interval:
                interval_str = f"INTERVAL '{interval}'"
            
            query = f"""
                SELECT 
                    time_bucket({interval_str}, timestamp) AS bucket,
                    {aggregation.value}(value) AS value,
                    COUNT(*) AS sample_count
                FROM kpi_results
                WHERE kpi_id = $1
                AND timestamp >= $2
                AND timestamp <= $3
            """
            params = [kpi_id, start_time, end_time]
            
            if ne_id:
                query += " AND ne_id = $4"
                params.append(ne_id)
            
            query += " GROUP BY bucket ORDER BY bucket"
            
            rows = await self._db_pool.fetch_all(query, tuple(params))
            
            results = []
            for row in rows:
                results.append(KPIResult(
                    kpi_id=kpi_id,
                    value=row["value"],
                    unit=kpi_def.unit,
                    timestamp=row["bucket"],
                    ne_id=ne_id,
                    metadata={"sample_count": row["sample_count"]},
                ))
            
            return results
            
        except Exception as e:
            logger.error(f"Failed to get KPI history: {e}")
            return []
    
    def _get_simulated_history(
        self,
        kpi_def: KPIDefinition,
        start_time: datetime,
        end_time: datetime,
        ne_id: Optional[str],
    ) -> List[KPIResult]:
        """Generate simulated historical data.
        
        Args:
            kpi_def: KPI definition.
            start_time: Start time.
            end_time: End time.
            ne_id: Network element ID.
            
        Returns:
            Simulated historical KPI results.
        """
        import random
        
        results = []
        current = start_time
        delta = timedelta(minutes=15)
        
        while current <= end_time:
            # Generate realistic value based on KPI type
            if "success_rate" in kpi_def.kpi_id:
                value = round(random.uniform(90.0, 99.5), 2)
            elif "throughput" in kpi_def.kpi_id:
                value = round(random.uniform(30.0, 100.0), 2)
            elif "utilization" in kpi_def.kpi_id:
                value = round(random.uniform(40.0, 80.0), 2)
            elif "drop_rate" in kpi_def.kpi_id:
                value = round(random.uniform(0.5, 3.0), 2)
            else:
                value = round(random.uniform(50.0, 100.0), 2)
            
            results.append(KPIResult(
                kpi_id=kpi_def.kpi_id,
                value=value,
                unit=kpi_def.unit,
                timestamp=current,
                ne_id=ne_id,
            ))
            current += delta
        
        return results
    
    async def get_dashboard_data(
        self,
        dashboard_id: Optional[str] = None,
        ne_ids: Optional[List[str]] = None,
        # Alternative signature support
        ne_id: Optional[str] = None,
        **kwargs,
    ) -> Optional[Dict[str, Any]]:
        """Get aggregated dashboard data.
        
        Supports two signatures:
        1. get_dashboard_data(dashboard_id, ne_ids)
        2. get_dashboard_data(ne_id) - returns simplified dashboard data
        
        Args:
            dashboard_id: Dashboard identifier.
            ne_ids: Optional list of network element IDs.
            ne_id: Single network element ID (alternative signature).
            
        Returns:
            Dashboard data dict or None.
        """
        # Handle alternative signature - single ne_id
        if ne_id is not None and ne_ids is None:
            ne_ids = [ne_id]
        
        # Default dashboard_id if not provided
        if dashboard_id is None:
            dashboard_id = "default"
        
        # Define default dashboards
        dashboards = self._get_default_dashboards()
        
        dashboard_config = dashboards.get(dashboard_id)
        if dashboard_config is None:
            # Return simplified dashboard data for the alternative signature
            kpis = {}
            for kpi_def in self.catalog.list_all()[:5]:  # Get first 5 KPIs
                result = await self.get_kpi(kpi_def.kpi_id, ne_id)
                if result:
                    kpis[kpi_def.kpi_id] = result.to_dict()
            return {
                "kpis": kpis,
                "ne_id": ne_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        
        # Fetch KPI data for each widget
        kpi_data: Dict[str, List[KPIResult]] = {}
        
        for widget in dashboard_config["widgets"]:
            widget_id = widget["widget_id"]
            kpi_ids = widget.get("kpi_ids", [])
            
            for kpi_id in kpi_ids:
                results = []
                targets = ne_ids or [None]
                
                for target_ne_id in targets:
                    result = await self.get_kpi(kpi_id, target_ne_id)
                    if result:
                        results.append(result)
                
                if widget_id not in kpi_data:
                    kpi_data[widget_id] = []
                kpi_data[widget_id].extend(results)
        
        return DashboardData(
            dashboard_id=dashboard_id,
            title=dashboard_config["title"],
            widgets=dashboard_config["widgets"],
            kpi_data=kpi_data,
            last_updated=datetime.now(timezone.utc),
        )
    
    def _get_default_dashboards(self) -> Dict[str, Dict[str, Any]]:
        """Get default dashboard configurations.
        
        Returns:
            Dictionary of dashboard configurations.
        """
        return {
            "network_overview": {
                "title": "Network Overview",
                "widgets": [
                    {
                        "widget_id": "mobility_kpis",
                        "title": "Mobility KPIs",
                        "type": "gauge",
                        "kpi_ids": ["rrc_success_rate", "ho_success_rate"],
                    },
                    {
                        "widget_id": "quality_kpis",
                        "title": "Quality KPIs",
                        "type": "chart",
                        "kpi_ids": ["erab_success_rate", "rrc_drop_rate"],
                    },
                    {
                        "widget_id": "throughput",
                        "title": "Throughput",
                        "type": "chart",
                        "kpi_ids": ["dl_throughput", "ul_throughput"],
                    },
                    {
                        "widget_id": "capacity",
                        "title": "Capacity",
                        "type": "gauge",
                        "kpi_ids": ["prb_utilization", "cpu_utilization", "memory_utilization"],
                    },
                ],
            },
            "cell_health": {
                "title": "Cell Health Dashboard",
                "widgets": [
                    {
                        "widget_id": "availability",
                        "title": "Cell Availability",
                        "type": "gauge",
                        "kpi_ids": ["cell_availability"],
                    },
                    {
                        "widget_id": "connection_metrics",
                        "title": "Connection Metrics",
                        "type": "chart",
                        "kpi_ids": ["rrc_success_rate", "erab_success_rate"],
                    },
                ],
            },
            "5g_dashboard": {
                "title": "5G NR Dashboard",
                "widgets": [
                    {
                        "widget_id": "nr_metrics",
                        "title": "NR Metrics",
                        "type": "chart",
                        "kpi_ids": ["nr_ran_success_rate", "dl_throughput", "ul_throughput"],
                    },
                ],
            },
        }
    
    def get_subscription(self, subscription_id: str) -> Optional[KPISubscription]:
        """Get subscription by ID.
        
        Args:
            subscription_id: Subscription identifier.
            
        Returns:
            Subscription or None.
        """
        return self._subscriptions.get(subscription_id)
    
    def get_active_subscriptions(self) -> List[KPISubscription]:
        """Get all active subscriptions.
        
        Returns:
            List of active subscriptions.
        """
        return [
            sub for sub in self._subscriptions.values()
            if sub.status == SubscriptionStatus.ACTIVE and not sub.is_expired()
        ]
    
    async def close(self) -> None:
        """Close the KPI manager and cancel all subscriptions."""
        for subscription_id in list(self._subscriptions.keys()):
            await self.unsubscribe(subscription_id)
        
        self._subscriptions.clear()
        logger.info("KPIManager closed")


# Export classes
__all__ = [
    "KPICategory",
    "KPIAggregation",
    "SubscriptionStatus",
    "KPIDefinition",
    "KPIResult",
    "DashboardData",
    "KPICatalog",
    "KPISubscription",
    "KPIManager",
]
