"""
Performance Management Module for Unified OSS Framework.

This module provides comprehensive Performance Management capabilities
implementing the FCAPS (Fault, Configuration, Accounting, Performance, Security)
framework's Performance Management domain.

The module includes:

    - **KPI Management**: KPI catalog, subscriptions, and dashboard aggregation
    - **KPI Computation**: Multi-vendor counter mapping and formula evaluation
    - **Threshold Monitoring**: Rule management, breach detection, and alerts

Key Classes:
    - KPIManager: Main KPI management and retrieval
    - KPICatalog: Catalog of predefined telecommunications KPIs
    - KPISubscription: Real-time KPI subscription management
    - KPIComputer: KPI computation engine with formula evaluation
    - CounterMapper: Multi-vendor counter mapping to CIM model
    - ThresholdMonitor: Threshold monitoring and breach detection
    - ThresholdRule: Threshold rule configuration

Example:
    >>> from unified_oss.fcaps.performance import KPIManager, ThresholdMonitor
    >>> 
    >>> # Initialize KPI manager
    >>> kpi_manager = KPIManager(db_pool, cache)
    >>> 
    >>> # Get current KPI value
    >>> result = await kpi_manager.get_kpi("rrc_success_rate", ne_id="ENB001")
    >>> print(f"RRC Success Rate: {result.value}%")
    >>> 
    >>> # Set up threshold monitoring
    >>> monitor = ThresholdMonitor()
    >>> rule = monitor.create_rule(
    ...     name="CPU High",
    ...     kpi_id="cpu_utilization",
    ...     warning_threshold=70.0,
    ...     critical_threshold=85.0,
    ... )
    >>> 
    >>> # Check threshold
    >>> breaches = await monitor.check_threshold("cpu_utilization", 87.5)

Supported Vendors:
    - Ericsson (pmXxx counters)
    - Huawei (VS.Xxx counters)
    - Nokia
    - ZTE
    - Samsung

Predefined KPIs:
    - RRC Connection Success Rate
    - Handover Success Rate
    - E-RAB Setup Success Rate
    - Cell Availability
    - Downlink/Uplink Throughput
    - PRB Utilization
    - CPU/Memory Utilization
    - 5G NR Connection Success Rate
    - VoLTE Call Success Rate
"""

from unified_oss.fcaps.performance.kpi_manager import (
    KPIManager,
    KPICatalog,
    KPISubscription,
    KPIDefinition,
    KPIResult,
    DashboardData,
    KPICategory,
    KPIAggregation,
    SubscriptionStatus,
)

# Alias for backward compatibility with tests
KPIStatus = SubscriptionStatus

from unified_oss.fcaps.performance.computation import (
    KPIComputer,
    CounterMapper,
    FormulaEvaluator,
    CounterMapping,
    ComputationResult,
    QualityFlag,
    CounterType,
)

from unified_oss.fcaps.performance.thresholds import (
    ThresholdMonitor,
    ThresholdRule,
    ThresholdBreach,
    ThresholdAlert,
    ThresholdSeverity,
    ThresholdType,
    BreachState,
    HysteresisConfig,
)

__all__ = [
    # KPI Manager
    "KPIManager",
    "KPICatalog",
    "KPISubscription",
    "KPIDefinition",
    "KPIResult",
    "DashboardData",
    "KPICategory",
    "KPIAggregation",
    "SubscriptionStatus",
    "KPIStatus",  # Alias for backward compatibility
    # Computation
    "KPIComputer",
    "CounterMapper",
    "FormulaEvaluator",
    "CounterMapping",
    "ComputationResult",
    "QualityFlag",
    "CounterType",
    # Thresholds
    "ThresholdMonitor",
    "ThresholdRule",
    "ThresholdBreach",
    "ThresholdAlert",
    "ThresholdSeverity",
    "ThresholdType",
    "BreachState",
    "HysteresisConfig",
]

__version__ = "1.0.0"
