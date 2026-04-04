"""
Threshold Monitoring Module for Performance Management.

This module provides comprehensive threshold monitoring capabilities including
rule management, breach detection, alert generation, and hysteresis support.

Supports:
    - Threshold rule management (warning, critical levels)
    - Threshold breach detection with hysteresis
    - Alert generation for threshold violations
    - Threshold policy management
    - Prevention of alert flapping

Example:
    >>> from unified_oss.fcaps.performance.thresholds import ThresholdMonitor
    >>> monitor = ThresholdMonitor()
    >>> rule = monitor.create_rule("cpu_high", kpi_id="cpu_utilization",
    ...     warning_threshold=70.0, critical_threshold=85.0)
    >>> breaches = await monitor.check_threshold("cpu_utilization", 87.5)
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import (
    Any,
    Awaitable,
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

# Type aliases
AlertCallback = Callable[["ThresholdBreach"], Awaitable[None]]


class ThresholdSeverity(Enum):
    """Threshold severity levels.
    
    Attributes:
        WARNING: Warning threshold exceeded.
        CRITICAL: Critical threshold exceeded.
        CLEARED: Threshold breach cleared.
    """
    
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"
    CLEARED = "CLEARED"


class ThresholdType(Enum):
    """Type of threshold comparison.
    
    Attributes:
        UPPER: Threshold is exceeded when value is above threshold.
        LOWER: Threshold is exceeded when value is below threshold.
        RANGE: Threshold is within a specified range.
        EQUALITY: Threshold is exact value match.
    """
    
    UPPER = "UPPER"
    LOWER = "LOWER"
    RANGE = "RANGE"
    EQUALITY = "EQUALITY"


class BreachState(Enum):
    """State of a threshold breach.
    
    Attributes:
        ACTIVE: Breach is currently active.
        CLEARED: Breach has been cleared.
        ACKNOWLEDGED: Breach has been acknowledged.
        SUPPRESSED: Breach is suppressed.
    """
    
    ACTIVE = "ACTIVE"
    CLEARED = "CLEARED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    SUPPRESSED = "SUPPRESSED"


@dataclass
class HysteresisConfig:
    """Configuration for threshold hysteresis.
    
    Hysteresis prevents flapping by requiring the value to cross
    a different threshold when returning to normal state.
    
    Attributes:
        warning_hysteresis: Hysteresis margin for warning threshold.
        critical_hysteresis: Hysteresis margin for critical threshold.
        min_breach_duration: Minimum duration before breach is raised.
        min_clear_duration: Minimum duration before breach is cleared.
    """
    
    warning_hysteresis: float = 2.0
    critical_hysteresis: float = 3.0
    min_breach_duration: timedelta = field(default_factory=lambda: timedelta(minutes=2))
    min_clear_duration: timedelta = field(default_factory=lambda: timedelta(minutes=5))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.
        
        Returns:
            Dictionary representation.
        """
        return {
            "warning_hysteresis": self.warning_hysteresis,
            "critical_hysteresis": self.critical_hysteresis,
            "min_breach_duration": self.min_breach_duration.total_seconds(),
            "min_clear_duration": self.min_clear_duration.total_seconds(),
        }


@dataclass
class ThresholdRule:
    """Configuration for a threshold monitoring rule.
    
    Attributes:
        rule_id: Unique identifier for the rule.
        name: Human-readable rule name.
        kpi_id: KPI identifier to monitor.
        warning_threshold: Warning threshold value.
        critical_threshold: Critical threshold value.
        threshold_type: Type of threshold comparison.
        hysteresis: Hysteresis configuration.
        enabled: Whether the rule is enabled.
        ne_filter: Optional network element filter.
        tags: Tags for categorization.
        created_at: Rule creation timestamp.
        updated_at: Last update timestamp.
        breach_count: Number of breaches for this rule.
        last_breach: Last breach timestamp.
    """
    
    rule_id: str
    name: str
    kpi_id: str
    warning_threshold: float
    critical_threshold: float
    threshold_type: ThresholdType = ThresholdType.UPPER
    hysteresis: HysteresisConfig = field(default_factory=HysteresisConfig)
    enabled: bool = True
    ne_filter: Optional[List[str]] = None
    tags: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    breach_count: int = 0
    last_breach: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.
        
        Returns:
            Dictionary representation.
        """
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "kpi_id": self.kpi_id,
            "warning_threshold": self.warning_threshold,
            "critical_threshold": self.critical_threshold,
            "threshold_type": self.threshold_type.value,
            "hysteresis": self.hysteresis.to_dict(),
            "enabled": self.enabled,
            "ne_filter": self.ne_filter,
            "tags": self.tags,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "breach_count": self.breach_count,
            "last_breach": self.last_breach.isoformat() if self.last_breach else None,
        }
    
    def check_value(
        self,
        value: float,
        consider_hysteresis: bool = False,
        previous_state: Optional[ThresholdSeverity] = None,
    ) -> Optional[ThresholdSeverity]:
        """Check if a value breaches the threshold.
        
        Args:
            value: Value to check.
            consider_hysteresis: Whether to apply hysteresis.
            previous_state: Previous threshold state.
            
        Returns:
            Severity level if breached, None otherwise.
        """
        if self.threshold_type == ThresholdType.UPPER:
            return self._check_upper_threshold(
                value, consider_hysteresis, previous_state
            )
        elif self.threshold_type == ThresholdType.LOWER:
            return self._check_lower_threshold(
                value, consider_hysteresis, previous_state
            )
        elif self.threshold_type == ThresholdType.RANGE:
            return self._check_range_threshold(value)
        
        return None
    
    def _check_upper_threshold(
        self,
        value: float,
        consider_hysteresis: bool,
        previous_state: Optional[ThresholdSeverity],
    ) -> Optional[ThresholdSeverity]:
        """Check upper threshold with hysteresis.
        
        Args:
            value: Value to check.
            consider_hysteresis: Whether to apply hysteresis.
            previous_state: Previous threshold state.
            
        Returns:
            Severity level if breached.
        """
        # Apply hysteresis for clearing
        if consider_hysteresis and previous_state in (
            ThresholdSeverity.WARNING,
            ThresholdSeverity.CRITICAL,
        ):
            if previous_state == ThresholdSeverity.CRITICAL:
                clear_threshold = (
                    self.critical_threshold - self.hysteresis.critical_hysteresis
                )
                if value < clear_threshold:
                    # Check if below warning threshold
                    warning_clear = (
                        self.warning_threshold - self.hysteresis.warning_hysteresis
                    )
                    if value < warning_clear:
                        return None
                    return ThresholdSeverity.WARNING
                return ThresholdSeverity.CRITICAL
            
            elif previous_state == ThresholdSeverity.WARNING:
                clear_threshold = (
                    self.warning_threshold - self.hysteresis.warning_hysteresis
                )
                if value < clear_threshold:
                    return None
                # Check if escalated to critical
                if value >= self.critical_threshold:
                    return ThresholdSeverity.CRITICAL
                return ThresholdSeverity.WARNING
        
        # Normal threshold check (no hysteresis)
        if value >= self.critical_threshold:
            return ThresholdSeverity.CRITICAL
        elif value >= self.warning_threshold:
            return ThresholdSeverity.WARNING
        
        return None
    
    def _check_lower_threshold(
        self,
        value: float,
        consider_hysteresis: bool,
        previous_state: Optional[ThresholdSeverity],
    ) -> Optional[ThresholdSeverity]:
        """Check lower threshold with hysteresis.
        
        Args:
            value: Value to check.
            consider_hysteresis: Whether to apply hysteresis.
            previous_state: Previous threshold state.
            
        Returns:
            Severity level if breached.
        """
        # Apply hysteresis for clearing
        if consider_hysteresis and previous_state in (
            ThresholdSeverity.WARNING,
            ThresholdSeverity.CRITICAL,
        ):
            if previous_state == ThresholdSeverity.CRITICAL:
                clear_threshold = (
                    self.critical_threshold + self.hysteresis.critical_hysteresis
                )
                if value > clear_threshold:
                    warning_clear = (
                        self.warning_threshold + self.hysteresis.warning_hysteresis
                    )
                    if value > warning_clear:
                        return None
                    return ThresholdSeverity.WARNING
                return ThresholdSeverity.CRITICAL
            
            elif previous_state == ThresholdSeverity.WARNING:
                clear_threshold = (
                    self.warning_threshold + self.hysteresis.warning_hysteresis
                )
                if value > clear_threshold:
                    return None
                if value <= self.critical_threshold:
                    return ThresholdSeverity.CRITICAL
                return ThresholdSeverity.WARNING
        
        # Normal threshold check (no hysteresis)
        if value <= self.critical_threshold:
            return ThresholdSeverity.CRITICAL
        elif value <= self.warning_threshold:
            return ThresholdSeverity.WARNING
        
        return None
    
    def _check_range_threshold(self, value: float) -> Optional[ThresholdSeverity]:
        """Check range threshold.
        
        Args:
            value: Value to check.
            
        Returns:
            Severity level if breached.
        """
        # For range, warning is the outer bound, critical is the inner
        if value < self.critical_threshold or value > self.warning_threshold:
            return ThresholdSeverity.CRITICAL
        if value < self.warning_threshold * 0.9 or value > self.critical_threshold * 1.1:
            return ThresholdSeverity.WARNING
        
        return None


@dataclass
class ThresholdBreach:
    """Record of a threshold breach event.
    
    Attributes:
        breach_id: Unique identifier for the breach.
        rule_id: Associated threshold rule ID.
        kpi_id: KPI identifier.
        severity: Breach severity level.
        value: Value that caused the breach.
        kpi_id: KPI identifier.
        ne_id: Network element identifier.
        value: Value that caused the breach.
        threshold_value: Threshold that was breached.
        severity: Severity of the breach.
        state: Current state of the breach.
        first_raised: When the breach was first raised.
        last_updated: Last update timestamp.
        cleared_at: When the breach was cleared.
        duration: Duration of the breach.
        alert_sent: Whether an alert was sent.
        acknowledged: Whether the breach was acknowledged.
        acknowledged_by: User who acknowledged.
        metadata: Additional metadata.
    """
    
    breach_id: str
    rule_id: str
    kpi_id: str
    ne_id: Optional[str]
    value: float
    threshold_value: float
    severity: ThresholdSeverity
    state: BreachState = BreachState.ACTIVE
    first_raised: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    cleared_at: Optional[datetime] = None
    duration: Optional[timedelta] = None
    alert_sent: bool = False
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.
        
        Returns:
            Dictionary representation.
        """
        return {
            "breach_id": self.breach_id,
            "rule_id": self.rule_id,
            "kpi_id": self.kpi_id,
            "ne_id": self.ne_id,
            "value": self.value,
            "threshold_value": self.threshold_value,
            "severity": self.severity.value,
            "state": self.state.value,
            "first_raised": self.first_raised.isoformat(),
            "last_updated": self.last_updated.isoformat(),
            "cleared_at": self.cleared_at.isoformat() if self.cleared_at else None,
            "duration": self.duration.total_seconds() if self.duration else None,
            "alert_sent": self.alert_sent,
            "acknowledged": self.acknowledged,
            "acknowledged_by": self.acknowledged_by,
            "metadata": self.metadata,
        }
    
    def clear(self) -> None:
        """Mark the breach as cleared."""
        self.state = BreachState.CLEARED
        self.cleared_at = datetime.now(timezone.utc)
        self.duration = self.cleared_at - self.first_raised
        self.last_updated = self.cleared_at
    
    def acknowledge(self, user: str) -> None:
        """Acknowledge the breach.
        
        Args:
            user: User who acknowledged.
        """
        self.acknowledged = True
        self.acknowledged_by = user
        self.state = BreachState.ACKNOWLEDGED
        self.last_updated = datetime.now(timezone.utc)


@dataclass
class ThresholdAlert:
    """Alert generated from a threshold breach.
    
    Attributes:
        alert_id: Unique alert identifier.
        breach_id: Associated breach ID.
        kpi_id: KPI identifier.
        ne_id: Network element identifier.
        severity: Alert severity.
        message: Alert message.
        timestamp: Alert timestamp.
        details: Additional alert details.
    """
    
    alert_id: str
    breach_id: str
    kpi_id: str
    ne_id: Optional[str]
    severity: ThresholdSeverity
    message: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.
        
        Returns:
            Dictionary representation.
        """
        return {
            "alert_id": self.alert_id,
            "breach_id": self.breach_id,
            "kpi_id": self.kpi_id,
            "ne_id": self.ne_id,
            "severity": self.severity.value,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details,
        }


class ThresholdMonitor:
    """Threshold monitoring and breach detection system.
    
    This class provides comprehensive threshold monitoring including:
    - Rule management
    - Breach detection with hysteresis
    - Alert generation
    - Breach tracking and history
    
    Attributes:
        rules: Dictionary of threshold rules.
        active_breaches: Currently active breaches.
        alert_callbacks: Registered alert callbacks.
    """
    
    def __init__(self) -> None:
        """Initialize threshold monitor."""
        self._rules: Dict[str, ThresholdRule] = {}
        self._active_breaches: Dict[str, ThresholdBreach] = {}
        self._breach_history: List[ThresholdBreach] = []
        self._alert_callbacks: List[AlertCallback] = []
        self._previous_states: Dict[str, ThresholdSeverity] = {}
        self._state_timestamps: Dict[str, datetime] = {}
        
        # Initialize default rules
        self._initialize_default_rules()
        
        logger.info("ThresholdMonitor initialized")
    
    def _initialize_default_rules(self) -> None:
        """Initialize default threshold rules."""
        default_rules = [
            {
                "name": "CPU Utilization High",
                "kpi_id": "cpu_utilization",
                "warning_threshold": 70.0,
                "critical_threshold": 85.0,
                "threshold_type": ThresholdType.UPPER,
                "tags": ["system", "capacity"],
            },
            {
                "name": "Memory Utilization High",
                "kpi_id": "memory_utilization",
                "warning_threshold": 70.0,
                "critical_threshold": 85.0,
                "threshold_type": ThresholdType.UPPER,
                "tags": ["system", "capacity"],
            },
            {
                "name": "PRB Utilization High",
                "kpi_id": "prb_utilization",
                "warning_threshold": 70.0,
                "critical_threshold": 85.0,
                "threshold_type": ThresholdType.UPPER,
                "tags": ["capacity", "radio"],
            },
            {
                "name": "RRC Success Rate Low",
                "kpi_id": "rrc_success_rate",
                "warning_threshold": 95.0,
                "critical_threshold": 90.0,
                "threshold_type": ThresholdType.LOWER,
                "tags": ["quality", "mobility"],
            },
            {
                "name": "Handover Success Rate Low",
                "kpi_id": "ho_success_rate",
                "warning_threshold": 95.0,
                "critical_threshold": 90.0,
                "threshold_type": ThresholdType.LOWER,
                "tags": ["quality", "mobility"],
            },
            {
                "name": "Cell Availability Low",
                "kpi_id": "cell_availability",
                "warning_threshold": 99.0,
                "critical_threshold": 95.0,
                "threshold_type": ThresholdType.LOWER,
                "tags": ["availability"],
            },
        ]
        
        for rule_config in default_rules:
            rule_id = str(uuid.uuid4())
            self._rules[rule_id] = ThresholdRule(
                rule_id=rule_id,
                **rule_config,
            )
        
        logger.info(f"Initialized {len(default_rules)} default threshold rules")
    
    def create_rule(
        self,
        name: str,
        kpi_id: str,
        warning_threshold: float,
        critical_threshold: float,
        threshold_type: ThresholdType = ThresholdType.UPPER,
        hysteresis: Optional[HysteresisConfig] = None,
        ne_filter: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
    ) -> ThresholdRule:
        """Create a new threshold rule.
        
        Args:
            name: Rule name.
            kpi_id: KPI identifier to monitor.
            warning_threshold: Warning threshold value.
            critical_threshold: Critical threshold value.
            threshold_type: Type of threshold comparison.
            hysteresis: Optional hysteresis configuration.
            ne_filter: Optional network element filter.
            tags: Optional tags.
            
        Returns:
            Created threshold rule.
        """
        rule_id = str(uuid.uuid4())
        
        rule = ThresholdRule(
            rule_id=rule_id,
            name=name,
            kpi_id=kpi_id,
            warning_threshold=warning_threshold,
            critical_threshold=critical_threshold,
            threshold_type=threshold_type,
            hysteresis=hysteresis or HysteresisConfig(),
            ne_filter=ne_filter,
            tags=tags or [],
        )
        
        self._rules[rule_id] = rule
        logger.info(f"Created threshold rule: {rule_id} ({name})")
        
        return rule
    
    async def check_threshold(
        self,
        kpi_id: str,
        value: float,
        ne_id: Optional[str] = None,
    ) -> List[ThresholdBreach]:
        """Check a KPI value against threshold rules.
        
        Args:
            kpi_id: KPI identifier.
            value: Current KPI value.
            ne_id: Optional network element ID.
            
        Returns:
            List of breaches detected.
        """
        breaches: List[ThresholdBreach] = []
        
        for rule in self._rules.values():
            if not rule.enabled:
                continue
            if rule.kpi_id != kpi_id:
                continue
            if rule.ne_filter and ne_id not in rule.ne_filter:
                continue
            
            # Get previous state for hysteresis
            state_key = f"{rule.rule_id}:{ne_id or 'global'}"
            previous_state = self._previous_states.get(state_key)
            
            # Check threshold with hysteresis
            severity = rule.check_value(value, True, previous_state)
            
            if severity is not None:
                # Check if breach already exists
                existing_breach = self._find_active_breach(rule.rule_id, ne_id)
                
                if existing_breach:
                    # Update existing breach if severity changed
                    if existing_breach.severity != severity:
                        existing_breach.severity = severity
                        existing_breach.value = value
                        existing_breach.last_updated = datetime.now(timezone.utc)
                        existing_breach.alert_sent = False
                        
                        # Generate alert for severity escalation
                        alert = await self.generate_alert(existing_breach)
                        if alert:
                            await self._send_alert(alert)
                        
                        breaches.append(existing_breach)
                else:
                    # Create new breach
                    threshold_value = (
                        rule.critical_threshold
                        if severity == ThresholdSeverity.CRITICAL
                        else rule.warning_threshold
                    )
                    
                    breach = ThresholdBreach(
                        breach_id=str(uuid.uuid4()),
                        rule_id=rule.rule_id,
                        kpi_id=kpi_id,
                        ne_id=ne_id,
                        value=value,
                        threshold_value=threshold_value,
                        severity=severity,
                    )
                    
                    self._active_breaches[breach.breach_id] = breach
                    self._previous_states[state_key] = severity
                    self._state_timestamps[state_key] = datetime.now(timezone.utc)
                    
                    # Generate alert
                    alert = await self.generate_alert(breach)
                    if alert:
                        await self._send_alert(alert)
                    
                    breaches.append(breach)
                    
                    # Update rule statistics
                    rule.breach_count += 1
                    rule.last_breach = datetime.now(timezone.utc)
            else:
                # No breach - check for clearing
                existing_breach = self._find_active_breach(rule.rule_id, ne_id)
                
                if existing_breach:
                    existing_breach.clear()
                    del self._active_breaches[existing_breach.breach_id]
                    self._breach_history.append(existing_breach)
                    self._previous_states[state_key] = ThresholdSeverity.CLEARED
                    
                    # Generate clear alert
                    existing_breach.severity = ThresholdSeverity.CLEARED
                    alert = await self.generate_alert(existing_breach)
                    if alert:
                        await self._send_alert(alert)
        
        return breaches
    
    def _find_active_breach(
        self,
        rule_id: str,
        ne_id: Optional[str],
    ) -> Optional[ThresholdBreach]:
        """Find active breach for a rule and NE.
        
        Args:
            rule_id: Rule identifier.
            ne_id: Network element ID.
            
        Returns:
            Active breach or None.
        """
        for breach in self._active_breaches.values():
            if breach.rule_id == rule_id and breach.ne_id == ne_id:
                return breach
        return None
    
    async def generate_alert(self, breach: ThresholdBreach) -> Optional[ThresholdAlert]:
        """Generate an alert from a threshold breach.
        
        Args:
            breach: Threshold breach.
            
        Returns:
            Generated alert or None.
        """
        if breach.alert_sent:
            return None
        
        rule = self._rules.get(breach.rule_id)
        if rule is None:
            return None
        
        # Build alert message
        if breach.severity == ThresholdSeverity.CLEARED:
            message = (
                f"Threshold breach cleared for {breach.kpi_id} "
                f"on {breach.ne_id or 'system'}. "
                f"Current value: {breach.value}"
            )
        elif breach.severity == ThresholdSeverity.CRITICAL:
            message = (
                f"CRITICAL: {rule.name} threshold exceeded. "
                f"KPI: {breach.kpi_id}, NE: {breach.ne_id or 'system'}, "
                f"Value: {breach.value} (threshold: {breach.threshold_value})"
            )
        else:
            message = (
                f"WARNING: {rule.name} threshold exceeded. "
                f"KPI: {breach.kpi_id}, NE: {breach.ne_id or 'system'}, "
                f"Value: {breach.value} (threshold: {breach.threshold_value})"
            )
        
        alert = ThresholdAlert(
            alert_id=str(uuid.uuid4()),
            breach_id=breach.breach_id,
            kpi_id=breach.kpi_id,
            ne_id=breach.ne_id,
            severity=breach.severity,
            message=message,
            details={
                "rule_name": rule.name,
                "threshold_type": rule.threshold_type.value,
                "duration": (
                    breach.duration.total_seconds() if breach.duration else None
                ),
            },
        )
        
        breach.alert_sent = True
        return alert
    
    async def _send_alert(self, alert: ThresholdAlert) -> None:
        """Send alert to registered callbacks.
        
        Args:
            alert: Alert to send.
        """
        for callback in self._alert_callbacks:
            try:
                await callback(alert)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")
        
        logger.info(f"Alert sent: {alert.alert_id}")
    
    def register_alert_callback(self, callback: AlertCallback) -> None:
        """Register a callback for alerts.
        
        Args:
            callback: Async callback function.
        """
        self._alert_callbacks.append(callback)
        logger.info("Alert callback registered")
    
    def get_breaches(
        self,
        active_only: bool = True,
        kpi_id: Optional[str] = None,
        ne_id: Optional[str] = None,
        severity: Optional[ThresholdSeverity] = None,
    ) -> List[ThresholdBreach]:
        """Get threshold breaches.
        
        Args:
            active_only: Whether to return only active breaches.
            kpi_id: Optional KPI filter.
            ne_id: Optional NE filter.
            severity: Optional severity filter.
            
        Returns:
            List of threshold breaches.
        """
        if active_only:
            breaches = list(self._active_breaches.values())
        else:
            breaches = list(self._active_breaches.values()) + self._breach_history
        
        # Apply filters
        if kpi_id:
            breaches = [b for b in breaches if b.kpi_id == kpi_id]
        if ne_id:
            breaches = [b for b in breaches if b.ne_id == ne_id]
        if severity:
            breaches = [b for b in breaches if b.severity == severity]
        
        return sorted(breaches, key=lambda b: b.first_raised, reverse=True)
    
    def get_rule(self, rule_id: str) -> Optional[ThresholdRule]:
        """Get a threshold rule by ID.
        
        Args:
            rule_id: Rule identifier.
            
        Returns:
            Threshold rule or None.
        """
        return self._rules.get(rule_id)
    
    def get_rules(
        self,
        kpi_id: Optional[str] = None,
        enabled_only: bool = True,
    ) -> List[ThresholdRule]:
        """Get threshold rules.
        
        Args:
            kpi_id: Optional KPI filter.
            enabled_only: Whether to return only enabled rules.
            
        Returns:
            List of threshold rules.
        """
        rules = list(self._rules.values())
        
        if kpi_id:
            rules = [r for r in rules if r.kpi_id == kpi_id]
        if enabled_only:
            rules = [r for r in rules if r.enabled]
        
        return rules
    
    def update_rule(
        self,
        rule_id: str,
        **kwargs: Any,
    ) -> Optional[ThresholdRule]:
        """Update a threshold rule.
        
        Args:
            rule_id: Rule identifier.
            **kwargs: Fields to update.
            
        Returns:
            Updated rule or None.
        """
        rule = self._rules.get(rule_id)
        if rule is None:
            return None
        
        for key, value in kwargs.items():
            if hasattr(rule, key):
                setattr(rule, key, value)
        
        rule.updated_at = datetime.now(timezone.utc)
        logger.info(f"Updated threshold rule: {rule_id}")
        
        return rule
    
    def delete_rule(self, rule_id: str) -> bool:
        """Delete a threshold rule.
        
        Args:
            rule_id: Rule identifier.
            
        Returns:
            True if deleted, False if not found.
        """
        if rule_id not in self._rules:
            return False
        
        del self._rules[rule_id]
        logger.info(f"Deleted threshold rule: {rule_id}")
        
        return True
    
    async def acknowledge_breach(
        self,
        breach_id: str,
        user: str,
    ) -> Optional[ThresholdBreach]:
        """Acknowledge a threshold breach.
        
        Args:
            breach_id: Breach identifier.
            user: User who acknowledged.
            
        Returns:
            Acknowledged breach or None.
        """
        breach = self._active_breaches.get(breach_id)
        if breach is None:
            return None
        
        breach.acknowledge(user)
        logger.info(f"Breach acknowledged: {breach_id} by {user}")
        
        return breach
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get threshold monitoring statistics.
        
        Returns:
            Dictionary of statistics.
        """
        active_count = len(self._active_breaches)
        critical_count = sum(
            1 for b in self._active_breaches.values()
            if b.severity == ThresholdSeverity.CRITICAL
        )
        warning_count = sum(
            1 for b in self._active_breaches.values()
            if b.severity == ThresholdSeverity.WARNING
        )
        
        return {
            "total_rules": len(self._rules),
            "enabled_rules": sum(1 for r in self._rules.values() if r.enabled),
            "active_breaches": active_count,
            "critical_breaches": critical_count,
            "warning_breaches": warning_count,
            "historical_breaches": len(self._breach_history),
            "registered_callbacks": len(self._alert_callbacks),
        }


# Export classes
__all__ = [
    "ThresholdSeverity",
    "ThresholdType",
    "BreachState",
    "HysteresisConfig",
    "ThresholdRule",
    "ThresholdBreach",
    "ThresholdAlert",
    "ThresholdMonitor",
]
