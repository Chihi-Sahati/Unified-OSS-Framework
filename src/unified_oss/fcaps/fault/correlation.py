"""
Alarm Correlation Module for FCAPS Fault Management.

This module provides comprehensive alarm correlation functionality including
temporal, topological, and causal correlation for root cause identification
in the Unified OSS Framework.

Supports:
    - Temporal correlation (time-window based)
    - Topological correlation (same site/region)
    - Causal correlation (root cause identification)
    - Confidence scoring (0.0-1.0)
    - Cross-vendor correlation support
"""

from __future__ import annotations

import asyncio
import logging
import re
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
AlarmDict = Dict[str, Any]


class CorrelationType(Enum):
    """Enumeration of correlation types.
    
    Attributes:
        TEMPORAL: Time-based correlation.
        SPATIAL: Location/site-based correlation (same as topological).
        TOPOLOGICAL: Location/site-based correlation.
        CAUSAL: Cause-effect correlation.
        CROSS_VENDOR: Cross-vendor correlation.
        PATTERN: Pattern-based correlation.
    """
    TEMPORAL = "TEMPORAL"
    SPATIAL = "SPATIAL"
    TOPOLOGICAL = "TOPOLOGICAL"
    CAUSAL = "CAUSAL"
    CROSS_VENDOR = "CROSS_VENDOR"
    PATTERN = "PATTERN"


# Alias for backward compatibility with tests
CorrelationMethod = CorrelationType


class CorrelationPriority(Enum):
    """Priority levels for correlated alarm groups.
    
    Attributes:
        CRITICAL: High-confidence root cause found.
        HIGH: Strong correlation identified.
        MEDIUM: Moderate correlation confidence.
        LOW: Weak correlation.
    """
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class CorrelationError(Exception):
    """Base exception for correlation operations."""
    pass


class RuleEvaluationError(CorrelationError):
    """Exception raised during rule evaluation."""
    pass


@dataclass
class CorrelationResult:
    """Dataclass representing the result of correlation analysis.
    
    Attributes:
        total_alarms: Total number of alarms processed.
        correlation_groups: List of correlated alarm groups.
        root_cause_candidates: List of root cause candidates.
        processing_time_ms: Processing time in milliseconds.
    """
    total_alarms: int
    correlation_groups: List["CorrelatedAlarmGroup"] = field(default_factory=list)
    root_cause_candidates: List["RootCauseCandidate"] = field(default_factory=list)
    processing_time_ms: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary representation.
        
        Returns:
            Dictionary containing result attributes.
        """
        return {
            "total_alarms": self.total_alarms,
            "correlation_groups": [g.to_dict() for g in self.correlation_groups],
            "root_cause_candidates": [c.to_dict() for c in self.root_cause_candidates],
            "processing_time_ms": self.processing_time_ms,
        }


@dataclass
class RootCauseCandidate:
    """Dataclass representing a root cause candidate.
    
    Attributes:
        alarm: The alarm identified as potential root cause.
        confidence: Confidence score (0.0-1.0).
        affected_alarms: List of alarms affected by this root cause.
        reasoning: Explanation of why this is a root cause.
    """
    alarm: AlarmDict
    confidence: float
    affected_alarms: List[AlarmDict] = field(default_factory=list)
    reasoning: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert candidate to dictionary representation.
        
        Returns:
            Dictionary containing candidate attributes.
        """
        return {
            "alarm": self.alarm,
            "confidence": self.confidence,
            "affected_alarms": self.affected_alarms,
            "reasoning": self.reasoning,
            "affected_count": len(self.affected_alarms),
        }


@dataclass
class CorrelationMetrics:
    """Dataclass for tracking correlation metrics.
    
    Attributes:
        total_correlations: Total number of correlations performed.
        avg_processing_time_ms: Average processing time in milliseconds.
        total_alarms_processed: Total alarms processed.
    """
    total_correlations: int = 0
    avg_processing_time_ms: float = 0.0
    total_alarms_processed: int = 0
    
    def record(self, processing_time_ms: float, alarms_processed: int) -> None:
        """Record a correlation operation.
        
        Args:
            processing_time_ms: Processing time in milliseconds.
            alarms_processed: Number of alarms processed.
        """
        # Update running average
        if self.total_correlations == 0:
            self.avg_processing_time_ms = processing_time_ms
            self.total_correlations = 1
        else:
            total_time = self.avg_processing_time_ms * self.total_correlations
            total_time += processing_time_ms
            self.total_correlations += 1
            self.avg_processing_time_ms = total_time / self.total_correlations
        
        self.total_alarms_processed += alarms_processed


@dataclass
class CorrelationRule:
    """Dataclass representing a correlation rule.
    
    Attributes:
        rule_id: Unique identifier for the rule.
        name: Human-readable name.
        description: Rule description.
        correlation_type: Type of correlation.
        conditions: List of conditions to evaluate.
        time_window: Time window for temporal correlation.
        confidence_weight: Weight for confidence calculation.
        enabled: Whether the rule is active.
        priority: Rule priority for ordering.
        tags: Tags for categorization.
    """
    rule_id: str
    name: str
    correlation_type: CorrelationType
    conditions: List[Dict[str, Any]] = field(default_factory=list)
    time_window: timedelta = field(default_factory=lambda: timedelta(minutes=5))
    confidence_weight: float = 0.8
    description: str = ""
    enabled: bool = True
    priority: int = 0
    tags: List[str] = field(default_factory=list)

    def evaluate(self, alarm: AlarmDict, context: Optional[Dict[str, Any]] = None) -> bool:
        """Evaluate the rule against an alarm.
        
        Args:
            alarm: Alarm to evaluate.
            context: Additional context for evaluation.
            
        Returns:
            True if alarm matches the rule conditions.
        """
        if not self.enabled:
            return False

        context = context or {}

        for condition in self.conditions:
            if not self._evaluate_condition(condition, alarm, context):
                return False

        return True

    def matches(self, alarm: AlarmDict) -> bool:
        """Check if an alarm matches the rule conditions.
        
        This is an alias for the evaluate method for simpler API.
        
        Args:
            alarm: Alarm to check.
            
        Returns:
            True if alarm matches the rule conditions.
        """
        return self.evaluate(alarm)

    def _evaluate_condition(
        self,
        condition: Dict[str, Any],
        alarm: AlarmDict,
        context: Dict[str, Any],
    ) -> bool:
        """Evaluate a single condition.
        
        Args:
            condition: Condition to evaluate.
            alarm: Alarm to check.
            context: Evaluation context.
            
        Returns:
            True if condition matches.
        """
        field_path = condition.get("field", "")
        operator = condition.get("operator", "equals")
        expected = condition.get("value")

        # Get field value using path
        value = self._get_field_value(alarm, field_path)

        # Evaluate based on operator
        if operator == "equals":
            return value == expected
        elif operator == "not_equals":
            return value != expected
        elif operator == "contains":
            return isinstance(value, str) and expected in value
        elif operator == "matches":
            return isinstance(value, str) and bool(re.match(expected, value))
        elif operator == "in":
            return value in expected if isinstance(expected, list) else False
        elif operator == "greater_than":
            return isinstance(value, (int, float)) and value > expected
        elif operator == "less_than":
            return isinstance(value, (int, float)) and value < expected
        elif operator == "exists":
            return value is not None

        return False

    def _get_field_value(self, alarm: AlarmDict, path: str) -> Any:
        """Get a field value from nested dictionary using dot notation.
        
        Args:
            alarm: Alarm dictionary.
            path: Dot-separated field path.
            
        Returns:
            Field value or None if not found.
        """
        if not path:
            return None

        parts = path.split(".")
        value = alarm

        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            elif hasattr(value, part):
                value = getattr(value, part)
            else:
                return None

        return value

    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary representation.
        
        Returns:
            Dictionary containing rule attributes.
        """
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "correlation_type": self.correlation_type.value,
            "conditions": self.conditions,
            "time_window_seconds": self.time_window.total_seconds(),
            "confidence_weight": self.confidence_weight,
            "enabled": self.enabled,
            "priority": self.priority,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CorrelationRule":
        """Create a CorrelationRule from dictionary.
        
        Args:
            data: Dictionary containing rule attributes.
            
        Returns:
            CorrelationRule instance.
        """
        return cls(
            rule_id=data.get("rule_id", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            correlation_type=CorrelationType(data.get("correlation_type", "TEMPORAL")),
            conditions=data.get("conditions", []),
            time_window=timedelta(seconds=data.get("time_window_seconds", 300)),
            confidence_weight=data.get("confidence_weight", 0.8),
            enabled=data.get("enabled", True),
            priority=data.get("priority", 0),
            tags=data.get("tags", []),
        )


@dataclass
class CorrelatedAlarmGroup:
    """Dataclass representing a group of correlated alarms.
    
    Attributes:
        group_id: Unique identifier for the group.
        root_cause_alarm: The identified root cause alarm.
        correlated_alarms: List of correlated alarms.
        correlation_type: Type of correlation.
        confidence: Confidence score (0.0-1.0).
        priority: Correlation priority.
        created_at: Group creation timestamp.
        updated_at: Last update timestamp.
        metadata: Additional metadata.
    """
    group_id: str
    root_cause_alarm: Optional[AlarmDict] = None
    correlated_alarms: List[AlarmDict] = field(default_factory=list)
    correlation_type: CorrelationType = CorrelationType.TEMPORAL
    confidence: float = 0.0
    priority: CorrelationPriority = CorrelationPriority.MEDIUM
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_alarm(self, alarm: AlarmDict) -> None:
        """Add an alarm to the correlated group.
        
        Args:
            alarm: Alarm to add.
        """
        self.correlated_alarms.append(alarm)
        self.updated_at = datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        """Convert group to dictionary representation.
        
        Returns:
            Dictionary containing group attributes.
        """
        return {
            "group_id": self.group_id,
            "root_cause_alarm": self.root_cause_alarm,
            "correlated_alarms": self.correlated_alarms,
            "correlation_type": self.correlation_type.value,
            "confidence": self.confidence,
            "priority": self.priority.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "metadata": self.metadata,
            "alarm_count": len(self.correlated_alarms),
        }


@dataclass
class TopologyInfo:
    """Dataclass representing topology information for an alarm.
    
    Attributes:
        resource_path: Resource path in CIM format.
        site_id: Site identifier.
        region_id: Region identifier.
        parent_element: Parent network element.
        child_elements: List of child network elements.
        connections: List of connected elements.
    """
    resource_path: str
    site_id: Optional[str] = None
    region_id: Optional[str] = None
    parent_element: Optional[str] = None
    child_elements: List[str] = field(default_factory=list)
    connections: List[str] = field(default_factory=list)


class CorrelationEngine:
    """Core correlation engine for alarm analysis.
    
    This class provides the main correlation logic including rule
    evaluation, confidence calculation, and group management.
    
    Attributes:
        rules: Active correlation rules.
    """

    def __init__(self, max_groups: int = 10000) -> None:
        """Initialize the correlation engine.
        
        Args:
            max_groups: Maximum number of correlation groups to maintain.
        """
        self._rules: Dict[str, CorrelationRule] = {}
        self._groups: Dict[str, CorrelatedAlarmGroup] = {}
        self._max_groups = max_groups
        self._topology_cache: Dict[str, TopologyInfo] = {}

        # Statistics
        self._stats = {
            "total_correlations": 0,
            "temporal_correlations": 0,
            "topological_correlations": 0,
            "causal_correlations": 0,
            "cross_vendor_correlations": 0,
        }

    def add_rule(self, rule: CorrelationRule) -> None:
        """Add a correlation rule.
        
        Args:
            rule: Rule to add.
        """
        self._rules[rule.rule_id] = rule
        logger.info(f"Added correlation rule: {rule.rule_id}")

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a correlation rule.
        
        Args:
            rule_id: Rule identifier.
            
        Returns:
            True if removed, False if not found.
        """
        if rule_id in self._rules:
            del self._rules[rule_id]
            logger.info(f"Removed correlation rule: {rule_id}")
            return True
        return False

    def get_rules(self, correlation_type: Optional[CorrelationType] = None) -> List[CorrelationRule]:
        """Get correlation rules, optionally filtered by type.
        
        Args:
            correlation_type: Optional type filter.
            
        Returns:
            List of rules.
        """
        if correlation_type:
            return [r for r in self._rules.values() if r.correlation_type == correlation_type]
        return list(self._rules.values())

    async def correlate(
        self,
        alarm: Union[AlarmDict, List[AlarmDict]],
        existing_alarms: Optional[List[AlarmDict]] = None,
        correlation_type: Optional[CorrelationType] = None,
    ) -> Union[Optional[CorrelatedAlarmGroup], CorrelationResult]:
        """Correlate alarms.
        
        This method supports two modes:
        1. Single alarm mode: Pass a single alarm dict and existing_alarms list
        2. Batch mode: Pass a list of alarms to correlate together
        
        Args:
            alarm: Single alarm dict or list of alarms to correlate.
            existing_alarms: List of existing alarms (for single alarm mode).
            correlation_type: Optional correlation type to use.
            
        Returns:
            CorrelatedAlarmGroup (single mode) or CorrelationResult (batch mode).
        """
        # Check if we're in batch mode (alarm is a list)
        if isinstance(alarm, list):
            return await self._correlate_batch(alarm, correlation_type)
        
        # Single alarm mode
        if existing_alarms is None:
            existing_alarms = []
        
        # If correlation_type is specified, use specific method
        if correlation_type:
            return await self._correlate_by_type(alarm, existing_alarms, correlation_type)
        
        # Try each correlation type in order of priority
        correlation_methods = [
            (self._correlate_causal, CorrelationType.CAUSAL),
            (self._correlate_topological, CorrelationType.TOPOLOGICAL),
            (self._correlate_temporal, CorrelationType.TEMPORAL),
            (self._correlate_cross_vendor, CorrelationType.CROSS_VENDOR),
        ]

        for method, corr_type in correlation_methods:
            result = await method(alarm, existing_alarms)
            if result:
                self._stats["total_correlations"] += 1
                self._stats[f"{corr_type.value.lower()}_correlations"] += 1
                return result

        return None

    async def _correlate_by_type(
        self,
        alarm: AlarmDict,
        existing_alarms: List[AlarmDict],
        correlation_type: CorrelationType,
    ) -> Optional[CorrelatedAlarmGroup]:
        """Correlate using a specific correlation type.
        
        Args:
            alarm: Alarm to correlate.
            existing_alarms: Existing alarms.
            correlation_type: Type of correlation to perform.
            
        Returns:
            CorrelatedAlarmGroup if correlation found.
        """
        method_map = {
            CorrelationType.CAUSAL: self._correlate_causal,
            CorrelationType.TOPOLOGICAL: self._correlate_topological,
            CorrelationType.SPATIAL: self._correlate_topological,  # SPATIAL is same as TOPOLOGICAL
            CorrelationType.TEMPORAL: self._correlate_temporal,
            CorrelationType.CROSS_VENDOR: self._correlate_cross_vendor,
        }
        
        method = method_map.get(correlation_type)
        if method:
            result = await method(alarm, existing_alarms)
            if result:
                self._stats["total_correlations"] += 1
                self._stats[f"{correlation_type.value.lower()}_correlations"] += 1
            return result
        
        return None

    async def _correlate_batch(
        self,
        alarms: List[AlarmDict],
        correlation_type: Optional[CorrelationType] = None,
    ) -> CorrelationResult:
        """Correlate a batch of alarms together.
        
        Args:
            alarms: List of alarms to correlate.
            correlation_type: Optional correlation type to use.
            
        Returns:
            CorrelationResult with correlation results.
        """
        start_time = datetime.now(timezone.utc)
        
        result = CorrelationResult(
            total_alarms=len(alarms),
            correlation_groups=[],
            root_cause_candidates=[],
        )
        
        if not alarms:
            return result
        
        # Helper to get parsed time
        def get_time(a: Any) -> datetime:
            time_str = getattr(a, "raised_at", None) if not isinstance(a, dict) else a.get("raised_at")
            if isinstance(time_str, datetime):
                return time_str
            if time_str:
                try:
                    return datetime.fromisoformat(time_str.replace("Z", "+00:00"))
                except ValueError:
                    pass
            return start_time
            
        # O(N log N) pre-sorting based on time for sliding window optimization
        sorted_alarms = sorted(alarms, key=get_time)
        groups_map: Dict[str, CorrelatedAlarmGroup] = {}
        processed_alarm_ids: Set[str] = set()
        
        # Max window seconds to look ahead (default 10 mins)
        window_seconds = 600
        
        for i, alarm in enumerate(sorted_alarms):
            alarm_id = str(getattr(alarm, 'alarm_id', alarm.get('alarm_id', id(alarm)) if isinstance(alarm, dict) else id(alarm)))
            if alarm_id in processed_alarm_ids:
                continue
                
            # Collect candidates within the sliding window
            candidates = []
            alarm_time = get_time(alarm)
            
            for j in range(i + 1, len(sorted_alarms)):
                other_alarm = sorted_alarms[j]
                other_id = str(getattr(other_alarm, 'alarm_id', other_alarm.get('alarm_id', id(other_alarm)) if isinstance(other_alarm, dict) else id(other_alarm)))
                
                if other_id in processed_alarm_ids:
                    continue
                    
                time_diff = (get_time(other_alarm) - alarm_time).total_seconds()
                if time_diff <= window_seconds:
                    candidates.append(other_alarm)
                else:
                    # Since it is sorted, we can break early and abandon the inner loop!
                    break
            
            if candidates:
                # Perform correlation passing ALL candidates at once
                group = await self._correlate_by_type(
                    alarm, candidates, 
                    correlation_type or CorrelationType.TEMPORAL
                )
                
                if group and group.correlated_alarms:
                    groups_map[group.group_id] = group
                    processed_alarm_ids.add(alarm_id)
                    for correlated in group.correlated_alarms:
                        correlated_id = str(getattr(correlated, 'alarm_id', correlated.get('alarm_id', id(correlated)) if isinstance(correlated, dict) else id(correlated)))
                        processed_alarm_ids.add(correlated_id)
        
        result.correlation_groups = list(groups_map.values())
        
        # Find root cause candidates
        for group in result.correlation_groups:
            if group.root_cause_alarm:
                candidate = RootCauseCandidate(
                    alarm=group.root_cause_alarm,
                    confidence=group.confidence,
                    affected_alarms=group.correlated_alarms,
                    reasoning=f"Identified as root cause via {group.correlation_type.value} correlation",
                )
                result.root_cause_candidates.append(candidate)
        
        # Calculate processing time
        end_time = datetime.now(timezone.utc)
        result.processing_time_ms = (end_time - start_time).total_seconds() * 1000
        
        return result

    async def _correlate_temporal(
        self,
        alarm: AlarmDict,
        existing_alarms: List[AlarmDict],
    ) -> Optional[CorrelatedAlarmGroup]:
        """Perform temporal correlation.
        
        Args:
            alarm: New alarm.
            existing_alarms: Existing alarms.
            
        Returns:
            CorrelatedAlarmGroup if correlation found.
        """
        rules = self.get_rules(CorrelationType.TEMPORAL)
        if not rules:
            return None

        alarm_time = getattr(alarm, "raised_at", None) if not isinstance(alarm, dict) else alarm.get("raised_at")
        if isinstance(alarm_time, str):
            alarm_time = datetime.fromisoformat(alarm_time.replace("Z", "+00:00"))
        elif not isinstance(alarm_time, datetime):
            alarm_time = datetime.now(timezone.utc)
        correlated = []

        for rule in rules:
            if not rule.enabled:
                continue

            time_window = rule.time_window

            for existing in existing_alarms:
                existing_time = getattr(existing, "raised_at", None) if not isinstance(existing, dict) else existing.get("raised_at")
                if isinstance(existing_time, str):
                    existing_time = datetime.fromisoformat(existing_time.replace("Z", "+00:00"))
                elif not isinstance(existing_time, datetime):
                    existing_time = datetime.now(timezone.utc)

                # Check if within time window
                time_diff = abs((alarm_time - existing_time).total_seconds())
                if time_diff <= time_window.total_seconds():
                    # Check if alarms match rule conditions
                    if rule.evaluate(alarm) and rule.evaluate(existing):
                        correlated.append(existing)

        if correlated:
            confidence = self.calculate_confidence(
                alarm, correlated, CorrelationType.TEMPORAL
            )
            alarm_id_str = getattr(alarm, "alarm_id", alarm.get("alarm_id", "") if isinstance(alarm, dict) else "")
            group = CorrelatedAlarmGroup(
                group_id=f"temporal-{alarm_id_str}",
                root_cause_alarm=alarm,
                correlated_alarms=correlated,
                correlation_type=CorrelationType.TEMPORAL,
                confidence=confidence,
                priority=self._determine_priority(confidence),
            )
            self._groups[group.group_id] = group
            return group

        return None

    async def _correlate_topological(
        self,
        alarm: AlarmDict,
        existing_alarms: List[AlarmDict],
    ) -> Optional[CorrelatedAlarmGroup]:
        """Perform topological correlation.
        
        Args:
            alarm: New alarm.
            existing_alarms: Existing alarms.
            
        Returns:
            CorrelatedAlarmGroup if correlation found.
        """
        alarm_path = getattr(alarm, "resource_path", None) if not isinstance(alarm, dict) else alarm.get("resource_path", "")
        if not alarm_path:
            alarm_path = getattr(alarm, "ne_id", "") if not isinstance(alarm, dict) else alarm.get("ne_id", "")
            
        alarm_topology = self._topology_cache.get(alarm_path)

        if not alarm_topology:
            # Try to extract topology from resource path
            alarm_topology = self._extract_topology(alarm_path)

        correlated = []

        for existing in existing_alarms:
            existing_path = getattr(existing, "resource_path", None) if not isinstance(existing, dict) else existing.get("resource_path", "")
            if not existing_path:
                existing_path = getattr(existing, "ne_id", "") if not isinstance(existing, dict) else existing.get("ne_id", "")
                
            existing_topology = self._topology_cache.get(existing_path)

            if not existing_topology:
                existing_topology = self._extract_topology(existing_path)

            # Check for topological relationship
            if self._is_topologically_related(alarm_topology, existing_topology):
                correlated.append(existing)

        if correlated:
            confidence = self.calculate_confidence(
                alarm, correlated, CorrelationType.TOPOLOGICAL
            )
            alarm_id_str = getattr(alarm, "alarm_id", alarm.get("alarm_id", "") if isinstance(alarm, dict) else "")
            group = CorrelatedAlarmGroup(
                group_id=f"topo-{alarm_id_str}",
                root_cause_alarm=alarm,
                correlated_alarms=correlated,
                correlation_type=CorrelationType.TOPOLOGICAL,
                confidence=confidence,
                priority=self._determine_priority(confidence),
                metadata={
                    "site_id": alarm_topology.site_id if alarm_topology else None,
                    "region_id": alarm_topology.region_id if alarm_topology else None,
                },
            )
            self._groups[group.group_id] = group
            return group

        return None

    def _extract_topology(self, resource_path: str) -> TopologyInfo:
        """Extract topology information from resource path.
        
        Args:
            resource_path: CIM resource path.
            
        Returns:
            TopologyInfo extracted from path.
        """
        # Parse CIM-format path: /network/elements/{id} or /network/sites/{site}/elements/{id}
        parts = resource_path.strip("/").split("/")
        site_id = None
        region_id = None

        if "sites" in parts:
            site_idx = parts.index("sites")
            if site_idx + 1 < len(parts):
                site_id = parts[site_idx + 1]

        if "regions" in parts:
            region_idx = parts.index("regions")
            if region_idx + 1 < len(parts):
                region_id = parts[region_idx + 1]

        return TopologyInfo(
            resource_path=resource_path,
            site_id=site_id,
            region_id=region_id,
        )

    def _is_topologically_related(
        self,
        topology1: TopologyInfo,
        topology2: TopologyInfo,
    ) -> bool:
        """Check if two resources are topologically related.
        
        Args:
            topology1: First resource topology.
            topology2: Second resource topology.
            
        Returns:
            True if resources are related.
        """
        # Same site
        if topology1.site_id and topology1.site_id == topology2.site_id:
            return True

        # Same region
        if topology1.region_id and topology1.region_id == topology2.region_id:
            return True

        # Parent-child relationship
        if topology1.parent_element == topology2.resource_path:
            return True
        if topology2.parent_element == topology1.resource_path:
            return True

        # Connected elements
        if topology2.resource_path in topology1.connections:
            return True
        if topology1.resource_path in topology2.connections:
            return True

        return False

    async def _correlate_causal(
        self,
        alarm: AlarmDict,
        existing_alarms: List[AlarmDict],
    ) -> Optional[CorrelatedAlarmGroup]:
        """Perform causal correlation for root cause identification.
        
        Args:
            alarm: New alarm.
            existing_alarms: Existing alarms.
            
        Returns:
            CorrelatedAlarmGroup if correlation found.
        """
        rules = self.get_rules(CorrelationType.CAUSAL)
        if not rules:
            return None

        # Causal patterns: link down -> site down, power failure -> equipment failure
        causal_patterns = [
            {
                "cause_pattern": ["link", "transmission", "backhaul"],
                "effect_pattern": ["site", "element", "node"],
                "severity_boost": 0.2,
            },
            {
                "cause_pattern": ["power", "battery", "supply"],
                "effect_pattern": ["equipment", "hardware", "board"],
                "severity_boost": 0.15,
            },
            {
                "cause_pattern": ["temperature", "cooling", "fan"],
                "effect_pattern": ["thermal", "overheat", "shutdown"],
                "severity_boost": 0.1,
            },
        ]

        alarm_text = (alarm.get("alarm_text", "") if isinstance(alarm, dict) else getattr(alarm, "alarm_text", "") or getattr(alarm, "probable_cause", "")).lower()
        alarm_severity = alarm.get("severity", "INDETERMINATE") if isinstance(alarm, dict) else getattr(alarm, "severity", "INDETERMINATE")

        for pattern in causal_patterns:
            cause_keywords = pattern["cause_pattern"]
            is_cause = any(kw in alarm_text for kw in cause_keywords)

            if not is_cause:
                continue

            # Find potential effect alarms
            effect_keywords = pattern["effect_pattern"]
            correlated = []

            for existing in existing_alarms:
                existing_text = (existing.get("alarm_text", "") if isinstance(existing, dict) else getattr(existing, "alarm_text", "") or getattr(existing, "probable_cause", "")).lower()
                if any(kw in existing_text for kw in effect_keywords):
                    # Check topological proximity
                    alarm_path = alarm.get("resource_path", "") if isinstance(alarm, dict) else getattr(alarm, "resource_path", getattr(alarm, "ne_id", ""))
                    existing_path = existing.get("resource_path", "") if isinstance(existing, dict) else getattr(existing, "resource_path", getattr(existing, "ne_id", ""))
                    if self._is_topologically_related(
                        self._extract_topology(alarm_path),
                        self._extract_topology(existing_path),
                    ):
                        correlated.append(existing)

            if correlated:
                confidence = self.calculate_confidence(
                    alarm, correlated, CorrelationType.CAUSAL
                )
                confidence += pattern["severity_boost"]
                confidence = min(confidence, 1.0)

                alarm_id_str = getattr(alarm, "alarm_id", alarm.get("alarm_id", "") if isinstance(alarm, dict) else "")
                group = CorrelatedAlarmGroup(
                    group_id=f"causal-{alarm_id_str}",
                    root_cause_alarm=alarm,  # This alarm is the root cause
                    correlated_alarms=correlated,  # These are the effects
                    correlation_type=CorrelationType.CAUSAL,
                    confidence=confidence,
                    priority=CorrelationPriority.CRITICAL if confidence > 0.8 else CorrelationPriority.HIGH,
                    metadata={
                        "cause_keywords": cause_keywords,
                        "effect_keywords": effect_keywords,
                    },
                )
                self._groups[group.group_id] = group
                return group

        return None

    async def _correlate_cross_vendor(
        self,
        alarm: AlarmDict,
        existing_alarms: List[AlarmDict],
    ) -> Optional[CorrelatedAlarmGroup]:
        """Perform cross-vendor correlation.
        
        Args:
            alarm: New alarm.
            existing_alarms: Existing alarms.
            
        Returns:
            CorrelatedAlarmGroup if correlation found.
        """
        alarm_source = alarm.get("source", "") if isinstance(alarm, dict) else getattr(alarm, "source", getattr(alarm, "vendor", ""))
        alarm_path = alarm.get("resource_path", "") if isinstance(alarm, dict) else getattr(alarm, "resource_path", getattr(alarm, "ne_id", ""))
        alarm_site = self._extract_topology(alarm_path).site_id

        if not alarm_site:
            return None

        # Find alarms from different vendors at same site
        correlated = []

        for existing in existing_alarms:
            existing_source = existing.get("source", "") if isinstance(existing, dict) else getattr(existing, "source", getattr(existing, "vendor", ""))
            existing_path = existing.get("resource_path", "") if isinstance(existing, dict) else getattr(existing, "resource_path", getattr(existing, "ne_id", ""))
            existing_site = self._extract_topology(existing_path).site_id

            # Same site, different vendor
            if existing_site == alarm_site and existing_source != alarm_source:
                correlated.append(existing)

        if correlated:
            confidence = self.calculate_confidence(
                alarm, correlated, CorrelationType.CROSS_VENDOR
            )
            alarm_id_str = getattr(alarm, "alarm_id", alarm.get("alarm_id", "") if isinstance(alarm, dict) else "")
            group = CorrelatedAlarmGroup(
                group_id=f"xvendor-{alarm_id_str}",
                root_cause_alarm=alarm,
                correlated_alarms=correlated,
                correlation_type=CorrelationType.CROSS_VENDOR,
                confidence=confidence,
                priority=self._determine_priority(confidence),
                metadata={
                    "vendors_involved": list(set(
                        [alarm_source] + [a.get("source", "") for a in correlated]
                    )),
                    "site_id": alarm_site,
                },
            )
            self._groups[group.group_id] = group
            return group

        return None

    def calculate_confidence(
        self,
        primary_alarm: AlarmDict,
        correlated_alarms: List[AlarmDict],
        correlation_type: CorrelationType,
    ) -> float:
        """Calculate confidence score for correlation.
        
        Args:
            primary_alarm: Primary alarm.
            correlated_alarms: Correlated alarms.
            correlation_type: Type of correlation.
            
        Returns:
            Confidence score between 0.0 and 1.0.
        """
        base_confidence = 0.5

        # Factor 1: Number of correlated alarms
        count_factor = min(len(correlated_alarms) / 5.0, 1.0) * 0.2

        def _get_severity(obj):
            val = obj.get("severity", "INDETERMINATE") if isinstance(obj, dict) else getattr(obj, "severity", "INDETERMINATE")
            if hasattr(val, "value"):
                return val.value
            return str(val)

        # Factor 2: Severity alignment
        primary_severity = _get_severity(primary_alarm)
        severity_match = sum(
            1 for a in correlated_alarms
            if _get_severity(a) == primary_severity
        ) / max(len(correlated_alarms), 1)
        severity_factor = severity_match * 0.15

        def _get_time(obj):
            val = getattr(obj, "raised_at", None) if not isinstance(obj, dict) else obj.get("raised_at")
            if isinstance(val, datetime):
                return val
            if isinstance(val, str):
                return datetime.fromisoformat(val.replace("Z", "+00:00"))
            return datetime.now(timezone.utc)

        # Factor 3: Time proximity (for temporal correlation)
        time_factor = 0.0
        if correlation_type == CorrelationType.TEMPORAL:
            primary_time = _get_time(primary_alarm)
            time_diffs = []
            for a in correlated_alarms:
                a_time = _get_time(a)
                time_diffs.append(abs((primary_time - a_time).total_seconds()))

            avg_time_diff = sum(time_diffs) / len(time_diffs) if time_diffs else 300
            time_factor = max(0, 1.0 - avg_time_diff / 600) * 0.15

        # Factor 4: Correlation type weight
        type_weights = {
            CorrelationType.CAUSAL: 0.1,
            CorrelationType.TOPOLOGICAL: 0.05,
            CorrelationType.TEMPORAL: 0.0,
            CorrelationType.CROSS_VENDOR: 0.03,
        }
        type_factor = type_weights.get(correlation_type, 0.0)

        # Calculate final confidence
        confidence = base_confidence + count_factor + severity_factor + time_factor + type_factor
        return min(max(confidence, 0.0), 1.0)

    def _determine_priority(self, confidence: float) -> CorrelationPriority:
        """Determine correlation priority from confidence.
        
        Args:
            confidence: Confidence score.
            
        Returns:
            CorrelationPriority level.
        """
        if confidence >= 0.85:
            return CorrelationPriority.CRITICAL
        elif confidence >= 0.7:
            return CorrelationPriority.HIGH
        elif confidence >= 0.5:
            return CorrelationPriority.MEDIUM
        else:
            return CorrelationPriority.LOW

    async def find_root_cause(
        self,
        alarms: List[AlarmDict],
    ) -> Optional[AlarmDict]:
        """Find the root cause alarm among a group of alarms.
        
        Args:
            alarms: List of related alarms.
            
        Returns:
            Root cause alarm or None.
        """
        if not alarms:
            return None

        if len(alarms) == 1:
            return alarms[0]

        # Score each alarm as potential root cause
        scores: List[Tuple[AlarmDict, float]] = []

        severity_weights = {
            "CRITICAL": 0.4,
            "HIGH": 0.3,
            "MEDIUM": 0.2,
            "LOW": 0.1,
            "INDETERMINATE": 0.05,
            "CLEARED": 0.0,
        }

        for alarm in alarms:
            score = 0.0

            # Severity weight
            severity = alarm.get("severity", "INDETERMINATE")
            score += severity_weights.get(severity, 0.05)

            # Earliest alarm (root cause typically appears first)
            alarm_time = datetime.fromisoformat(
                alarm.get("raised_at", datetime.now(timezone.utc).isoformat())
            )
            earliest_bonus = 0.3  # Higher bonus for being earlier

            # Alarm text analysis (infrastructure issues are often root causes)
            alarm_text = alarm.get("alarm_text", "").lower()
            root_cause_keywords = [
                "link", "power", "temperature", "fan", "battery", 
                "transmission", "backhaul", "fiber", "optical", "hardware",
            ]
            for kw in root_cause_keywords:
                if kw in alarm_text:
                    score += 0.1
                    break

            scores.append((alarm, score))

        # Sort by score descending, then by time ascending
        scores.sort(key=lambda x: (-x[1], datetime.fromisoformat(x[0].get("raised_at", ""))))

        return scores[0][0] if scores else None

    def get_correlated_alarms(self, alarm_id: str) -> List[CorrelatedAlarmGroup]:
        """Get all correlation groups containing an alarm.
        
        Args:
            alarm_id: Alarm identifier.
            
        Returns:
            List of correlation groups.
        """
        groups = []
        for group in self._groups.values():
            if group.root_cause_alarm and group.root_cause_alarm.get("alarm_id") == alarm_id:
                groups.append(group)
                continue

            for alarm in group.correlated_alarms:
                if alarm.get("alarm_id") == alarm_id:
                    groups.append(group)
                    break

        return groups

    def get_groups(self, priority: Optional[CorrelationPriority] = None) -> List[CorrelatedAlarmGroup]:
        """Get correlation groups, optionally filtered by priority.
        
        Args:
            priority: Optional priority filter.
            
        Returns:
            List of correlation groups.
        """
        if priority:
            return [g for g in self._groups.values() if g.priority == priority]
        return list(self._groups.values())

    def get_stats(self) -> Dict[str, Any]:
        """Get correlation statistics.
        
        Returns:
            Dictionary of statistics.
        """
        return {
            **self._stats,
            "active_groups": len(self._groups),
            "rules_count": len(self._rules),
        }


class AlarmCorrelator:
    """High-level alarm correlation coordinator.
    
    This class coordinates the correlation process, integrating with
    the alarm manager and correlation engine.
    
    Example:
        >>> correlator = AlarmCorrelator()
        >>> correlator.add_default_rules()
        >>> group = await correlator.correlate_alarm(alarm, active_alarms)
    """

    def __init__(
        self,
        engine: Optional[CorrelationEngine] = None,
    ) -> None:
        """Initialize the alarm correlator.
        
        Args:
            engine: Optional pre-configured correlation engine.
        """
        self._engine = engine or CorrelationEngine()
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize the correlator with default rules."""
        if self._initialized:
            return

        self._add_default_rules()
        self._initialized = True
        logger.info("AlarmCorrelator initialized")

    def _add_default_rules(self) -> None:
        """Add default correlation rules."""
        # Temporal rules
        self._engine.add_rule(CorrelationRule(
            rule_id="temporal-default",
            name="Default Temporal Correlation",
            description="Correlate alarms within 5 minutes",
            correlation_type=CorrelationType.TEMPORAL,
            time_window=timedelta(minutes=5),
            confidence_weight=0.7,
            priority=10,
        ))

        # Causal rules - Link failures
        self._engine.add_rule(CorrelationRule(
            rule_id="causal-link-failure",
            name="Link Failure Correlation",
            description="Correlate link failures with site failures",
            correlation_type=CorrelationType.CAUSAL,
            conditions=[
                {"field": "alarm_text", "operator": "contains", "value": "link"},
                {"field": "alarm_text", "operator": "contains", "value": "down"},
            ],
            confidence_weight=0.9,
            priority=100,
        ))

        # Causal rules - Power failures
        self._engine.add_rule(CorrelationRule(
            rule_id="causal-power-failure",
            name="Power Failure Correlation",
            description="Correlate power failures with equipment failures",
            correlation_type=CorrelationType.CAUSAL,
            conditions=[
                {"field": "alarm_text", "operator": "contains", "value": "power"},
            ],
            confidence_weight=0.95,
            priority=150,
        ))

        # Topological rules
        self._engine.add_rule(CorrelationRule(
            rule_id="topo-site",
            name="Same Site Correlation",
            description="Correlate alarms from the same site",
            correlation_type=CorrelationType.TOPOLOGICAL,
            confidence_weight=0.75,
            priority=50,
        ))

        logger.info(f"Added {len(self._engine.get_rules())} default correlation rules")

    async def correlate(
        self,
        alarm: AlarmDict,
        existing_alarms: List[AlarmDict],
    ) -> Optional[CorrelatedAlarmGroup]:
        """Correlate an alarm with existing alarms.
        
        Args:
            alarm: New alarm to correlate.
            existing_alarms: List of existing active alarms.
            
        Returns:
            CorrelatedAlarmGroup if correlation found.
        """
        if not self._initialized:
            await self.initialize()

        return await self._engine.correlate(alarm, existing_alarms)

    async def find_root_cause(self, alarms: List[AlarmDict]) -> Optional[AlarmDict]:
        """Find root cause among a group of alarms.
        
        Args:
            alarms: List of alarms to analyze.
            
        Returns:
            Root cause alarm or None.
        """
        return await self._engine.find_root_cause(alarms)

    def calculate_confidence(
        self,
        primary_alarm: AlarmDict,
        correlated_alarms: List[AlarmDict],
        correlation_type: CorrelationType,
    ) -> float:
        """Calculate confidence score for a correlation.
        
        Args:
            primary_alarm: Primary alarm.
            correlated_alarms: Correlated alarms.
            correlation_type: Type of correlation.
            
        Returns:
            Confidence score.
        """
        return self._engine.calculate_confidence(
            primary_alarm, correlated_alarms, correlation_type
        )

    def get_correlated_alarms(self, alarm_id: str) -> List[CorrelatedAlarmGroup]:
        """Get correlation groups for an alarm.
        
        Args:
            alarm_id: Alarm identifier.
            
        Returns:
            List of correlation groups.
        """
        return self._engine.get_correlated_alarms(alarm_id)

    def add_rule(self, rule: CorrelationRule) -> None:
        """Add a custom correlation rule.
        
        Args:
            rule: Rule to add.
        """
        self._engine.add_rule(rule)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a correlation rule.
        
        Args:
            rule_id: Rule identifier.
            
        Returns:
            True if removed.
        """
        return self._engine.remove_rule(rule_id)

    def get_stats(self) -> Dict[str, Any]:
        """Get correlation statistics.
        
        Returns:
            Statistics dictionary.
        """
        return self._engine.get_stats()


class AlarmGrouper:
    """Utility class for grouping alarms by various criteria.
    
    This class provides methods for grouping alarms by network element,
    severity, time window, and alarm type.
    
    Example:
        >>> grouper = AlarmGrouper()
        >>> groups = grouper.group_by_ne(alarms)
        >>> print(groups)  # {"router-001": [alarm1, alarm2], ...}
    """
    
    def __init__(self) -> None:
        """Initialize the alarm grouper."""
        pass

    def group_by_ne(self, alarms: List[Any]) -> Dict[str, List[Any]]:
        """Group alarms by network element ID.
        
        Args:
            alarms: List of alarms to group.
            
        Returns:
            Dictionary mapping NE ID to list of alarms.
        """
        groups: Dict[str, List[Any]] = {}
        
        for alarm in alarms:
            # Get ne_id from alarm (handle both dict and object)
            if hasattr(alarm, 'ne_id'):
                ne_id = alarm.ne_id
            elif isinstance(alarm, dict):
                ne_id = alarm.get('ne_id', alarm.get('neId', 'unknown'))
            else:
                ne_id = 'unknown'
            
            if ne_id not in groups:
                groups[ne_id] = []
            groups[ne_id].append(alarm)
        
        return groups

    def group_by_severity(self, alarms: List[Any]) -> Dict[str, List[Any]]:
        """Group alarms by severity level.
        
        Args:
            alarms: List of alarms to group.
            
        Returns:
            Dictionary mapping severity to list of alarms.
        """
        groups: Dict[str, List[Any]] = {}
        
        for alarm in alarms:
            # Get severity from alarm (handle both dict and object)
            if hasattr(alarm, 'severity'):
                severity = alarm.severity
                if hasattr(severity, 'value'):
                    severity = severity.value
            elif isinstance(alarm, dict):
                severity = alarm.get('severity', 'INDETERMINATE')
            else:
                severity = 'INDETERMINATE'
            
            if severity not in groups:
                groups[severity] = []
            groups[severity].append(alarm)
        
        return groups

    def group_by_time_window(
        self,
        alarms: List[Any],
        window_seconds: int = 60,
    ) -> List[List[Any]]:
        """Group alarms by time window.
        
        Args:
            alarms: List of alarms to group.
            window_seconds: Time window in seconds.
            
        Returns:
            List of alarm groups within each time window.
        """
        if not alarms:
            return []
        
        # Sort alarms by timestamp
        sorted_alarms = sorted(
            alarms,
            key=lambda a: self._get_timestamp(a)
        )
        
        groups: List[List[Any]] = []
        current_group: List[Any] = []
        window_start = None
        
        for alarm in sorted_alarms:
            alarm_time = self._get_timestamp(alarm)
            
            if window_start is None:
                window_start = alarm_time
                current_group = [alarm]
            elif (alarm_time - window_start).total_seconds() <= window_seconds:
                current_group.append(alarm)
            else:
                if current_group:
                    groups.append(current_group)
                window_start = alarm_time
                current_group = [alarm]
        
        if current_group:
            groups.append(current_group)
        
        return groups

    def group_by_alarm_type(self, alarms: List[Any]) -> Dict[str, List[Any]]:
        """Group alarms by alarm type.
        
        Args:
            alarms: List of alarms to group.
            
        Returns:
            Dictionary mapping alarm type to list of alarms.
        """
        groups: Dict[str, List[Any]] = {}
        
        for alarm in alarms:
            # Get alarm_type from alarm (handle both dict and object)
            if hasattr(alarm, 'alarm_type'):
                alarm_type = alarm.alarm_type
                if hasattr(alarm_type, 'value'):
                    alarm_type = alarm_type.value
            elif isinstance(alarm, dict):
                alarm_type = alarm.get('alarm_type', alarm.get('alarmType', 'OTHER'))
            else:
                alarm_type = 'OTHER'
            
            if alarm_type not in groups:
                groups[alarm_type] = []
            groups[alarm_type].append(alarm)
        
        return groups

    def _get_timestamp(self, alarm: Any) -> datetime:
        """Extract timestamp from alarm.
        
        Args:
            alarm: Alarm object or dictionary.
            
        Returns:
            Alarm timestamp.
        """
        if hasattr(alarm, 'timestamp'):
            ts = alarm.timestamp
            if isinstance(ts, datetime):
                return ts
        elif hasattr(alarm, 'raised_at'):
            ts = alarm.raised_at
            if isinstance(ts, datetime):
                return ts
        elif isinstance(alarm, dict):
            ts_str = alarm.get('timestamp', alarm.get('raised_at', alarm.get('raisedAt', '')))
            if isinstance(ts_str, datetime):
                return ts_str
            elif isinstance(ts_str, str):
                try:
                    return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                except ValueError:
                    pass
        
        return datetime.now(timezone.utc)
