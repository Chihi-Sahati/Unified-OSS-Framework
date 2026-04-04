"""
Zero Trust Module for Unified OSS Framework Security Management.

This module implements Zero Trust Architecture (ZTA) following NIST SP 800-207
guidelines, providing continuous verification, anomaly detection, and adaptive
access control for the FCAPS Security Management domain.

Features:
    - Zero Trust authorization decision engine (NIST SP 800-207 compliant)
    - Multi-factor anomaly scoring:
        * Time-based anomaly detection
        * Location-based anomaly detection
        * Behavior-based anomaly detection
        * Resource-based anomaly detection
    - Rule-based access control with priority ordering
    - MFA challenge for high anomaly scores
    - Continuous verification capabilities

Example:
    >>> from unified_oss.fcaps.security.zero_trust import (
    ...     ZeroTrustEngine, AnomalyScorer, AccessDecision
    ... )
    >>> engine = ZeroTrustEngine()
    >>> decision = await engine.evaluate_access(
    ...     user_id="user123",
    ...     resource="router-01",
    ...     action="configure",
    ...     context={"ip_address": "192.168.1.100"}
    ... )
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, time as dt_time, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger(__name__)


class TrustLevel(Enum):
    """Trust level enumeration for Zero Trust.

    Attributes:
        NONE: No trust - access denied.
        LOW: Low trust - requires MFA and monitoring.
        MEDIUM: Medium trust - standard access with logging.
        HIGH: High trust - elevated access with minimal friction.
        FULL: Full trust - administrative access.
    """

    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    FULL = 4


class AccessDecisionResult(Enum):
    """Access decision result enumeration.

    Attributes:
        ALLOW: Access allowed.
        DENY: Access denied.
        CHALLENGE: Requires MFA challenge.
        STEP_UP: Requires step-up authentication.
        MONITORED: Allowed with enhanced monitoring.
    """

    ALLOW = "allow"
    DENY = "deny"
    CHALLENGE = "challenge"
    STEP_UP = "step_up"
    MONITORED = "monitored"


class AnomalyType(Enum):
    """Anomaly type enumeration.

    Attributes:
        TIME_BASED: Anomaly based on access time.
        LOCATION_BASED: Anomaly based on access location.
        BEHAVIOR_BASED: Anomaly based on user behavior.
        RESOURCE_BASED: Anomaly based on resource sensitivity.
        DEVICE_BASED: Anomaly based on device trust.
        VELOCITY_BASED: Anomaly based on access frequency.
    """

    TIME_BASED = "time_based"
    LOCATION_BASED = "location_based"
    BEHAVIOR_BASED = "behavior_based"
    RESOURCE_BASED = "resource_based"
    DEVICE_BASED = "device_based"
    VELOCITY_BASED = "velocity_based"


class AccessRulePriority(Enum):
    """Priority levels for access rules.

    Attributes:
        CRITICAL: Critical rules that override all others.
        HIGH: High priority rules.
        MEDIUM: Medium priority rules.
        LOW: Low priority rules.
        DEFAULT: Default rules with lowest priority.
    """

    CRITICAL = 100
    HIGH = 75
    MEDIUM = 50
    LOW = 25
    DEFAULT = 0


@dataclass
class AnomalyScore:
    """Anomaly score with breakdown by type.

    Attributes:
        total_score: Combined anomaly score (0.0 to 1.0).
        time_based: Time-based anomaly component.
        location_based: Location-based anomaly component.
        behavior_based: Behavior-based anomaly component.
        resource_based: Resource-based anomaly component.
        device_based: Device-based anomaly component.
        velocity_based: Velocity-based anomaly component.
        contributing_factors: List of contributing anomaly factors.
        calculated_at: Timestamp when score was calculated.
    """

    total_score: float = 0.0
    time_based: float = 0.0
    location_based: float = 0.0
    behavior_based: float = 0.0
    resource_based: float = 0.0
    device_based: float = 0.0
    velocity_based: float = 0.0
    contributing_factors: List[str] = field(default_factory=list)
    calculated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def is_high_risk(self, threshold: float = 0.5) -> bool:
        """Check if anomaly score indicates high risk.

        Args:
            threshold: Risk threshold (default: 0.5).

        Returns:
            True if total score exceeds threshold.
        """
        return self.total_score >= threshold

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary representation of the anomaly score.
        """
        return {
            "total_score": round(self.total_score, 4),
            "components": {
                "time_based": round(self.time_based, 4),
                "location_based": round(self.location_based, 4),
                "behavior_based": round(self.behavior_based, 4),
                "resource_based": round(self.resource_based, 4),
                "device_based": round(self.device_based, 4),
                "velocity_based": round(self.velocity_based, 4),
            },
            "contributing_factors": self.contributing_factors,
            "calculated_at": self.calculated_at.isoformat(),
            "high_risk": self.is_high_risk(),
        }


@dataclass
class UserBehaviorProfile:
    """User behavior profile for anomaly detection.

    Attributes:
        user_id: User identifier.
        typical_access_times: List of typical access time ranges.
        typical_ip_ranges: List of typical IP ranges.
        typical_resources: Set of typically accessed resources.
        typical_actions: Set of typically performed actions.
        device_fingerprints: Set of known device fingerprints.
        access_patterns: Historical access patterns.
        last_updated: Profile last update timestamp.
    """

    user_id: str
    typical_access_times: List[Tuple[dt_time, dt_time]] = field(default_factory=list)
    typical_ip_ranges: List[str] = field(default_factory=list)
    typical_resources: Set[str] = field(default_factory=set)
    typical_actions: Set[str] = field(default_factory=set)
    device_fingerprints: Set[str] = field(default_factory=set)
    access_patterns: Dict[str, int] = field(default_factory=dict)
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def update_access_pattern(self, resource: str, action: str) -> None:
        """Update access pattern statistics.

        Args:
            resource: Accessed resource.
            action: Performed action.
        """
        key = f"{resource}:{action}"
        self.access_patterns[key] = self.access_patterns.get(key, 0) + 1
        self.typical_resources.add(resource)
        self.typical_actions.add(action)
        self.last_updated = datetime.now(timezone.utc)


@dataclass
class AccessRule:
    """Access rule for Zero Trust decision engine.

    Attributes:
        rule_id: Unique rule identifier.
        name: Human-readable rule name.
        description: Rule description.
        priority: Rule priority (higher = evaluated first).
        conditions: Conditions that must be met.
        effect: Rule effect (allow, deny, challenge, etc.).
        trust_level_required: Minimum trust level required.
        anomaly_threshold: Maximum allowed anomaly score.
        mfa_required: Whether MFA is required.
        enabled: Whether the rule is enabled.
    """

    rule_id: str
    name: str
    description: str = ""
    priority: int = 0
    conditions: Dict[str, Any] = field(default_factory=dict)
    effect: AccessDecisionResult = AccessDecisionResult.ALLOW
    trust_level_required: TrustLevel = TrustLevel.LOW
    anomaly_threshold: float = 0.7
    mfa_required: bool = False
    enabled: bool = True

    def matches(self, context: Dict[str, Any]) -> bool:
        """Check if rule matches the given context.

        Args:
            context: Request context.

        Returns:
            True if rule matches, False otherwise.
        """
        if not self.enabled:
            return False

        for key, expected_value in self.conditions.items():
            actual_value = context.get(key)

            if actual_value is None:
                return False

            # Handle list conditions (any match)
            if isinstance(expected_value, list):
                if actual_value not in expected_value:
                    return False
            # Handle dict conditions (nested matching)
            elif isinstance(expected_value, dict):
                if not isinstance(actual_value, dict):
                    return False
                for sub_key, sub_value in expected_value.items():
                    if actual_value.get(sub_key) != sub_value:
                        return False
            # Handle string pattern matching
            elif isinstance(expected_value, str) and expected_value.startswith("~"):
                import re
                pattern = expected_value[1:]
                if not re.match(pattern, str(actual_value)):
                    return False
            # Handle exact match
            elif actual_value != expected_value:
                return False

        return True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary representation of the rule.
        """
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "priority": self.priority,
            "conditions": self.conditions,
            "effect": self.effect.value,
            "trust_level_required": self.trust_level_required.value,
            "anomaly_threshold": self.anomaly_threshold,
            "mfa_required": self.mfa_required,
            "enabled": self.enabled,
        }


@dataclass
class AccessDecision:
    """Zero Trust access decision.

    Attributes:
        decision_id: Unique decision identifier.
        user_id: User identifier.
        resource: Resource being accessed.
        action: Action being performed.
        result: Access decision result.
        trust_level: Calculated trust level.
        anomaly_score: Anomaly score details.
        matched_rules: List of matched rule IDs.
        mfa_required: Whether MFA is required.
        mfa_challenge_id: MFA challenge ID if applicable.
        conditions: Additional conditions for access.
        monitoring_level: Monitoring level for the access.
        expires_at: Decision expiration timestamp.
        created_at: Decision creation timestamp.
        reason: Reason for the decision.
    """

    decision_id: str
    user_id: str
    resource: str
    action: str
    result: AccessDecisionResult
    trust_level: TrustLevel = TrustLevel.LOW
    anomaly_score: Optional[AnomalyScore] = None
    matched_rules: List[str] = field(default_factory=list)
    mfa_required: bool = False
    mfa_challenge_id: Optional[str] = None
    conditions: Dict[str, Any] = field(default_factory=dict)
    monitoring_level: str = "standard"
    expires_at: Optional[datetime] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    reason: str = ""

    def is_valid(self) -> bool:
        """Check if decision is still valid.

        Returns:
            True if decision is valid, False if expired.
        """
        if self.expires_at is None:
            return True
        return datetime.now(timezone.utc) < self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary representation of the decision.
        """
        return {
            "decision_id": self.decision_id,
            "user_id": self.user_id,
            "resource": self.resource,
            "action": self.action,
            "result": self.result.value,
            "trust_level": self.trust_level.value,
            "anomaly_score": self.anomaly_score.to_dict() if self.anomaly_score else None,
            "matched_rules": self.matched_rules,
            "mfa_required": self.mfa_required,
            "mfa_challenge_id": self.mfa_challenge_id,
            "conditions": self.conditions,
            "monitoring_level": self.monitoring_level,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "created_at": self.created_at.isoformat(),
            "reason": self.reason,
        }


@dataclass
class MFAChallenge:
    """MFA challenge for Zero Trust verification.

    Attributes:
        challenge_id: Unique challenge identifier.
        user_id: User identifier.
        challenge_type: Type of MFA challenge.
        code: Challenge code (for SMS, EMAIL).
        created_at: Challenge creation timestamp.
        expires_at: Challenge expiration timestamp.
        verified: Whether challenge has been verified.
        attempts: Number of verification attempts.
        max_attempts: Maximum allowed attempts.
        context: Challenge context for verification.
    """

    challenge_id: str
    user_id: str
    challenge_type: str = "totp"
    code: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc) + timedelta(minutes=5)
    )
    verified: bool = False
    attempts: int = 0
    max_attempts: int = 3
    context: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        """Check if challenge has expired.

        Returns:
            True if expired, False otherwise.
        """
        return datetime.now(timezone.utc) > self.expires_at

    def can_attempt(self) -> bool:
        """Check if more attempts are allowed.

        Returns:
            True if attempts remaining, False otherwise.
        """
        return self.attempts < self.max_attempts


class AnomalyScorer:
    """Anomaly score calculator for Zero Trust.

    This class calculates multi-factor anomaly scores based on various
    signals including time, location, behavior, resource sensitivity,
    device trust, and access velocity.

    Attributes:
        weights: Weights for different anomaly components.
        thresholds: Thresholds for anomaly detection.
    """

    def __init__(
        self,
        weights: Optional[Dict[AnomalyType, float]] = None,
        thresholds: Optional[Dict[str, float]] = None,
    ) -> None:
        """Initialize the anomaly scorer.

        Args:
            weights: Custom weights for anomaly components.
            thresholds: Custom thresholds for anomaly detection.
        """
        # Default weights for anomaly components
        self._weights = weights or {
            AnomalyType.TIME_BASED: 0.15,
            AnomalyType.LOCATION_BASED: 0.25,
            AnomalyType.BEHAVIOR_BASED: 0.20,
            AnomalyType.RESOURCE_BASED: 0.15,
            AnomalyType.DEVICE_BASED: 0.15,
            AnomalyType.VELOCITY_BASED: 0.10,
        }

        # Default thresholds
        self._thresholds = thresholds or {
            "unusual_hour_start": 6,  # Before 6 AM
            "unusual_hour_end": 22,  # After 10 PM
            "max_velocity_per_minute": 10,  # Max requests per minute
            "max_velocity_per_hour": 100,  # Max requests per hour
            "sensitive_resource_keywords": ["admin", "config", "security", "credential"],
        }

        self._user_profiles: Dict[str, UserBehaviorProfile] = {}
        self._access_history: Dict[str, List[datetime]] = {}
        self._lock = asyncio.Lock()

        logger.info("AnomalyScorer initialized")

    async def calculate_anomaly_score(
        self,
        user_id: str,
        resource: str,
        action: str,
        context: Dict[str, Any],
    ) -> AnomalyScore:
        """Calculate comprehensive anomaly score.

        Args:
            user_id: User identifier.
            resource: Resource being accessed.
            action: Action being performed.
            context: Request context including IP, device, etc.

        Returns:
            AnomalyScore with detailed breakdown.
        """
        async with self._lock:
            # Get or create user profile
            profile = self._user_profiles.get(user_id)
            if profile is None:
                profile = UserBehaviorProfile(user_id=user_id)
                self._user_profiles[user_id] = profile

            score = AnomalyScore()
            factors: List[str] = []

            # Calculate time-based anomaly
            time_score = await self._calculate_time_anomaly(context)
            score.time_based = time_score
            if time_score > 0.3:
                factors.append(f"Unusual access time (score: {time_score:.2f})")

            # Calculate location-based anomaly
            location_score = await self._calculate_location_anomaly(
                user_id, context, profile
            )
            score.location_based = location_score
            if location_score > 0.3:
                factors.append(f"Unusual access location (score: {location_score:.2f})")

            # Calculate behavior-based anomaly
            behavior_score = await self._calculate_behavior_anomaly(
                user_id, resource, action, profile
            )
            score.behavior_based = behavior_score
            if behavior_score > 0.3:
                factors.append(f"Unusual behavior pattern (score: {behavior_score:.2f})")

            # Calculate resource-based anomaly
            resource_score = await self._calculate_resource_anomaly(resource, action)
            score.resource_based = resource_score
            if resource_score > 0.3:
                factors.append(f"Sensitive resource access (score: {resource_score:.2f})")

            # Calculate device-based anomaly
            device_score = await self._calculate_device_anomaly(user_id, context, profile)
            score.device_based = device_score
            if device_score > 0.3:
                factors.append(f"Unrecognized device (score: {device_score:.2f})")

            # Calculate velocity-based anomaly
            velocity_score = await self._calculate_velocity_anomaly(user_id)
            score.velocity_based = velocity_score
            if velocity_score > 0.3:
                factors.append(f"High access velocity (score: {velocity_score:.2f})")

            # Calculate weighted total score
            total = 0.0
            for anomaly_type, weight in self._weights.items():
                component_score = getattr(score, f"{anomaly_type.value}", 0.0)
                total += component_score * weight

            score.total_score = min(total, 1.0)
            score.contributing_factors = factors

            # Update access history
            await self._record_access(user_id, resource, action)

            logger.debug(
                f"Anomaly score for user {user_id}: {score.total_score:.4f} "
                f"(factors: {len(factors)})"
            )

            return score

    async def _calculate_time_anomaly(self, context: Dict[str, Any]) -> float:
        """Calculate time-based anomaly score.

        Checks if the access is happening at unusual hours.

        Args:
            context: Request context.

        Returns:
            Time-based anomaly score (0.0 to 1.0).
        """
        access_time = context.get("access_time", datetime.now(timezone.utc))

        if isinstance(access_time, str):
            access_time = datetime.fromisoformat(access_time.replace("Z", "+00:00"))

        hour = access_time.hour

        # Check if outside normal business hours
        unusual_start = self._thresholds["unusual_hour_start"]
        unusual_end = self._thresholds["unusual_hour_end"]

        if hour < unusual_start or hour >= unusual_end:
            # Higher score for more unusual times
            if hour < 3 or hour >= 24:
                return 0.8  # Very unusual (late night/early morning)
            else:
                return 0.4  # Somewhat unusual (early morning/late evening)

        # Check if it's a weekend
        if access_time.weekday() >= 5:  # Saturday or Sunday
            return 0.2

        return 0.0

    async def _calculate_location_anomaly(
        self,
        user_id: str,
        context: Dict[str, Any],
        profile: UserBehaviorProfile,
    ) -> float:
        """Calculate location-based anomaly score.

        Checks if the access is from an unusual IP address or region.

        Args:
            user_id: User identifier.
            context: Request context.
            profile: User behavior profile.

        Returns:
            Location-based anomaly score (0.0 to 1.0).
        """
        ip_address = context.get("ip_address")
        if not ip_address:
            return 0.3  # No IP provided is somewhat suspicious

        # Check if IP is in known ranges
        if profile.typical_ip_ranges:
            for ip_range in profile.typical_ip_ranges:
                try:
                    if "/" in ip_range:
                        network = ipaddress.ip_network(ip_range, strict=False)
                        ip = ipaddress.ip_address(ip_address)
                        if ip in network:
                            return 0.0  # Known IP range
                except ValueError:
                    continue

        # Check if IP is in private range (generally more trusted)
        try:
            ip = ipaddress.ip_address(ip_address)
            if ip.is_private:
                return 0.2  # Private IP, somewhat trusted
            elif ip.is_loopback:
                return 0.1  # Localhost, mostly trusted
            else:
                return 0.6  # Unknown public IP
        except ValueError:
            return 0.7  # Invalid IP format

    async def _calculate_behavior_anomaly(
        self,
        user_id: str,
        resource: str,
        action: str,
        profile: UserBehaviorProfile,
    ) -> float:
        """Calculate behavior-based anomaly score.

        Checks if the access pattern is unusual for this user.

        Args:
            user_id: User identifier.
            resource: Resource being accessed.
            action: Action being performed.
            profile: User behavior profile.

        Returns:
            Behavior-based anomaly score (0.0 to 1.0).
        """
        if not profile.typical_resources:
            # New user, no baseline yet
            return 0.3

        score = 0.0

        # Check if resource is typical for this user
        if resource not in profile.typical_resources:
            score += 0.4

        # Check if action is typical for this user
        action_key = f"{resource}:{action}"
        if action_key not in profile.access_patterns:
            score += 0.3
        else:
            # Reduce score based on frequency
            frequency = profile.access_patterns.get(action_key, 0)
            if frequency > 10:
                score -= 0.2

        return min(max(score, 0.0), 1.0)

    async def _calculate_resource_anomaly(
        self,
        resource: str,
        action: str,
    ) -> float:
        """Calculate resource-based anomaly score.

        Checks if the resource is sensitive or the action is privileged.

        Args:
            resource: Resource being accessed.
            action: Action being performed.

        Returns:
            Resource-based anomaly score (0.0 to 1.0).
        """
        resource_lower = resource.lower()
        score = 0.0

        sensitive_keywords = self._thresholds["sensitive_resource_keywords"]

        # Check for sensitive resource keywords
        for keyword in sensitive_keywords:
            if keyword in resource_lower:
                score += 0.3
                break

        # Check for sensitive actions
        sensitive_actions = ["delete", "admin", "configure", "execute"]
        if action.lower() in sensitive_actions:
            score += 0.3

        # Check for production environment
        if "prod" in resource_lower or "live" in resource_lower:
            score += 0.2

        return min(score, 1.0)

    async def _calculate_device_anomaly(
        self,
        user_id: str,
        context: Dict[str, Any],
        profile: UserBehaviorProfile,
    ) -> float:
        """Calculate device-based anomaly score.

        Checks if the device is recognized and trusted.

        Args:
            user_id: User identifier.
            context: Request context.
            profile: User behavior profile.

        Returns:
            Device-based anomaly score (0.0 to 1.0).
        """
        device_fingerprint = context.get("device_fingerprint")
        user_agent = context.get("user_agent", "")

        if not device_fingerprint:
            return 0.4  # No device fingerprint provided

        if device_fingerprint in profile.device_fingerprints:
            return 0.0  # Known device

        # Check user agent for suspicious patterns
        suspicious_agents = ["bot", "crawler", "script", "curl", "wget"]
        user_agent_lower = user_agent.lower()
        for agent in suspicious_agents:
            if agent in user_agent_lower:
                return 0.7  # Suspicious user agent

        return 0.5  # Unknown device

    async def _calculate_velocity_anomaly(self, user_id: str) -> float:
        """Calculate velocity-based anomaly score.

        Checks if the access frequency is unusually high.

        Args:
            user_id: User identifier.

        Returns:
            Velocity-based anomaly score (0.0 to 1.0).
        """
        now = datetime.now(timezone.utc)
        one_minute_ago = now - timedelta(minutes=1)
        one_hour_ago = now - timedelta(hours=1)

        history = self._access_history.get(user_id, [])

        # Count accesses in the last minute
        recent_minute = sum(1 for t in history if t > one_minute_ago)

        # Count accesses in the last hour
        recent_hour = sum(1 for t in history if t > one_hour_ago)

        score = 0.0

        # Check velocity thresholds
        if recent_minute > self._thresholds["max_velocity_per_minute"]:
            score += 0.6

        if recent_hour > self._thresholds["max_velocity_per_hour"]:
            score += 0.4

        return min(score, 1.0)

    async def _record_access(self, user_id: str, resource: str, action: str) -> None:
        """Record an access for velocity tracking.

        Args:
            user_id: User identifier.
            resource: Resource accessed.
            action: Action performed.
        """
        now = datetime.now(timezone.utc)

        if user_id not in self._access_history:
            self._access_history[user_id] = []

        self._access_history[user_id].append(now)

        # Update user profile
        if user_id in self._user_profiles:
            self._user_profiles[user_id].update_access_pattern(resource, action)

        # Clean up old history (keep last hour)
        one_hour_ago = now - timedelta(hours=1)
        self._access_history[user_id] = [
            t for t in self._access_history[user_id] if t > one_hour_ago
        ]

    def update_user_profile(
        self,
        user_id: str,
        typical_ip_ranges: Optional[List[str]] = None,
        typical_access_times: Optional[List[Tuple[dt_time, dt_time]]] = None,
        device_fingerprints: Optional[Set[str]] = None,
    ) -> None:
        """Update user behavior profile.

        Args:
            user_id: User identifier.
            typical_ip_ranges: Typical IP ranges for the user.
            typical_access_times: Typical access time ranges.
            device_fingerprints: Known device fingerprints.
        """
        if user_id not in self._user_profiles:
            self._user_profiles[user_id] = UserBehaviorProfile(user_id=user_id)

        profile = self._user_profiles[user_id]

        if typical_ip_ranges:
            profile.typical_ip_ranges.extend(typical_ip_ranges)

        if typical_access_times:
            profile.typical_access_times.extend(typical_access_times)

        if device_fingerprints:
            profile.device_fingerprints.update(device_fingerprints)

        profile.last_updated = datetime.now(timezone.utc)


class ZeroTrustEngine:
    """Zero Trust authorization decision engine.

    This class implements Zero Trust Architecture (ZTA) following NIST SP 800-207,
    providing continuous verification, adaptive access control, and MFA challenges.

    Attributes:
        anomaly_scorer: Anomaly score calculator.
        rules: Access rules for decision evaluation.
        mfa_threshold: Threshold for MFA challenge requirement.
        decision_ttl: Time-to-live for access decisions.
    """

    def __init__(
        self,
        anomaly_scorer: Optional[AnomalyScorer] = None,
        mfa_threshold: float = 0.5,
        decision_ttl: timedelta = timedelta(minutes=15),
        deny_threshold: float = 0.8,
    ) -> None:
        """Initialize the Zero Trust engine.

        Args:
            anomaly_scorer: Anomaly score calculator (created if not provided).
            mfa_threshold: Anomaly score threshold for MFA requirement.
            decision_ttl: Time-to-live for access decisions.
            deny_threshold: Anomaly score threshold for automatic denial.
        """
        self.anomaly_scorer = anomaly_scorer or AnomalyScorer()
        self.mfa_threshold = mfa_threshold
        self.decision_ttl = decision_ttl
        self.deny_threshold = deny_threshold

        self._rules: Dict[str, AccessRule] = {}
        self._decisions: Dict[str, AccessDecision] = {}
        self._mfa_challenges: Dict[str, MFAChallenge] = {}
        self._trust_levels: Dict[str, TrustLevel] = {}
        self._lock = asyncio.Lock()

        # Initialize default rules
        self._initialize_default_rules()

        logger.info(
            f"ZeroTrustEngine initialized (MFA threshold: {mfa_threshold}, "
            f"deny threshold: {deny_threshold})"
        )

    def _initialize_default_rules(self) -> None:
        """Initialize default access rules."""
        # Rule: Admin resources require high trust
        self._rules["admin_access"] = AccessRule(
            rule_id="admin_access",
            name="Admin Access Control",
            description="Admin resources require high trust level",
            priority=AccessRulePriority.CRITICAL.value,
            conditions={"resource": "~.*admin.*"},
            effect=AccessDecisionResult.CHALLENGE,
            trust_level_required=TrustLevel.HIGH,
            anomaly_threshold=0.3,
            mfa_required=True,
        )

        # Rule: Configuration changes require MFA
        self._rules["config_change"] = AccessRule(
            rule_id="config_change",
            name="Configuration Change Control",
            description="Configuration changes require MFA verification",
            priority=AccessRulePriority.HIGH.value,
            conditions={"action": ["configure", "update", "delete"]},
            effect=AccessDecisionResult.CHALLENGE,
            trust_level_required=TrustLevel.MEDIUM,
            anomaly_threshold=0.4,
            mfa_required=True,
        )

        # Rule: Deny access from unknown IPs to sensitive resources
        self._rules["sensitive_deny"] = AccessRule(
            rule_id="sensitive_deny",
            name="Sensitive Resource Protection",
            description="Deny access to sensitive resources from unknown locations",
            priority=AccessRulePriority.HIGH.value,
            conditions={"resource": "~.*security.*|.*credential.*"},
            effect=AccessDecisionResult.DENY,
            trust_level_required=TrustLevel.FULL,
            anomaly_threshold=0.0,
            mfa_required=True,
        )

        # Rule: Default allow for normal operations
        self._rules["default_allow"] = AccessRule(
            rule_id="default_allow",
            name="Default Access",
            description="Default allow rule for standard operations",
            priority=AccessRulePriority.DEFAULT.value,
            conditions={},
            effect=AccessDecisionResult.ALLOW,
            trust_level_required=TrustLevel.LOW,
            anomaly_threshold=0.7,
            mfa_required=False,
        )

    async def evaluate_access(
        self,
        user_id: str,
        resource: str,
        action: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> AccessDecision:
        """Evaluate access request using Zero Trust principles.

        This method implements the Zero Trust decision engine by:
        1. Calculating anomaly scores
        2. Evaluating access rules in priority order
        3. Determining trust level
        4. Requiring MFA for high-risk access

        Args:
            user_id: User identifier.
            resource: Resource being accessed.
            action: Action being performed.
            context: Request context (IP, device, time, etc.).

        Returns:
            AccessDecision with the evaluation result.
        """
        ctx = context or {}
        ctx["user_id"] = user_id
        ctx["resource"] = resource
        ctx["action"] = action

        # Calculate anomaly score
        anomaly_score = await self.anomaly_scorer.calculate_anomaly_score(
            user_id=user_id,
            resource=resource,
            action=action,
            context=ctx,
        )

        # Get user's current trust level
        trust_level = self._trust_levels.get(user_id, TrustLevel.MEDIUM)

        # Sort rules by priority (highest first)
        sorted_rules = sorted(
            self._rules.values(),
            key=lambda r: r.priority,
            reverse=True,
        )

        matched_rules: List[str] = []
        result = AccessDecisionResult.ALLOW
        mfa_required = False
        reason = "Access allowed by default policy"

        # Evaluate rules in priority order
        for rule in sorted_rules:
            if rule.matches(ctx):
                matched_rules.append(rule.rule_id)

                # Check trust level requirement
                if trust_level.value < rule.trust_level_required.value:
                    result = AccessDecisionResult.STEP_UP
                    reason = f"Insufficient trust level (required: {rule.trust_level_required.name})"
                    break

                # Check anomaly threshold
                if anomaly_score.total_score > rule.anomaly_threshold:
                    if rule.effect == AccessDecisionResult.ALLOW:
                        result = AccessDecisionResult.MONITORED
                        reason = f"High anomaly score ({anomaly_score.total_score:.2f}), enhanced monitoring"
                    else:
                        result = rule.effect
                        reason = f"Anomaly score ({anomaly_score.total_score:.2f}) exceeds threshold"
                    break

                # Apply rule effect
                result = rule.effect
                mfa_required = rule.mfa_required
                reason = f"Matched rule: {rule.name}"

                # Deny rules take immediate effect
                if result == AccessDecisionResult.DENY:
                    break

        # Apply global thresholds
        if anomaly_score.total_score >= self.deny_threshold:
            result = AccessDecisionResult.DENY
            reason = f"Anomaly score ({anomaly_score.total_score:.2f}) exceeds deny threshold"
            mfa_required = False  # No MFA for denied access
        elif anomaly_score.total_score >= self.mfa_threshold:
            if result == AccessDecisionResult.ALLOW:
                result = AccessDecisionResult.CHALLENGE
                mfa_required = True
                reason = f"High anomaly score ({anomaly_score.total_score:.2f}) requires MFA"

        # Create decision
        decision_id = secrets.token_urlsafe(16)

        decision = AccessDecision(
            decision_id=decision_id,
            user_id=user_id,
            resource=resource,
            action=action,
            result=result,
            trust_level=trust_level,
            anomaly_score=anomaly_score,
            matched_rules=matched_rules,
            mfa_required=mfa_required,
            expires_at=datetime.now(timezone.utc) + self.decision_ttl,
            reason=reason,
        )

        # Store decision
        async with self._lock:
            self._decisions[decision_id] = decision

        # Create MFA challenge if required
        if mfa_required and result == AccessDecisionResult.CHALLENGE:
            challenge = await self.challenge_mfa(user_id, decision_id)
            decision.mfa_challenge_id = challenge.challenge_id

        logger.info(
            f"Access decision for user {user_id}: {result.value} "
            f"(anomaly: {anomaly_score.total_score:.2f}, rules: {len(matched_rules)})"
        )

        return decision

    async def calculate_anomaly_score(
        self,
        user_id: str,
        resource: str,
        action: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> AnomalyScore:
        """Calculate anomaly score for an access request.

        Args:
            user_id: User identifier.
            resource: Resource being accessed.
            action: Action being performed.
            context: Request context.

        Returns:
            AnomalyScore with detailed breakdown.
        """
        return await self.anomaly_scorer.calculate_anomaly_score(
            user_id=user_id,
            resource=resource,
            action=action,
            context=context or {},
        )

    async def get_decision(self, decision_id: str) -> Optional[AccessDecision]:
        """Get an existing access decision.

        Args:
            decision_id: Decision identifier.

        Returns:
            AccessDecision if found and valid, None otherwise.
        """
        decision = self._decisions.get(decision_id)

        if decision is None or not decision.is_valid():
            return None

        return decision

    async def challenge_mfa(
        self,
        user_id: str,
        decision_id: Optional[str] = None,
        challenge_type: str = "totp",
    ) -> MFAChallenge:
        """Create an MFA challenge for a user.

        Args:
            user_id: User identifier.
            decision_id: Associated decision ID (optional).
            challenge_type: Type of MFA challenge.

        Returns:
            Created MFAChallenge.
        """
        challenge_id = secrets.token_urlsafe(16)
        code = None

        # Generate code for SMS/Email challenges
        if challenge_type in ("sms", "email"):
            code = "".join(secrets.choice("0123456789") for _ in range(6))

        challenge = MFAChallenge(
            challenge_id=challenge_id,
            user_id=user_id,
            challenge_type=challenge_type,
            code=code,
            context={"decision_id": decision_id},
        )

        async with self._lock:
            self._mfa_challenges[challenge_id] = challenge

        logger.info(f"Created MFA challenge {challenge_id} for user {user_id}")

        # In production, send SMS/Email here
        if code:
            logger.debug(f"MFA code for user {user_id}: {code}")

        return challenge

    async def verify_mfa(
        self,
        challenge_id: str,
        code: str,
    ) -> Tuple[bool, Optional[AccessDecision]]:
        """Verify an MFA challenge.

        Args:
            challenge_id: Challenge identifier.
            code: Verification code.

        Returns:
            Tuple of (success, updated_decision).
        """
        async with self._lock:
            challenge = self._mfa_challenges.get(challenge_id)

            if challenge is None:
                logger.warning(f"MFA challenge {challenge_id} not found")
                return False, None

            if challenge.is_expired():
                del self._mfa_challenges[challenge_id]
                logger.warning(f"MFA challenge {challenge_id} has expired")
                return False, None

            if not challenge.can_attempt():
                del self._mfa_challenges[challenge_id]
                logger.warning(f"MFA challenge {challenge_id} max attempts exceeded")
                return False, None

            challenge.attempts += 1

            # Verify code
            if challenge.code and code == challenge.code:
                challenge.verified = True
                del self._mfa_challenges[challenge_id]

                # Update associated decision if exists
                decision_id = challenge.context.get("decision_id")
                if decision_id and decision_id in self._decisions:
                    decision = self._decisions[decision_id]
                    decision.result = AccessDecisionResult.ALLOW
                    decision.mfa_required = False
                    decision.reason = "Access granted after MFA verification"
                    logger.info(f"MFA verified for decision {decision_id}")
                    return True, decision

                # Elevate trust level
                self._trust_levels[challenge.user_id] = TrustLevel.HIGH

                logger.info(f"MFA challenge {challenge_id} verified for user {challenge.user_id}")
                return True, None

            logger.warning(
                f"MFA verification failed for challenge {challenge_id} "
                f"(attempt {challenge.attempts}/{challenge.max_attempts})"
            )
            return False, None

    def add_rule(self, rule: AccessRule) -> None:
        """Add an access rule to the engine.

        Args:
            rule: Access rule to add.
        """
        self._rules[rule.rule_id] = rule
        logger.info(f"Added access rule: {rule.rule_id}")

    def remove_rule(self, rule_id: str) -> bool:
        """Remove an access rule from the engine.

        Args:
            rule_id: Rule identifier to remove.

        Returns:
            True if removed, False if not found.
        """
        if rule_id in self._rules:
            del self._rules[rule_id]
            logger.info(f"Removed access rule: {rule_id}")
            return True
        return False

    def set_trust_level(self, user_id: str, level: TrustLevel) -> None:
        """Set trust level for a user.

        Args:
            user_id: User identifier.
            level: Trust level to set.
        """
        self._trust_levels[user_id] = level
        logger.info(f"Set trust level for user {user_id} to {level.name}")

    def get_trust_level(self, user_id: str) -> TrustLevel:
        """Get trust level for a user.

        Args:
            user_id: User identifier.

        Returns:
            Current trust level.
        """
        return self._trust_levels.get(user_id, TrustLevel.MEDIUM)

    async def continuous_verify(
        self,
        user_id: str,
        session_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, Optional[AccessDecision]]:
        """Perform continuous verification for an active session.

        This method is called periodically to verify that the user's
        access should continue based on current conditions.

        Args:
            user_id: User identifier.
            session_id: Session identifier.
            context: Current request context.

        Returns:
            Tuple of (continue_session, access_decision).
        """
        ctx = context or {}
        ctx["session_id"] = session_id

        # Calculate current anomaly score
        anomaly_score = await self.anomaly_scorer.calculate_anomaly_score(
            user_id=user_id,
            resource="session",
            action="continue",
            context=ctx,
        )

        # Check if session should be terminated
        if anomaly_score.total_score >= self.deny_threshold:
            decision = AccessDecision(
                decision_id=secrets.token_urlsafe(16),
                user_id=user_id,
                resource="session",
                action="continue",
                result=AccessDecisionResult.DENY,
                trust_level=self.get_trust_level(user_id),
                anomaly_score=anomaly_score,
                reason="Session terminated due to high anomaly score",
            )

            # Downgrade trust level
            self._trust_levels[user_id] = TrustLevel.LOW

            logger.warning(
                f"Session {session_id} terminated for user {user_id} "
                f"due to anomaly score: {anomaly_score.total_score:.2f}"
            )

            return False, decision

        # Check if step-up authentication is needed
        if anomaly_score.total_score >= self.mfa_threshold:
            decision = AccessDecision(
                decision_id=secrets.token_urlsafe(16),
                user_id=user_id,
                resource="session",
                action="continue",
                result=AccessDecisionResult.CHALLENGE,
                trust_level=self.get_trust_level(user_id),
                anomaly_score=anomaly_score,
                mfa_required=True,
                reason="Step-up authentication required",
            )

            return True, decision

        return True, None

    def update_user_behavior(
        self,
        user_id: str,
        typical_ip_ranges: Optional[List[str]] = None,
        typical_access_times: Optional[List[Tuple[dt_time, dt_time]]] = None,
        device_fingerprints: Optional[Set[str]] = None,
    ) -> None:
        """Update user behavior profile for anomaly detection.

        Args:
            user_id: User identifier.
            typical_ip_ranges: Typical IP ranges for the user.
            typical_access_times: Typical access time ranges.
            device_fingerprints: Known device fingerprints.
        """
        self.anomaly_scorer.update_user_profile(
            user_id=user_id,
            typical_ip_ranges=typical_ip_ranges,
            typical_access_times=typical_access_times,
            device_fingerprints=device_fingerprints,
        )

    def get_rules(self) -> List[AccessRule]:
        """Get all access rules.

        Returns:
            List of all access rules.
        """
        return list(self._rules.values())

    def get_pending_challenges(self, user_id: str) -> List[MFAChallenge]:
        """Get pending MFA challenges for a user.

        Args:
            user_id: User identifier.

        Returns:
            List of pending challenges.
        """
        return [
            c for c in self._mfa_challenges.values()
            if c.user_id == user_id and not c.verified and not c.is_expired()
        ]
