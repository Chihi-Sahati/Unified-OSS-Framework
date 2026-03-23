"""
Pydantic models for Unified OSS Framework REST API.
All request and response schemas for FCAPS operations.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, Generic, List, Optional, TypeVar
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


# =============================================================================
# Base Models
# =============================================================================

class BaseResponseModel(BaseModel):
    """Base model for all API responses."""
    model_config = ConfigDict(
        from_attributes=True,
        use_enum_values=True,
        populate_by_name=True,
    )


class PaginationParams(BaseModel):
    """Pagination parameters for list endpoints."""
    page: int = Field(default=1, ge=1, description="Page number")
    page_size: int = Field(default=20, ge=1, le=100, description="Items per page")


class PaginatedResponse(BaseResponseModel, Generic[TypeVar('T')]):
    """Generic paginated response wrapper."""
    items: List[Any] = Field(default_factory=list, description="List of items")
    total: int = Field(..., description="Total number of items")
    page: int = Field(..., description="Current page number")
    page_size: int = Field(..., description="Items per page")
    total_pages: int = Field(..., description="Total number of pages")
    has_next: bool = Field(..., description="Whether there is a next page")
    has_previous: bool = Field(..., description="Whether there is a previous page")


class ErrorResponse(BaseResponseModel):
    """Standard error response."""
    error_code: str = Field(..., description="Error code")
    error_message: str = Field(..., description="Human-readable error message")
    details: Optional[Dict[str, Any]] = Field(default=None, description="Additional error details")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Error timestamp")
    request_id: Optional[UUID] = Field(default=None, description="Request correlation ID")


class HealthStatus(BaseResponseModel):
    """Health check response."""
    status: str = Field(..., description="Service status")
    version: str = Field(..., description="API version")
    uptime_seconds: float = Field(..., description="Service uptime in seconds")
    components: Dict[str, str] = Field(default_factory=dict, description="Component health status")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# =============================================================================
# Alarm Schemas
# =============================================================================

class AlarmSeverity(str, Enum):
    """Alarm severity levels."""
    CRITICAL = "critical"
    MAJOR = "major"
    MINOR = "minor"
    WARNING = "warning"
    CLEARED = "cleared"
    INDETERMINATE = "indeterminate"


class AlarmStatus(str, Enum):
    """Alarm status values."""
    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    CLEARED = "cleared"
    SUPPRESSED = "suppressed"


class AlarmType(str, Enum):
    """Alarm types per ITU-T X.733."""
    COMMUNICATIONS_ALARM = "communicationsAlarm"
    EQUIPMENT_ALARM = "equipmentAlarm"
    PROCESSING_ERROR_ALARM = "processingErrorAlarm"
    QUALITY_OF_SERVICE_ALARM = "qualityOfServiceAlarm"
    ENVIRONMENTAL_ALARM = "environmentalAlarm"
    INTEGRITY_VIOLATION = "integrityViolation"
    OPERATIONAL_VIOLATION = "operationalViolation"
    PHYSICAL_VIOLATION = "physicalViolation"
    SECURITY_SERVICE_OR_MECHANISM_VIOLATION = "securityServiceOrMechanismViolation"
    TIME_DOMAIN_VIOLATION = "timeDomainViolation"


class AlarmFilter(BaseModel):
    """Filter parameters for alarm queries."""
    severity: Optional[List[AlarmSeverity]] = Field(default=None, description="Filter by severity")
    status: Optional[List[AlarmStatus]] = Field(default=None, description="Filter by status")
    alarm_type: Optional[List[AlarmType]] = Field(default=None, description="Filter by alarm type")
    ne_id: Optional[List[str]] = Field(default=None, description="Filter by network element ID")
    start_time: Optional[datetime] = Field(default=None, description="Filter alarms after this time")
    end_time: Optional[datetime] = Field(default=None, description="Filter alarms before this time")
    contains_text: Optional[str] = Field(default=None, description="Text search in alarm message")
    acknowledged_by: Optional[str] = Field(default=None, description="Filter by acknowledging user")


class AlarmResponse(BaseResponseModel):
    """Alarm data response."""
    alarm_id: UUID = Field(..., description="Unique alarm identifier")
    ne_id: str = Field(..., description="Network element identifier")
    ne_type: str = Field(..., description="Network element type")
    alarm_type: AlarmType = Field(..., description="Alarm type per ITU-T X.733")
    severity: AlarmSeverity = Field(..., description="Alarm severity")
    status: AlarmStatus = Field(..., description="Current alarm status")
    probable_cause: str = Field(..., description="Probable cause code")
    specific_problem: Optional[str] = Field(default=None, description="Specific problem description")
    alarm_text: str = Field(..., description="Detailed alarm message")
    raise_time: datetime = Field(..., description="Time alarm was raised")
    clear_time: Optional[datetime] = Field(default=None, description="Time alarm was cleared")
    acknowledge_time: Optional[datetime] = Field(default=None, description="Time alarm was acknowledged")
    acknowledge_user: Optional[str] = Field(default=None, description="User who acknowledged")
    service_affecting: bool = Field(default=False, description="Whether alarm affects service")
    additional_info: Dict[str, Any] = Field(default_factory=dict, description="Additional alarm info")
    correlated_alarms: List[UUID] = Field(default_factory=list, description="Correlated alarm IDs")
    root_cause: Optional[UUID] = Field(default=None, description="Root cause alarm ID")


class AlarmAcknowledgeRequest(BaseModel):
    """Request to acknowledge alarms."""
    alarm_ids: List[UUID] = Field(..., min_length=1, description="Alarm IDs to acknowledge")
    ack_user: str = Field(..., min_length=1, max_length=100, description="User acknowledging alarms")
    ack_note: Optional[str] = Field(default=None, max_length=500, description="Acknowledgment note")


class AlarmAcknowledgeResponse(BaseResponseModel):
    """Response from alarm acknowledgment."""
    acknowledged_count: int = Field(..., description="Number of alarms acknowledged")
    failed_count: int = Field(default=0, description="Number of alarms that failed")
    acknowledged_ids: List[UUID] = Field(default_factory=list, description="Successfully acknowledged IDs")
    failed_ids: List[Dict[str, Any]] = Field(default_factory=list, description="Failed IDs with reasons")


class AlarmClearRequest(BaseModel):
    """Request to clear alarms."""
    alarm_ids: List[UUID] = Field(..., min_length=1, description="Alarm IDs to clear")
    clear_user: str = Field(..., min_length=1, max_length=100, description="User clearing alarms")
    clear_reason: Optional[str] = Field(default=None, max_length=500, description="Clear reason")


class AlarmClearResponse(BaseResponseModel):
    """Response from alarm clearing."""
    cleared_count: int = Field(..., description="Number of alarms cleared")
    failed_count: int = Field(default=0, description="Number of alarms that failed")
    cleared_ids: List[UUID] = Field(default_factory=list, description="Successfully cleared IDs")
    failed_ids: List[Dict[str, Any]] = Field(default_factory=list, description="Failed IDs with reasons")


class AlarmStatistics(BaseResponseModel):
    """Alarm statistics summary."""
    total_active: int = Field(default=0, description="Total active alarms")
    critical_count: int = Field(default=0, description="Critical severity count")
    major_count: int = Field(default=0, description="Major severity count")
    minor_count: int = Field(default=0, description="Minor severity count")
    warning_count: int = Field(default=0, description="Warning severity count")
    service_affecting_count: int = Field(default=0, description="Service-affecting alarm count")
    acknowledged_count: int = Field(default=0, description="Acknowledged alarm count")
    last_24h_count: int = Field(default=0, description="Alarms in last 24 hours")
    by_ne_type: Dict[str, int] = Field(default_factory=dict, description="Counts by NE type")
    by_alarm_type: Dict[str, int] = Field(default_factory=dict, description="Counts by alarm type")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class AlarmWebSocketMessage(BaseResponseModel):
    """WebSocket message for real-time alarm notifications."""
    event_type: str = Field(..., description="Event type: created, updated, cleared")
    alarm: AlarmResponse = Field(..., description="Alarm data")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# =============================================================================
# Performance Schemas
# =============================================================================

class KPIType(str, Enum):
    """KPI measurement types."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"


class KPICategory(str, Enum):
    """KPI categories."""
    AVAILABILITY = "availability"
    THROUGHPUT = "throughput"
    LATENCY = "latency"
    ERROR_RATE = "error_rate"
    UTILIZATION = "utilization"
    QUALITY = "quality"


class KPIResponse(BaseResponseModel):
    """KPI data response."""
    kpi_id: UUID = Field(..., description="Unique KPI identifier")
    kpi_name: str = Field(..., description="KPI name")
    kpi_type: KPIType = Field(..., description="KPI measurement type")
    category: KPICategory = Field(..., description="KPI category")
    ne_id: str = Field(..., description="Network element identifier")
    ne_type: str = Field(..., description="Network element type")
    value: float = Field(..., description="Current KPI value")
    unit: str = Field(..., description="Measurement unit")
    threshold_warning: Optional[float] = Field(default=None, description="Warning threshold")
    threshold_critical: Optional[float] = Field(default=None, description="Critical threshold")
    timestamp: datetime = Field(..., description="Measurement timestamp")
    tags: Dict[str, str] = Field(default_factory=dict, description="Additional tags")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class KPIFilter(BaseModel):
    """Filter parameters for KPI queries."""
    kpi_name: Optional[List[str]] = Field(default=None, description="Filter by KPI name")
    category: Optional[List[KPICategory]] = Field(default=None, description="Filter by category")
    ne_id: Optional[List[str]] = Field(default=None, description="Filter by network element ID")
    ne_type: Optional[List[str]] = Field(default=None, description="Filter by NE type")
    start_time: Optional[datetime] = Field(default=None, description="Start time for range query")
    end_time: Optional[datetime] = Field(default=None, description="End time for range query")
    include_history: bool = Field(default=False, description="Include historical data")


class ThresholdComparison(str, Enum):
    """Threshold comparison operators."""
    GREATER_THAN = "gt"
    GREATER_THAN_OR_EQUAL = "gte"
    LESS_THAN = "lt"
    LESS_THAN_OR_EQUAL = "lte"
    EQUAL = "eq"
    NOT_EQUAL = "neq"


class ThresholdRequest(BaseModel):
    """Request to create or update a threshold."""
    kpi_name: str = Field(..., min_length=1, description="KPI name")
    ne_id: Optional[str] = Field(default=None, description="Network element ID (null for global)")
    warning_value: float = Field(..., description="Warning threshold value")
    critical_value: float = Field(..., description="Critical threshold value")
    comparison: ThresholdComparison = Field(default=ThresholdComparison.GREATER_THAN, description="Comparison operator")
    hysteresis: Optional[float] = Field(default=None, ge=0, le=100, description="Hysteresis percentage")
    description: Optional[str] = Field(default=None, max_length=500, description="Threshold description")
    enabled: bool = Field(default=True, description="Whether threshold is enabled")


class ThresholdResponse(BaseResponseModel):
    """Threshold configuration response."""
    threshold_id: UUID = Field(..., description="Unique threshold identifier")
    kpi_name: str = Field(..., description="KPI name")
    ne_id: Optional[str] = Field(default=None, description="Network element ID")
    warning_value: float = Field(..., description="Warning threshold value")
    critical_value: float = Field(..., description="Critical threshold value")
    comparison: ThresholdComparison = Field(..., description="Comparison operator")
    hysteresis: Optional[float] = Field(default=None, description="Hysteresis percentage")
    description: Optional[str] = Field(default=None, description="Threshold description")
    enabled: bool = Field(default=True, description="Whether threshold is enabled")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    created_by: str = Field(..., description="User who created the threshold")


class DashboardWidget(BaseResponseModel):
    """Dashboard widget configuration."""
    widget_id: UUID = Field(..., description="Widget identifier")
    widget_type: str = Field(..., description="Widget type (chart, gauge, table)")
    title: str = Field(..., description="Widget title")
    kpi_names: List[str] = Field(..., description="KPIs displayed in widget")
    ne_ids: Optional[List[str]] = Field(default=None, description="Network elements")
    time_range: str = Field(default="1h", description="Time range for data")
    refresh_interval: int = Field(default=30, description="Refresh interval in seconds")
    config: Dict[str, Any] = Field(default_factory=dict, description="Widget-specific config")


class PerformanceDashboard(BaseResponseModel):
    """Performance dashboard response."""
    dashboard_id: UUID = Field(..., description="Dashboard identifier")
    name: str = Field(..., description="Dashboard name")
    description: Optional[str] = Field(default=None, description="Dashboard description")
    widgets: List[DashboardWidget] = Field(default_factory=list, description="Dashboard widgets")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")


# =============================================================================
# Configuration Schemas
# =============================================================================

class ConfigState(str, Enum):
    """Configuration state values."""
    IN_SYNC = "in_sync"
    DRIFT_DETECTED = "drift_detected"
    PENDING = "pending"
    FAILED = "failed"
    UNKNOWN = "unknown"


class ConfigChangeType(str, Enum):
    """Configuration change types."""
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    REPLACE = "replace"


class ConfigResponse(BaseResponseModel):
    """Configuration data response."""
    ne_id: str = Field(..., description="Network element identifier")
    ne_type: str = Field(..., description="Network element type")
    ne_name: str = Field(..., description="Network element name")
    config_state: ConfigState = Field(..., description="Current configuration state")
    last_sync_time: Optional[datetime] = Field(default=None, description="Last synchronization time")
    last_sync_status: Optional[str] = Field(default=None, description="Last sync status")
    running_config: Dict[str, Any] = Field(default_factory=dict, description="Running configuration")
    startup_config: Dict[str, Any] = Field(default_factory=dict, description="Startup configuration")
    candidate_config: Optional[Dict[str, Any]] = Field(default=None, description="Candidate configuration")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Configuration metadata")


class ConfigApplyRequest(BaseModel):
    """Request to apply configuration changes."""
    ne_ids: List[str] = Field(..., min_length=1, description="Target network elements")
    config_data: Dict[str, Any] = Field(..., description="Configuration data to apply")
    change_type: ConfigChangeType = Field(default=ConfigChangeType.UPDATE, description="Change type")
    description: Optional[str] = Field(default=None, max_length=500, description="Change description")
    schedule_time: Optional[datetime] = Field(default=None, description="Scheduled application time")
    validate_only: bool = Field(default=False, description="Validate without applying")
    auto_rollback: bool = Field(default=True, description="Auto rollback on failure")


class ConfigApplyResponse(BaseResponseModel):
    """Response from configuration application."""
    transaction_id: UUID = Field(..., description="Transaction identifier")
    ne_id: str = Field(..., description="Network element identifier")
    status: str = Field(..., description="Application status")
    applied_at: Optional[datetime] = Field(default=None, description="Application timestamp")
    changes_applied: int = Field(default=0, description="Number of changes applied")
    errors: List[str] = Field(default_factory=list, description="Error messages")
    warnings: List[str] = Field(default_factory=list, description="Warning messages")


class ConfigRollbackRequest(BaseModel):
    """Request to rollback configuration."""
    transaction_id: UUID = Field(..., description="Transaction to rollback")
    ne_ids: Optional[List[str]] = Field(default=None, description="Specific NEs to rollback")
    rollback_reason: Optional[str] = Field(default=None, max_length=500, description="Rollback reason")


class ConfigRollbackResponse(BaseResponseModel):
    """Response from configuration rollback."""
    rollback_id: UUID = Field(..., description="Rollback transaction identifier")
    original_transaction_id: UUID = Field(..., description="Original transaction")
    status: str = Field(..., description="Rollback status")
    rolled_back_at: Optional[datetime] = Field(default=None, description="Rollback timestamp")
    changes_reverted: int = Field(default=0, description="Number of changes reverted")
    errors: List[str] = Field(default_factory=list, description="Error messages")


class ConfigDriftItem(BaseResponseModel):
    """Configuration drift detail."""
    ne_id: str = Field(..., description="Network element identifier")
    path: str = Field(..., description="Configuration path with drift")
    expected_value: Any = Field(..., description="Expected value")
    actual_value: Any = Field(..., description="Actual value")
    drift_type: str = Field(..., description="Type of drift")
    severity: str = Field(default="medium", description="Drift severity")
    detected_at: datetime = Field(..., description="Detection timestamp")


class ConfigDriftResponse(BaseResponseModel):
    """Configuration drift response."""
    ne_id: str = Field(..., description="Network element identifier")
    has_drift: bool = Field(..., description="Whether drift is detected")
    drift_count: int = Field(default=0, description="Number of drift items")
    drift_items: List[ConfigDriftItem] = Field(default_factory=list, description="Drift details")
    last_check_time: datetime = Field(..., description="Last drift check time")


class ConfigHistoryItem(BaseResponseModel):
    """Configuration history item."""
    transaction_id: UUID = Field(..., description="Transaction identifier")
    ne_id: str = Field(..., description="Network element identifier")
    change_type: ConfigChangeType = Field(..., description="Type of change")
    description: Optional[str] = Field(default=None, description="Change description")
    changed_by: str = Field(..., description="User who made the change")
    changed_at: datetime = Field(..., description="Change timestamp")
    status: str = Field(..., description="Change status")
    changes_count: int = Field(default=0, description="Number of changes")


class ConfigHistoryResponse(BaseResponseModel):
    """Configuration history response."""
    ne_id: str = Field(..., description="Network element identifier")
    history: List[ConfigHistoryItem] = Field(default_factory=list, description="History items")
    total_count: int = Field(default=0, description="Total history items")


# =============================================================================
# Security Schemas
# =============================================================================

class AuthProvider(str, Enum):
    """Authentication providers."""
    LOCAL = "local"
    LDAP = "ldap"
    RADIUS = "radius"
    TACACS = "tacacs"
    SAML = "saml"
    OAUTH2 = "oauth2"


class AuthenticationRequest(BaseModel):
    """Authentication request."""
    username: str = Field(..., min_length=1, max_length=100, description="Username")
    password: str = Field(..., min_length=1, description="Password")
    provider: AuthProvider = Field(default=AuthProvider.LOCAL, description="Auth provider")
    mfa_code: Optional[str] = Field(default=None, min_length=6, max_length=8, description="MFA code")
    remember_me: bool = Field(default=False, description="Extended session")


class AuthenticationResponse(BaseResponseModel):
    """Authentication response."""
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="Bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiry in seconds")
    user_id: str = Field(..., description="User identifier")
    username: str = Field(..., description="Username")
    roles: List[str] = Field(default_factory=list, description="User roles")
    permissions: List[str] = Field(default_factory=list, description="User permissions")
    auth_provider: AuthProvider = Field(..., description="Authentication provider used")


class AccessEvaluationRequest(BaseModel):
    """Zero-trust access evaluation request."""
    user_id: str = Field(..., description="User identifier")
    resource: str = Field(..., description="Resource being accessed")
    action: str = Field(..., description="Action being performed")
    context: Dict[str, Any] = Field(default_factory=dict, description="Additional context")
    ne_id: Optional[str] = Field(default=None, description="Network element context")


class AccessEvaluationResponse(BaseResponseModel):
    """Zero-trust access evaluation response."""
    decision: str = Field(..., description="Access decision: allow, deny, challenge")
    confidence_score: float = Field(..., ge=0, le=1, description="Confidence score")
    reasons: List[str] = Field(default_factory=list, description="Decision reasons")
    conditions: List[str] = Field(default_factory=list, description="Conditional requirements")
    session_duration: Optional[int] = Field(default=None, description="Session duration seconds")
    requires_mfa: bool = Field(default=False, description="Whether MFA is required")
    evaluated_at: datetime = Field(default_factory=datetime.utcnow)


class AuditLogEntry(BaseResponseModel):
    """Audit log entry."""
    log_id: UUID = Field(..., description="Log entry identifier")
    timestamp: datetime = Field(..., description="Event timestamp")
    user_id: str = Field(..., description="User identifier")
    username: str = Field(..., description="Username")
    action: str = Field(..., description="Action performed")
    resource: str = Field(..., description="Resource affected")
    resource_id: Optional[str] = Field(default=None, description="Resource identifier")
    ne_id: Optional[str] = Field(default=None, description="Network element")
    result: str = Field(..., description="Action result: success, failure")
    ip_address: Optional[str] = Field(default=None, description="Client IP address")
    user_agent: Optional[str] = Field(default=None, description="Client user agent")
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional details")


class AuditLogFilter(BaseModel):
    """Audit log filter parameters."""
    user_id: Optional[str] = Field(default=None, description="Filter by user")
    action: Optional[List[str]] = Field(default=None, description="Filter by action")
    resource: Optional[List[str]] = Field(default=None, description="Filter by resource")
    ne_id: Optional[str] = Field(default=None, description="Filter by NE")
    result: Optional[str] = Field(default=None, description="Filter by result")
    start_time: Optional[datetime] = Field(default=None, description="Start time")
    end_time: Optional[datetime] = Field(default=None, description="End time")


class CredentialRotationRequest(BaseModel):
    """Credential rotation request."""
    credential_type: str = Field(..., description="Type of credential")
    target_id: str = Field(..., description="Target identifier")
    rotation_reason: Optional[str] = Field(default=None, max_length=500, description="Rotation reason")
    notify_owner: bool = Field(default=True, description="Notify credential owner")
    revoke_old_immediately: bool = Field(default=False, description="Revoke old credential immediately")


class CredentialRotationResponse(BaseResponseModel):
    """Credential rotation response."""
    rotation_id: UUID = Field(..., description="Rotation transaction ID")
    credential_type: str = Field(..., description="Credential type")
    target_id: str = Field(..., description="Target identifier")
    status: str = Field(..., description="Rotation status")
    rotated_at: Optional[datetime] = Field(default=None, description="Rotation timestamp")
    old_credential_expiry: Optional[datetime] = Field(default=None, description="Old credential expiry")
    new_credential_id: Optional[str] = Field(default=None, description="New credential ID")


# =============================================================================
# Accounting Schemas
# =============================================================================

class LicenseType(str, Enum):
    """License types."""
    PERPETUAL = "perpetual"
    SUBSCRIPTION = "subscription"
    TRIAL = "trial"
    EVALUATION = "evaluation"


class LicenseStatus(str, Enum):
    """License status values."""
    ACTIVE = "active"
    EXPIRED = "expired"
    EXPIRING_SOON = "expiring_soon"
    OVER_LIMIT = "over_limit"
    INVALID = "invalid"


class LicenseInfo(BaseResponseModel):
    """License information."""
    license_id: str = Field(..., description="License identifier")
    license_type: LicenseType = Field(..., description="License type")
    product: str = Field(..., description="Licensed product")
    feature: str = Field(..., description="Licensed feature")
    max_usage: Optional[int] = Field(default=None, description="Maximum usage allowed")
    current_usage: int = Field(default=0, description="Current usage")
    status: LicenseStatus = Field(..., description="License status")
    valid_from: datetime = Field(..., description="Valid from date")
    valid_until: Optional[datetime] = Field(default=None, description="Valid until date")
    days_until_expiry: Optional[int] = Field(default=None, description="Days until expiry")


class LicenseStatusResponse(BaseResponseModel):
    """License status summary response."""
    total_licenses: int = Field(..., description="Total licenses")
    active_licenses: int = Field(..., description="Active licenses")
    expiring_licenses: int = Field(default=0, description="Licenses expiring in 30 days")
    over_limit_licenses: int = Field(default=0, description="Licenses over limit")
    licenses: List[LicenseInfo] = Field(default_factory=list, description="License details")
    compliance_status: str = Field(..., description="Overall compliance status")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class CapacityMetric(BaseResponseModel):
    """Capacity metric."""
    metric_name: str = Field(..., description="Metric name")
    current_value: float = Field(..., description="Current value")
    max_value: Optional[float] = Field(default=None, description="Maximum value")
    utilization_percent: Optional[float] = Field(default=None, description="Utilization percentage")
    unit: str = Field(..., description="Measurement unit")
    trend: str = Field(default="stable", description="Trend direction")
    forecast_days: Optional[int] = Field(default=None, description="Days until capacity reached")


class CapacitySummaryResponse(BaseResponseModel):
    """Capacity summary response."""
    ne_id: Optional[str] = Field(default=None, description="Network element (null for aggregate)")
    ne_type: Optional[str] = Field(default=None, description="Network element type")
    metrics: List[CapacityMetric] = Field(default_factory=list, description="Capacity metrics")
    overall_utilization: float = Field(default=0, description="Overall utilization percentage")
    health_score: float = Field(default=100, ge=0, le=100, description="Health score")
    alerts: List[str] = Field(default_factory=list, description="Capacity alerts")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class RecommendationType(str, Enum):
    """Recommendation types."""
    SCALE_UP = "scale_up"
    SCALE_DOWN = "scale_down"
    OPTIMIZE = "optimize"
    UPGRADE = "upgrade"
    MIGRATE = "migrate"
    DECOMMISSION = "decommission"


class Recommendation(BaseResponseModel):
    """Optimization recommendation."""
    recommendation_id: UUID = Field(..., description="Recommendation identifier")
    recommendation_type: RecommendationType = Field(..., description="Recommendation type")
    target: str = Field(..., description="Target resource")
    title: str = Field(..., description="Recommendation title")
    description: str = Field(..., description="Detailed description")
    impact: str = Field(..., description="Expected impact")
    priority: str = Field(default="medium", description="Priority level")
    estimated_savings: Optional[float] = Field(default=None, description="Estimated cost savings")
    confidence: float = Field(default=0.8, ge=0, le=1, description="Confidence score")
    created_at: datetime = Field(default_factory=datetime.utcnow)


class RecommendationsResponse(BaseResponseModel):
    """Recommendations response."""
    recommendations: List[Recommendation] = Field(default_factory=list, description="Recommendations")
    total_count: int = Field(default=0, description="Total recommendations")
    high_priority_count: int = Field(default=0, description="High priority count")
    potential_savings: float = Field(default=0, description="Total potential savings")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# =============================================================================
# Metrics Schema (for Prometheus format)
# =============================================================================

class MetricLabel(BaseModel):
    """Metric label."""
    name: str = Field(..., description="Label name")
    value: str = Field(..., description="Label value")


class MetricSample(BaseResponseModel):
    """Metric sample."""
    metric_name: str = Field(..., description="Metric name")
    labels: List[MetricLabel] = Field(default_factory=list, description="Metric labels")
    value: float = Field(..., description="Metric value")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Sample timestamp")


class MetricsResponse(BaseResponseModel):
    """Metrics response for Prometheus scraping."""
    metrics: List[MetricSample] = Field(default_factory=list, description="Metric samples")
    scrape_duration_seconds: float = Field(..., description="Scrape duration")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# Export all models
__all__ = [
    # Base models
    "BaseResponseModel",
    "PaginationParams",
    "PaginatedResponse",
    "ErrorResponse",
    "HealthStatus",
    # Alarm models
    "AlarmSeverity",
    "AlarmStatus",
    "AlarmType",
    "AlarmFilter",
    "AlarmResponse",
    "AlarmAcknowledgeRequest",
    "AlarmAcknowledgeResponse",
    "AlarmClearRequest",
    "AlarmClearResponse",
    "AlarmStatistics",
    "AlarmWebSocketMessage",
    # Performance models
    "KPIType",
    "KPICategory",
    "KPIResponse",
    "KPIFilter",
    "ThresholdComparison",
    "ThresholdRequest",
    "ThresholdResponse",
    "DashboardWidget",
    "PerformanceDashboard",
    # Configuration models
    "ConfigState",
    "ConfigChangeType",
    "ConfigResponse",
    "ConfigApplyRequest",
    "ConfigApplyResponse",
    "ConfigRollbackRequest",
    "ConfigRollbackResponse",
    "ConfigDriftItem",
    "ConfigDriftResponse",
    "ConfigHistoryItem",
    "ConfigHistoryResponse",
    # Security models
    "AuthProvider",
    "AuthenticationRequest",
    "AuthenticationResponse",
    "AccessEvaluationRequest",
    "AccessEvaluationResponse",
    "AuditLogEntry",
    "AuditLogFilter",
    "CredentialRotationRequest",
    "CredentialRotationResponse",
    # Accounting models
    "LicenseType",
    "LicenseStatus",
    "LicenseInfo",
    "LicenseStatusResponse",
    "CapacityMetric",
    "CapacitySummaryResponse",
    "RecommendationType",
    "Recommendation",
    "RecommendationsResponse",
    # Metrics models
    "MetricLabel",
    "MetricSample",
    "MetricsResponse",
]
