"""
Accounting Management REST API Routes.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter()


class LicenseStatus(str, Enum):
    """License status enumeration."""
    VALID = "VALID"
    EXPIRED = "EXPIRED"
    EXCEEDED = "EXCEEDED"
    NOT_INSTALLED = "NOT_INSTALLED"
    SUSPENDED = "SUSPENDED"
    PENDING_ACTIVATION = "PENDING_ACTIVATION"


class LicenseResponse(BaseModel):
    """License response model."""
    license_id: str
    license_name: str
    vendor: str
    status: LicenseStatus
    license_type: str
    feature_name: str
    total_capacity: int
    used_capacity: int
    utilization_percent: float
    expiration_date: Optional[datetime] = None
    days_to_expiry: Optional[int] = None
    alerts: List[Dict[str, Any]] = Field(default_factory=list)


class CapacityType(str, Enum):
    """Capacity type enumeration."""
    RF_SPECTRUM = "RF_SPECTRUM"
    RF_POWER = "RF_POWER"
    THROUGHPUT = "THROUGHPUT"
    SUBSCRIBER_ACTIVE = "SUBSCRIBER_ACTIVE"
    SUBSCRIBER_TOTAL = "SUBSCRIBER_TOTAL"
    SESSION = "SESSION"
    BEARER = "BEARER"


class CapacityMetric(BaseModel):
    """Capacity metric model."""
    metric_id: str
    capacity_type: CapacityType
    vendor: str
    ne_id: str
    ne_name: str
    total_capacity: float
    used_capacity: float
    utilization_percent: float
    unit: str
    timestamp: datetime


class CapacitySummary(BaseModel):
    """Capacity summary model."""
    capacity_type: CapacityType
    total_capacity: float
    used_capacity: float
    utilization_percent: float
    unit: str
    by_vendor: Dict[str, float]
    trend: str


class ProcurementRecommendation(BaseModel):
    """Procurement recommendation model."""
    recommendation_id: str
    capacity_type: CapacityType
    vendor: str
    current_utilization: float
    projected_utilization: float
    recommended_action: str
    estimated_cost: Optional[float] = None
    priority: str
    justification: str


@router.get("/license-status", response_model=List[LicenseResponse])
async def get_license_status(
    vendor: Optional[str] = Query(None),
    status: Optional[LicenseStatus] = Query(None),
):
    """
    Get license status across all vendors.
    
    Returns license information with expiration alerts and utilization.
    """
    return []


@router.get("/license-status/{license_id}", response_model=LicenseResponse)
async def get_license(license_id: str):
    """Get details of a specific license."""
    raise HTTPException(status_code=404, detail=f"License {license_id} not found")


@router.get("/license-alerts")
async def get_license_alerts(
    days_threshold: int = Query(30, description="Days until expiration for alerts"),
):
    """
    Get license expiration alerts.
    
    Returns licenses expiring within the specified number of days.
    """
    return {
        "critical": [],  # Expired
        "warning": [],   # Expiring within days_threshold
        "info": [],      # Expiring within 90 days
    }


@router.get("/capacity-summary", response_model=List[CapacitySummary])
async def get_capacity_summary(
    vendor: Optional[str] = Query(None),
    capacity_type: Optional[CapacityType] = Query(None),
):
    """
    Get capacity utilization summary.
    
    Returns aggregated capacity metrics across vendors.
    """
    return [
        CapacitySummary(
            capacity_type=CapacityType.RF_SPECTRUM,
            total_capacity=0.0,
            used_capacity=0.0,
            utilization_percent=0.0,
            unit="MHz",
            by_vendor={"ERICSSON": 0.0, "HUAWEI": 0.0},
            trend="stable",
        ),
    ]


@router.get("/capacity-metrics", response_model=List[CapacityMetric])
async def get_capacity_metrics(
    vendor: Optional[str] = Query(None),
    ne_id: Optional[str] = Query(None),
    capacity_type: Optional[CapacityType] = Query(None),
    min_utilization: Optional[float] = Query(None),
    max_utilization: Optional[float] = Query(None),
):
    """Get detailed capacity metrics."""
    return []


@router.get("/recommendations", response_model=List[ProcurementRecommendation])
async def get_procurement_recommendations(
    priority: Optional[str] = Query(None),
    capacity_type: Optional[CapacityType] = Query(None),
):
    """
    Get procurement recommendations.
    
    Returns capacity expansion recommendations based on utilization trends.
    """
    return []


@router.get("/trends")
async def get_capacity_trends(
    capacity_type: CapacityType,
    period_days: int = Query(30, ge=7, le=365),
):
    """Get capacity utilization trends."""
    return {
        "capacity_type": capacity_type,
        "period_days": period_days,
        "trend_data": [],
        "forecast": None,
    }


@router.post("/sync")
async def sync_capacity_data():
    """
    Trigger capacity data synchronization.
    
    Initiates a sync with vendor systems for capacity data.
    """
    return {
        "sync_id": f"sync-{datetime.utcnow().timestamp()}",
        "status": "INITIATED",
    }
