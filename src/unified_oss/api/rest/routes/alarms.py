"""
Alarm Management REST API Routes.
"""

from datetime import datetime
from typing import List, Optional
from enum import Enum

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from unified_oss.core.constants import SEVERITY_CRITICAL, SEVERITY_MAJOR, SEVERITY_MINOR, SEVERITY_WARNING

router = APIRouter()


class SeverityEnum(str, Enum):
    """Alarm severity enumeration."""
    CRITICAL = "CRITICAL"
    MAJOR = "MAJOR"
    MINOR = "MINOR"
    WARNING = "WARNING"
    INDETERMINATE = "INDETERMINATE"
    CLEARED = "CLEARED"


class AlarmStateEnum(str, Enum):
    """Alarm state enumeration."""
    ACTIVE = "ACTIVE"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    CLEARED = "CLEARED"
    RESOLVING = "RESOLVING"
    SUPPRESSED = "SUPPRESSED"


class AlarmResponse(BaseModel):
    """Alarm response model."""
    alarm_id: str
    alarm_name: str
    alarm_type: str
    severity: SeverityEnum
    state: AlarmStateEnum
    vendor: str
    ne_id: str
    ne_name: str
    ne_type: str
    timestamp: datetime
    probable_cause: str
    specific_problem: Optional[str] = None
    affected_resource: str
    additional_text: Optional[str] = None
    correlation_id: Optional[str] = None
    root_cause_alarm_id: Optional[str] = None
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    cleared_at: Optional[datetime] = None
    
    class Config:
        use_enum_values = True


class AlarmListResponse(BaseModel):
    """Paginated alarm list response."""
    total: int
    page: int
    page_size: int
    items: List[AlarmResponse]


class AcknowledgeRequest(BaseModel):
    """Alarm acknowledgment request."""
    alarm_ids: List[str]
    acknowledged_by: str
    notes: Optional[str] = None


class AcknowledgeResponse(BaseModel):
    """Alarm acknowledgment response."""
    success: List[str] = Field(default_factory=list)
    failed: List[dict] = Field(default_factory=list)


class ClearRequest(BaseModel):
    """Alarm clear request."""
    alarm_ids: List[str]
    cleared_by: str
    clearance_reason: str
    notes: Optional[str] = None


class AlarmStatistics(BaseModel):
    """Alarm statistics model."""
    total_active: int
    by_severity: dict
    by_vendor: dict
    by_type: dict
    acknowledged_count: int
    unacknowledged_count: int
    average_age_hours: float


@router.get("", response_model=AlarmListResponse)
async def list_alarms(
    severity: Optional[SeverityEnum] = Query(None, description="Filter by severity"),
    state: Optional[AlarmStateEnum] = Query(None, description="Filter by state"),
    vendor: Optional[str] = Query(None, description="Filter by vendor"),
    ne_id: Optional[str] = Query(None, description="Filter by network element ID"),
    ne_type: Optional[str] = Query(None, description="Filter by NE type"),
    alarm_type: Optional[str] = Query(None, description="Filter by alarm type"),
    start_time: Optional[datetime] = Query(None, description="Start time filter"),
    end_time: Optional[datetime] = Query(None, description="End time filter"),
    search: Optional[str] = Query(None, description="Search in alarm text"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    sort_by: str = Query("timestamp", description="Sort field"),
    sort_order: str = Query("desc", regex="^(asc|desc)$", description="Sort order"),
):
    """
    List alarms with filtering, pagination, and sorting.
    
    Returns a paginated list of alarms matching the specified criteria.
    """
    # Simulated response - in production, query database
    return AlarmListResponse(
        total=0,
        page=page,
        page_size=page_size,
        items=[]
    )


@router.get("/statistics", response_model=AlarmStatistics)
async def get_alarm_statistics(
    vendor: Optional[str] = Query(None),
    ne_type: Optional[str] = Query(None),
):
    """
    Get alarm statistics.
    
    Returns aggregated statistics about current alarms.
    """
    return AlarmStatistics(
        total_active=0,
        by_severity={
            "CRITICAL": 0,
            "MAJOR": 0,
            "MINOR": 0,
            "WARNING": 0,
        },
        by_vendor={
            "ERICSSON": 0,
            "HUAWEI": 0,
        },
        by_type={},
        acknowledged_count=0,
        unacknowledged_count=0,
        average_age_hours=0.0,
    )


@router.get("/{alarm_id}", response_model=AlarmResponse)
async def get_alarm(alarm_id: str):
    """
    Get a specific alarm by ID.
    
    Returns detailed information about the specified alarm.
    """
    raise HTTPException(status_code=404, detail=f"Alarm {alarm_id} not found")


@router.post("/acknowledge", response_model=AcknowledgeResponse)
async def acknowledge_alarms(request: AcknowledgeRequest):
    """
    Acknowledge one or more alarms.
    
    Marks the specified alarms as acknowledged by the given user.
    """
    return AcknowledgeResponse(
        success=request.alarm_ids,
        failed=[]
    )


@router.post("/clear", response_model=dict)
async def clear_alarms(request: ClearRequest):
    """
    Clear one or more alarms.
    
    Manually clears the specified alarms with a reason.
    """
    return {
        "cleared": request.alarm_ids,
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.post("/{alarm_id}/unacknowledge")
async def unacknowledge_alarm(alarm_id: str):
    """
    Unacknowledge an alarm.
    
    Reverts an alarm from acknowledged back to active state.
    """
    return {"alarm_id": alarm_id, "state": "ACTIVE"}


@router.get("/{alarm_id}/correlated")
async def get_correlated_alarms(alarm_id: str):
    """
    Get alarms correlated with the specified alarm.
    
    Returns all alarms that are temporally, topologically, or causally
    related to the specified alarm.
    """
    return {
        "alarm_id": alarm_id,
        "correlated_alarms": [],
        "correlation_confidence": 0.0,
        "correlation_method": None,
    }


@router.get("/{alarm_id}/history")
async def get_alarm_history(alarm_id: str):
    """
    Get the history of state changes for an alarm.
    
    Returns a chronological list of all state transitions.
    """
    return {
        "alarm_id": alarm_id,
        "history": [],
    }


class ConnectionManager:
    """WebSocket connection manager for real-time alarm notifications."""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    
    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
    
    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            await connection.send_json(message)


manager = ConnectionManager()


@router.websocket("/ws")
async def alarm_websocket(websocket: WebSocket):
    """
    WebSocket endpoint for real-time alarm notifications.
    
    Clients receive real-time updates when alarms are raised, updated,
    acknowledged, or cleared.
    """
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Handle client messages (subscriptions, filters, etc.)
            await websocket.send_json({
                "type": "connected",
                "message": "Connected to alarm stream"
            })
    except WebSocketDisconnect:
        manager.disconnect(websocket)
