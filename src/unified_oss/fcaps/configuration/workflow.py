"""
Configuration Workflow Module for Unified OSS Framework.

This module implements NETCONF-based configuration workflows including
the standard 7-step workflow, confirmed-commit, and approval processes
for network element configuration management.

Features:
    - NETCONF 7-step workflow implementation
    - Candidate datastore lock/edit/validate/commit
    - Confirmed-commit with configurable timeout
    - Automatic rollback on failure
    - Approval workflow support
    - Audit logging with SHA-256 hashes

Author: Unified OSS Framework Team
Version: 1.0.0
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

# Configure module logger
logger = logging.getLogger(__name__)


# =============================================================================
# Enums and Constants
# =============================================================================


class WorkflowState(Enum):
    """Workflow execution states."""
    PENDING = "pending"
    INITIALIZING = "initializing"
    LOCKING = "locking"
    EDITING = "editing"
    VALIDATING = "validating"
    COMMITTING = "committing"
    CONFIRMING = "confirming"
    ROLLING_BACK = "rolling_back"
    UNLOCKING = "unlocking"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class WorkflowStep(Enum):
    """Steps in the NETCONF configuration workflow."""
    INITIALIZE = "initialize"
    LOCK = "lock"
    EDIT_CONFIG = "edit_config"
    VALIDATE = "validate"
    COMMIT = "commit"
    VERIFY = "verify"
    UNLOCK = "unlock"

    @classmethod
    def get_ordered_steps(cls) -> List[WorkflowStep]:
        """Get ordered list of workflow steps.

        Returns:
            Ordered list of steps.
        """
        return [
            cls.INITIALIZE,
            cls.LOCK,
            cls.EDIT_CONFIG,
            cls.VALIDATE,
            cls.COMMIT,
            cls.VERIFY,
            cls.UNLOCK,
        ]


class DatastoreType(Enum):
    """NETCONF datastore types."""
    RUNNING = "running"
    CANDIDATE = "candidate"
    STARTUP = "startup"


class CommitMode(Enum):
    """Commit modes for configuration deployment."""
    STANDARD = "standard"
    CONFIRMED = "confirmed"
    ATOMIC = "atomic"


class ApprovalStatus(Enum):
    """Approval workflow status."""
    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class WorkflowErrorType(Enum):
    """Types of workflow errors."""
    LOCK_FAILED = "lock_failed"
    EDIT_FAILED = "edit_failed"
    VALIDATION_FAILED = "validation_failed"
    COMMIT_FAILED = "commit_failed"
    TIMEOUT = "timeout"
    CONNECTION_ERROR = "connection_error"
    ROLLBACK_FAILED = "rollback_failed"


# =============================================================================
# Exceptions
# =============================================================================


class WorkflowError(Exception):
    """Base exception for workflow errors."""

    def __init__(
        self,
        message: str,
        workflow_id: str,
        step: Optional[WorkflowStep] = None,
        error_type: Optional[WorkflowErrorType] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Initialize workflow error.

        Args:
            message: Error message.
            workflow_id: Workflow identifier.
            step: Workflow step where error occurred.
            error_type: Type of error.
            details: Additional error details.
        """
        super().__init__(message)
        self.workflow_id = workflow_id
        self.step = step
        self.error_type = error_type
        self.details = details or {}


class LockFailedError(WorkflowError):
    """Exception raised when datastore lock fails."""

    def __init__(self, workflow_id: str, datastore: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Initialize lock failed error.

        Args:
            workflow_id: Workflow identifier.
            datastore: Datastore that failed to lock.
            details: Additional details.
        """
        super().__init__(
            f"Failed to lock datastore: {datastore}",
            workflow_id,
            WorkflowStep.LOCK,
            WorkflowErrorType.LOCK_FAILED,
            details
        )
        self.datastore = datastore


class ValidationError(WorkflowError):
    """Exception raised when validation fails."""

    def __init__(
        self,
        workflow_id: str,
        errors: List[str],
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Initialize validation error.

        Args:
            workflow_id: Workflow identifier.
            errors: List of validation errors.
            details: Additional details.
        """
        super().__init__(
            f"Validation failed with {len(errors)} error(s)",
            workflow_id,
            WorkflowStep.VALIDATE,
            WorkflowErrorType.VALIDATION_FAILED,
            details
        )
        self.validation_errors = errors


class CommitFailedError(WorkflowError):
    """Exception raised when commit fails."""

    def __init__(
        self,
        workflow_id: str,
        reason: str,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Initialize commit failed error.

        Args:
            workflow_id: Workflow identifier.
            reason: Failure reason.
            details: Additional details.
        """
        super().__init__(
            f"Commit failed: {reason}",
            workflow_id,
            WorkflowStep.COMMIT,
            WorkflowErrorType.COMMIT_FAILED,
            details
        )
        self.reason = reason


class TimeoutError(WorkflowError):
    """Exception raised when operation times out."""

    def __init__(
        self,
        workflow_id: str,
        timeout_seconds: float,
        step: Optional[WorkflowStep] = None
    ) -> None:
        """Initialize timeout error.

        Args:
            workflow_id: Workflow identifier.
            timeout_seconds: Timeout duration.
            step: Step that timed out.
        """
        super().__init__(
            f"Operation timed out after {timeout_seconds} seconds",
            workflow_id,
            step,
            WorkflowErrorType.TIMEOUT
        )
        self.timeout_seconds = timeout_seconds


# =============================================================================
# Dataclasses
# =============================================================================


@dataclass
class WorkflowStepResult:
    """Result of a workflow step execution.

    Attributes:
        step: Workflow step.
        success: Whether step succeeded.
        message: Result message.
        timestamp: Execution timestamp.
        duration_ms: Execution duration in milliseconds.
        output: Step output data.
        errors: List of errors if failed.
    """

    step: WorkflowStep
    success: bool = True
    message: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    duration_ms: float = 0.0
    output: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary representation.
        """
        return {
            "step": self.step.value,
            "success": self.success,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "duration_ms": self.duration_ms,
            "output": self.output,
            "errors": self.errors,
        }


@dataclass
class AuditLogEntry:
    """Audit log entry for workflow operations.

    Attributes:
        entry_id: Unique entry identifier.
        workflow_id: Workflow identifier.
        step: Workflow step.
        action: Action performed.
        user: User who initiated the action.
        timestamp: Action timestamp.
        config_hash: SHA-256 hash of configuration.
        before_hash: Hash before change.
        after_hash: Hash after change.
        details: Additional details.
    """

    entry_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    workflow_id: str = ""
    step: WorkflowStep = WorkflowStep.INITIALIZE
    action: str = ""
    user: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    config_hash: str = ""
    before_hash: str = ""
    after_hash: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def calculate_hash(self, content: str) -> str:
        """Calculate SHA-256 hash of content.

        Args:
            content: Content to hash.

        Returns:
            Hash string.
        """
        return hashlib.sha256(content.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary representation.
        """
        return {
            "entry_id": self.entry_id,
            "workflow_id": self.workflow_id,
            "step": self.step.value,
            "action": self.action,
            "user": self.user,
            "timestamp": self.timestamp.isoformat(),
            "config_hash": self.config_hash,
            "before_hash": self.before_hash,
            "after_hash": self.after_hash,
            "details": self.details,
        }


@dataclass
class ApprovalRequest:
    """Approval request for configuration changes.

    Attributes:
        request_id: Unique request identifier.
        workflow_id: Associated workflow ID.
        ne_id: Network element identifier.
        config_content: Configuration content to approve.
        config_hash: Hash of configuration.
        requested_by: User who requested approval.
        requested_at: Request timestamp.
        status: Approval status.
        approvers: List of required approvers.
        approvals: List of received approvals.
        rejections: List of rejections.
        expires_at: Expiration timestamp.
        comment: Request comment.
    """

    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    workflow_id: str = ""
    ne_id: str = ""
    config_content: str = ""
    config_hash: str = ""
    requested_by: str = ""
    requested_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: ApprovalStatus = ApprovalStatus.PENDING
    approvers: List[str] = field(default_factory=list)
    approvals: List[Dict[str, Any]] = field(default_factory=list)
    rejections: List[Dict[str, Any]] = field(default_factory=list)
    expires_at: Optional[datetime] = None
    comment: str = ""

    def __post_init__(self) -> None:
        """Calculate hash if not set."""
        if self.config_content and not self.config_hash:
            self.config_hash = hashlib.sha256(
                self.config_content.encode()
            ).hexdigest()

        if not self.expires_at:
            self.expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

    def is_expired(self) -> bool:
        """Check if request is expired.

        Returns:
            True if expired.
        """
        if not self.expires_at:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    def is_approved(self) -> bool:
        """Check if request is approved.

        Returns:
            True if approved.
        """
        return self.status == ApprovalStatus.APPROVED

    def add_approval(self, approver: str, comment: str = "") -> None:
        """Add an approval.

        Args:
            approver: Approver username.
            comment: Approval comment.
        """
        self.approvals.append({
            "approver": approver,
            "comment": comment,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        if len(self.approvals) >= len(self.approvers):
            self.status = ApprovalStatus.APPROVED

    def add_rejection(self, approver: str, reason: str = "") -> None:
        """Add a rejection.

        Args:
            approver: Approver username.
            reason: Rejection reason.
        """
        self.rejections.append({
            "approver": approver,
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        self.status = ApprovalStatus.REJECTED

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary representation.
        """
        return {
            "request_id": self.request_id,
            "workflow_id": self.workflow_id,
            "ne_id": self.ne_id,
            "config_hash": self.config_hash,
            "requested_by": self.requested_by,
            "requested_at": self.requested_at.isoformat(),
            "status": self.status.value,
            "approvers": self.approvers,
            "approvals": self.approvals,
            "rejections": self.rejections,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "comment": self.comment,
        }


@dataclass
class WorkflowResult:
    """Complete workflow execution result.

    Attributes:
        workflow_id: Workflow identifier.
        state: Final workflow state.
        ne_id: Network element identifier.
        started_at: Start timestamp.
        completed_at: Completion timestamp.
        duration_ms: Total duration in milliseconds.
        step_results: Results for each step.
        audit_entries: Audit log entries.
        error: Error information if failed.
        rollback_performed: Whether rollback was performed.
    """

    workflow_id: str = ""
    state: WorkflowState = WorkflowState.PENDING
    ne_id: str = ""
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    duration_ms: float = 0.0
    step_results: List[WorkflowStepResult] = field(default_factory=list)
    audit_entries: List[AuditLogEntry] = field(default_factory=list)
    error: Optional[Dict[str, Any]] = None
    rollback_performed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary representation.
        """
        return {
            "workflow_id": self.workflow_id,
            "state": self.state.value,
            "ne_id": self.ne_id,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_ms": self.duration_ms,
            "step_results": [r.to_dict() for r in self.step_results],
            "audit_entries": [e.to_dict() for e in self.audit_entries],
            "error": self.error,
            "rollback_performed": self.rollback_performed,
        }


# =============================================================================
# Configuration Workflow
# =============================================================================


class ConfigWorkflow:
    """NETCONF 7-step configuration workflow implementation.

    Implements the standard NETCONF configuration workflow:
    1. Lock candidate datastore
    2. Edit-config with changes
    3. Validate configuration
    4. Confirmed-commit with timeout
    5. Get-config for verification
    6. Commit (confirmation) or Rollback
    7. Unlock candidate datastore

    Attributes:
        workflow_id: Unique workflow identifier.
        ne_id: Network element identifier.
        state: Current workflow state.
        config: Configuration content.
        commit_mode: Commit mode (standard/confirmed).

    Example:
        >>> workflow = ConfigWorkflow(ne_id="router-001")
        >>> result = await workflow.execute_workflow(
        ...     config_content=config_xml,
        ...     user="admin",
        ...     confirmed_commit=True
        ... )
    """

    DEFAULT_CONFIRM_TIMEOUT = 600  # 10 minutes
    DEFAULT_LOCK_TIMEOUT = 30
    DEFAULT_OPERATION_TIMEOUT = 60

    def __init__(
        self,
        ne_id: str,
        workflow_id: Optional[str] = None
    ) -> None:
        """Initialize configuration workflow.

        Args:
            ne_id: Network element identifier.
            workflow_id: Optional workflow identifier.
        """
        self.workflow_id = workflow_id or str(uuid.uuid4())
        self.ne_id = ne_id
        self.state = WorkflowState.PENDING

        self._config: str = ""
        self._original_config: str = ""
        self._commit_mode = CommitMode.STANDARD
        self._confirm_timeout = self.DEFAULT_CONFIRM_TIMEOUT
        self._current_step: Optional[WorkflowStep] = None
        self._step_results: List[WorkflowStepResult] = []
        self._audit_entries: List[AuditLogEntry] = []
        self._lock_acquired = False
        self._rollback_needed = False
        self._started_at: Optional[datetime] = None
        self._lock = asyncio.Lock()

        logger.info("ConfigWorkflow initialized: %s for NE %s", self.workflow_id[:8], ne_id)

    async def execute_workflow(
        self,
        config_content: str,
        user: str,
        operation: str = "merge",
        confirmed_commit: bool = False,
        confirm_timeout: Optional[int] = None,
        require_approval: bool = False,
        approvers: Optional[List[str]] = None,
        validate_only: bool = False
    ) -> WorkflowResult:
        """Execute the complete configuration workflow.

        Args:
            config_content: Configuration XML content.
            user: User executing the workflow.
            operation: Configuration operation (merge/replace/delete).
            confirmed_commit: Whether to use confirmed commit.
            confirm_timeout: Timeout for confirmed commit in seconds.
            require_approval: Whether approval is required.
            approvers: List of required approvers.
            validate_only: Only validate, don't apply.

        Returns:
            WorkflowResult with execution details.

        Raises:
            WorkflowError: If workflow execution fails.
        """
        self._config = config_content
        self._commit_mode = CommitMode.CONFIRMED if confirmed_commit else CommitMode.STANDARD
        self._confirm_timeout = confirm_timeout or self.DEFAULT_CONFIRM_TIMEOUT
        self._started_at = datetime.now(timezone.utc)

        result = WorkflowResult(
            workflow_id=self.workflow_id,
            ne_id=self.ne_id,
            started_at=self._started_at,
        )

        logger.info(
            "Starting workflow %s for NE %s by %s (confirmed=%s)",
            self.workflow_id[:8], self.ne_id, user, confirmed_commit
        )

        try:
            async with self._lock:
                # Handle approval workflow if required
                if require_approval:
                    approval = await self._request_approval(user, approvers or [])
                    result.audit_entries = self._audit_entries.copy()
                    if not approval.is_approved():
                        result.state = WorkflowState.PENDING
                        result.error = {
                            "type": "approval_required",
                            "approval_id": approval.request_id,
                            "message": "Configuration requires approval",
                        }
                        return result

                # Execute workflow steps
                self.state = WorkflowState.INITIALIZING

                # Step 1: Initialize and get original config
                step_result = await self._execute_step(
                    WorkflowStep.INITIALIZE,
                    self._initialize,
                    user
                )
                result.step_results.append(step_result)
                if not step_result.success:
                    raise WorkflowError(
                        "Initialization failed",
                        self.workflow_id,
                        WorkflowStep.INITIALIZE,
                        details=step_result.output
                    )

                if validate_only:
                    # Only validate, don't apply
                    step_result = await self._execute_step(
                        WorkflowStep.VALIDATE,
                        self.validate,
                        config_content
                    )
                    result.step_results.append(step_result)
                    result.state = WorkflowState.COMPLETED if step_result.success else WorkflowState.FAILED
                    result.completed_at = datetime.now(timezone.utc)
                    result.duration_ms = (
                        result.completed_at - result.started_at
                    ).total_seconds() * 1000
                    return result

                # Step 2: Lock candidate datastore
                self.state = WorkflowState.LOCKING
                step_result = await self._execute_step(
                    WorkflowStep.LOCK,
                    self.lock_datastore,
                    DatastoreType.CANDIDATE
                )
                result.step_results.append(step_result)
                if not step_result.success:
                    raise LockFailedError(
                        self.workflow_id,
                        DatastoreType.CANDIDATE.value,
                        step_result.output
                    )
                self._lock_acquired = True

                try:
                    # Step 3: Edit configuration
                    self.state = WorkflowState.EDITING
                    step_result = await self._execute_step(
                        WorkflowStep.EDIT_CONFIG,
                        self.edit_config,
                        config_content,
                        operation
                    )
                    result.step_results.append(step_result)
                    if not step_result.success:
                        raise WorkflowError(
                            "Edit-config failed",
                            self.workflow_id,
                            WorkflowStep.EDIT_CONFIG,
                            WorkflowErrorType.EDIT_FAILED,
                            step_result.output
                        )

                    # Step 4: Validate configuration
                    self.state = WorkflowState.VALIDATING
                    step_result = await self._execute_step(
                        WorkflowStep.VALIDATE,
                        self.validate,
                        DatastoreType.CANDIDATE
                    )
                    result.step_results.append(step_result)
                    if not step_result.success:
                        raise ValidationError(
                            self.workflow_id,
                            step_result.errors,
                            step_result.output
                        )

                    # Step 5: Commit configuration
                    self.state = WorkflowState.COMMITTING
                    step_result = await self._execute_step(
                        WorkflowStep.COMMIT,
                        self.commit,
                        confirmed=confirmed_commit,
                        confirm_timeout=self._confirm_timeout
                    )
                    result.step_results.append(step_result)
                    if not step_result.success:
                        raise CommitFailedError(
                            self.workflow_id,
                            step_result.message,
                            step_result.output
                        )

                    # Step 6: Verify configuration
                    self.state = WorkflowState.CONFIRMING if confirmed_commit else WorkflowState.COMPLETED
                    step_result = await self._execute_step(
                        WorkflowStep.VERIFY,
                        self._verify_config,
                        config_content
                    )
                    result.step_results.append(step_result)

                    self.state = WorkflowState.COMPLETED
                    result.state = WorkflowState.COMPLETED

                except WorkflowError as e:
                    self.state = WorkflowState.ROLLING_BACK
                    self._rollback_needed = True

                    # Attempt rollback
                    rollback_result = await self._execute_step(
                        WorkflowStep.EDIT_CONFIG,
                        self.rollback,
                        reason=str(e)
                    )
                    result.step_results.append(rollback_result)
                    result.rollback_performed = rollback_result.success

                    raise

                finally:
                    # Step 7: Unlock candidate datastore
                    if self._lock_acquired:
                        self.state = WorkflowState.UNLOCKING
                        step_result = await self._execute_step(
                            WorkflowStep.UNLOCK,
                            self.unlock_datastore,
                            DatastoreType.CANDIDATE
                        )
                        result.step_results.append(step_result)
                        self._lock_acquired = False

            result.audit_entries = self._audit_entries.copy()

        except WorkflowError as e:
            self.state = WorkflowState.FAILED
            result.state = WorkflowState.FAILED
            result.error = {
                "type": e.error_type.value if e.error_type else "unknown",
                "message": str(e),
                "step": e.step.value if e.step else None,
                "details": e.details,
            }
            logger.error("Workflow %s failed: %s", self.workflow_id[:8], e)

        except asyncio.TimeoutError as e:
            self.state = WorkflowState.TIMEOUT
            result.state = WorkflowState.TIMEOUT
            result.error = {
                "type": "timeout",
                "message": "Workflow execution timed out",
            }
            logger.error("Workflow %s timed out", self.workflow_id[:8])

        except Exception as e:
            self.state = WorkflowState.FAILED
            result.state = WorkflowState.FAILED
            result.error = {
                "type": "unexpected",
                "message": str(e),
            }
            logger.exception("Workflow %s failed with unexpected error", self.workflow_id[:8])

        finally:
            result.completed_at = datetime.now(timezone.utc)
            result.duration_ms = (
                result.completed_at - result.started_at
            ).total_seconds() * 1000


            # Add final audit entry
            self._add_audit_entry(
                step=WorkflowStep.UNLOCK,
                action="WORKFLOW_COMPLETE",
                user=user,
                details={"state": result.state.value, "duration_ms": result.duration_ms}
            )
            result.audit_entries = self._audit_entries.copy()

        logger.info(
            "Workflow %s completed: state=%s, duration=%.2f ms",
            self.workflow_id[:8], result.state.value, result.duration_ms
        )

        return result

    async def _execute_step(
        self,
        step: WorkflowStep,
        func: Callable[..., Any],
        *args: Any,
        **kwargs: Any
    ) -> WorkflowStepResult:
        """Execute a workflow step with timing and error handling.

        Args:
            step: Workflow step.
            func: Step function to execute.
            args: Positional arguments.
            kwargs: Keyword arguments.

        Returns:
            Step result.
        """
        self._current_step = step
        start_time = datetime.now(timezone.utc)

        try:
            result = await func(*args, **kwargs)

            duration_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

            if isinstance(result, WorkflowStepResult):
                return result

            return WorkflowStepResult(
                step=step,
                success=True,
                message=f"Step {step.value} completed successfully",
                duration_ms=duration_ms,
                output=result if isinstance(result, dict) else {"result": result},
            )

        except Exception as e:
            duration_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

            return WorkflowStepResult(
                step=step,
                success=False,
                message=str(e),
                duration_ms=duration_ms,
                errors=[str(e)],
            )

    async def lock_datastore(
        self,
        datastore: DatastoreType
    ) -> WorkflowStepResult:
        """Lock a NETCONF datastore.

        Args:
            datastore: Datastore to lock.

        Returns:
            Step result.

        Raises:
            LockFailedError: If lock acquisition fails.
        """
        logger.info(
            "Workflow %s: Locking datastore %s",
            self.workflow_id[:8], datastore.value
        )

        # Simulate NETCONF lock operation
        await asyncio.sleep(0.1)  # Simulate network latency

        # Add audit entry
        self._add_audit_entry(
            step=WorkflowStep.LOCK,
            action="LOCK_DATASTORE",
            user="system",
            details={"datastore": datastore.value}
        )

        self._lock_acquired = True

        return WorkflowStepResult(
            step=WorkflowStep.LOCK,
            success=True,
            message=f"Successfully locked {datastore.value} datastore",
            output={"datastore": datastore.value},
        )

    async def edit_config(
        self,
        config: str,
        operation: str = "merge"
    ) -> WorkflowStepResult:
        """Edit configuration in candidate datastore.

        Args:
            config: Configuration XML.
            operation: Operation type (merge/replace/delete).

        Returns:
            Step result.
        """
        logger.info(
            "Workflow %s: Editing config with operation %s",
            self.workflow_id[:8], operation
        )

        # Calculate config hash
        config_hash = hashlib.sha256(config.encode()).hexdigest()

        # Simulate NETCONF edit-config operation
        await asyncio.sleep(0.2)  # Simulate network latency

        # Add audit entry
        self._add_audit_entry(
            step=WorkflowStep.EDIT_CONFIG,
            action="EDIT_CONFIG",
            user="system",
            config_hash=config_hash,
            details={"operation": operation, "config_length": len(config)}
        )

        return WorkflowStepResult(
            step=WorkflowStep.EDIT_CONFIG,
            success=True,
            message="Configuration edited successfully",
            output={
                "operation": operation,
                "config_hash": config_hash,
            },
        )

    async def validate(
        self,
        target: Union[DatastoreType, str]
    ) -> WorkflowStepResult:
        """Validate configuration.

        Args:
            target: Datastore or configuration content to validate.

        Returns:
            Step result.
        """
        logger.info(
            "Workflow %s: Validating configuration",
            self.workflow_id[:8]
        )

        errors: List[str] = []

        # Get content to validate
        if isinstance(target, DatastoreType):
            config = self._config
        else:
            config = target

        # Basic validation checks
        if not config or not config.strip():
            errors.append("Configuration is empty")

        # XML validation
        if config.strip().startswith("<"):
            try:
                from xml.etree import ElementTree as ET
                ET.fromstring(config)
            except ET.ParseError as e:
                errors.append(f"XML parsing error: {e}")

        # Add audit entry
        self._add_audit_entry(
            step=WorkflowStep.VALIDATE,
            action="VALIDATE",
            user="system",
            details={"valid": len(errors) == 0, "error_count": len(errors)}
        )

        if errors:
            return WorkflowStepResult(
                step=WorkflowStep.VALIDATE,
                success=False,
                message="Validation failed",
                errors=errors,
            )

        return WorkflowStepResult(
            step=WorkflowStep.VALIDATE,
            success=True,
            message="Validation successful",
        )

    async def commit(
        self,
        confirmed: bool = False,
        confirm_timeout: Optional[int] = None
    ) -> WorkflowStepResult:
        """Commit configuration changes.

        Args:
            confirmed: Whether to use confirmed commit.
            confirm_timeout: Timeout for confirmed commit in seconds.

        Returns:
            Step result.
        """
        logger.info(
            "Workflow %s: Committing (confirmed=%s, timeout=%s)",
            self.workflow_id[:8], confirmed, confirm_timeout
        )

        # Simulate NETCONF commit operation
        await asyncio.sleep(0.3)  # Simulate network latency

        config_hash = hashlib.sha256(self._config.encode()).hexdigest()

        # Add audit entry
        self._add_audit_entry(
            step=WorkflowStep.COMMIT,
            action="COMMIT" if not confirmed else "CONFIRMED_COMMIT",
            user="system",
            config_hash=config_hash,
            details={
                "confirmed": confirmed,
                "confirm_timeout": confirm_timeout,
            }
        )

        return WorkflowStepResult(
            step=WorkflowStep.COMMIT,
            success=True,
            message="Commit successful",
            output={
                "confirmed": confirmed,
                "confirm_timeout": confirm_timeout,
                "config_hash": config_hash,
            },
        )

    async def rollback(self, reason: str = "") -> WorkflowStepResult:
        """Rollback configuration changes.

        Args:
            reason: Reason for rollback.

        Returns:
            Step result.
        """
        logger.warning(
            "Workflow %s: Rolling back configuration - %s",
            self.workflow_id[:8], reason
        )

        # Simulate NETCONF discard-changes and restore
        await asyncio.sleep(0.2)

        # Add audit entry
        self._add_audit_entry(
            step=WorkflowStep.EDIT_CONFIG,
            action="ROLLBACK",
            user="system",
            details={"reason": reason}
        )

        return WorkflowStepResult(
            step=WorkflowStep.EDIT_CONFIG,
            success=True,
            message=f"Rollback successful: {reason}",
            output={"rollback": True, "reason": reason},
        )

    async def unlock_datastore(
        self,
        datastore: DatastoreType
    ) -> WorkflowStepResult:
        """Unlock a NETCONF datastore.

        Args:
            datastore: Datastore to unlock.

        Returns:
            Step result.
        """
        logger.info(
            "Workflow %s: Unlocking datastore %s",
            self.workflow_id[:8], datastore.value
        )

        # Simulate NETCONF unlock operation
        await asyncio.sleep(0.1)

        # Add audit entry
        self._add_audit_entry(
            step=WorkflowStep.UNLOCK,
            action="UNLOCK_DATASTORE",
            user="system",
            details={"datastore": datastore.value}
        )

        self._lock_acquired = False

        return WorkflowStepResult(
            step=WorkflowStep.UNLOCK,
            success=True,
            message=f"Successfully unlocked {datastore.value} datastore",
            output={"datastore": datastore.value},
        )

    async def _initialize(self, user: str) -> Dict[str, Any]:
        """Initialize workflow and retrieve original configuration.

        Args:
            user: User initializing the workflow.

        Returns:
            Initialization result.
        """
        logger.info(
            "Workflow %s: Initializing for user %s",
            self.workflow_id[:8], user
        )

        # Simulate getting original config from device
        await asyncio.sleep(0.1)

        # Add audit entry
        self._add_audit_entry(
            step=WorkflowStep.INITIALIZE,
            action="WORKFLOW_START",
            user=user,
            details={"ne_id": self.ne_id}
        )

        return {"initialized": True, "ne_id": self.ne_id}

    async def _verify_config(self, expected_config: str) -> Dict[str, Any]:
        """Verify configuration was applied correctly.

        Args:
            expected_config: Expected configuration content.

        Returns:
            Verification result.
        """
        logger.info(
            "Workflow %s: Verifying configuration",
            self.workflow_id[:8]
        )

        # Simulate get-config and comparison
        await asyncio.sleep(0.2)

        expected_hash = hashlib.sha256(expected_config.encode()).hexdigest()

        # Add audit entry
        self._add_audit_entry(
            step=WorkflowStep.VERIFY,
            action="VERIFY_CONFIG",
            user="system",
            config_hash=expected_hash,
            details={"verified": True}
        )

        return {
            "verified": True,
            "expected_hash": expected_hash,
        }

    async def _request_approval(
        self,
        user: str,
        approvers: List[str]
    ) -> ApprovalRequest:
        """Request approval for configuration changes.

        Args:
            user: User requesting approval.
            approvers: List of required approvers.

        Returns:
            Approval request.
        """
        approval = ApprovalRequest(
            workflow_id=self.workflow_id,
            ne_id=self.ne_id,
            config_content=self._config,
            requested_by=user,
            approvers=approvers,
        )

        # Add audit entry
        self._add_audit_entry(
            step=WorkflowStep.INITIALIZE,
            action="APPROVAL_REQUESTED",
            user=user,
            config_hash=approval.config_hash,
            details={"approvers": approvers}
        )

        logger.info(
            "Workflow %s: Approval requested from %s",
            self.workflow_id[:8], approvers
        )

        # In a real implementation, this would wait for approval
        # For now, auto-approve if no approvers specified
        if not approvers:
            approval.status = ApprovalStatus.NOT_REQUIRED

        return approval

    def _add_audit_entry(
        self,
        step: WorkflowStep,
        action: str,
        user: str,
        config_hash: str = "",
        before_hash: str = "",
        after_hash: str = "",
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Add an audit log entry.

        Args:
            step: Workflow step.
            action: Action performed.
            user: User performing action.
            config_hash: Configuration hash.
            before_hash: Hash before change.
            after_hash: Hash after change.
            details: Additional details.
        """
        entry = AuditLogEntry(
            workflow_id=self.workflow_id,
            step=step,
            action=action,
            user=user,
            config_hash=config_hash,
            before_hash=before_hash,
            after_hash=after_hash,
            details=details or {},
        )
        self._audit_entries.append(entry)

    @property
    def current_step(self) -> Optional[WorkflowStep]:
        """Get current workflow step.

        Returns:
            Current step or None.
        """
        return self._current_step

    @property
    def is_active(self) -> bool:
        """Check if workflow is still active.

        Returns:
            True if workflow is active.
        """
        return self.state in (
            WorkflowState.PENDING,
            WorkflowState.INITIALIZING,
            WorkflowState.LOCKING,
            WorkflowState.EDITING,
            WorkflowState.VALIDATING,
            WorkflowState.COMMITTING,
            WorkflowState.CONFIRMING,
            WorkflowState.UNLOCKING,
        )

    def get_audit_log(self) -> List[Dict[str, Any]]:
        """Get workflow audit log.

        Returns:
            List of audit entries.
        """
        return [e.to_dict() for e in self._audit_entries]


# =============================================================================
# Workflow Manager
# =============================================================================


class WorkflowManager:
    """Manages multiple concurrent configuration workflows.

    Provides workflow lifecycle management, tracking, and cleanup.

    Attributes:
        active_workflows: Dictionary of active workflows.

    Example:
        >>> manager = WorkflowManager()
        >>> workflow = await manager.create_workflow(ne_id="router-001")
        >>> result = await manager.execute_workflow(workflow, config, user)
    """

    def __init__(self, max_concurrent: int = 10) -> None:
        """Initialize workflow manager.

        Args:
            max_concurrent: Maximum concurrent workflows.
        """
        self.max_concurrent = max_concurrent
        self._active_workflows: Dict[str, ConfigWorkflow] = {}
        self._workflow_history: Dict[str, WorkflowResult] = {}
        self._lock = asyncio.Lock()

        logger.info("WorkflowManager initialized with max_concurrent=%d", max_concurrent)

    async def create_workflow(self, ne_id: str) -> ConfigWorkflow:
        """Create a new configuration workflow.

        Args:
            ne_id: Network element identifier.

        Returns:
            Created workflow.

        Raises:
            WorkflowError: If max concurrent workflows reached.
        """
        async with self._lock:
            if len(self._active_workflows) >= self.max_concurrent:
                raise WorkflowError(
                    f"Maximum concurrent workflows ({self.max_concurrent}) reached",
                    "",
                    details={"active_count": len(self._active_workflows)}
                )

            workflow = ConfigWorkflow(ne_id=ne_id)
            self._active_workflows[workflow.workflow_id] = workflow

            logger.info(
                "Created workflow %s for NE %s",
                workflow.workflow_id[:8], ne_id
            )

            return workflow

    async def execute_workflow(
        self,
        workflow: ConfigWorkflow,
        config: str,
        user: str,
        **kwargs: Any
    ) -> WorkflowResult:
        """Execute a workflow.

        Args:
            workflow: Workflow to execute.
            config: Configuration content.
            user: User executing the workflow.
            kwargs: Additional workflow arguments.

        Returns:
            Workflow result.
        """
        try:
            result = await workflow.execute_workflow(
                config_content=config,
                user=user,
                **kwargs
            )

            # Store result in history
            async with self._lock:
                self._workflow_history[workflow.workflow_id] = result
                self._active_workflows.pop(workflow.workflow_id, None)

            return result

        except Exception as e:
            async with self._lock:
                self._active_workflows.pop(workflow.workflow_id, None)
            raise

    async def cancel_workflow(self, workflow_id: str) -> bool:
        """Cancel an active workflow.

        Args:
            workflow_id: Workflow identifier.

        Returns:
            True if cancelled.
        """
        async with self._lock:
            workflow = self._active_workflows.get(workflow_id)
            if not workflow:
                return False

            workflow.state = WorkflowState.CANCELLED
            self._active_workflows.pop(workflow_id, None)

            logger.info("Cancelled workflow %s", workflow_id[:8])
            return True

    async def get_workflow(self, workflow_id: str) -> Optional[ConfigWorkflow]:
        """Get an active workflow by ID.

        Args:
            workflow_id: Workflow identifier.

        Returns:
            Workflow or None.
        """
        return self._active_workflows.get(workflow_id)

    async def get_workflow_result(self, workflow_id: str) -> Optional[WorkflowResult]:
        """Get a completed workflow result.

        Args:
            workflow_id: Workflow identifier.

        Returns:
            Result or None.
        """
        return self._workflow_history.get(workflow_id)

    def get_active_count(self) -> int:
        """Get count of active workflows.

        Returns:
            Active workflow count.
        """
        return len(self._active_workflows)

    def get_stats(self) -> Dict[str, Any]:
        """Get workflow manager statistics.

        Returns:
            Statistics dictionary.
        """
        return {
            "active_workflows": len(self._active_workflows),
            "max_concurrent": self.max_concurrent,
            "total_completed": len(self._workflow_history),
            "active_workflow_ids": [
                wf_id[:8] for wf_id in self._active_workflows.keys()
            ],
        }

    async def cleanup_expired(self, max_age_hours: int = 24) -> int:
        """Clean up expired workflow history.

        Args:
            max_age_hours: Maximum age in hours.

        Returns:
            Number of cleaned up workflows.
        """
        async with self._lock:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
            expired = [
                wf_id for wf_id, result in self._workflow_history.items()
                if result.completed_at and result.completed_at < cutoff
            ]

            for wf_id in expired:
                del self._workflow_history[wf_id]

            if expired:
                logger.info("Cleaned up %d expired workflow results", len(expired))

            return len(expired)
