"""
Unit tests for Configuration Workflow module.

Tests cover NETCONF 7-step workflow, confirmed-commit, and rollback.
"""

import asyncio
import hashlib
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from unified_oss.fcaps.configuration.workflow import (
    ConfigWorkflow,
    WorkflowResult,
    WorkflowStepResult,
    AuditLogEntry,
    ApprovalRequest,
    WorkflowState,
    WorkflowStep,
    DatastoreType,
    CommitMode,
    ApprovalStatus,
    WorkflowError,
    LockFailedError,
    ValidationError,
    CommitFailedError,
    TimeoutError as WorkflowTimeoutError,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def config_workflow():
    """Create a ConfigWorkflow instance for testing."""
    return ConfigWorkflow(ne_id="router-001")


@pytest.fixture
def sample_config_xml():
    """Create sample configuration XML."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<config>
    <system>
        <hostname>router-001</hostname>
        <timezone>UTC</timezone>
    </system>
    <interfaces>
        <interface>
            <name>eth0</name>
            <ip-address>192.168.1.1</ip-address>
            <enabled>true</enabled>
        </interface>
    </interfaces>
</config>
"""


@pytest.fixture
def invalid_config_xml():
    """Create invalid configuration XML."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<config>
    <system>
        <hostname>router-001</hostname>
        <!-- Missing closing tag -->
"""


# =============================================================================
# ConfigWorkflow Tests
# =============================================================================

class TestConfigWorkflow:
    """Tests for ConfigWorkflow class."""

    def test_workflow_initialization(self, config_workflow):
        """Test workflow initialization."""
        assert config_workflow.ne_id == "router-001"
        assert config_workflow.state == WorkflowState.PENDING

    @pytest.mark.asyncio
    async def test_execute_workflow_standard(self, config_workflow, sample_config_xml):
        """Test executing standard workflow."""
        result = await config_workflow.execute_workflow(
            config_content=sample_config_xml,
            user="admin",
        )
        
        assert result.state == WorkflowState.COMPLETED
        assert len(result.step_results) > 0

    @pytest.mark.asyncio
    async def test_execute_workflow_confirmed_commit(self, config_workflow, sample_config_xml):
        """Test executing workflow with confirmed commit."""
        result = await config_workflow.execute_workflow(
            config_content=sample_config_xml,
            user="admin",
            confirmed_commit=True,
            confirm_timeout=300,
        )
        
        assert result.state == WorkflowState.COMPLETED

    @pytest.mark.asyncio
    async def test_execute_workflow_validate_only(self, config_workflow, sample_config_xml):
        """Test executing workflow in validate-only mode."""
        result = await config_workflow.execute_workflow(
            config_content=sample_config_xml,
            user="admin",
            validate_only=True,
        )
        
        assert result.state == WorkflowState.COMPLETED
        # Should not have all steps
        steps = [r.step for r in result.step_results]
        assert WorkflowStep.COMMIT not in steps

    @pytest.mark.asyncio
    async def test_execute_workflow_invalid_config(self, config_workflow, invalid_config_xml):
        """Test executing workflow with invalid configuration."""
        result = await config_workflow.execute_workflow(
            config_content=invalid_config_xml,
            user="admin",
        )
        
        # Should fail during validation
        assert result.state in [WorkflowState.FAILED, WorkflowState.ROLLING_BACK]

    @pytest.mark.asyncio
    async def test_execute_workflow_with_approval(self, config_workflow, sample_config_xml):
        """Test executing workflow requiring approval."""
        result = await config_workflow.execute_workflow(
            config_content=sample_config_xml,
            user="admin",
            require_approval=True,
            approvers=["approver-1", "approver-2"],
        )
        
        # Should be pending approval
        assert result.state == WorkflowState.PENDING

    @pytest.mark.asyncio
    async def test_lock_datastore(self, config_workflow):
        """Test locking datastore."""
        result = await config_workflow.lock_datastore(DatastoreType.CANDIDATE)
        
        assert result.success is True
        assert "candidate" in result.message.lower()

    @pytest.mark.asyncio
    async def test_unlock_datastore(self, config_workflow):
        """Test unlocking datastore."""
        await config_workflow.lock_datastore(DatastoreType.CANDIDATE)
        result = await config_workflow.unlock_datastore(DatastoreType.CANDIDATE)
        
        assert result.success is True

    @pytest.mark.asyncio
    async def test_edit_config(self, config_workflow, sample_config_xml):
        """Test editing configuration."""
        result = await config_workflow.edit_config(sample_config_xml, operation="merge")
        
        assert result.success is True

    @pytest.mark.asyncio
    async def test_validate_valid_config(self, config_workflow, sample_config_xml):
        """Test validating valid configuration."""
        result = await config_workflow.validate(sample_config_xml)
        
        assert result.success is True

    @pytest.mark.asyncio
    async def test_validate_invalid_config(self, config_workflow, invalid_config_xml):
        """Test validating invalid configuration."""
        result = await config_workflow.validate(invalid_config_xml)
        
        assert result.success is False
        assert len(result.errors) > 0

    @pytest.mark.asyncio
    async def test_commit(self, config_workflow, sample_config_xml):
        """Test committing configuration."""
        await config_workflow.edit_config(sample_config_xml)
        result = await config_workflow.commit()
        
        assert result.success is True

    @pytest.mark.asyncio
    async def test_confirmed_commit(self, config_workflow, sample_config_xml):
        """Test confirmed commit."""
        await config_workflow.edit_config(sample_config_xml)
        result = await config_workflow.commit(
            confirmed=True,
            confirm_timeout=300
        )
        
        assert result.success is True
        assert result.output.get("confirmed") is True

    @pytest.mark.asyncio
    async def test_rollback(self, config_workflow, sample_config_xml):
        """Test rollback operation."""
        result = await config_workflow.rollback(reason="Test rollback")
        
        assert result.success is True

    def test_add_audit_entry(self, config_workflow):
        """Test adding audit entry."""
        config_workflow._add_audit_entry(
            step=WorkflowStep.EDIT_CONFIG,
            action="TEST",
            user="test_user",
            config_hash="abc123",
        )
        
        assert len(config_workflow._audit_entries) == 1


# =============================================================================
# WorkflowResult Tests
# =============================================================================

class TestWorkflowResult:
    """Tests for WorkflowResult dataclass."""

    def test_result_creation(self):
        """Test creating workflow result."""
        result = WorkflowResult(
            workflow_id="workflow-001",
            state=WorkflowState.COMPLETED,
            ne_id="router-001",
        )
        
        assert result.state == WorkflowState.COMPLETED
        assert result.rollback_performed is False

    def test_result_to_dict(self):
        """Test result serialization."""
        result = WorkflowResult(
            workflow_id="workflow-001",
            state=WorkflowState.COMPLETED,
            ne_id="router-001",
        )
        
        result_dict = result.to_dict()
        
        assert "workflow_id" in result_dict
        assert "state" in result_dict
        assert result_dict["state"] == "completed"


# =============================================================================
# WorkflowStepResult Tests
# =============================================================================

class TestWorkflowStepResult:
    """Tests for WorkflowStepResult dataclass."""

    def test_step_result_success(self):
        """Test successful step result."""
        result = WorkflowStepResult(
            step=WorkflowStep.LOCK,
            success=True,
            message="Lock successful",
        )
        
        assert result.success is True
        assert len(result.errors) == 0

    def test_step_result_failure(self):
        """Test failed step result."""
        result = WorkflowStepResult(
            step=WorkflowStep.VALIDATE,
            success=False,
            errors=["Invalid configuration"],
        )
        
        assert result.success is False
        assert len(result.errors) == 1

    def test_step_result_to_dict(self):
        """Test step result serialization."""
        result = WorkflowStepResult(
            step=WorkflowStep.COMMIT,
            success=True,
            message="Commit successful",
        )
        
        result_dict = result.to_dict()
        
        assert "step" in result_dict
        assert "success" in result_dict


# =============================================================================
# AuditLogEntry Tests
# =============================================================================

class TestAuditLogEntry:
    """Tests for AuditLogEntry dataclass."""

    def test_entry_creation(self):
        """Test creating audit log entry."""
        entry = AuditLogEntry(
            workflow_id="workflow-001",
            step=WorkflowStep.EDIT_CONFIG,
            action="EDIT_CONFIG",
            user="admin",
        )
        
        assert entry.workflow_id == "workflow-001"
        assert entry.user == "admin"

    def test_entry_hash_calculation(self):
        """Test calculating hash in audit entry."""
        entry = AuditLogEntry()
        
        content = "test content"
        hash_value = entry.calculate_hash(content)
        
        expected = hashlib.sha256(content.encode()).hexdigest()
        assert hash_value == expected

    def test_entry_to_dict(self):
        """Test entry serialization."""
        entry = AuditLogEntry(
            workflow_id="workflow-001",
            step=WorkflowStep.LOCK,
            action="LOCK",
            user="admin",
        )
        
        entry_dict = entry.to_dict()
        
        assert "workflow_id" in entry_dict
        assert "timestamp" in entry_dict


# =============================================================================
# ApprovalRequest Tests
# =============================================================================

class TestApprovalRequest:
    """Tests for ApprovalRequest dataclass."""

    def test_request_creation(self):
        """Test creating approval request."""
        request = ApprovalRequest(
            workflow_id="workflow-001",
            ne_id="router-001",
            config_content="<config/>",
            requested_by="admin",
            approvers=["approver-1"],
        )
        
        assert request.status == ApprovalStatus.PENDING

    def test_request_expiry(self):
        """Test approval request expiry."""
        request = ApprovalRequest(
            workflow_id="workflow-001",
            ne_id="router-001",
            config_content="<config/>",
            requested_by="admin",
            approvers=["approver-1"],
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        
        assert request.is_expired() is True

    def test_add_approval(self):
        """Test adding approval."""
        request = ApprovalRequest(
            workflow_id="workflow-001",
            ne_id="router-001",
            config_content="<config/>",
            requested_by="admin",
            approvers=["approver-1"],
        )
        
        request.add_approval("approver-1", "Looks good")
        
        assert request.status == ApprovalStatus.APPROVED

    def test_add_rejection(self):
        """Test adding rejection."""
        request = ApprovalRequest(
            workflow_id="workflow-001",
            ne_id="router-001",
            config_content="<config/>",
            requested_by="admin",
            approvers=["approver-1"],
        )
        
        request.add_rejection("approver-1", "Not approved")
        
        assert request.status == ApprovalStatus.REJECTED

    def test_is_approved(self):
        """Test checking if approved."""
        request = ApprovalRequest(
            workflow_id="workflow-001",
            ne_id="router-001",
            config_content="<config/>",
            requested_by="admin",
            approvers=["approver-1"],
        )
        
        assert not request.is_approved()
        
        request.add_approval("approver-1", "Approved")
        assert request.is_approved()


# =============================================================================
# WorkflowState Tests
# =============================================================================

class TestWorkflowState:
    """Tests for WorkflowState enum."""

    def test_state_values(self):
        """Test state enum values."""
        assert WorkflowState.PENDING.value == "pending"
        assert WorkflowState.COMPLETED.value == "completed"
        assert WorkflowState.FAILED.value == "failed"

    def test_state_ordering(self):
        """Test logical state transitions."""
        # Normal flow
        states = [
            WorkflowState.PENDING,
            WorkflowState.INITIALIZING,
            WorkflowState.LOCKING,
            WorkflowState.EDITING,
            WorkflowState.VALIDATING,
            WorkflowState.COMMITTING,
            WorkflowState.COMPLETED,
        ]
        
        for i, state in enumerate(states):
            if i > 0:
                # Each state should be different
                assert state != states[i-1]


# =============================================================================
# WorkflowStep Tests
# =============================================================================

class TestWorkflowStep:
    """Tests for WorkflowStep enum."""

    def test_ordered_steps(self):
        """Test getting ordered steps."""
        steps = WorkflowStep.get_ordered_steps()
        
        assert len(steps) == 7
        assert steps[0] == WorkflowStep.INITIALIZE
        assert steps[-1] == WorkflowStep.UNLOCK

    def test_step_values(self):
        """Test step enum values."""
        assert WorkflowStep.LOCK.value == "lock"
        assert WorkflowStep.EDIT_CONFIG.value == "edit_config"
        assert WorkflowStep.COMMIT.value == "commit"


# =============================================================================
# Exception Tests
# =============================================================================

class TestWorkflowExceptions:
    """Tests for workflow exception classes."""

    def test_workflow_error(self):
        """Test base workflow error."""
        error = WorkflowError(
            message="Test error",
            workflow_id="workflow-001",
        )
        
        assert str(error) == "Test error"
        assert error.workflow_id == "workflow-001"

    def test_lock_failed_error(self):
        """Test lock failed error."""
        error = LockFailedError(
            workflow_id="workflow-001",
            datastore="candidate",
        )
        
        assert "candidate" in str(error)
        assert error.datastore == "candidate"

    def test_validation_error(self):
        """Test validation error."""
        error = ValidationError(
            workflow_id="workflow-001",
            errors=["Error 1", "Error 2"],
        )
        
        assert error.validation_errors == ["Error 1", "Error 2"]

    def test_commit_failed_error(self):
        """Test commit failed error."""
        error = CommitFailedError(
            workflow_id="workflow-001",
            reason="Device rejected",
        )
        
        assert error.reason == "Device rejected"

    def test_timeout_error(self):
        """Test timeout error."""
        error = WorkflowTimeoutError(
            workflow_id="workflow-001",
            timeout_seconds=30.0,
        )
        
        assert error.timeout_seconds == 30.0


# =============================================================================
# Integration Tests
# =============================================================================

class TestWorkflowIntegration:
    """Integration tests for configuration workflow."""

    @pytest.mark.asyncio
    async def test_full_workflow_execution(self, sample_config_xml):
        """Test complete workflow execution."""
        workflow = ConfigWorkflow(ne_id="router-001")
        
        result = await workflow.execute_workflow(
            config_content=sample_config_xml,
            user="admin",
            operation="merge",
        )
        
        assert result.state == WorkflowState.COMPLETED
        assert len(result.step_results) >= 7
        assert len(result.audit_entries) > 0

    @pytest.mark.asyncio
    async def test_workflow_with_failure_and_rollback(self, invalid_config_xml):
        """Test workflow with failure and rollback."""
        workflow = ConfigWorkflow(ne_id="router-001")
        
        result = await workflow.execute_workflow(
            config_content=invalid_config_xml,
            user="admin",
        )
        
        # Should have failed
        assert result.state in [WorkflowState.FAILED, WorkflowState.ROLLING_BACK]
        
        # Should have error details
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_concurrent_workflows(self, sample_config_xml):
        """Test concurrent workflow executions."""
        workflows = [
            ConfigWorkflow(ne_id=f"router-{i}")
            for i in range(5)
        ]
        
        tasks = [
            w.execute_workflow(
                config_content=sample_config_xml,
                user="admin"
            )
            for w in workflows
        ]
        
        results = await asyncio.gather(*tasks)
        
        assert len(results) == 5
        assert all(r.state == WorkflowState.COMPLETED for r in results)


# =============================================================================
# Performance Tests
# =============================================================================

class TestWorkflowPerformance:
    """Performance tests for workflow execution."""

    @pytest.mark.asyncio
    async def test_workflow_duration(self, config_workflow, sample_config_xml):
        """Test workflow execution duration."""
        import time
        
        start_time = time.time()
        await config_workflow.execute_workflow(
            config_content=sample_config_xml,
            user="admin",
        )
        duration = time.time() - start_time
        
        # Should complete within reasonable time
        assert duration < 5.0

    @pytest.mark.asyncio
    async def test_large_config_workflow(self, config_workflow):
        """Test workflow with large configuration."""
        # Generate large config
        interfaces = []
        for i in range(100):
            interfaces.append(f"""
                <interface>
                    <name>eth{i}</name>
                    <ip-address>192.168.{i}.1</ip-address>
                </interface>
            """)
        
        config = f"""<?xml version="1.0"?>
<config>
    <interfaces>
        {''.join(interfaces)}
    </interfaces>
</config>"""
        
        result = await config_workflow.execute_workflow(
            config_content=config,
            user="admin",
        )
        
        assert result.state == WorkflowState.COMPLETED


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
