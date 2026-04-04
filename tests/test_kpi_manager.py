"""
Unit tests for KPI Manager module.

Tests cover KPI catalog management, computation, subscriptions, and
historical data retrieval.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from unified_oss.fcaps.performance.kpi_manager import (
    KPIManager,
    KPIResult,
    KPIDefinition,
    KPICategory,
    KPIAggregation,
    KPISubscription,
    SubscriptionStatus,
    DashboardData,
)
from unified_oss.fcaps.performance.computation import (
    KPIComputer,
    CounterMapper,
    FormulaEvaluator,
    ComputationResult,
    QualityFlag,
    CounterType,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
async def kpi_manager():
    """Create a KPIManager instance for testing."""
    manager = KPIManager()
    yield manager
    await manager.close()


@pytest.fixture
def kpi_computer():
    """Create a KPIComputer instance for testing."""
    return KPIComputer()


@pytest.fixture
def counter_mapper():
    """Create a CounterMapper instance for testing."""
    return CounterMapper()


@pytest.fixture
def formula_evaluator():
    """Create a FormulaEvaluator instance for testing."""
    return FormulaEvaluator()


@pytest.fixture
def sample_counters():
    """Create sample counter values for testing."""
    return {
        "rrc_conn_attempts": 1000,
        "rrc_conn_success": 980,
        "ho_attempts": 500,
        "ho_success": 490,
        "erab_setup_attempts": 2000,
        "erab_setup_success": 1950,
    }


@pytest.fixture
def sample_kpi_definition():
    """Create a sample KPI definition."""
    return KPIDefinition(
        kpi_id="test_kpi",
        name="Test KPI",
        description="Test KPI for unit testing",
        category=KPICategory.QUALITY,
        unit="%",
        formula="(success / attempts) * 100",
        vendor_mappings={
            "ericsson": {"success": "pmSuccess", "attempts": "pmAttempts"},
            "huawei": {"success": "VS.Success", "attempts": "VS.Attempts"},
        },
        thresholds={"warning": 95.0, "critical": 90.0},
    )


# =============================================================================
# KPIManager Tests
# =============================================================================

class TestKPIManager:
    """Tests for KPIManager class."""

    def test_catalog_initialization(self, kpi_manager):
        """Test that KPI catalog is initialized with predefined KPIs."""
        kpis = kpi_manager.catalog.get_all_kpis()
        
        assert len(kpis) > 0
        # Should have common telecom KPIs
        kpi_ids = [k.kpi_id for k in kpis]
        assert "rrc_success_rate" in kpi_ids

    @pytest.mark.asyncio
    async def test_get_kpi(self, kpi_manager):
        """Test getting KPI value."""
        result = await kpi_manager.get_kpi("rrc_success_rate", ne_id="router-001")
        
        assert result is not None
        assert result.kpi_id == "rrc_success_rate"
        assert result.unit == "%"

    @pytest.mark.asyncio
    async def test_get_kpi_not_found(self, kpi_manager):
        """Test getting non-existent KPI."""
        result = await kpi_manager.get_kpi("non_existent_kpi")
        
        assert result is None

    @pytest.mark.asyncio
    async def test_compute_kpi(self, kpi_manager):
        """Test KPI computation."""
        result = await kpi_manager.compute_kpi("rrc_success_rate", ne_id="router-001")
        
        assert result is not None
        assert result.value is not None
        assert 0 <= result.value <= 100  # Should be percentage

    @pytest.mark.asyncio
    async def test_subscribe_kpi(self, kpi_manager):
        """Test KPI subscription."""
        callback = AsyncMock()
        
        subscription = await kpi_manager.subscribe_kpi(
            kpi_ids=["rrc_success_rate"],
            callback=callback,
            ne_ids=["router-001"],
            interval=60,
        )
        
        assert subscription is not None
        assert subscription.status == SubscriptionStatus.ACTIVE

    @pytest.mark.asyncio
    async def test_unsubscribe(self, kpi_manager):
        """Test KPI unsubscription."""
        callback = AsyncMock()
        
        subscription = await kpi_manager.subscribe_kpi(
            kpi_ids=["rrc_success_rate"],
            callback=callback,
        )
        
        result = await kpi_manager.unsubscribe(subscription.subscription_id)
        
        assert result is True

    @pytest.mark.asyncio
    async def test_get_kpi_history(self, kpi_manager):
        """Test getting KPI history."""
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=1)
        
        history = await kpi_manager.get_kpi_history(
            kpi_id="rrc_success_rate",
            start_time=start_time,
            end_time=end_time,
            ne_id="router-001",
        )
        
        assert isinstance(history, list)

    def test_get_catalog_kpis(self, kpi_manager):
        """Test getting KPIs from catalog."""
        kpis = kpi_manager.catalog.get_all_kpis()
        
        assert len(kpis) > 0

    def test_get_kpis_by_category(self, kpi_manager):
        """Test filtering KPIs by category."""
        kpis = kpi_manager.catalog.get_kpis_by_category(KPICategory.MOBILITY)
        
        for kpi in kpis:
            assert kpi.category == KPICategory.MOBILITY

    def test_search_kpis(self, kpi_manager):
        """Test searching KPIs."""
        results = kpi_manager.catalog.search_kpis("success")
        
        assert len(results) > 0
        for kpi in results:
            assert "success" in kpi.name.lower() or "success" in kpi.kpi_id.lower()


# =============================================================================
# KPIComputer Tests
# =============================================================================

class TestKPIComputer:
    """Tests for KPIComputer class."""

    @pytest.mark.asyncio
    async def test_compute_success_rate(self, kpi_computer, sample_counters):
        """Test computing success rate KPI."""
        result = await kpi_computer.compute(
            "rrc_success_rate",
            sample_counters
        )
        
        assert result.quality_flag == QualityFlag.NORMAL
        assert result.value is not None
        assert 0 <= result.value <= 100

    @pytest.mark.asyncio
    async def test_compute_with_zero_denominator(self, kpi_computer):
        """Test computing KPI with zero denominator."""
        counters = {
            "rrc_conn_attempts": 0,
            "rrc_conn_success": 0,
        }
        
        result = await kpi_computer.compute(
            "rrc_success_rate",
            counters
        )
        
        assert result.quality_flag == QualityFlag.ZERO_DENOMINATOR

    @pytest.mark.asyncio
    async def test_compute_with_missing_counters(self, kpi_computer):
        """Test computing KPI with missing counters."""
        counters = {}
        
        result = await kpi_computer.compute(
            "rrc_success_rate",
            counters
        )
        
        assert result.quality_flag == QualityFlag.NO_DATA

    @pytest.mark.asyncio
    async def test_compute_with_vendor_mapping(self, kpi_computer):
        """Test computing KPI with vendor-specific counters."""
        vendor_counters = {
            "pmRrcConnEstabAtt": 1000,
            "pmRrcConnEstabSuccess": 950,
        }
        
        result = await kpi_computer.compute(
            "rrc_success_rate",
            vendor_counters,
            vendor="ericsson"
        )
        
        assert result.value is not None

    def test_get_supported_kpis(self, kpi_computer):
        """Test getting list of supported KPIs."""
        kpis = kpi_computer.get_supported_kpis()
        
        assert len(kpis) > 0

    def test_add_kpi_formula(self, kpi_computer):
        """Test adding custom KPI formula."""
        kpi_computer.add_kpi_formula(
            kpi_name="custom_kpi",
            formula="(a + b) / 2",
            unit="count",
            description="Custom KPI"
        )
        
        kpis = kpi_computer.get_supported_kpis()
        assert "custom_kpi" in kpis

    def test_check_denominator(self, kpi_computer):
        """Test denominator check."""
        formula = "(success / attempts) * 100"
        counters = {"attempts": 0, "success": 100}
        
        result = kpi_computer.check_denominator(formula, counters)
        
        assert result is False

    def test_evaluate_formula(self, kpi_computer):
        """Test formula evaluation."""
        value, flag = kpi_computer.evaluate_formula(
            "(980 / 1000) * 100",
            {"dummy": 1}
        )
        
        assert value == 98.0
        assert flag == QualityFlag.NORMAL


# =============================================================================
# CounterMapper Tests
# =============================================================================

class TestCounterMapper:
    """Tests for CounterMapper class."""

    def test_map_ericsson_counters(self, counter_mapper):
        """Test mapping Ericsson counters."""
        vendor_counters = {
            "pmRrcConnEstabAtt": 1000,
            "pmRrcConnEstabSuccess": 980,
            "pmHoAtt": 500,
        }
        
        mapped = counter_mapper.map_counters("ericsson", vendor_counters)
        
        assert "rrc_conn_attempts" in mapped
        assert mapped["rrc_conn_attempts"] == 1000

    def test_map_huawei_counters(self, counter_mapper):
        """Test mapping Huawei counters."""
        vendor_counters = {
            "VS.RRC.ConnEstab.Att": 1000,
            "VS.RRC.ConnEstab.Success": 980,
        }
        
        mapped = counter_mapper.map_counters("huawei", vendor_counters)
        
        assert "rrc_conn_attempts" in mapped

    def test_map_nokia_counters(self, counter_mapper):
        """Test mapping Nokia counters."""
        vendor_counters = {
            "RRC_CONN_ESTAB_ATT": 1000,
            "RRC_CONN_ESTAB_SUCCESS": 980,
        }
        
        mapped = counter_mapper.map_counters("nokia", vendor_counters)
        
        assert "rrc_conn_attempts" in mapped

    def test_map_unknown_counter(self, counter_mapper):
        """Test mapping unknown counter."""
        vendor_counters = {
            "unknownCounter": 123,
        }
        
        mapped = counter_mapper.map_counters("ericsson", vendor_counters)
        
        # Should keep original name if no mapping
        assert "unknownCounter" in mapped

    def test_get_vendor_counter_name(self, counter_mapper):
        """Test getting vendor-specific counter name."""
        vendor_name = counter_mapper.get_vendor_counter_name(
            "rrc_conn_attempts",
            "ericsson"
        )
        
        assert vendor_name == "pmRrcConnEstabAtt"

    def test_add_mapping(self, counter_mapper):
        """Test adding custom counter mapping."""
        from unified_oss.fcaps.performance.computation import CounterMapping
        
        mapping = CounterMapping(
            cim_name="test_counter",
            vendor="custom_vendor",
            vendor_name="customCounter",
        )
        
        counter_mapper.add_mapping(mapping)
        
        # Should be able to map new counter
        mapped = counter_mapper.map_counters(
            "custom_vendor",
            {"customCounter": 100}
        )
        assert "test_counter" in mapped

    def test_get_supported_vendors(self, counter_mapper):
        """Test getting list of supported vendors."""
        vendors = counter_mapper.get_supported_vendors()
        
        assert "ericsson" in vendors
        assert "huawei" in vendors
        assert "nokia" in vendors


# =============================================================================
# FormulaEvaluator Tests
# =============================================================================

class TestFormulaEvaluator:
    """Tests for FormulaEvaluator class."""

    def test_evaluate_simple_formula(self, formula_evaluator):
        """Test evaluating simple formula."""
        value, error = formula_evaluator.evaluate(
            "(100 / 200) * 100",
            {}
        )
        
        assert value == 50.0
        assert error is None

    def test_evaluate_with_variables(self, formula_evaluator):
        """Test evaluating formula with variables."""
        value, error = formula_evaluator.evaluate(
            "(success / attempts) * 100",
            {"success": 980, "attempts": 1000}
        )
        
        assert value == 98.0
        assert error is None

    def test_evaluate_division_by_zero(self, formula_evaluator):
        """Test handling division by zero."""
        value, error = formula_evaluator.evaluate(
            "(success / 0) * 100",
            {"success": 100}
        )
        
        assert value is None
        assert "zero" in error.lower()

    def test_validate_formula(self, formula_evaluator):
        """Test formula validation."""
        is_valid, variables = formula_evaluator.validate_formula(
            "(a / b) * 100"
        )
        
        assert is_valid is True
        assert "a" in variables
        assert "b" in variables

    def test_validate_invalid_formula(self, formula_evaluator):
        """Test validating invalid formula."""
        is_valid, errors = formula_evaluator.validate_formula(
            "((a + b"  # Unbalanced parentheses
        )
        
        assert is_valid is False

    def test_evaluate_with_function(self, formula_evaluator):
        """Test evaluating formula with function."""
        value, error = formula_evaluator.evaluate(
            "abs(-50)",
            {}
        )
        
        assert value == 50.0

    def test_evaluate_with_round(self, formula_evaluator):
        """Test evaluating formula with round function."""
        value, error = formula_evaluator.evaluate(
            "round(98.567, 2)",
            {}
        )
        
        assert value == 98.57


# =============================================================================
# KPIResult Tests
# =============================================================================

class TestKPIResult:
    """Tests for KPIResult dataclass."""

    def test_result_creation(self):
        """Test creating KPI result."""
        result = KPIResult(
            kpi_id="test_kpi",
            value=95.5,
            unit="%",
            timestamp=datetime.now(timezone.utc),
            ne_id="router-001",
        )
        
        assert result.kpi_id == "test_kpi"
        assert result.value == 95.5
        assert result.quality_flag == "NORMAL"

    def test_result_to_dict(self):
        """Test result serialization."""
        result = KPIResult(
            kpi_id="test_kpi",
            value=95.5,
            unit="%",
            timestamp=datetime.now(timezone.utc),
        )
        
        result_dict = result.to_dict()
        
        assert "kpi_id" in result_dict
        assert "value" in result_dict
        assert "timestamp" in result_dict


# =============================================================================
# KPIDefinition Tests
# =============================================================================

class TestKPIDefinition:
    """Tests for KPIDefinition dataclass."""

    def test_definition_creation(self, sample_kpi_definition):
        """Test creating KPI definition."""
        assert sample_kpi_definition.kpi_id == "test_kpi"
        assert sample_kpi_definition.category == KPICategory.QUALITY

    def test_definition_to_dict(self, sample_kpi_definition):
        """Test definition serialization."""
        def_dict = sample_kpi_definition.to_dict()
        
        assert "kpi_id" in def_dict
        assert "formula" in def_dict
        assert "vendor_mappings" in def_dict


# =============================================================================
# KPISubscription Tests
# =============================================================================

class TestKPISubscription:
    """Tests for KPISubscription dataclass."""

    def test_subscription_creation(self):
        """Test creating subscription."""
        sub = KPISubscription(
            subscription_id="sub-001",
            kpi_ids=["kpi-1", "kpi-2"],
            interval=60,
        )
        
        assert sub.status == SubscriptionStatus.ACTIVE
        assert sub.interval == 60

    def test_subscription_expiry(self):
        """Test subscription expiry check."""
        sub = KPISubscription(
            subscription_id="sub-001",
            kpi_ids=["kpi-1"],
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        
        assert sub.is_expired() is True

    def test_subscription_should_notify(self):
        """Test subscription notification check."""
        sub = KPISubscription(
            subscription_id="sub-001",
            kpi_ids=["kpi-1"],
            status=SubscriptionStatus.ACTIVE,
        )
        
        assert sub.should_notify() is True
        
        sub.status = SubscriptionStatus.PAUSED
        assert sub.should_notify() is False

    def test_subscription_to_dict(self):
        """Test subscription serialization."""
        sub = KPISubscription(
            subscription_id="sub-001",
            kpi_ids=["kpi-1"],
        )
        
        sub_dict = sub.to_dict()
        
        assert "subscription_id" in sub_dict
        assert "kpi_ids" in sub_dict


# =============================================================================
# Integration Tests
# =============================================================================

class TestKPIIntegration:
    """Integration tests for KPI management."""

    @pytest.mark.asyncio
    async def test_full_kpi_workflow(self, kpi_manager):
        """Test complete KPI workflow."""
        # Get KPI definition
        kpi_def = kpi_manager.catalog.get_kpi("rrc_success_rate")
        assert kpi_def is not None
        
        # Compute KPI
        result = await kpi_manager.get_kpi("rrc_success_rate", ne_id="router-001")
        assert result is not None
        
        # Subscribe to KPI updates
        callback = AsyncMock()
        subscription = await kpi_manager.subscribe_kpi(
            kpi_ids=["rrc_success_rate"],
            callback=callback,
            interval=60,
        )
        assert subscription is not None

    @pytest.mark.asyncio
    async def test_multi_vendor_computation(self, kpi_computer):
        """Test KPI computation across vendors."""
        vendors = [
            ("ericsson", {"pmRrcConnEstabAtt": 1000, "pmRrcConnEstabSuccess": 950}),
            ("huawei", {"VS.RRC.ConnEstab.Att": 1000, "VS.RRC.ConnEstab.Success": 960}),
            ("nokia", {"RRC_CONN_ESTAB_ATT": 1000, "RRC_CONN_ESTAB_SUCCESS": 970}),
        ]
        
        for vendor, counters in vendors:
            result = await kpi_computer.compute(
                "rrc_success_rate",
                counters,
                vendor=vendor
            )
            assert result.value is not None


# =============================================================================
# Performance Tests
# =============================================================================

class TestKPIPerformance:
    """Performance tests for KPI management."""

    @pytest.mark.asyncio
    async def test_bulk_kpi_computation(self, kpi_manager):
        """Test computing multiple KPIs."""
        kpi_ids = kpi_manager.catalog.get_all_kpis()
        kpi_ids = [k.kpi_id for k in kpi_ids[:10]]
        
        tasks = [
            kpi_manager.get_kpi(kpi_id, ne_id="router-001")
            for kpi_id in kpi_ids
        ]
        
        import time
        start_time = time.time()
        results = await asyncio.gather(*tasks)
        duration = time.time() - start_time
        
        assert len(results) == len(kpi_ids)
        assert duration < 2.0

    @pytest.mark.asyncio
    async def test_historical_query_performance(self, kpi_manager):
        """Test historical data query performance."""
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=7)
        
        import time
        start = time.time()
        history = await kpi_manager.get_kpi_history(
            kpi_id="rrc_success_rate",
            start_time=start_time,
            end_time=end_time,
        )
        duration = time.time() - start
        
        assert duration < 1.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
