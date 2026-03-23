"""
Unit tests for KPI Manager and Computation.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch
import uuid

from unified_oss.fcaps.performance.kpi_manager import (
    KPIManager,
    KPICatalog,
    KPISubscription,
    KPIStatus,
)
from unified_oss.fcaps.performance.computation import (
    KPIComputer,
    CounterMapper,
    FormulaEvaluator,
    QualityFlag,
)


@pytest.fixture
def kpi_manager():
    """Create KPIManager instance for testing."""
    return KPIManager()


@pytest.fixture
def sample_counters():
    """Sample PM counters for testing."""
    return {
        "rrc_conn_attempts": 1000,
        "rrc_conn_successes": 950,
        "ho_attempts": 500,
        "ho_successes": 475,
        "erab_attempts": 800,
        "erab_successes": 780,
        "throughput_dl": 1500000000,
        "throughput_ul": 300000000,
        "active_users": 120,
    }


class TestKPIManager:
    """Test cases for KPIManager."""
    
    @pytest.mark.asyncio
    async def test_get_kpi_returns_value(self, kpi_manager, sample_counters):
        """Test that get_kpi returns computed value."""
        kpi = await kpi_manager.get_kpi(
            kpi_name="rrc_success_rate",
            ne_id="ENB-001",
            counters=sample_counters
        )
        
        assert kpi is not None
        assert 0 <= kpi.value <= 100
    
    @pytest.mark.asyncio
    async def test_compute_rrc_success_rate(self, kpi_manager, sample_counters):
        """Test RRC success rate computation."""
        result = await kpi_manager.compute_kpi(
            kpi_name="rrc_success_rate",
            counters=sample_counters
        )
        
        # 950/1000 * 100 = 95%
        assert result.value == pytest.approx(95.0, rel=0.01)
    
    @pytest.mark.asyncio
    async def test_compute_handover_success_rate(self, kpi_manager, sample_counters):
        """Test handover success rate computation."""
        result = await kpi_manager.compute_kpi(
            kpi_name="ho_success_rate",
            counters=sample_counters
        )
        
        # 475/500 * 100 = 95%
        assert result.value == pytest.approx(95.0, rel=0.01)
    
    @pytest.mark.asyncio
    async def test_zero_denominator_protection(self, kpi_manager):
        """Test protection against zero denominator."""
        counters = {
            "rrc_conn_attempts": 0,
            "rrc_conn_successes": 0,
        }
        
        result = await kpi_manager.compute_kpi(
            kpi_name="rrc_success_rate",
            counters=counters
        )
        
        assert result.quality_flag == QualityFlag.NO_DATA
        assert result.value is None
    
    @pytest.mark.asyncio
    async def test_subscribe_kpi(self, kpi_manager):
        """Test KPI subscription for real-time updates."""
        received = []
        
        async def callback(kpi_value):
            received.append(kpi_value)
        
        subscription = await kpi_manager.subscribe_kpi(
            kpi_name="rrc_success_rate",
            ne_id="ENB-001",
            callback=callback,
            interval_seconds=60
        )
        
        assert subscription is not None
        assert subscription.kpi_name == "rrc_success_rate"
    
    @pytest.mark.asyncio
    async def test_get_kpi_history(self, kpi_manager):
        """Test retrieving historical KPI values."""
        history = await kpi_manager.get_kpi_history(
            kpi_name="rrc_success_rate",
            ne_id="ENB-001",
            start_time=datetime.utcnow() - timedelta(hours=24),
            end_time=datetime.utcnow()
        )
        
        assert isinstance(history, list)
    
    @pytest.mark.asyncio
    async def test_get_dashboard_data(self, kpi_manager):
        """Test dashboard data aggregation."""
        dashboard = await kpi_manager.get_dashboard_data(
            ne_id="ENB-001"
        )
        
        assert dashboard is not None
        assert "kpis" in dashboard


class TestCounterMapper:
    """Test cases for CounterMapper."""
    
    @pytest.fixture
    def mapper(self):
        """Create CounterMapper instance."""
        return CounterMapper()
    
    def test_map_ericsson_counter(self, mapper):
        """Test Ericsson counter mapping."""
        cim_counter = mapper.map_counter(
            vendor_counter="pmRrcConnEstabAtt",
            vendor="ERICSSON"
        )
        
        assert cim_counter == "rrc_conn_attempts"
    
    def test_map_huawei_counter(self, mapper):
        """Test Huawei counter mapping."""
        cim_counter = mapper.map_counter(
            vendor_counter="VS.RRC.ConnEstab.Att",
            vendor="HUAWEI"
        )
        
        assert cim_counter == "rrc_conn_attempts"
    
    def test_reverse_map_to_ericsson(self, mapper):
        """Test reverse mapping to Ericsson format."""
        vendor_counter = mapper.reverse_map(
            cim_counter="rrc_conn_attempts",
            vendor="ERICSSON"
        )
        
        assert vendor_counter == "pmRrcConnEstabAtt"
    
    def test_reverse_map_to_huawei(self, mapper):
        """Test reverse mapping to Huawei format."""
        vendor_counter = mapper.reverse_map(
            cim_counter="rrc_conn_attempts",
            vendor="HUAWEI"
        )
        
        assert vendor_counter == "VS.RRC.ConnEstab.Att"
    
    def test_unknown_counter_returns_none(self, mapper):
        """Test that unknown counter returns None."""
        result = mapper.map_counter(
            vendor_counter="unknownCounter",
            vendor="ERICSSON"
        )
        
        assert result is None


class TestFormulaEvaluator:
    """Test cases for FormulaEvaluator."""
    
    @pytest.fixture
    def evaluator(self):
        """Create FormulaEvaluator instance."""
        return FormulaEvaluator()
    
    def test_simple_division_formula(self, evaluator):
        """Test simple division formula."""
        result = evaluator.evaluate(
            formula="(successes / attempts) * 100",
            variables={"successes": 950, "attempts": 1000}
        )
        
        assert result == 95.0
    
    def test_complex_formula(self, evaluator):
        """Test complex formula with multiple operations."""
        result = evaluator.evaluate(
            formula="(a + b) / (c - d) * 100",
            variables={"a": 100, "b": 50, "c": 200, "d": 50}
        )
        
        assert result == 100.0
    
    def test_zero_denominator_raises(self, evaluator):
        """Test that zero denominator is handled."""
        result = evaluator.evaluate(
            formula="(a / b) * 100",
            variables={"a": 100, "b": 0}
        )
        
        assert result is None or result == float('inf')
    
    def test_formula_with_constants(self, evaluator):
        """Test formula with numeric constants."""
        result = evaluator.evaluate(
            formula="value * 1.5 + 10",
            variables={"value": 20}
        )
        
        assert result == 40.0
    
    def test_formula_validation(self, evaluator):
        """Test formula validation for safety."""
        # Valid formulas
        assert evaluator.validate("(a / b) * 100")
        assert evaluator.validate("a + b - c")
        
        # Invalid formulas (would reject dangerous operations)
        assert evaluator.validate("__import__('os')") is False


class TestKPIComputer:
    """Test cases for KPIComputer."""
    
    @pytest.fixture
    def computer(self):
        """Create KPIComputer instance."""
        return KPIComputer()
    
    def test_compute_with_valid_data(self, computer, sample_counters):
        """Test computation with valid counter data."""
        result = computer.compute(
            kpi_name="rrc_success_rate",
            counters=sample_counters
        )
        
        assert result.value is not None
        assert result.quality_flag == QualityFlag.NORMAL
    
    def test_assign_quality_flag_normal(self, computer, sample_counters):
        """Test quality flag assignment for normal data."""
        flag = computer.assign_quality_flag(
            value=95.0,
            expected_range=(0, 100),
            data_completeness=1.0
        )
        
        assert flag == QualityFlag.NORMAL
    
    def test_assign_quality_flag_degraded(self, computer):
        """Test quality flag for degraded data."""
        flag = computer.assign_quality_flag(
            value=95.0,
            expected_range=(0, 100),
            data_completeness=0.6  # Missing 40% of data
        )
        
        assert flag == QualityFlag.DEGRADED
    
    def test_assign_quality_flag_no_data(self, computer):
        """Test quality flag for no data."""
        flag = computer.assign_quality_flag(
            value=None,
            expected_range=(0, 100),
            data_completeness=0.0
        )
        
        assert flag == QualityFlag.NO_DATA
    
    def test_map_vendor_counters(self, computer):
        """Test vendor counter mapping in computation."""
        vendor_counters = {
            "pmRrcConnEstabAtt": 1000,
            "pmRrcConnEstabSucc": 950,
        }
        
        mapped = computer.map_counters(vendor_counters, vendor="ERICSSON")
        
        assert "rrc_conn_attempts" in mapped
        assert mapped["rrc_conn_attempts"] == 1000


class TestKPICatalog:
    """Test cases for KPICatalog."""
    
    def test_get_kpi_definition(self):
        """Test retrieving KPI definition."""
        catalog = KPICatalog()
        
        kpi = catalog.get_kpi("rrc_success_rate")
        
        assert kpi is not None
        assert kpi.name == "rrc_success_rate"
    
    def test_list_all_kpis(self):
        """Test listing all available KPIs."""
        catalog = KPICatalog()
        
        kpis = catalog.list_all()
        
        assert len(kpis) > 0
    
    def test_kpi_has_required_fields(self):
        """Test that KPI definitions have required fields."""
        catalog = KPICatalog()
        
        kpi = catalog.get_kpi("rrc_success_rate")
        
        assert hasattr(kpi, "name")
        assert hasattr(kpi, "formula")
        assert hasattr(kpi, "unit")
        assert hasattr(kpi, "category")


class TestThroughputKPIs:
    """Test throughput-related KPI computations."""
    
    @pytest.mark.asyncio
    async def test_cell_throughput_computation(self, kpi_manager):
        """Test cell throughput KPI computation."""
        counters = {
            "throughput_dl": 1500000000,  # 1.5 Gbps
            "throughput_ul": 300000000,   # 300 Mbps
            "active_users": 120,
        }
        
        result = await kpi_manager.compute_kpi(
            kpi_name="cell_throughput",
            counters=counters
        )
        
        assert result is not None
    
    @pytest.mark.asyncio
    async def test_per_user_throughput(self, kpi_manager):
        """Test per-user throughput computation."""
        counters = {
            "throughput_dl": 1500000000,
            "active_users": 120,
        }
        
        result = await kpi_manager.compute_kpi(
            kpi_name="per_user_throughput",
            counters=counters
        )
        
        # 1.5 Gbps / 120 users = 12.5 Mbps per user
        assert result.value == pytest.approx(12.5, rel=0.1)
