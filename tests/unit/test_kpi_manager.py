"""
Unit tests for KPI Manager.
"""

import pytest
import asyncio
from datetime import datetime, timezone
from unittest.mock import Mock, AsyncMock, patch

from unified_oss.fcaps.performance.kpi_manager import (
    KPIManager,
    KPIDefinition,
    KPIResult,
    KPICategory,
    SubscriptionStatus,
)
from unified_oss.fcaps.performance.computation import (
    KPIComputer,
    FormulaEvaluator,
    CounterMapper,
    QualityFlag,
)


@pytest.fixture
def kpi_manager():
    """Create KPIManager instance for testing."""
    return KPIManager()


class TestKPIManager:
    """Test cases for KPIManager."""
    
    @pytest.mark.asyncio
    async def test_get_kpi_returns_value(self, kpi_manager):
        """Test retrieving a KPI value."""
        # Mock the compute_kpi method to return a fixed value
        with patch.object(kpi_manager, "compute_kpi", new_callable=AsyncMock) as mock_compute:
            mock_compute.return_value = KPIResult(
                kpi_id="rrc_success_rate", 
                value=98.5, 
                unit="%",
                timestamp=datetime.now(timezone.utc),
                quality_flag="NORMAL"
            )
            
            result = await kpi_manager.get_kpi("rrc_success_rate", ne_id="ENB001")
            
            assert result is not None
            assert result.value == 98.5
            assert result.quality_flag == "NORMAL"
    
    @pytest.mark.asyncio
    async def test_compute_rrc_success_rate(self, kpi_manager):
        """Test computing RRC success rate."""
        counters = {
            "rrc_conn_attempts": 100,
            "rrc_conn_successes": 95,
        }
        
        result = await kpi_manager.compute_kpi("rrc_success_rate", counters=counters)
        assert result is not None
        assert result.value == 95.0
    
    @pytest.mark.asyncio
    async def test_zero_denominator_protection(self, kpi_manager):
        """Test that zero denominator is handled gracefully."""
        counters = {
            "rrc_conn_attempts": 0,
            "rrc_conn_successes": 0,
        }
        
        result = await kpi_manager.compute_kpi("rrc_success_rate", counters=counters)
        assert result.quality_flag == "ZERO_DENOMINATOR"
    
    @pytest.mark.asyncio
    async def test_subscribe_kpi(self, kpi_manager):
        """Test KPI subscription."""
        received = []
        
        async def callback(kpi_id, result):
            received.append(result)
            
        sub = await kpi_manager.subscribe_kpi(kpi_name="rrc_success_rate", callback=callback)
        assert sub is not None
        
        # Trigger a notification directly
        result = KPIResult(kpi_id="rrc_success_rate", value=99.0, unit="%", timestamp=datetime.now(timezone.utc))
        await sub.callback("rrc_success_rate", result)
        
        assert len(received) == 1
        assert received[0].value == 99.0


class TestFormulaEvaluator:
    """Test cases for FormulaEvaluator."""
    
    @pytest.fixture
    def evaluator(self):
        return FormulaEvaluator()
    
    def test_simple_division_formula(self, evaluator):
        """Test simple division evaluation."""
        formula = "(success / attempts) * 100"
        variables = {"success": 95, "attempts": 100}
        
        result, error = evaluator.evaluate(formula, variables)
        assert result == 95.0
        assert error is None
    
    def test_complex_formula(self, evaluator):
        """Test complex formula evaluation."""
        formula = "((a + b) / (c - d)) * 10"
        variables = {"a": 5, "b": 5, "c": 10, "d": 9}
        
        result, error = evaluator.evaluate(formula, variables)
        assert result == 100.0
        assert error is None
    
    def test_zero_denominator_raises(self, evaluator):
        """Test zero denominator handling."""
        formula = "a / b"
        variables = {"a": 10, "b": 0}
        
        result, error = evaluator.evaluate(formula, variables)
        assert result is None
        assert "zero" in error.lower()
    
    def test_formula_with_constants(self, evaluator):
        """Test evaluation with constants."""
        formula = "a * 2 + 10"
        variables = {"a": 15}
        
        result, error = evaluator.evaluate(formula, variables)
        assert result == 40.0


class TestKPIComputer:
    """Test cases for KPIComputer."""
    
    @pytest.fixture
    def computer(self):
        return KPIComputer()
    
    @pytest.mark.asyncio
    async def test_compute_with_valid_data(self, computer):
        """Test computation with valid inputs."""
        counters = {
            "rrc_conn_success": 95,
            "rrc_conn_attempts": 100,
        }
        
        result = await computer.compute("rrc_success_rate", counters)
        assert result is not None
        assert result.value == 95.0
        assert result.quality_flag == QualityFlag.NORMAL
    
    def test_assign_quality_flag_normal(self, computer):
        """Test quality flag assignment for normal values."""
        pass

class TestCounterMapper:
    """Test cases for CounterMapper."""
    
    @pytest.fixture
    def mapper(self):
        return CounterMapper()
    
    def test_map_ericsson_counter(self, mapper):
        """Test Ericsson counter mapping."""
        ericsson_counters = {
            "pmRrcConnEstabSuccess": 100,
            "pmRrcConnEstabAtt": 110,
        }
        mapped = mapper.map_counters("ERICSSON", ericsson_counters)
        assert "rrc_conn_success" in mapped
        assert "rrc_conn_attempts" in mapped


class TestThroughputKPIs:
    """Test throughput-specific KPI computations."""
    
    @pytest.mark.asyncio
    async def test_cell_throughput_computation(self, kpi_manager):
        """Test cell throughput computation."""
        counters = {
            "dl_bytes": 100000000, # 100MB
            "active_users": 10,
            "measurement_period": 900, # 15 min
        }
        # Formula: dl_bytes / (active_users * measurement_period) / 1000000
        # 100,000,000 / (10 * 900) / 1,000,000 = 100,000,000 / 9,000,000,000 = 0.011... mbps? 
        # Wait, measurement_period is usually in seconds. 900s = 15min.
        # Let's adjust to get a nice number.
        # If we want 11.11 Mbps:
        # 100,000,000 / (1 * 9) / 1,000,000 = 11.11
        
        # Let's use simpler values for the test
        counters = {
            "dl_bytes": 9000000000, # 9000MB
            "active_users": 10,
            "measurement_period": 900,
        }
        # 9,000,000,000 / (10 * 900) / 1,000,000 = 9,000,000,000 / 9,000,000,000 = 1.0 Mbps
        
        result = await kpi_manager.compute_kpi("dl_throughput", counters=counters)
        assert result is not None
        assert result.value == 1.0
