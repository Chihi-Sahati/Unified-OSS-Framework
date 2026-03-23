"""
KPI Computation Module for Performance Management.

This module provides comprehensive KPI computation capabilities including
multi-vendor counter mapping, formula evaluation, and quality assessment.

Supports:
    - Multi-vendor counter mapping (Ericsson, Huawei, Nokia, ZTE, Samsung)
    - Formula parsing and evaluation
    - Zero denominator protection
    - Quality flag assignment
    - Support for success rates, utilization, throughput formulas

Example:
    >>> from unified_oss.fcaps.performance.computation import KPIComputer
    >>> computer = KPIComputer()
    >>> result = await computer.compute("rrc_success_rate", counters, vendor="ERICSSON")
"""

from __future__ import annotations

import ast
import logging
import operator
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

from unified_oss.core.constants import (
    VENDOR_ERICSSON,
    VENDOR_HUAWEI,
    VENDOR_NOKIA,
    VENDOR_ZTE,
    VENDOR_SAMSUNG,
)

# Configure module logger
logger = logging.getLogger(__name__)

# Type aliases
CounterValue = Union[int, float]
CounterDict = Dict[str, CounterValue]


class QualityFlag(Enum):
    """Quality flag for KPI computation results.
    
    Attributes:
        NORMAL: Normal quality, data is reliable.
        DEGRADED: Degraded quality, partial data available.
        NO_DATA: No data available for computation.
        ZERO_DENOMINATOR: Division by zero occurred.
        STALE_DATA: Data is stale (too old).
        COMPUTATION_ERROR: Error during computation.
        INSUFFICIENT_SAMPLES: Not enough samples for computation.
    """
    
    NORMAL = "NORMAL"
    DEGRADED = "DEGRADED"
    NO_DATA = "NO_DATA"
    ZERO_DENOMINATOR = "ZERO_DENOMINATOR"
    STALE_DATA = "STALE_DATA"
    COMPUTATION_ERROR = "COMPUTATION_ERROR"
    INSUFFICIENT_SAMPLES = "INSUFFICIENT_SAMPLES"


class CounterType(Enum):
    """Type of PM counter.
    
    Attributes:
        COUNTER: Cumulative counter that increments.
        GAUGE: Point-in-time gauge value.
        DERIVE: Derived value from rate calculation.
        ABSOLUTE: Absolute value that resets.
    """
    
    COUNTER = "COUNTER"
    GAUGE = "GAUGE"
    DERIVE = "DERIVE"
    ABSOLUTE = "ABSOLUTE"


@dataclass
class CounterMapping:
    """Mapping between vendor-specific counters and CIM model.
    
    Attributes:
        cim_name: CIM model counter name.
        vendor: Vendor identifier.
        vendor_name: Vendor-specific counter name.
        counter_type: Type of counter.
        description: Counter description.
        unit: Unit of measurement.
        conversion_factor: Factor to convert to standard unit.
    """
    
    cim_name: str
    vendor: str
    vendor_name: str
    counter_type: CounterType = CounterType.COUNTER
    description: str = ""
    unit: str = "count"
    conversion_factor: float = 1.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.
        
        Returns:
            Dictionary representation.
        """
        return {
            "cim_name": self.cim_name,
            "vendor": self.vendor,
            "vendor_name": self.vendor_name,
            "counter_type": self.counter_type.value,
            "description": self.description,
            "unit": self.unit,
            "conversion_factor": self.conversion_factor,
        }


@dataclass
class ComputationResult:
    """Result of KPI computation.
    
    Attributes:
        value: Computed KPI value.
        quality_flag: Quality indicator.
        unit: Unit of measurement.
        timestamp: Computation timestamp.
        formula: Formula used for computation.
        input_counters: Counter values used as input.
        warnings: Warning messages during computation.
        metadata: Additional metadata.
    """
    
    value: Optional[float]
    quality_flag: QualityFlag
    unit: str = "count"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    formula: str = ""
    input_counters: CounterDict = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.
        
        Returns:
            Dictionary representation.
        """
        return {
            "value": self.value,
            "quality_flag": self.quality_flag.value,
            "unit": self.unit,
            "timestamp": self.timestamp.isoformat(),
            "formula": self.formula,
            "input_counters": self.input_counters,
            "warnings": self.warnings,
            "metadata": self.metadata,
        }


class CounterMapper:
    """Multi-vendor counter mapping to CIM model.
    
    This class provides bidirectional mapping between vendor-specific
    counter names and the Common Information Model (CIM) standard names.
    
    Attributes:
        mappings: Dictionary of counter mappings by vendor.
    """
    
    def __init__(self) -> None:
        """Initialize counter mapper with default mappings."""
        self._mappings: Dict[str, Dict[str, CounterMapping]] = {}
        self._reverse_mappings: Dict[str, Dict[str, str]] = {}
        
        # Initialize default vendor mappings
        self._initialize_ericsson_mappings()
        self._initialize_huawei_mappings()
        self._initialize_nokia_mappings()
        self._initialize_zte_mappings()
        self._initialize_samsung_mappings()
        
        logger.info(
            f"CounterMapper initialized with mappings for "
            f"{len(self._mappings)} vendors"
        )
    
    def _initialize_ericsson_mappings(self) -> None:
        """Initialize Ericsson counter mappings."""
        mappings = {
            # RRC Connection Counters
            "rrc_conn_attempts": CounterMapping(
                cim_name="rrc_conn_attempts",
                vendor=VENDOR_ERICSSON,
                vendor_name="pmRrcConnEstabAtt",
                counter_type=CounterType.COUNTER,
                description="RRC Connection Establishment Attempts",
                unit="count",
            ),
            "rrc_conn_success": CounterMapping(
                cim_name="rrc_conn_success",
                vendor=VENDOR_ERICSSON,
                vendor_name="pmRrcConnEstabSuccess",
                counter_type=CounterType.COUNTER,
                description="RRC Connection Establishment Success",
                unit="count",
            ),
            "rrc_conn_fail": CounterMapping(
                cim_name="rrc_conn_fail",
                vendor=VENDOR_ERICSSON,
                vendor_name="pmRrcConnEstabFail",
                counter_type=CounterType.COUNTER,
                description="RRC Connection Establishment Failures",
                unit="count",
            ),
            # E-RAB Counters
            "erab_setup_attempts": CounterMapping(
                cim_name="erab_setup_attempts",
                vendor=VENDOR_ERICSSON,
                vendor_name="pmErabEstabAtt",
                counter_type=CounterType.COUNTER,
                description="E-RAB Setup Attempts",
                unit="count",
            ),
            "erab_setup_success": CounterMapping(
                cim_name="erab_setup_success",
                vendor=VENDOR_ERICSSON,
                vendor_name="pmErabEstabSuccess",
                counter_type=CounterType.COUNTER,
                description="E-RAB Setup Success",
                unit="count",
            ),
            # Handover Counters
            "ho_attempts": CounterMapping(
                cim_name="ho_attempts",
                vendor=VENDOR_ERICSSON,
                vendor_name="pmHoAtt",
                counter_type=CounterType.COUNTER,
                description="Handover Attempts",
                unit="count",
            ),
            "ho_success": CounterMapping(
                cim_name="ho_success",
                vendor=VENDOR_ERICSSON,
                vendor_name="pmHoSuccess",
                counter_type=CounterType.COUNTER,
                description="Handover Success",
                unit="count",
            ),
            "ho_fail": CounterMapping(
                cim_name="ho_fail",
                vendor=VENDOR_ERICSSON,
                vendor_name="pmHoFail",
                counter_type=CounterType.COUNTER,
                description="Handover Failures",
                unit="count",
            ),
            # Throughput Counters
            "dl_bytes": CounterMapping(
                cim_name="dl_bytes",
                vendor=VENDOR_ERICSSON,
                vendor_name="pmDlBytes",
                counter_type=CounterType.COUNTER,
                description="Downlink Bytes Transmitted",
                unit="bytes",
            ),
            "ul_bytes": CounterMapping(
                cim_name="ul_bytes",
                vendor=VENDOR_ERICSSON,
                vendor_name="pmUlBytes",
                counter_type=CounterType.COUNTER,
                description="Uplink Bytes Received",
                unit="bytes",
            ),
            # PRB Counters
            "prb_used_dl": CounterMapping(
                cim_name="prb_used_dl",
                vendor=VENDOR_ERICSSON,
                vendor_name="pmPrbUsedDl",
                counter_type=CounterType.GAUGE,
                description="Used DL PRBs",
                unit="count",
            ),
            "prb_total_dl": CounterMapping(
                cim_name="prb_total_dl",
                vendor=VENDOR_ERICSSON,
                vendor_name="pmPrbTotalDl",
                counter_type=CounterType.GAUGE,
                description="Total DL PRBs",
                unit="count",
            ),
            # System Counters
            "cpu_usage": CounterMapping(
                cim_name="cpu_usage",
                vendor=VENDOR_ERICSSON,
                vendor_name="pmCpuUsage",
                counter_type=CounterType.GAUGE,
                description="CPU Usage Percentage",
                unit="%",
            ),
            "memory_usage": CounterMapping(
                cim_name="memory_usage",
                vendor=VENDOR_ERICSSON,
                vendor_name="pmMemoryUsage",
                counter_type=CounterType.GAUGE,
                description="Memory Usage Percentage",
                unit="%",
            ),
        }
        
        self._mappings[VENDOR_ERICSSON] = mappings
        self._build_reverse_mapping(VENDOR_ERICSSON, mappings)
    
    def _initialize_huawei_mappings(self) -> None:
        """Initialize Huawei counter mappings."""
        mappings = {
            # RRC Connection Counters
            "rrc_conn_attempts": CounterMapping(
                cim_name="rrc_conn_attempts",
                vendor=VENDOR_HUAWEI,
                vendor_name="VS.RRC.ConnEstab.Att",
                counter_type=CounterType.COUNTER,
                description="RRC Connection Establishment Attempts",
                unit="count",
            ),
            "rrc_conn_success": CounterMapping(
                cim_name="rrc_conn_success",
                vendor=VENDOR_HUAWEI,
                vendor_name="VS.RRC.ConnEstab.Success",
                counter_type=CounterType.COUNTER,
                description="RRC Connection Establishment Success",
                unit="count",
            ),
            "rrc_conn_fail": CounterMapping(
                cim_name="rrc_conn_fail",
                vendor=VENDOR_HUAWEI,
                vendor_name="VS.RRC.ConnEstab.Fail",
                counter_type=CounterType.COUNTER,
                description="RRC Connection Establishment Failures",
                unit="count",
            ),
            # E-RAB Counters
            "erab_setup_attempts": CounterMapping(
                cim_name="erab_setup_attempts",
                vendor=VENDOR_HUAWEI,
                vendor_name="VS.ERAB.Setup.Att",
                counter_type=CounterType.COUNTER,
                description="E-RAB Setup Attempts",
                unit="count",
            ),
            "erab_setup_success": CounterMapping(
                cim_name="erab_setup_success",
                vendor=VENDOR_HUAWEI,
                vendor_name="VS.ERAB.Setup.Success",
                counter_type=CounterType.COUNTER,
                description="E-RAB Setup Success",
                unit="count",
            ),
            # Handover Counters
            "ho_attempts": CounterMapping(
                cim_name="ho_attempts",
                vendor=VENDOR_HUAWEI,
                vendor_name="VS.HO.Att",
                counter_type=CounterType.COUNTER,
                description="Handover Attempts",
                unit="count",
            ),
            "ho_success": CounterMapping(
                cim_name="ho_success",
                vendor=VENDOR_HUAWEI,
                vendor_name="VS.HO.Success",
                counter_type=CounterType.COUNTER,
                description="Handover Success",
                unit="count",
            ),
            # Throughput Counters
            "dl_bytes": CounterMapping(
                cim_name="dl_bytes",
                vendor=VENDOR_HUAWEI,
                vendor_name="VS.DL.Bytes",
                counter_type=CounterType.COUNTER,
                description="Downlink Bytes Transmitted",
                unit="bytes",
            ),
            "ul_bytes": CounterMapping(
                cim_name="ul_bytes",
                vendor=VENDOR_HUAWEI,
                vendor_name="VS.UL.Bytes",
                counter_type=CounterType.COUNTER,
                description="Uplink Bytes Received",
                unit="bytes",
            ),
            # PRB Counters
            "prb_used_dl": CounterMapping(
                cim_name="prb_used_dl",
                vendor=VENDOR_HUAWEI,
                vendor_name="VS.PRB.Used.DL",
                counter_type=CounterType.GAUGE,
                description="Used DL PRBs",
                unit="count",
            ),
            "prb_total_dl": CounterMapping(
                cim_name="prb_total_dl",
                vendor=VENDOR_HUAWEI,
                vendor_name="VS.PRB.Total.DL",
                counter_type=CounterType.GAUGE,
                description="Total DL PRBs",
                unit="count",
            ),
            # System Counters
            "cpu_usage": CounterMapping(
                cim_name="cpu_usage",
                vendor=VENDOR_HUAWEI,
                vendor_name="VS.CPU.Usage",
                counter_type=CounterType.GAUGE,
                description="CPU Usage Percentage",
                unit="%",
            ),
            "memory_usage": CounterMapping(
                cim_name="memory_usage",
                vendor=VENDOR_HUAWEI,
                vendor_name="VS.Memory.Usage",
                counter_type=CounterType.GAUGE,
                description="Memory Usage Percentage",
                unit="%",
            ),
        }
        
        self._mappings[VENDOR_HUAWEI] = mappings
        self._build_reverse_mapping(VENDOR_HUAWEI, mappings)
    
    def _initialize_nokia_mappings(self) -> None:
        """Initialize Nokia counter mappings."""
        mappings = {
            "rrc_conn_attempts": CounterMapping(
                cim_name="rrc_conn_attempts",
                vendor=VENDOR_NOKIA,
                vendor_name="RRC_CONN_ESTAB_ATT",
                counter_type=CounterType.COUNTER,
                description="RRC Connection Establishment Attempts",
                unit="count",
            ),
            "rrc_conn_success": CounterMapping(
                cim_name="rrc_conn_success",
                vendor=VENDOR_NOKIA,
                vendor_name="RRC_CONN_ESTAB_SUCCESS",
                counter_type=CounterType.COUNTER,
                description="RRC Connection Establishment Success",
                unit="count",
            ),
            "ho_attempts": CounterMapping(
                cim_name="ho_attempts",
                vendor=VENDOR_NOKIA,
                vendor_name="HO_ATT",
                counter_type=CounterType.COUNTER,
                description="Handover Attempts",
                unit="count",
            ),
            "ho_success": CounterMapping(
                cim_name="ho_success",
                vendor=VENDOR_NOKIA,
                vendor_name="HO_SUCCESS",
                counter_type=CounterType.COUNTER,
                description="Handover Success",
                unit="count",
            ),
            "cpu_usage": CounterMapping(
                cim_name="cpu_usage",
                vendor=VENDOR_NOKIA,
                vendor_name="CPU_USAGE",
                counter_type=CounterType.GAUGE,
                description="CPU Usage Percentage",
                unit="%",
            ),
        }
        
        self._mappings[VENDOR_NOKIA] = mappings
        self._build_reverse_mapping(VENDOR_NOKIA, mappings)
    
    def _initialize_zte_mappings(self) -> None:
        """Initialize ZTE counter mappings."""
        mappings = {
            "rrc_conn_attempts": CounterMapping(
                cim_name="rrc_conn_attempts",
                vendor=VENDOR_ZTE,
                vendor_name="rrcConnEstabAtt",
                counter_type=CounterType.COUNTER,
                description="RRC Connection Establishment Attempts",
                unit="count",
            ),
            "rrc_conn_success": CounterMapping(
                cim_name="rrc_conn_success",
                vendor=VENDOR_ZTE,
                vendor_name="rrcConnEstabSucc",
                counter_type=CounterType.COUNTER,
                description="RRC Connection Establishment Success",
                unit="count",
            ),
            "ho_attempts": CounterMapping(
                cim_name="ho_attempts",
                vendor=VENDOR_ZTE,
                vendor_name="hoAtt",
                counter_type=CounterType.COUNTER,
                description="Handover Attempts",
                unit="count",
            ),
            "ho_success": CounterMapping(
                cim_name="ho_success",
                vendor=VENDOR_ZTE,
                vendor_name="hoSucc",
                counter_type=CounterType.COUNTER,
                description="Handover Success",
                unit="count",
            ),
        }
        
        self._mappings[VENDOR_ZTE] = mappings
        self._build_reverse_mapping(VENDOR_ZTE, mappings)
    
    def _initialize_samsung_mappings(self) -> None:
        """Initialize Samsung counter mappings."""
        mappings = {
            "rrc_conn_attempts": CounterMapping(
                cim_name="rrc_conn_attempts",
                vendor=VENDOR_SAMSUNG,
                vendor_name="RRCCONNESTABATT",
                counter_type=CounterType.COUNTER,
                description="RRC Connection Establishment Attempts",
                unit="count",
            ),
            "rrc_conn_success": CounterMapping(
                cim_name="rrc_conn_success",
                vendor=VENDOR_SAMSUNG,
                vendor_name="RRCCONNESTABSUCC",
                counter_type=CounterType.COUNTER,
                description="RRC Connection Establishment Success",
                unit="count",
            ),
            "ho_attempts": CounterMapping(
                cim_name="ho_attempts",
                vendor=VENDOR_SAMSUNG,
                vendor_name="HOATT",
                counter_type=CounterType.COUNTER,
                description="Handover Attempts",
                unit="count",
            ),
            "ho_success": CounterMapping(
                cim_name="ho_success",
                vendor=VENDOR_SAMSUNG,
                vendor_name="HOSUCC",
                counter_type=CounterType.COUNTER,
                description="Handover Success",
                unit="count",
            ),
        }
        
        self._mappings[VENDOR_SAMSUNG] = mappings
        self._build_reverse_mapping(VENDOR_SAMSUNG, mappings)
    
    def _build_reverse_mapping(
        self,
        vendor: str,
        mappings: Dict[str, CounterMapping],
    ) -> None:
        """Build reverse mapping from vendor name to CIM name.
        
        Args:
            vendor: Vendor identifier.
            mappings: Counter mappings.
        """
        reverse: Dict[str, str] = {}
        for cim_name, mapping in mappings.items():
            reverse[mapping.vendor_name] = cim_name
        self._reverse_mappings[vendor] = reverse
    
    def map_counters(
        self,
        vendor: str,
        counters: CounterDict,
    ) -> CounterDict:
        """Map vendor-specific counters to CIM names.
        
        Args:
            vendor: Vendor identifier.
            counters: Dictionary of vendor-specific counter values.
            
        Returns:
            Dictionary with CIM names as keys.
        """
        reverse_map = self._reverse_mappings.get(vendor, {})
        mapped: CounterDict = {}
        warnings: List[str] = []
        
        for vendor_name, value in counters.items():
            cim_name = reverse_map.get(vendor_name)
            if cim_name:
                mapped[cim_name] = value
            else:
                # Keep original name if no mapping exists
                mapped[vendor_name] = value
                warnings.append(f"No CIM mapping for counter: {vendor_name}")
        
        if warnings:
            logger.debug(f"Counter mapping warnings: {warnings}")
        
        return mapped
    
    def map_counter(
        self,
        vendor_counter: str,
        vendor: str,
    ) -> Optional[str]:
        """Map a single vendor counter to CIM name.
        
        Args:
            vendor_counter: Vendor-specific counter name.
            vendor: Vendor identifier.
            
        Returns:
            CIM counter name or None if not found.
        """
        reverse_map = self._reverse_mappings.get(vendor, {})
        return reverse_map.get(vendor_counter)
    
    def get_vendor_counter_name(
        self,
        cim_name: str,
        vendor: str,
    ) -> Optional[str]:
        """Get vendor-specific counter name for a CIM name.
        
        Args:
            cim_name: CIM counter name.
            vendor: Vendor identifier.
            
        Returns:
            Vendor-specific counter name or None.
        """
        vendor_mappings = self._mappings.get(vendor, {})
        mapping = vendor_mappings.get(cim_name)
        return mapping.vendor_name if mapping else None
    
    # Alias for backward compatibility
    def reverse_map(
        self,
        cim_counter: str,
        vendor: str,
    ) -> Optional[str]:
        """Map a CIM counter name back to vendor-specific name.
        
        Alias for get_vendor_counter_name.
        
        Args:
            cim_counter: CIM counter name.
            vendor: Vendor identifier.
            
        Returns:
            Vendor-specific counter name or None if not found.
        """
        return self.get_vendor_counter_name(cim_counter, vendor)
    
    def get_mapping(self, cim_name: str, vendor: str) -> Optional[CounterMapping]:
        """Get counter mapping for a CIM name and vendor.
        
        Args:
            cim_name: CIM counter name.
            vendor: Vendor identifier.
            
        Returns:
            Counter mapping or None.
        """
        vendor_mappings = self._mappings.get(vendor, {})
        return vendor_mappings.get(cim_name)
    
    def add_mapping(self, mapping: CounterMapping) -> None:
        """Add a new counter mapping.
        
        Args:
            mapping: Counter mapping to add.
        """
        vendor = mapping.vendor
        if vendor not in self._mappings:
            self._mappings[vendor] = {}
            self._reverse_mappings[vendor] = {}
        
        self._mappings[vendor][mapping.cim_name] = mapping
        self._reverse_mappings[vendor][mapping.vendor_name] = mapping.cim_name
        
        logger.info(f"Added counter mapping: {mapping.cim_name} -> {mapping.vendor_name}")
    
    def get_supported_vendors(self) -> List[str]:
        """Get list of supported vendors.
        
        Returns:
            List of vendor identifiers.
        """
        return list(self._mappings.keys())
    
    def map_counter(
        self,
        vendor_counter: str,
        vendor: str,
    ) -> Optional[str]:
        """Map a single vendor counter to CIM name.
        
        Args:
            vendor_counter: Vendor-specific counter name.
            vendor: Vendor identifier.
            
        Returns:
            CIM counter name or None if not found.
        """
        reverse_map = self._reverse_mappings.get(vendor, {})
        return reverse_map.get(vendor_counter)
    
    def reverse_map(
        self,
        cim_counter: str,
        vendor: str,
    ) -> Optional[str]:
        """Map a CIM counter name back to vendor-specific name.
        
        Args:
            cim_counter: CIM counter name.
            vendor: Vendor identifier.
            
        Returns:
            Vendor-specific counter name or None if not found.
        """
        vendor_mappings = self._mappings.get(vendor, {})
        mapping = vendor_mappings.get(cim_counter)
        return mapping.vendor_name if mapping else None


class FormulaEvaluator:
    """Safe formula evaluator for KPI computation.
    
    This class provides safe evaluation of mathematical formulas
    used in KPI computation with protection against division by zero.
    
    Attributes:
        operators: Allowed mathematical operators.
        functions: Allowed mathematical functions.
    """
    
    def __init__(self) -> None:
        """Initialize formula evaluator."""
        self._operators = {
            ast.Add: operator.add,
            ast.Sub: operator.sub,
            ast.Mult: operator.mul,
            ast.Div: operator.truediv,
            ast.FloorDiv: operator.floordiv,
            ast.Mod: operator.mod,
            ast.Pow: operator.pow,
            ast.USub: operator.neg,
            ast.UAdd: operator.pos,
        }
        
        self._functions = {
            "abs": abs,
            "round": round,
            "min": min,
            "max": max,
            "sum": sum,
        }
        
        self._denominator_threshold = 0.0001
    
    def evaluate(
        self,
        formula: str,
        variables: CounterDict,
    ) -> Union[Optional[float], Tuple[Optional[float], Optional[str]]]:
        """Evaluate a formula with variable substitution.
        
        This method supports two return styles:
        1. Single value: result = evaluate(formula, variables)
        2. Tuple: value, error = evaluate(formula, variables)
        
        When used in tuple unpacking context, returns (value, error).
        When used directly, returns just the value.
        
        Args:
            formula: Formula string to evaluate.
            variables: Variable values for substitution.
            
        Returns:
            Result value or tuple of (result, error_message).
        """
        try:
            # Substitute variables
            expr = self._substitute_variables(formula, variables)
            
            # Check for division by zero
            if not self._check_denominators(expr):
                return None, "Division by zero detected"
            
            # Parse and evaluate safely
            result = self._safe_eval(expr)
            return result, None
            
        except ZeroDivisionError:
            return None, "Division by zero"
        except Exception as e:
            return None, str(e)
    
    def validate(self, formula: str) -> bool:
        """Validate a formula for safety.
        
        Checks that the formula contains only allowed operations
        and doesn't contain dangerous code.
        
        Args:
            formula: Formula string to validate.
            
        Returns:
            True if formula is safe, False otherwise.
        """
        try:
            # Check for dangerous patterns
            dangerous_patterns = [
                '__import__', 'eval', 'exec', 'compile', 'open',
                'file', 'input', 'raw_input', 'globals', 'locals',
                'dir', 'vars', 'getattr', 'setattr', 'delattr',
                'hasattr', 'callable', 'type', 'class', 'bases',
            ]
            
            for pattern in dangerous_patterns:
                if pattern in formula:
                    return False
            
            # Try parsing the formula
            ast.parse(formula, mode='eval')
            return True
            
        except SyntaxError:
            return False
        except Exception:
            return False
    
    def _substitute_variables(
        self,
        formula: str,
        variables: CounterDict,
    ) -> str:
        """Substitute variables in formula with values.
        
        Args:
            formula: Formula string.
            variables: Variable values.
            
        Returns:
            Formula with substituted values.
        """
        result = formula
        
        # Sort by length (longest first) to avoid partial substitutions
        sorted_vars = sorted(variables.keys(), key=len, reverse=True)
        
        for var_name in sorted_vars:
            var_value = variables[var_name]
            if var_value is not None:
                result = result.replace(var_name, str(float(var_value)))
        
        return result
    
    def _check_denominators(self, expr: str) -> bool:
        """Check for potential division by zero.
        
        Args:
            expr: Expression string.
            
        Returns:
            True if safe, False if potential division by zero.
        """
        # Find all division operations
        div_pattern = r'/\s*([\d.]+)'
        matches = re.findall(div_pattern, expr)
        
        for match in matches:
            try:
                value = float(match)
                if abs(value) < self._denominator_threshold:
                    return False
            except ValueError:
                pass
        
        return True
    
    def _safe_eval(self, expr: str) -> float:
        """Safely evaluate a mathematical expression.
        
        Args:
            expr: Expression string.
            
        Returns:
            Evaluated result.
            
        Raises:
            ValueError: If expression is invalid.
        """
        try:
            tree = ast.parse(expr, mode='eval')
            result = self._eval_node(tree.body)
            return float(result) if result is not None else 0.0
        except (SyntaxError, TypeError) as e:
            raise ValueError(f"Invalid expression: {expr}") from e
    
    def _eval_node(self, node: ast.AST) -> Any:
        """Recursively evaluate AST node.
        
        Args:
            node: AST node.
            
        Returns:
            Evaluated value.
        """
        if isinstance(node, ast.Constant):
            return node.value
        
        if isinstance(node, ast.Num):  # Python < 3.8 compatibility
            return node.n
        
        if isinstance(node, ast.BinOp):
            left = self._eval_node(node.left)
            right = self._eval_node(node.right)
            op_func = self._operators.get(type(node.op))
            
            if op_func is None:
                raise ValueError(f"Unsupported operator: {type(node.op)}")
            
            return op_func(left, right)
        
        if isinstance(node, ast.UnaryOp):
            operand = self._eval_node(node.operand)
            op_func = self._operators.get(type(node.op))
            
            if op_func is None:
                raise ValueError(f"Unsupported operator: {type(node.op)}")
            
            return op_func(operand)
        
        if isinstance(node, ast.Call):
            func_name = node.func.id if isinstance(node.func, ast.Name) else None
            
            if func_name not in self._functions:
                raise ValueError(f"Unsupported function: {func_name}")
            
            args = [self._eval_node(arg) for arg in node.args]
            return self._functions[func_name](*args)
        
        raise ValueError(f"Unsupported node type: {type(node)}")
    
    def validate_formula(self, formula: str) -> Tuple[bool, List[str]]:
        """Validate a formula syntax.
        
        Args:
            formula: Formula string to validate.
            
        Returns:
            Tuple of (is_valid, list_of_errors).
        """
        errors: List[str] = []
        
        try:
            # Extract variable names
            var_pattern = r'[a-zA-Z_][a-zA-Z0-9_]*'
            potential_vars = set(re.findall(var_pattern, formula))
            
            # Filter out functions and operators
            reserved = set(self._functions.keys()) | {'and', 'or', 'not', 'if', 'else'}
            variables = potential_vars - reserved
            
            # Try parsing
            ast.parse(formula, mode='eval')
            
            return True, list(variables)
            
        except SyntaxError as e:
            errors.append(f"Syntax error: {e}")
            return False, errors


class KPIComputer:
    """Main KPI computation engine.
    
    This class provides KPI computation capabilities including:
    - Multi-vendor counter mapping
    - Formula evaluation with safety checks
    - Quality flag assignment
    - Support for various KPI types
    
    Attributes:
        counter_mapper: Counter mapping utility.
        formula_evaluator: Formula evaluation utility.
    """
    
    def __init__(self) -> None:
        """Initialize KPI computer."""
        self.counter_mapper = CounterMapper()
        self.formula_evaluator = FormulaEvaluator()
        self._kpi_formulas = self._initialize_formulas()
        
        logger.info("KPIComputer initialized")
    
    def _initialize_formulas(self) -> Dict[str, Dict[str, Any]]:
        """Initialize predefined KPI formulas.
        
        Returns:
            Dictionary of KPI formulas.
        """
        return {
            "rrc_success_rate": {
                "formula": "(rrc_conn_success / rrc_conn_attempts) * 100",
                "unit": "%",
                "description": "RRC Connection Success Rate",
            },
            "ho_success_rate": {
                "formula": "(ho_success / ho_attempts) * 100",
                "unit": "%",
                "description": "Handover Success Rate",
            },
            "erab_success_rate": {
                "formula": "(erab_setup_success / erab_setup_attempts) * 100",
                "unit": "%",
                "description": "E-RAB Setup Success Rate",
            },
            "rrc_drop_rate": {
                "formula": "(rrc_conn_fail / rrc_conn_success) * 100",
                "unit": "%",
                "description": "RRC Connection Drop Rate",
            },
            "prb_utilization": {
                "formula": "(prb_used_dl / prb_total_dl) * 100",
                "unit": "%",
                "description": "PRB Utilization",
            },
            "dl_throughput_mbps": {
                "formula": "dl_bytes / 1000000",
                "unit": "Mbps",
                "description": "Downlink Throughput",
            },
            "ul_throughput_mbps": {
                "formula": "ul_bytes / 1000000",
                "unit": "Mbps",
                "description": "Uplink Throughput",
            },
        }
    
    async def compute(
        self,
        kpi_name: str,
        counters: CounterDict,
        vendor: Optional[str] = None,
    ) -> ComputationResult:
        """Compute a KPI from raw counters.
        
        Args:
            kpi_name: Name of the KPI to compute.
            counters: Raw counter values.
            vendor: Optional vendor for counter mapping.
            
        Returns:
            Computation result with quality flag.
        """
        # Map counters if vendor specified
        if vendor:
            mapped_counters = self.counter_mapper.map_counters(vendor, counters)
        else:
            mapped_counters = counters
        
        # Get formula
        kpi_config = self._kpi_formulas.get(kpi_name)
        if kpi_config is None:
            return ComputationResult(
                value=None,
                quality_flag=QualityFlag.COMPUTATION_ERROR,
                warnings=[f"Unknown KPI: {kpi_name}"],
            )
        
        formula = kpi_config["formula"]
        
        # Check for required counters
        is_valid, required_vars = self.formula_evaluator.validate_formula(formula)
        
        if not is_valid:
            return ComputationResult(
                value=None,
                quality_flag=QualityFlag.COMPUTATION_ERROR,
                formula=formula,
                warnings=["Invalid formula"],
            )
        
        # Check if all required counters are present
        missing_vars = []
        zero_vars = []
        
        for var in required_vars:
            if var not in mapped_counters:
                missing_vars.append(var)
            elif mapped_counters[var] == 0:
                zero_vars.append(var)
        
        if missing_vars:
            return ComputationResult(
                value=None,
                quality_flag=QualityFlag.NO_DATA,
                formula=formula,
                input_counters=mapped_counters,
                warnings=[f"Missing counters: {missing_vars}"],
            )
        
        # Check denominator
        denominator_check = self.check_denominator(formula, mapped_counters)
        if not denominator_check:
            return ComputationResult(
                value=None,
                quality_flag=QualityFlag.ZERO_DENOMINATOR,
                formula=formula,
                input_counters=mapped_counters,
                warnings=["Division by zero detected"],
            )
        
        # Evaluate formula
        value, error = self.formula_evaluator.evaluate(formula, mapped_counters)
        
        if error:
            return ComputationResult(
                value=None,
                quality_flag=QualityFlag.COMPUTATION_ERROR,
                formula=formula,
                input_counters=mapped_counters,
                warnings=[error],
            )
        
        # Assign quality flag
        quality_flag = self.assign_quality_flag(
            value,
            mapped_counters,
            zero_vars,
        )
        
        return ComputationResult(
            value=value,
            quality_flag=quality_flag,
            unit=kpi_config["unit"],
            formula=formula,
            input_counters=mapped_counters,
            metadata={"kpi_description": kpi_config["description"]},
        )
    
    def check_denominator(
        self,
        formula: str,
        counters: CounterDict,
    ) -> bool:
        """Check if formula has zero denominators.
        
        Args:
            formula: Formula string.
            counters: Counter values.
            
        Returns:
            True if no zero denominators, False otherwise.
        """
        # Find division operations
        div_pattern = r'(\w+)\s*/\s*(\w+)'
        matches = re.findall(div_pattern, formula)
        
        for numerator, denominator in matches:
            if denominator in counters:
                if counters[denominator] == 0:
                    return False
        
        return True
    
    def assign_quality_flag(
        self,
        value: Optional[float],
        counters: Optional[CounterDict] = None,
        zero_vars: Optional[List[str]] = None,
        # Alternative signature support
        expected_range: Optional[Tuple[float, float]] = None,
        data_completeness: float = 1.0,
    ) -> QualityFlag:
        """Assign quality flag based on computation result.
        
        Supports two signatures:
        1. assign_quality_flag(value, counters, zero_vars)
        2. assign_quality_flag(value, expected_range, data_completeness)
        
        Args:
            value: Computed KPI value.
            counters: Counter values used (original signature).
            zero_vars: List of zero-valued counters (original signature).
            expected_range: Tuple of (min, max) expected values.
            data_completeness: Percentage of data available (0.0 to 1.0).
            
        Returns:
            Appropriate quality flag.
        """
        # Handle alternative signature
        if expected_range is not None:
            # Alternative signature: assign_quality_flag(value, expected_range, data_completeness)
            if value is None:
                return QualityFlag.NO_DATA
            
            # Check if value is within expected range
            min_val, max_val = expected_range
            if min_val <= value <= max_val:
                # Check data completeness
                if data_completeness >= 0.8:
                    return QualityFlag.NORMAL
                elif data_completeness >= 0.5:
                    return QualityFlag.DEGRADED
                else:
                    return QualityFlag.NO_DATA
            else:
                return QualityFlag.DEGRADED
        
        # Original signature: assign_quality_flag(value, counters, zero_vars)
        if value is None:
            return QualityFlag.NO_DATA
        
        if counters is None or not counters:
            return QualityFlag.NO_DATA
        
        if zero_vars is None:
            zero_vars = []
        
        # Check for zero denominator situations
        if zero_vars:
            for var in zero_vars:
                # Check if zero var is used as denominator
                if "attempt" in var.lower() or "att" in var.lower():
                    return QualityFlag.ZERO_DENOMINATOR
        
        # Check for negative values (invalid for most KPIs)
        if value < 0:
            return QualityFlag.COMPUTATION_ERROR
        
        # Check for unrealistic values
        if value > 100 and "rate" in str(value).lower():
            return QualityFlag.DEGRADED
        
        return QualityFlag.NORMAL
    
    def map_counters(
        self,
        vendor_counters: CounterDict,
        vendor: str,
    ) -> CounterDict:
        """Map vendor-specific counters to CIM names.
        
        Args:
            vendor_counters: Dictionary of vendor-specific counter values.
            vendor: Vendor identifier.
            
        Returns:
            Dictionary with CIM names as keys.
        """
        return self.counter_mapper.map_counters(vendor, vendor_counters)
    
    def evaluate_formula(
        self,
        formula: str,
        counters: CounterDict,
    ) -> Tuple[Optional[float], QualityFlag]:
        """Evaluate a custom formula.
        
        Args:
            formula: Custom formula string.
            counters: Counter values.
            
        Returns:
            Tuple of (value, quality_flag).
        """
        value, error = self.formula_evaluator.evaluate(formula, counters)
        
        if error:
            if "zero" in error.lower():
                return None, QualityFlag.ZERO_DENOMINATOR
            return None, QualityFlag.COMPUTATION_ERROR
        
        quality_flag = self.assign_quality_flag(value, counters, [])
        return value, quality_flag
    
    def add_kpi_formula(
        self,
        kpi_name: str,
        formula: str,
        unit: str,
        description: str = "",
    ) -> None:
        """Add a custom KPI formula.
        
        Args:
            kpi_name: Name of the KPI.
            formula: Formula string.
            unit: Unit of measurement.
            description: KPI description.
        """
        self._kpi_formulas[kpi_name] = {
            "formula": formula,
            "unit": unit,
            "description": description,
        }
        
        logger.info(f"Added KPI formula: {kpi_name}")
    
    def get_supported_kpis(self) -> List[str]:
        """Get list of supported KPI names.
        
        Returns:
            List of KPI names.
        """
        return list(self._kpi_formulas.keys())


# Export classes
__all__ = [
    "QualityFlag",
    "CounterType",
    "CounterMapping",
    "ComputationResult",
    "CounterMapper",
    "FormulaEvaluator",
    "KPIComputer",
]
