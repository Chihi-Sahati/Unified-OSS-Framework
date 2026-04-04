"""
Alarm Normalization Module for FCAPS Fault Management.

This module provides comprehensive alarm normalization functionality including
vendor-specific severity mapping, timestamp normalization, and resource path
generation for the Unified OSS Framework.

Supports:
    - Vendor-specific severity mapping
    - Timestamp normalization to ISO 8601
    - Alarm text normalization
    - Resource path generation (CIM format)
    - Probable cause mapping
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import (
    Any,
    Callable,
    Dict,
    Generic,
    List,
    Optional,
    Pattern,
    Tuple,
    TypeVar,
    Union,
)

# Configure module logger
logger = logging.getLogger(__name__)

# Type aliases
T = TypeVar("T")


class NormalizationError(Exception):
    """Base exception for normalization operations."""
    pass


class SeverityMappingError(NormalizationError):
    """Exception raised for severity mapping failures."""
    pass


class TimestampParsingError(NormalizationError):
    """Exception raised for timestamp parsing failures."""
    pass


class ResourcePathError(NormalizationError):
    """Exception raised for resource path generation failures."""
    pass


class CIMSeverity(Enum):
    """CIM-compliant severity enumeration.
    
    Attributes:
        CRITICAL: Critical severity requiring immediate attention.
        HIGH: Major severity requiring prompt attention.
        MEDIUM: Minor severity for non-critical issues.
        LOW: Warning severity for informational purposes.
        INDETERMINATE: Severity cannot be determined.
        CLEARED: Alarm has been cleared.
    """
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INDETERMINATE = "INDETERMINATE"
    CLEARED = "CLEARED"


class VendorType(Enum):
    """Supported vendor types.
    
    Attributes:
        ERICSSON: Ericsson network equipment.
        HUAWEI: Huawei network equipment.
        NOKIA: Nokia network equipment.
        ZTE: ZTE network equipment.
        CISCO: Cisco network equipment.
        UNKNOWN: Unknown vendor.
    """
    ERICSSON = "ERICSSON"
    HUAWEI = "HUAWEI"
    NOKIA = "NOKIA"
    ZTE = "ZTE"
    CISCO = "CISCO"
    UNKNOWN = "UNKNOWN"


@dataclass
class SeverityMapping:
    """Dataclass representing a severity mapping rule.
    
    Attributes:
        vendor: Vendor identifier.
        source_value: Original severity value.
        target_severity: Mapped CIM severity.
        confidence: Confidence level of the mapping.
        conditions: Additional conditions for mapping.
    """
    vendor: str
    source_value: Union[str, int]
    target_severity: CIMSeverity
    confidence: float = 1.0
    conditions: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NormalizationResult:
    """Dataclass representing the result of normalization.
    
    Attributes:
        success: Whether normalization was successful.
        normalized_data: Normalized alarm data.
        warnings: List of warning messages.
        original_data: Original input data.
        transformations: List of applied transformations.
        normalized_alarm: The normalized alarm object (if successful).
        error: Error message (if failed).
    """
    success: bool
    normalized_data: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    original_data: Dict[str, Any] = field(default_factory=dict)
    transformations: List[Dict[str, Any]] = field(default_factory=list)
    normalized_alarm: Optional["NormalizedAlarm"] = None
    error: Optional[str] = None

    def add_transformation(
        self,
        field_name: str,
        original: Any,
        normalized: Any,
    ) -> None:
        """Record a transformation.
        
        Args:
            field_name: Name of the transformed field.
            original: Original value.
            normalized: Normalized value.
        """
        self.transformations.append({
            "field": field_name,
            "original": original,
            "normalized": normalized,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })


@dataclass
class NormalizedAlarm:
    """Dataclass representing a normalized alarm.
    
    Attributes:
        alarm_id: Unique identifier for the alarm.
        ne_id: Network element identifier.
        alarm_type: Type of alarm (ITU-T standard).
        severity: Normalized severity level.
        probable_cause: ITU-T probable cause code.
        specific_problem: Vendor-specific problem description.
        timestamp: Alarm timestamp in ISO 8601 format.
        vendor: Vendor identifier.
        original_data: Original vendor alarm data.
    """
    alarm_id: str
    ne_id: str
    alarm_type: str
    severity: str
    probable_cause: str
    specific_problem: str
    timestamp: datetime
    vendor: str
    original_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert normalized alarm to dictionary representation.
        
        Returns:
            Dictionary containing all alarm attributes.
        """
        return {
            "alarm_id": self.alarm_id,
            "ne_id": self.ne_id,
            "alarm_type": self.alarm_type,
            "severity": self.severity,
            "probable_cause": self.probable_cause,
            "specific_problem": self.specific_problem,
            "timestamp": self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else self.timestamp,
            "vendor": self.vendor,
            "original_data": self.original_data,
        }

    def calculate_hash(self) -> str:
        """Calculate a hash for the alarm for deduplication.
        
        Returns:
            SHA-256 hash string.
        """
        import hashlib
        data = f"{self.alarm_id}:{self.ne_id}:{self.alarm_type}:{self.severity}:{self.probable_cause}"
        return hashlib.sha256(data.encode()).hexdigest()


class VendorAlarmParser:
    """Parser for vendor-specific alarm formats.
    
    This class provides methods for parsing alarm data from different
    vendors including Ericsson, Huawei, and Nokia.
    
    Example:
        >>> parser = VendorAlarmParser()
        >>> result = parser.parse_ericsson(ericsson_data)
        >>> print(result["alarm_id"])
    """

    # Ericsson severity mappings
    ERICSSON_SEVERITY_MAP: Dict[str, str] = {
        "critical": "CRITICAL",
        "a1": "CRITICAL",
        "major": "MAJOR",
        "a2": "MAJOR",
        "minor": "MINOR",
        "a3": "MINOR",
        "warning": "WARNING",
        "b1": "WARNING",
        "indeterminate": "MINOR",
        "cleared": "CLEARED",
    }

    # Huawei severity mappings (integer-based)
    HUAWEI_SEVERITY_MAP: Dict[int, str] = {
        1: "CRITICAL",
        2: "MAJOR",
        3: "MINOR",
        4: "WARNING",
        0: "MINOR",
        5: "CLEARED",
    }

    # Nokia severity mappings
    NOKIA_SEVERITY_MAP: Dict[str, str] = {
        "a1": "CRITICAL",
        "a2": "MAJOR",
        "a3": "MINOR",
        "critical": "CRITICAL",
        "major": "MAJOR",
        "minor": "MINOR",
        "warning": "WARNING",
    }

    def __init__(self) -> None:
        """Initialize the vendor alarm parser."""
        self._timestamp_normalizer = TimestampNormalizer()

    def parse_ericsson(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Ericsson alarm data.
        
        Args:
            data: Raw Ericsson alarm data.
            
        Returns:
            Parsed alarm dictionary.
        """
        return {
            "alarm_id": data.get("alarmId", data.get("alarm_id", "")),
            "ne_id": data.get("managedObject", data.get("moId", data.get("ne_id", ""))),
            "alarm_type": data.get("eventType", "EquipmentAlarm"),
            "severity": self.map_severity_ericsson(
                data.get("perceivedSeverity", data.get("severity", "indeterminate"))
            ),
            "probable_cause": data.get("probableCause", data.get("probable_cause", "")),
            "specific_problem": data.get("specificProblem", data.get("specific_problem", "")),
            "timestamp": self.parse_timestamp(data.get("eventTime", data.get("timestamp", ""))),
            "vendor": "ericsson",
            "raw_data": data,
        }

    def parse_huawei(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Huawei alarm data.
        
        Args:
            data: Raw Huawei alarm data.
            
        Returns:
            Parsed alarm dictionary.
        """
        severity_val = data.get("alarmLevel", data.get("severity", 0))
        if isinstance(severity_val, int):
            severity = self.map_severity_huawei(severity_val)
        else:
            severity = str(severity_val).upper()
            
        return {
            "alarm_id": data.get("alarmId", data.get("alarm_id", "")),
            "ne_id": data.get("neName", data.get("neId", data.get("ne_id", ""))),
            "alarm_type": data.get("alarmName", data.get("alarm_type", "EquipmentAlarm")),
            "severity": severity,
            "level": severity_val if isinstance(severity_val, int) else None,
            "probable_cause": data.get("probableCause", data.get("probable_cause", "")),
            "specific_problem": data.get("alarmTitle", data.get("specific_problem", "")),
            "timestamp": self.parse_timestamp(data.get("occurTime", data.get("timestamp", ""))),
            "vendor": "huawei",
            "raw_data": data,
        }

    def parse_nokia(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Nokia alarm data.
        
        Args:
            data: Raw Nokia alarm data.
            
        Returns:
            Parsed alarm dictionary.
        """
        return {
            "alarm_id": data.get("alarmId", data.get("alarm_id", "")),
            "ne_id": data.get("nodeName", data.get("ne_id", "")),
            "alarm_type": data.get("eventType", data.get("alarm_type", "EquipmentAlarm")),
            "severity": self.map_severity_nokia(
                data.get("alarmCode", data.get("severity", "minor"))
            ),
            "probable_cause": data.get("probableCause", data.get("probable_cause", "")),
            "specific_problem": data.get("alarmText", data.get("specific_problem", "")),
            "timestamp": self.parse_timestamp(data.get("eventTime", data.get("timestamp", ""))),
            "vendor": "nokia",
            "raw_data": data,
        }

    def map_severity_ericsson(self, severity: str) -> str:
        """Map Ericsson severity to standard format.
        
        Args:
            severity: Ericsson severity string.
            
        Returns:
            Standard severity string.
        """
        return self.ERICSSON_SEVERITY_MAP.get(severity.lower(), "MINOR")

    def map_severity_huawei(self, severity: int) -> str:
        """Map Huawei severity to standard format.
        
        Args:
            severity: Huawei severity integer.
            
        Returns:
            Standard severity string.
        """
        return self.HUAWEI_SEVERITY_MAP.get(severity, "MINOR")

    def map_severity_nokia(self, severity: str) -> str:
        """Map Nokia severity to standard format.
        
        Args:
            severity: Nokia severity string.
            
        Returns:
            Standard severity string.
        """
        return self.NOKIA_SEVERITY_MAP.get(severity.lower(), "MINOR")

    def parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse a timestamp string to datetime.
        
        Args:
            timestamp_str: Timestamp string in various formats.
            
        Returns:
            Parsed datetime or None if parsing fails.
        """
        if not timestamp_str:
            return None
            
        # Try ISO format first
        try:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            pass
            
        # Try common formats
        formats = [
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y%m%d%H%M%S",
        ]
        
        for fmt in formats:
            try:
                dt = datetime.strptime(timestamp_str, fmt)
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
                
        return None

    def extract_additional_info(
        self,
        data: Dict[str, Any],
        vendor: VendorType,
    ) -> Dict[str, Any]:
        """Extract additional information from alarm data.
        
        Args:
            data: Raw alarm data.
            vendor: Vendor type.
            
        Returns:
            Dictionary of additional information.
        """
        # Standard fields to exclude
        standard_fields = {
            "alarmId", "alarm_id", "managedObject", "moId", "neId", "ne_id",
            "neName", "nodeName", "eventType", "alarmName", "alarm_type",
            "perceivedSeverity", "severity", "alarmLevel", "alarmCode",
            "probableCause", "probable_cause", "specificProblem", "specific_problem",
            "eventTime", "timestamp", "occurTime", "alarmText", "alarmTitle",
            "additionalText", "neType", "alarmSource", "objectName",
        }
        
        additional = {}
        for key, value in data.items():
            if key.lower() not in {f.lower() for f in standard_fields}:
                additional[key] = value
                
        return additional


class ITUTMapper:
    """ITU-T X.733 standard mapper for alarm types and causes.
    
    This class provides mapping from vendor-specific alarm types and
    probable causes to ITU-T standard values.
    
    Example:
        >>> mapper = ITUTMapper()
        >>> alarm_type = mapper.map_alarm_type("EquipmentAlarm")
        >>> cause = mapper.map_probable_cause("Power Failure")
    """

    # ITU-T X.733 Alarm Types
    ALARM_TYPES: Dict[str, str] = {
        "equipmentalarm": "EQUIPMENT_ALARM",
        "communicationsalarm": "COMMUNICATIONS_ALARM",
        "processingerroralarm": "PROCESSING_ERROR_ALARM",
        "environmentalalarm": "ENVIRONMENTAL_ALARM",
        "qualityofservicealarm": "QUALITY_OF_SERVICE_ALARM",
        "integrityviolation": "INTEGRITY_VIOLATION",
        "operationalviolation": "OPERATIONAL_VIOLATION",
        "physicalviolation": "PHYSICAL_VIOLATION",
        "securityserviceormechanismviolation": "SECURITY_VIOLATION",
        "time_domain_violation": "TIME_DOMAIN_VIOLATION",
    }

    # ITU-T X.733 Probable Cause Codes
    PROBABLE_CAUSE_CODES: Dict[str, int] = {
        "adapterError": 1,
        "applicationSubsystemFailure": 2,
        "bandwidthReduced": 3,
        "callEstablishmentError": 4,
        "communicationsProtocolError": 5,
        "communicationsSubsystemFailure": 6,
        "configurationOrCustomizationError": 7,
        "congestion": 8,
        "corruptData": 9,
        "cpuCyclesLimitExceeded": 10,
        "dataSetOrModemError": 11,
        "degradedSignal": 12,
        "dteDceInterfaceError": 13,
        "enclosureDoorOpen": 14,
        "equipmentMalfunction": 15,
        "excessiveVibration": 16,
        "fileError": 17,
        "fireDetected": 18,
        "floodDetected": 19,
        "framingError": 20,
        "heatingOrVentilationSystemFailure": 21,
        "humidityUnacceptable": 22,
        "inputOutputDeviceError": 23,
        "inputDeviceError": 24,
        "lanError": 25,
        "leakDetected": 26,
        "localNodeTransmissionError": 27,
        "lossOfFrame": 28,
        "lossOfSignal": 29,
        "materialSupplyExhausted": 30,
        "multiplexerProblem": 31,
        "outOfMemory": 32,
        "outputDeviceError": 33,
        "performanceDegraded": 34,
        "powerProblem": 35,
        "pressureUnacceptable": 36,
        "processorProblem": 37,
        "pumpFailure": 38,
        "queueSizeExceeded": 39,
        "receiveFailure": 40,
        "receiverFailure": 41,
        "remoteNodeTransmissionError": 42,
        "resourceAtOrNearingCapacity": 43,
        "responseTimeExcessive": 44,
        "retransmissionRateExcessive": 45,
        "softwareError": 46,
        "softwareProgramAbnormallyTerminated": 47,
        "softwareProgramFault": 48,
        "storageCapacityProblem": 49,
        "temperatureUnacceptable": 50,
        "thresholdCrossed": 51,
        "timingProblem": 52,
        "toxicLeakDetected": 53,
        "transmitFailure": 54,
        "transmitterFailure": 55,
        "underlyingResourceUnavailable": 56,
        "versionMismatch": 57,
    }

    # Reverse mapping from code to cause
    PROBABLE_CAUSE_NAMES: Dict[int, str] = {
        v: k for k, v in PROBABLE_CAUSE_CODES.items()
    }

    # Alarm category mapping
    ALARM_CATEGORIES: Dict[str, str] = {
        "equipmentalarm": "EQUIPMENT",
        "communicationsalarm": "COMMUNICATIONS",
        "processingerroralarm": "PROCESSING",
        "environmentalalarm": "ENVIRONMENT",
        "qualityofservicealarm": "QUALITY_OF_SERVICE",
    }

    # Severity mapping to ITU-T values
    SEVERITY_TO_ITU: Dict[str, str] = {
        "CRITICAL": "critical",
        "MAJOR": "major",
        "MINOR": "minor",
        "WARNING": "warning",
        "INDETERMINATE": "indeterminate",
        "CLEARED": "cleared",
    }

    # Vendor cause name to ITU-T code mapping
    CAUSE_NAME_MAPPING: Dict[str, str] = {
        "power failure": "powerProblem",
        "power": "powerProblem",
        "link down": "lossOfSignal",
        "link failure": "lossOfSignal",
        "communication failure": "communicationsSubsystemFailure",
        "equipment failure": "equipmentMalfunction",
        "temperature": "temperatureUnacceptable",
        "overheating": "temperatureUnacceptable",
        "processor": "processorProblem",
        "cpu": "processorProblem",
        "memory": "outOfMemory",
        "software error": "softwareError",
        "timing": "timingProblem",
        "synchronization": "timingProblem",
        "threshold": "thresholdCrossed",
        "bandwidth": "bandwidthReduced",
        "congestion": "congestion",
        "threshold crossed": "thresholdCrossed",
    }

    def __init__(self) -> None:
        """Initialize the ITU-T mapper."""
        pass

    def map_alarm_type(self, vendor_type: str) -> str:
        """Map vendor alarm type to ITU-T standard.
        
        Args:
            vendor_type: Vendor-specific alarm type.
            
        Returns:
            ITU-T standard alarm type.
        """
        normalized = vendor_type.lower().replace(" ", "").replace("_", "")
        return self.ALARM_TYPES.get(normalized, "EQUIPMENT_ALARM")

    def map_probable_cause(self, cause: str) -> Union[int, str]:
        """Map probable cause to ITU-T code.
        
        Args:
            cause: Vendor probable cause string.
            
        Returns:
            ITU-T probable cause code (int) or name (str).
        """
        # Check direct mapping
        cause_lower = cause.lower()
        if cause_lower in self.CAUSE_NAME_MAPPING:
            itu_name = self.CAUSE_NAME_MAPPING[cause_lower]
            return self.PROBABLE_CAUSE_CODES.get(itu_name, 0)
            
        # Check if it's already an ITU-T cause name
        for itu_name, code in self.PROBABLE_CAUSE_CODES.items():
            if itu_name.lower() == cause_lower:
                return code
                
        return cause  # Return original if no mapping found

    def get_alarm_category(self, alarm_type: str) -> str:
        """Get ITU-T alarm category for an alarm type.
        
        Args:
            alarm_type: Alarm type string.
            
        Returns:
            ITU-T alarm category.
        """
        normalized = alarm_type.lower().replace(" ", "").replace("_", "")
        return self.ALARM_CATEGORIES.get(normalized, "EQUIPMENT")

    def map_severity_to_itu(self, severity: str) -> str:
        """Map severity to ITU-T standard value.
        
        Args:
            severity: Severity string.
            
        Returns:
            ITU-T severity value (lowercase).
        """
        return self.SEVERITY_TO_ITU.get(severity.upper(), "indeterminate")

    def lookup_probable_cause_code(self, cause_name: str) -> Optional[int]:
        """Look up probable cause code by name.
        
        Args:
            cause_name: Probable cause name.
            
        Returns:
            ITU-T code or None if not found.
        """
        cause_lower = cause_name.lower()
        
        # Check mapping first
        if cause_lower in self.CAUSE_NAME_MAPPING:
            itu_name = self.CAUSE_NAME_MAPPING[cause_lower]
            return self.PROBABLE_CAUSE_CODES.get(itu_name)
            
        # Check ITU-T names
        for name, code in self.PROBABLE_CAUSE_CODES.items():
            if name.lower() == cause_lower:
                return code
                
        return None

    def reverse_lookup(self, code: int) -> str:
        """Reverse lookup from code to cause name.
        
        Args:
            code: ITU-T probable cause code.
            
        Returns:
            Probable cause name.
        """
        return self.PROBABLE_CAUSE_NAMES.get(code, "")


class SeverityMapper:
    """Maps vendor-specific severity values to CIM severity.
    
    This class provides comprehensive severity mapping for multiple
    vendors including Ericsson (string-based) and Huawei (integer-based).
    
    Example:
        >>> mapper = SeverityMapper()
        >>> severity = mapper.map("critical", VendorType.ERICSSON)
        >>> print(severity)  # CIMSeverity.CRITICAL
    """

    # Ericsson severity mappings (string-based)
    ERICSSON_MAP: Dict[str, CIMSeverity] = {
        "critical": CIMSeverity.CRITICAL,
        "a1": CIMSeverity.CRITICAL,
        "major": CIMSeverity.HIGH,
        "a2": CIMSeverity.HIGH,
        "minor": CIMSeverity.MEDIUM,
        "a3": CIMSeverity.MEDIUM,
        "warning": CIMSeverity.LOW,
        "b1": CIMSeverity.LOW,
        "indeterminate": CIMSeverity.INDETERMINATE,
        "cleared": CIMSeverity.CLEARED,
        "clear": CIMSeverity.CLEARED,
        "normalized": CIMSeverity.CLEARED,
    }

    # Huawei severity mappings (integer-based)
    HUAWEI_MAP: Dict[int, CIMSeverity] = {
        1: CIMSeverity.CRITICAL,
        2: CIMSeverity.HIGH,
        3: CIMSeverity.MEDIUM,
        4: CIMSeverity.LOW,
        0: CIMSeverity.INDETERMINATE,
        5: CIMSeverity.CLEARED,
    }

    # Nokia severity mappings
    NOKIA_MAP: Dict[str, CIMSeverity] = {
        "critical": CIMSeverity.CRITICAL,
        "major": CIMSeverity.HIGH,
        "minor": CIMSeverity.MEDIUM,
        "warning": CIMSeverity.LOW,
        "indeterminate": CIMSeverity.INDETERMINATE,
        "cleared": CIMSeverity.CLEARED,
    }

    # ZTE severity mappings
    ZTE_MAP: Dict[int, CIMSeverity] = {
        1: CIMSeverity.CRITICAL,
        2: CIMSeverity.HIGH,
        3: CIMSeverity.MEDIUM,
        4: CIMSeverity.LOW,
        5: CIMSeverity.INDETERMINATE,
        6: CIMSeverity.CLEARED,
    }

    # Cisco severity mappings
    CISCO_MAP: Dict[int, CIMSeverity] = {
        1: CIMSeverity.CRITICAL,
        2: CIMSeverity.HIGH,
        3: CIMSeverity.MEDIUM,
        4: CIMSeverity.LOW,
        5: CIMSeverity.INDETERMINATE,
    }

    def __init__(self) -> None:
        """Initialize the severity mapper with default mappings."""
        self._mappings: Dict[VendorType, Dict[Any, CIMSeverity]] = {
            VendorType.ERICSSON: self.ERICSSON_MAP,
            VendorType.HUAWEI: self.HUAWEI_MAP,
            VendorType.NOKIA: self.NOKIA_MAP,
            VendorType.ZTE: self.ZTE_MAP,
            VendorType.CISCO: self.CISCO_MAP,
        }
        self._custom_mappings: Dict[str, Dict[Any, CIMSeverity]] = {}

    def map(
        self,
        severity_value: Union[str, int, float],
        vendor: VendorType,
        default: CIMSeverity = CIMSeverity.INDETERMINATE,
    ) -> CIMSeverity:
        """Map a vendor severity value to CIM severity.
        
        Args:
            severity_value: Original severity value.
            vendor: Vendor type.
            default: Default severity if mapping not found.
            
        Returns:
            Mapped CIM severity.
        """
        # Handle float by converting to int
        if isinstance(severity_value, float):
            severity_value = int(severity_value)

        # Get vendor mapping
        vendor_map = self._mappings.get(vendor, {})

        # For string values, try case-insensitive match
        if isinstance(severity_value, str):
            normalized_value = severity_value.lower().strip()
            
            # Check vendor-specific mapping
            if normalized_value in vendor_map:
                return vendor_map[normalized_value]
            
            # Check custom mappings
            for custom_map in self._custom_mappings.values():
                if normalized_value in custom_map:
                    return custom_map[normalized_value]
            
            # Fuzzy matching for common variations
            fuzzy_result = self._fuzzy_match_severity(normalized_value)
            if fuzzy_result:
                logger.debug(f"Fuzzy matched severity '{severity_value}' to {fuzzy_result.value}")
                return fuzzy_result

        # For integer values
        elif isinstance(severity_value, int):
            if severity_value in vendor_map:
                return vendor_map[severity_value]

        logger.warning(
            f"Unknown severity '{severity_value}' for vendor {vendor.value}, "
            f"defaulting to {default.value}"
        )
        return default

    def _fuzzy_match_severity(self, value: str) -> Optional[CIMSeverity]:
        """Attempt fuzzy matching for severity values.
        
        Args:
            value: Severity string to match.
            
        Returns:
            Matched CIM severity or None.
        """
        # Common patterns
        patterns = {
            r"crit": CIMSeverity.CRITICAL,
            r"emerg": CIMSeverity.CRITICAL,
            r"alert": CIMSeverity.HIGH,
            r"maj": CIMSeverity.HIGH,
            r"high": CIMSeverity.HIGH,
            r"min": CIMSeverity.MEDIUM,
            r"med": CIMSeverity.MEDIUM,
            r"warn": CIMSeverity.LOW,
            r"info": CIMSeverity.LOW,
            r"debug": CIMSeverity.LOW,
            r"clear": CIMSeverity.CLEARED,
            r"norm": CIMSeverity.CLEARED,
            r"resolv": CIMSeverity.CLEARED,
        }

        for pattern, severity in patterns.items():
            if re.search(pattern, value, re.IGNORECASE):
                return severity

        return None

    def add_custom_mapping(
        self,
        vendor_name: str,
        source_value: Union[str, int],
        target_severity: CIMSeverity,
    ) -> None:
        """Add a custom severity mapping.
        
        Args:
            vendor_name: Vendor identifier.
            source_value: Source severity value.
            target_severity: Target CIM severity.
        """
        if vendor_name not in self._custom_mappings:
            self._custom_mappings[vendor_name] = {}
        
        self._custom_mappings[vendor_name][source_value] = target_severity
        logger.info(f"Added custom severity mapping: {vendor_name}:{source_value} -> {target_severity.value}")

    def get_available_mappings(self) -> Dict[str, List[Tuple[Any, str]]]:
        """Get all available severity mappings.
        
        Returns:
            Dictionary of vendor -> list of (source, target) mappings.
        """
        result = {}

        for vendor, mapping in self._mappings.items():
            result[vendor.value] = [
                (src, tgt.value) for src, tgt in mapping.items()
            ]

        for vendor, mapping in self._custom_mappings.items():
            if vendor not in result:
                result[vendor] = []
            result[vendor].extend([
                (src, tgt.value) for src, tgt in mapping.items()
            ])

        return result


class TimestampNormalizer:
    """Normalizes vendor-specific timestamps to ISO 8601 format.
    
    This class handles various timestamp formats from different vendors
    and converts them to standardized ISO 8601 format with UTC timezone.
    
    Example:
        >>> normalizer = TimestampNormalizer()
        >>> iso_time = normalizer.normalize("2024-01-15 10:30:00", VendorType.ERICSSON)
        >>> print(iso_time)  # 2024-01-15T10:30:00+00:00
    """

    # Vendor-specific timestamp formats
    TIMESTAMP_FORMATS: Dict[VendorType, List[str]] = {
        VendorType.ERICSSON: [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f%z",
        ],
        VendorType.HUAWEI: [
            "%Y-%m-%d %H:%M:%S",
            "%Y%m%d%H%M%S",
            "%Y%m%d%H%M%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y/%m/%d %H:%M:%S",
        ],
        VendorType.NOKIA: [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%d-%m-%Y %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S%z",
        ],
        VendorType.ZTE: [
            "%Y-%m-%d %H:%M:%S",
            "%Y%m%d%H%M%S",
            "%Y-%m-%dT%H:%M:%S",
        ],
        VendorType.CISCO: [
            "%Y-%m-%d %H:%M:%S",
            "%b %d %H:%M:%S",
            "%Y %b %d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
        ],
        VendorType.UNKNOWN: [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y%m%d%H%M%S",
        ],
    }

    # Regex patterns for special formats
    EPOCH_PATTERN: Pattern = re.compile(r"^\d{10,13}$")

    def __init__(self, default_timezone: str = "UTC") -> None:
        """Initialize the timestamp normalizer.
        
        Args:
            default_timezone: Default timezone for timestamps without timezone info.
        """
        self._default_timezone = default_timezone
        self._custom_formats: Dict[str, List[str]] = {}

    def normalize(
        self,
        timestamp_value: Union[str, int, float, datetime],
        vendor: VendorType = VendorType.UNKNOWN,
    ) -> str:
        """Normalize a timestamp to ISO 8601 format.
        
        Args:
            timestamp_value: Original timestamp value.
            vendor: Vendor type for format hints.
            
        Returns:
            ISO 8601 formatted timestamp string.
            
        Raises:
            TimestampParsingError: If timestamp cannot be parsed.
        """
        # Handle datetime objects directly
        if isinstance(timestamp_value, datetime):
            return self._datetime_to_iso(timestamp_value)

        # Handle epoch timestamps (seconds or milliseconds)
        if isinstance(timestamp_value, (int, float)):
            return self._epoch_to_iso(timestamp_value)

        # Handle string timestamps
        if isinstance(timestamp_value, str):
            # Check for epoch as string
            if self.EPOCH_PATTERN.match(timestamp_value):
                return self._epoch_to_iso(int(timestamp_value))

            # Try vendor-specific formats
            return self._parse_string_timestamp(timestamp_value, vendor)

        raise TimestampParsingError(f"Unsupported timestamp type: {type(timestamp_value)}")

    def _datetime_to_iso(self, dt: datetime) -> str:
        """Convert a datetime object to ISO 8601 string.
        
        Args:
            dt: Datetime object.
            
        Returns:
            ISO 8601 formatted string.
        """
        # Ensure timezone info
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        
        return dt.isoformat()

    def _epoch_to_iso(self, epoch: Union[int, float]) -> str:
        """Convert an epoch timestamp to ISO 8601 string.
        
        Args:
            epoch: Epoch timestamp (seconds or milliseconds).
            
        Returns:
            ISO 8601 formatted string.
        """
        # Handle milliseconds
        if epoch > 1e12:
            epoch = epoch / 1000

        dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
        return dt.isoformat()

    def _parse_string_timestamp(self, timestamp_str: str, vendor: VendorType) -> str:
        """Parse a string timestamp using vendor-specific formats.
        
        Args:
            timestamp_str: Timestamp string.
            vendor: Vendor type.
            
        Returns:
            ISO 8601 formatted string.
            
        Raises:
            TimestampParsingError: If parsing fails.
        """
        timestamp_str = timestamp_str.strip()

        # Get formats to try
        formats = list(self.TIMESTAMP_FORMATS.get(vendor, []))
        
        # Add custom formats
        formats.extend(self._custom_formats.get(vendor.value, []))
        
        # Add generic formats
        formats.extend(self.TIMESTAMP_FORMATS[VendorType.UNKNOWN])

        # Remove duplicates while preserving order
        seen = set()
        unique_formats = []
        for fmt in formats:
            if fmt not in seen:
                seen.add(fmt)
                unique_formats.append(fmt)

        # Try each format
        for fmt in unique_formats:
            try:
                dt = datetime.strptime(timestamp_str, fmt)
                
                # Add timezone if not present
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                
                return dt.isoformat()
            except ValueError:
                continue

        # Try ISO format directly
        try:
            dt = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            return dt.isoformat()
        except ValueError:
            pass

        raise TimestampParsingError(
            f"Cannot parse timestamp '{timestamp_str}' for vendor {vendor.value}"
        )

    def add_custom_format(self, vendor_name: str, format_string: str) -> None:
        """Add a custom timestamp format for a vendor.
        
        Args:
            vendor_name: Vendor identifier.
            format_string: Python datetime format string.
        """
        if vendor_name not in self._custom_formats:
            self._custom_formats[vendor_name] = []
        
        self._custom_formats[vendor_name].append(format_string)
        logger.info(f"Added custom timestamp format for {vendor_name}: {format_string}")

    def now_iso(self) -> str:
        """Get current timestamp in ISO 8601 format.
        
        Returns:
            Current UTC timestamp as ISO 8601 string.
        """
        return datetime.now(timezone.utc).isoformat()


class ResourcePathGenerator:
    """Generates CIM-format resource paths from vendor-specific identifiers.
    
    This class handles the generation of standardized CIM resource paths
    from various vendor-specific naming conventions.
    
    Example:
        >>> generator = ResourcePathGenerator()
        >>> path = generator.generate("SubNetwork=SN1,ManagedElement=ME1", VendorType.ERICSSON)
        >>> print(path)  # /network/subnetworks/SN1/managedelements/ME1
    """

    # Resource type mappings
    ERICSSON_TYPE_MAP: Dict[str, str] = {
        "subnetwork": "subnetworks",
        "managedelement": "managedelements",
        "enodebfunction": "enodebs",
        "gnodebfunction": "gnodebs",
        "cell": "cells",
        "equipment": "equipment",
        "rru": "radiounits",
        "bbu": "basebandunits",
    }

    HUAWEI_TYPE_MAP: Dict[str, str] = {
        "ne": "elements",
        "enodeb": "enodebs",
        "gnodeb": "gnodebs",
        "cell": "cells",
        "board": "boards",
        "rru": "radiounits",
        "bbu": "basebandunits",
    }

    def __init__(self) -> None:
        """Initialize the resource path generator."""
        self._type_maps: Dict[VendorType, Dict[str, str]] = {
            VendorType.ERICSSON: self.ERICSSON_TYPE_MAP,
            VendorType.HUAWEI: self.HUAWEI_TYPE_MAP,
        }

    def generate(
        self,
        vendor_identifier: str,
        vendor: VendorType,
        site_id: Optional[str] = None,
        region_id: Optional[str] = None,
    ) -> str:
        """Generate a CIM-format resource path.
        
        Args:
            vendor_identifier: Vendor-specific resource identifier.
            vendor: Vendor type.
            site_id: Optional site identifier.
            region_id: Optional region identifier.
            
        Returns:
            CIM-format resource path.
        """
        if vendor == VendorType.ERICSSON:
            return self._generate_ericsson_path(vendor_identifier, site_id, region_id)
        elif vendor == VendorType.HUAWEI:
            return self._generate_huawei_path(vendor_identifier, site_id, region_id)
        elif vendor == VendorType.NOKIA:
            return self._generate_nokia_path(vendor_identifier, site_id, region_id)
        else:
            return self._generate_generic_path(vendor_identifier, site_id, region_id)

    def _generate_ericsson_path(
        self,
        identifier: str,
        site_id: Optional[str],
        region_id: Optional[str],
    ) -> str:
        """Generate resource path from Ericsson MO format.
        
        Ericsson uses comma-separated key=value pairs.
        Example: SubNetwork=SN1,ManagedElement=ME1
        
        Args:
            identifier: Ericsson managed object identifier.
            site_id: Optional site identifier.
            region_id: Optional region identifier.
            
        Returns:
            CIM-format resource path.
        """
        parts = []
        
        # Add region if provided
        if region_id:
            parts.extend(["regions", region_id])
        
        # Add site if provided
        if site_id:
            parts.extend(["sites", site_id])

        # Parse Ericsson MO identifier
        if identifier:
            mo_parts = identifier.split(",")
            for part in mo_parts:
                if "=" in part:
                    key, value = part.split("=", 1)
                    key_lower = key.lower().replace(" ", "")
                    
                    # Map to CIM type
                    type_map = self._type_maps.get(VendorType.ERICSSON, {})
                    cim_type = type_map.get(key_lower, key_lower + "s")
                    
                    parts.extend([cim_type, value])

        return f"/network/{'/'.join(parts)}" if parts else "/network/unknown"

    def _generate_huawei_path(
        self,
        identifier: str,
        site_id: Optional[str],
        region_id: Optional[str],
    ) -> str:
        """Generate resource path from Huawei NE format.
        
        Huawei uses simple identifiers or structured paths.
        
        Args:
            identifier: Huawei network element identifier.
            site_id: Optional site identifier.
            region_id: Optional region identifier.
            
        Returns:
            CIM-format resource path.
        """
        parts = []
        
        if region_id:
            parts.extend(["regions", region_id])
        
        if site_id:
            parts.extend(["sites", site_id])

        if identifier:
            # Check if it's a structured path
            if "/" in identifier:
                path_parts = identifier.strip("/").split("/")
                parts.extend(path_parts)
            else:
                parts.extend(["elements", identifier])

        return f"/network/{'/'.join(parts)}" if parts else "/network/unknown"

    def _generate_nokia_path(
        self,
        identifier: str,
        site_id: Optional[str],
        region_id: Optional[str],
    ) -> str:
        """Generate resource path from Nokia format.
        
        Args:
            identifier: Nokia resource identifier.
            site_id: Optional site identifier.
            region_id: Optional region identifier.
            
        Returns:
            CIM-format resource path.
        """
        parts = []
        
        if region_id:
            parts.extend(["regions", region_id])
        
        if site_id:
            parts.extend(["sites", site_id])

        if identifier:
            # Nokia uses similar format to Ericsson
            if "=" in identifier:
                return self._generate_ericsson_path(identifier, site_id, region_id)
            else:
                parts.extend(["elements", identifier])

        return f"/network/{'/'.join(parts)}" if parts else "/network/unknown"

    def _generate_generic_path(
        self,
        identifier: str,
        site_id: Optional[str],
        region_id: Optional[str],
    ) -> str:
        """Generate a generic resource path.
        
        Args:
            identifier: Generic resource identifier.
            site_id: Optional site identifier.
            region_id: Optional region identifier.
            
        Returns:
            CIM-format resource path.
        """
        parts = []
        
        if region_id:
            parts.extend(["regions", region_id])
        
        if site_id:
            parts.extend(["sites", site_id])

        if identifier:
            # Sanitize identifier
            sanitized = re.sub(r"[^a-zA-Z0-9_\-]", "_", identifier)
            parts.extend(["elements", sanitized])

        return f"/network/{'/'.join(parts)}" if parts else "/network/unknown"

    def extract_site_id(self, resource_path: str) -> Optional[str]:
        """Extract site ID from a resource path.
        
        Args:
            resource_path: CIM resource path.
            
        Returns:
            Site ID or None.
        """
        parts = resource_path.strip("/").split("/")
        try:
            site_idx = parts.index("sites")
            if site_idx + 1 < len(parts):
                return parts[site_idx + 1]
        except ValueError:
            pass
        return None

    def extract_element_id(self, resource_path: str) -> Optional[str]:
        """Extract element ID from a resource path.
        
        Args:
            resource_path: CIM resource path.
            
        Returns:
            Element ID or None.
        """
        parts = resource_path.strip("/").split("/")
        
        # Check for elements
        try:
            elem_idx = parts.index("elements")
            if elem_idx + 1 < len(parts):
                return parts[elem_idx + 1]
        except ValueError:
            pass
        
        # Check for other element types
        for i, part in enumerate(parts):
            if part.endswith("s") and i + 1 < len(parts):
                return parts[i + 1]
        
        return None


class ProbableCauseMapper:
    """Maps vendor-specific probable cause codes to standard values.
    
    This class provides mapping from vendor-specific probable cause codes
    to ITU-T X.733 standard probable cause values.
    """

    # ITU-T X.733 Standard Probable Causes
    ITU_PROBABLE_CAUSES: Dict[str, str] = {
        "adapterError": "Adapter Error",
        "applicationSubsystemFailure": "Application Subsystem Failure",
        "bandwidthReduced": "Bandwidth Reduced",
        "callEstablishmentError": "Call Establishment Error",
        "communicationsProtocolError": "Communications Protocol Error",
        "communicationsSubsystemFailure": "Communications Subsystem Failure",
        "configurationOrCustomizationError": "Configuration Error",
        "congestion": "Congestion",
        "corruptData": "Corrupt Data",
        "cpuCyclesLimitExceeded": "CPU Limit Exceeded",
        "dataSetOrModemError": "Data Set/Modem Error",
        "degradedSignal": "Degraded Signal",
        "dteDceInterfaceError": "DTE-DCE Interface Error",
        "enclosureDoorOpen": "Enclosure Door Open",
        "equipmentMalfunction": "Equipment Malfunction",
        "excessiveVibration": "Excessive Vibration",
        "fileError": "File Error",
        "fireDetected": "Fire Detected",
        "floodDetected": "Flood Detected",
        "framingError": "Framing Error",
        "heatingOrVentilationSystemFailure": "HVAC Failure",
        "humidityUnacceptable": "Humidity Unacceptable",
        "inputOutputDeviceError": "I/O Device Error",
        "inputDeviceError": "Input Device Error",
        "lanError": "LAN Error",
        "leakDetected": "Leak Detected",
        "localNodeTransmissionError": "Local Node Transmission Error",
        "lossOfFrame": "Loss of Frame",
        "lossOfSignal": "Loss of Signal",
        "materialSupplyExhausted": "Material Supply Exhausted",
        "multiplexerProblem": "Multiplexer Problem",
        "outOfMemory": "Out of Memory",
        "outputDeviceError": "Output Device Error",
        "performanceDegraded": "Performance Degraded",
        "powerProblem": "Power Problem",
        "pressureUnacceptable": "Pressure Unacceptable",
        "processorProblem": "Processor Problem",
        "pumpFailure": "Pump Failure",
        "queueSizeExceeded": "Queue Size Exceeded",
        "receiveFailure": "Receive Failure",
        "receiverFailure": "Receiver Failure",
        "remoteNodeTransmissionError": "Remote Node Transmission Error",
        "resourceAtOrNearingCapacity": "Resource At Capacity",
        "responseTimeExcessive": "Response Time Excessive",
        "retransmissionRateExcessive": "Retransmission Rate Excessive",
        "softwareError": "Software Error",
        "softwareProgramAbnormallyTerminated": "Software Terminated",
        "softwareProgramFault": "Software Fault",
        "storageCapacityProblem": "Storage Capacity Problem",
        "temperatureUnacceptable": "Temperature Unacceptable",
        "thresholdCrossed": "Threshold Crossed",
        "timingProblem": "Timing Problem",
        "toxicLeakDetected": "Toxic Leak Detected",
        "transmitFailure": "Transmit Failure",
        "transmitterFailure": "Transmitter Failure",
        "underlyingResourceUnavailable": "Resource Unavailable",
        "versionMismatch": "Version Mismatch",
    }

    # Vendor-specific mappings to ITU causes
    ERICSSON_CAUSE_MAP: Dict[str, str] = {
        "linkDown": "lossOfSignal",
        "linkUp": "thresholdCrossed",
        "equipmentFailure": "equipmentMalfunction",
        "powerFailure": "powerProblem",
        "temperatureAlarm": "temperatureUnacceptable",
        "fanFailure": "heatingOrVentilationSystemFailure",
        "boardFailure": "equipmentMalfunction",
        "licenseError": "softwareError",
        "synchronizationLost": "timingProblem",
        "connectionFailure": "communicationsSubsystemFailure",
    }

    HUAWEI_CAUSE_MAP: Dict[int, str] = {
        1001: "lossOfSignal",
        1002: "lossOfFrame",
        1003: "equipmentMalfunction",
        1004: "powerProblem",
        1005: "temperatureUnacceptable",
        1006: "heatingOrVentilationSystemFailure",
        1007: "boardFailure",
        1008: "softwareError",
        1009: "timingProblem",
        1010: "communicationsSubsystemFailure",
    }

    def __init__(self) -> None:
        """Initialize the probable cause mapper."""
        self._vendor_maps: Dict[VendorType, Dict[Any, str]] = {
            VendorType.ERICSSON: self.ERICSSON_CAUSE_MAP,
            VendorType.HUAWEI: self.HUAWEI_CAUSE_MAP,
        }

    def map(
        self,
        cause_value: Union[str, int],
        vendor: VendorType,
    ) -> Tuple[str, str]:
        """Map a vendor probable cause to ITU standard.
        
        Args:
            cause_value: Vendor-specific cause code.
            vendor: Vendor type.
            
        Returns:
            Tuple of (ITU code, ITU description).
        """
        vendor_map = self._vendor_maps.get(vendor, {})
        itu_code = vendor_map.get(cause_value, "indeterminate")

        if isinstance(cause_value, str) and cause_value.lower() in self.ITU_PROBABLE_CAUSES:
            itu_code = cause_value.lower()

        itu_desc = self.ITU_PROBABLE_CAUSES.get(itu_code, "Indeterminate")
        
        return itu_code, itu_desc


class AlarmNormalizer:
    """Comprehensive alarm normalizer combining all normalization components.
    
    This class provides a unified interface for normalizing alarms from
    any vendor to the CIM standard format.
    
    Example:
        >>> normalizer = AlarmNormalizer()
        >>> result = normalizer.normalize_alarm(vendor_data, VendorType.ERICSSON)
        >>> print(result.normalized_data)
    """

    def __init__(
        self,
        default_timezone: str = "UTC",
    ) -> None:
        """Initialize the alarm normalizer.
        
        Args:
            default_timezone: Default timezone for timestamps.
        """
        self._severity_mapper = SeverityMapper()
        self._timestamp_normalizer = TimestampNormalizer(default_timezone)
        self._path_generator = ResourcePathGenerator()
        self._cause_mapper = ProbableCauseMapper()

        # Normalization statistics
        self._stats = {
            "total_normalized": 0,
            "successful": 0,
            "failed": 0,
            "by_vendor": {},
        }

    def normalize_alarm(
        self,
        vendor_data: Dict[str, Any],
        vendor: VendorType = VendorType.UNKNOWN,
    ) -> NormalizationResult:
        """Normalize an alarm from vendor format to CIM format.
        
        Args:
            vendor_data: Raw vendor alarm data.
            vendor: Vendor type (auto-detected if UNKNOWN).
            
        Returns:
            NormalizationResult with normalized alarm data.
        """
        result = NormalizationResult(
            success=True,
            original_data=vendor_data.copy(),
        )

        self._stats["total_normalized"] += 1

        try:
            # Auto-detect vendor if not specified
            if vendor == VendorType.UNKNOWN:
                vendor = self._detect_vendor(vendor_data)

            # Track vendor statistics
            if vendor.value not in self._stats["by_vendor"]:
                self._stats["by_vendor"][vendor.value] = 0
            self._stats["by_vendor"][vendor.value] += 1

            # Normalize severity
            severity_value = self._extract_severity(vendor_data, vendor)
            normalized_severity = self._severity_mapper.map(severity_value, vendor)
            result.normalized_data["severity"] = normalized_severity.value
            result.add_transformation("severity", severity_value, normalized_severity.value)

            # Normalize timestamp
            timestamp_value = self._extract_timestamp(vendor_data, vendor)
            normalized_timestamp = self._timestamp_normalizer.normalize(timestamp_value, vendor)
            result.normalized_data["raised_at"] = normalized_timestamp
            result.add_transformation("raised_at", timestamp_value, normalized_timestamp)

            # Generate resource path
            resource_identifier = self._extract_resource_identifier(vendor_data, vendor)
            site_id = vendor_data.get("siteId", vendor_data.get("site_id"))
            region_id = vendor_data.get("regionId", vendor_data.get("region_id"))
            resource_path = self._path_generator.generate(resource_identifier, vendor, site_id, region_id)
            result.normalized_data["resource_path"] = resource_path
            result.add_transformation("resource_path", resource_identifier, resource_path)

            # Normalize probable cause
            cause_value = self._extract_probable_cause(vendor_data, vendor)
            itu_code, itu_desc = self._cause_mapper.map(cause_value, vendor)
            result.normalized_data["probable_cause_code"] = itu_code
            result.normalized_data["probable_cause_desc"] = itu_desc
            result.add_transformation("probable_cause", cause_value, itu_code)

            # Normalize alarm text
            alarm_text = self._extract_alarm_text(vendor_data, vendor)
            normalized_text = self._normalize_alarm_text(alarm_text)
            result.normalized_data["alarm_text"] = normalized_text
            result.add_transformation("alarm_text", alarm_text, normalized_text)

            # Copy additional fields
            result.normalized_data["alarm_id"] = vendor_data.get(
                "alarmId",
                vendor_data.get("alarm_id", "")
            )
            result.normalized_data["source"] = vendor.value
            result.normalized_data["vendor_data"] = vendor_data

            # Preserve additional info
            additional_fields = ["specific_problem", "additional_text", "acknowledged_by"]
            for field_name in additional_fields:
                if field_name in vendor_data:
                    result.normalized_data[field_name] = vendor_data[field_name]

            self._stats["successful"] += 1

        except Exception as e:
            result.success = False
            result.warnings.append(f"Normalization failed: {str(e)}")
            self._stats["failed"] += 1
            logger.error(f"Alarm normalization failed: {e}")

        return result

    def _detect_vendor(self, data: Dict[str, Any]) -> VendorType:
        """Detect vendor from alarm data.
        
        Args:
            data: Alarm data dictionary.
            
        Returns:
            Detected vendor type.
        """
        data_str = str(data).lower()

        if "ericsson" in data_str or "perceivedseverity" in data:
            return VendorType.ERICSSON
        elif "huawei" in data_str or ("severity" in data and isinstance(data.get("severity"), int)):
            return VendorType.HUAWEI
        elif "nokia" in data_str:
            return VendorType.NOKIA
        elif "zte" in data_str:
            return VendorType.ZTE
        elif "cisco" in data_str:
            return VendorType.CISCO

        return VendorType.UNKNOWN

    def _extract_severity(self, data: Dict[str, Any], vendor: VendorType) -> Union[str, int]:
        """Extract severity value from vendor data.
        
        Args:
            data: Alarm data.
            vendor: Vendor type.
            
        Returns:
            Severity value.
        """
        severity_keys = [
            "perceivedSeverity", "severity", "alarmSeverity",
            "severityCode", "alarmLevel", "eventSeverity",
        ]
        
        for key in severity_keys:
            if key in data:
                return data[key]
        
        return "indeterminate"

    def _extract_timestamp(self, data: Dict[str, Any], vendor: VendorType) -> Union[str, int]:
        """Extract timestamp from vendor data.
        
        Args:
            data: Alarm data.
            vendor: Vendor type.
            
        Returns:
            Timestamp value.
        """
        timestamp_keys = [
            "eventTime", "raisedTime", "raisedAt", "timestamp",
            "eventDateTime", "alarmTime", "createTime", "created_at",
        ]
        
        for key in timestamp_keys:
            if key in data:
                return data[key]
        
        return datetime.now(timezone.utc).isoformat()

    def _extract_resource_identifier(self, data: Dict[str, Any], vendor: VendorType) -> str:
        """Extract resource identifier from vendor data.
        
        Args:
            data: Alarm data.
            vendor: Vendor type.
            
        Returns:
            Resource identifier.
        """
        if vendor == VendorType.ERICSSON:
            return data.get("moId", data.get("managedObject", data.get("mo", "")))
        elif vendor == VendorType.HUAWEI:
            return data.get("neId", data.get("networkElementId", data.get("neName", "")))
        
        return data.get("resourceId", data.get("neId", data.get("moId", "")))

    def _extract_probable_cause(self, data: Dict[str, Any], vendor: VendorType) -> Union[str, int]:
        """Extract probable cause from vendor data.
        
        Args:
            data: Alarm data.
            vendor: Vendor type.
            
        Returns:
            Probable cause value.
        """
        cause_keys = ["probableCause", "probableCauseCode", "eventCategory", "alarmCategory"]
        
        for key in cause_keys:
            if key in data:
                return data[key]
        
        return "indeterminate"

    def _extract_alarm_text(self, data: Dict[str, Any], vendor: VendorType) -> str:
        """Extract alarm text from vendor data.
        
        Args:
            data: Alarm data.
            vendor: Vendor type.
            
        Returns:
            Alarm text.
        """
        text_keys = [
            "alarmText", "alarmName", "eventText", "specificProblem",
            "alarmTitle", "description", "additionalText",
        ]
        
        for key in text_keys:
            if key in data and data[key]:
                return str(data[key])
        
        return "Unknown alarm"

    def _normalize_alarm_text(self, text: str) -> str:
        """Normalize alarm text for consistency.
        
        Args:
            text: Original alarm text.
            
        Returns:
            Normalized alarm text.
        """
        # Remove excessive whitespace
        text = " ".join(text.split())
        
        # Remove control characters
        text = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", text)
        
        # Truncate if too long
        max_length = 500
        if len(text) > max_length:
            text = text[:max_length - 3] + "..."
        
        return text.strip()

    def map_severity(
        self,
        severity_value: Union[str, int],
        vendor: VendorType,
    ) -> str:
        """Map a severity value to CIM format.
        
        Args:
            severity_value: Original severity.
            vendor: Vendor type.
            
        Returns:
            CIM severity string.
        """
        return self._severity_mapper.map(severity_value, vendor).value

    def normalize_timestamp(
        self,
        timestamp_value: Union[str, int, float, datetime],
        vendor: VendorType = VendorType.UNKNOWN,
    ) -> str:
        """Normalize a timestamp to ISO 8601.
        
        Args:
            timestamp_value: Original timestamp.
            vendor: Vendor type.
            
        Returns:
            ISO 8601 timestamp string.
        """
        return self._timestamp_normalizer.normalize(timestamp_value, vendor)

    def generate_resource_path(
        self,
        identifier: str,
        vendor: VendorType,
        site_id: Optional[str] = None,
        region_id: Optional[str] = None,
    ) -> str:
        """Generate a CIM resource path.
        
        Args:
            identifier: Resource identifier.
            vendor: Vendor type.
            site_id: Optional site ID.
            region_id: Optional region ID.
            
        Returns:
            CIM resource path.
        """
        return self._path_generator.generate(identifier, vendor, site_id, region_id)

    def get_stats(self) -> Dict[str, Any]:
        """Get normalization statistics.
        
        Returns:
            Statistics dictionary.
        """
        return self._stats.copy()

    def normalize(
        self,
        vendor_data: Dict[str, Any],
        vendor: Union[VendorType, str] = VendorType.UNKNOWN,
        strict: bool = True,
    ) -> NormalizationResult:
        """Normalize alarm data from a vendor to standard format.
        
        This is the main normalization method that returns a NormalizationResult
        with a normalized_alarm attribute.
        
        Args:
            vendor_data: Raw vendor alarm data.
            vendor: Vendor type (VendorType enum or string).
            strict: If True, raise exception on missing required fields.
            
        Returns:
            NormalizationResult with normalized_alarm attribute.
        """
        result = NormalizationResult(
            success=True,
            original_data=vendor_data.copy(),
        )

        self._stats["total_normalized"] += 1
        
        # Track original vendor string for custom parsers
        vendor_str = None
        
        # Handle string vendor type
        if isinstance(vendor, str):
            vendor_str = vendor.lower()
            # Check for custom vendor parser
            if hasattr(self, "_vendor_parsers") and vendor_str in self._vendor_parsers:
                parser = self._vendor_parsers[vendor_str]
                try:
                    parsed = parser.parse(vendor_data)
                    if parsed:
                        result.normalized_alarm = NormalizedAlarm(
                            alarm_id=parsed.get("alarm_id", str(uuid.uuid4())),
                            ne_id=parsed.get("ne_id", ""),
                            alarm_type=parsed.get("alarm_type", "EQUIPMENT_ALARM"),
                            severity=parsed.get("severity", "MEDIUM"),
                            probable_cause=parsed.get("probable_cause", ""),
                            specific_problem=parsed.get("specific_problem", ""),
                            timestamp=datetime.now(timezone.utc),
                            vendor=vendor_str,
                            original_data=vendor_data,
                        )
                        result.normalized_data = result.normalized_alarm.to_dict()
                        self._stats["successful"] += 1
                        return result
                except Exception as e:
                    logger.warning(f"Custom parser failed: {e}")
            
            try:
                vendor = VendorType(vendor.upper())
            except ValueError:
                if strict:
                    raise NormalizationError(f"Unknown vendor type: {vendor}")
                vendor = VendorType.UNKNOWN

        try:
            # Auto-detect vendor if not specified
            if vendor == VendorType.UNKNOWN:
                vendor = self._detect_vendor(vendor_data)

            # Track vendor statistics
            if vendor.value not in self._stats["by_vendor"]:
                self._stats["by_vendor"][vendor.value] = 0
            self._stats["by_vendor"][vendor.value] += 1

            # Extract and normalize fields
            alarm_id = vendor_data.get(
                "alarmId",
                vendor_data.get("alarm_id", str(uuid.uuid4()))
            )
            
            ne_id = self._extract_resource_identifier(vendor_data, vendor)
            
            # Normalize severity
            severity_value = self._extract_severity(vendor_data, vendor)
            normalized_severity = self._severity_mapper.map(severity_value, vendor)
            severity_str = normalized_severity.value
            
            # Normalize alarm type
            alarm_type = vendor_data.get("eventType", vendor_data.get("alarm_type", "EQUIPMENT_ALARM"))
            
            # Normalize probable cause
            probable_cause = vendor_data.get(
                "probableCause",
                vendor_data.get("probable_cause", "unknown")
            )
            
            # Get specific problem
            specific_problem = vendor_data.get(
                "specificProblem",
                vendor_data.get("specific_problem", "")
            )
            
            # Normalize timestamp
            timestamp_value = self._extract_timestamp(vendor_data, vendor)
            if isinstance(timestamp_value, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp_value.replace("Z", "+00:00"))
                except ValueError:
                    timestamp = datetime.now(timezone.utc)
            elif isinstance(timestamp_value, datetime):
                timestamp = timestamp_value
            else:
                timestamp = datetime.now(timezone.utc)

            # Create normalized alarm object
            result.normalized_alarm = NormalizedAlarm(
                alarm_id=alarm_id,
                ne_id=ne_id,
                alarm_type=alarm_type,
                severity=severity_str,
                probable_cause=probable_cause,
                specific_problem=specific_problem,
                timestamp=timestamp,
                vendor=vendor.value.lower(),
                original_data=vendor_data,
            )

            # Also populate normalized_data for backward compatibility
            result.normalized_data = result.normalized_alarm.to_dict()
            
            self._stats["successful"] += 1

        except Exception as e:
            result.success = False
            result.error = str(e)
            result.warnings.append(f"Normalization failed: {str(e)}")
            self._stats["failed"] += 1
            
            if strict:
                raise NormalizationError(f"Normalization failed: {e}")

        return result

    def normalize_batch(
        self,
        alarms: List[Tuple[Dict[str, Any], Union[VendorType, str]]],
    ) -> List[NormalizationResult]:
        """Normalize a batch of alarms.
        
        Args:
            alarms: List of (alarm_data, vendor_type) tuples.
            
        Returns:
            List of NormalizationResult objects.
        """
        results = []
        for alarm_data, vendor in alarms:
            result = self.normalize(alarm_data, vendor, strict=False)
            results.append(result)
        return results

    def add_vendor_parser(
        self,
        vendor_name: str,
        parser: Any,
    ) -> None:
        """Add a custom vendor parser.
        
        Args:
            vendor_name: Vendor identifier.
            parser: Parser object with a parse() method.
        """
        if not hasattr(self, "_vendor_parsers"):
            self._vendor_parsers = {}
        self._vendor_parsers[vendor_name] = parser
        logger.info(f"Added vendor parser for: {vendor_name}")
