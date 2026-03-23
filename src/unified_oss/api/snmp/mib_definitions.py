"""
MIB Definitions for SNMP Trap Handler.

This module provides MIB (Management Information Base) definitions and
OID (Object Identifier) mapping functionality for the SNMP trap handler.
It supports standard MIB-II definitions as well as enterprise-specific MIBs
from vendors like Ericsson and Huawei.

Features:
    - Standard MIB-II object definitions
    - Enterprise MIB support for major vendors
    - OID to alarm type mapping
    - Variable binding parsing and resolution
    - Support for custom MIB definitions

Example:
    >>> from unified_oss.api.snmp import MIBDefinition, OIDMapper
    >>> mapper = OIDMapper()
    >>> name = mapper.resolve_oid("1.3.6.1.2.1.1.1.0")
    >>> print(name)  # sysDescr
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union

# Configure module logger
logger = logging.getLogger(__name__)


class MIBType(Enum):
    """Enumeration of MIB types.
    
    Attributes:
        STANDARD: Standard IETF MIB (MIB-II, IF-MIB, etc.).
        ENTERPRISE: Enterprise-specific vendor MIB.
        EXPERIMENTAL: Experimental MIB.
        CUSTOM: Custom user-defined MIB.
    """
    STANDARD = "standard"
    ENTERPRISE = "enterprise"
    EXPERIMENTAL = "experimental"
    CUSTOM = "custom"


class AlarmCategory(Enum):
    """Enumeration of alarm categories.
    
    Attributes:
        COMMUNICATIONS: Communications-related alarms.
        QUALITY_OF_SERVICE: QoS-related alarms.
        PROCESSING: Processing error alarms.
        EQUIPMENT: Equipment malfunction alarms.
        ENVIRONMENTAL: Environmental alarms.
        SECURITY: Security-related alarms.
        UNKNOWN: Unknown category.
    """
    COMMUNICATIONS = "communications"
    QUALITY_OF_SERVICE = "qualityOfService"
    PROCESSING = "processing"
    EQUIPMENT = "equipment"
    ENVIRONMENTAL = "environmental"
    SECURITY = "security"
    UNKNOWN = "unknown"


@dataclass
class VarBind:
    """Variable binding data structure.
    
    Represents a single variable binding in an SNMP trap,
    containing the OID, value, and optionally resolved name.
    
    Attributes:
        oid: Object identifier string.
        value: Variable value (type depends on SNMP type).
        resolved_name: Human-readable name from MIB.
        value_type: ASN.1 type of the value.
    """
    oid: str
    value: Any
    resolved_name: str = ""
    value_type: str = "unknown"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert varbind to dictionary representation.
        
        Returns:
            Dictionary containing varbind attributes.
        """
        return {
            "oid": self.oid,
            "value": str(self.value),
            "resolved_name": self.resolved_name,
            "value_type": self.value_type,
        }
    
    def __str__(self) -> str:
        """Return string representation."""
        name = self.resolved_name or self.oid
        return f"{name}={self.value}"


@dataclass
class OIDDefinition:
    """Single OID definition within a MIB.
    
    Attributes:
        oid: Object identifier string.
        name: Human-readable name.
        description: OID description.
        syntax: Syntax/type definition.
        access: Access mode (read-only, read-write, etc.).
        status: Status (current, deprecated, obsolete).
        alarm_category: Associated alarm category.
        alarm_severity: Default alarm severity.
    """
    oid: str
    name: str
    description: str = ""
    syntax: str = ""
    access: str = "read-only"
    status: str = "current"
    alarm_category: AlarmCategory = AlarmCategory.UNKNOWN
    alarm_severity: str = "indeterminate"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.
        
        Returns:
            Dictionary containing OID definition.
        """
        return {
            "oid": self.oid,
            "name": self.name,
            "description": self.description,
            "syntax": self.syntax,
            "access": self.access,
            "status": self.status,
            "alarm_category": self.alarm_category.value,
            "alarm_severity": self.alarm_severity,
        }


@dataclass
class TrapDefinition:
    """Trap definition within a MIB.
    
    Attributes:
        trap_oid: Trap object identifier.
        name: Trap name.
        description: Trap description.
        var_binds: List of variable binding OIDs.
        alarm_category: Associated alarm category.
        default_severity: Default alarm severity.
        enterprise_oid: Enterprise OID for this trap.
        notification_type: Notification type (trap or inform).
    """
    trap_oid: str
    name: str
    description: str = ""
    var_binds: List[str] = field(default_factory=list)
    alarm_category: AlarmCategory = AlarmCategory.UNKNOWN
    default_severity: str = "indeterminate"
    enterprise_oid: str = ""
    notification_type: str = "trap"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.
        
        Returns:
            Dictionary containing trap definition.
        """
        return {
            "trap_oid": self.trap_oid,
            "name": self.name,
            "description": self.description,
            "var_binds": self.var_binds,
            "alarm_category": self.alarm_category.value,
            "default_severity": self.default_severity,
            "enterprise_oid": self.enterprise_oid,
            "notification_type": self.notification_type,
        }


@dataclass
class MIBDefinition:
    """Complete MIB definition.
    
    Represents a complete MIB module with all its OID definitions,
    trap definitions, and metadata.
    
    Attributes:
        name: MIB module name.
        oid: Root OID for this MIB.
        mib_type: Type of MIB (standard, enterprise, etc.).
        vendor: Vendor name for enterprise MIBs.
        version: MIB version.
        description: MIB description.
        oids: Dictionary of OID definitions.
        traps: Dictionary of trap definitions.
        imports: List of imported MIBs.
        enterprise_oid: Enterprise OID for vendor MIBs.
    """
    name: str
    oid: str
    mib_type: MIBType = MIBType.STANDARD
    vendor: str = ""
    version: str = "1.0"
    description: str = ""
    oids: Dict[str, OIDDefinition] = field(default_factory=dict)
    traps: Dict[str, TrapDefinition] = field(default_factory=dict)
    imports: List[str] = field(default_factory=list)
    enterprise_oid: str = ""
    
    def add_oid(self, oid_def: OIDDefinition) -> None:
        """Add an OID definition.
        
        Args:
            oid_def: OID definition to add.
        """
        self.oids[oid_def.oid] = oid_def
    
    def add_trap(self, trap_def: TrapDefinition) -> None:
        """Add a trap definition.
        
        Args:
            trap_def: Trap definition to add.
        """
        self.traps[trap_def.trap_oid] = trap_def
    
    def get_oid(self, oid: str) -> Optional[OIDDefinition]:
        """Get an OID definition.
        
        Args:
            oid: Object identifier to look up.
            
        Returns:
            OID definition or None if not found.
        """
        return self.oids.get(oid)
    
    def get_trap(self, trap_oid: str) -> Optional[TrapDefinition]:
        """Get a trap definition.
        
        Args:
            trap_oid: Trap OID to look up.
            
        Returns:
            Trap definition or None if not found.
        """
        return self.traps.get(trap_oid)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.
        
        Returns:
            Dictionary containing MIB definition.
        """
        return {
            "name": self.name,
            "oid": self.oid,
            "mib_type": self.mib_type.value,
            "vendor": self.vendor,
            "version": self.version,
            "description": self.description,
            "oids": {k: v.to_dict() for k, v in self.oids.items()},
            "traps": {k: v.to_dict() for k, v in self.traps.items()},
            "imports": self.imports,
            "enterprise_oid": self.enterprise_oid,
        }


class EnterpriseMIB:
    """Factory for creating enterprise-specific MIBs.
    
    This class provides methods for creating MIB definitions
    for major telecom equipment vendors.
    """
    
    # Standard enterprise OIDs
    ENTERPRISE_OIDS = {
        "ericsson": "1.3.6.1.4.1.193",
        "huawei": "1.3.6.1.4.1.2011",
        "nokia": "1.3.6.1.4.1.637",
        "zte": "1.3.6.1.4.1.3902",
        "cisco": "1.3.6.1.4.1.9",
        "juniper": "1.3.6.1.4.1.2636",
        "hpe": "1.3.6.1.4.1.11",
    }
    
    @classmethod
    def create_ericsson_mib(cls) -> MIBDefinition:
        """Create Ericsson enterprise MIB.
        
        Returns:
            MIBDefinition for Ericsson equipment.
        """
        mib = MIBDefinition(
            name="ERICSSON-TC-MIB",
            oid="1.3.6.1.4.1.193",
            mib_type=MIBType.ENTERPRISE,
            vendor="ericsson",
            version="1.0",
            description="Ericsson Telecom MIB definitions",
            enterprise_oid="1.3.6.1.4.1.193",
        )
        
        # Add Ericsson-specific traps
        mib.add_trap(TrapDefinition(
            trap_oid="1.3.6.1.4.1.193.1.1.1",
            name="ericssonEquipmentFailure",
            description="Equipment failure detected",
            alarm_category=AlarmCategory.EQUIPMENT,
            default_severity="major",
            enterprise_oid="1.3.6.1.4.1.193",
        ))
        
        mib.add_trap(TrapDefinition(
            trap_oid="1.3.6.1.4.1.193.1.1.2",
            name="ericssonLinkFailure",
            description="Link failure detected",
            alarm_category=AlarmCategory.COMMUNICATIONS,
            default_severity="major",
            enterprise_oid="1.3.6.1.4.1.193",
        ))
        
        mib.add_trap(TrapDefinition(
            trap_oid="1.3.6.1.4.1.193.1.1.3",
            name="ericssonTemperatureAlarm",
            description="Temperature threshold exceeded",
            alarm_category=AlarmCategory.ENVIRONMENTAL,
            default_severity="warning",
            enterprise_oid="1.3.6.1.4.1.193",
        ))
        
        # Add Ericsson OIDs
        mib.add_oid(OIDDefinition(
            oid="1.3.6.1.4.1.193.1.1.1.1",
            name="ericssonEquipmentStatus",
            description="Equipment operational status",
            syntax="INTEGER { up(1), down(2), testing(3) }",
            alarm_category=AlarmCategory.EQUIPMENT,
        ))
        
        return mib
    
    @classmethod
    def create_huawei_mib(cls) -> MIBDefinition:
        """Create Huawei enterprise MIB.
        
        Returns:
            MIBDefinition for Huawei equipment.
        """
        mib = MIBDefinition(
            name="HUAWEI-ENTITY-EXT-MIB",
            oid="1.3.6.1.4.1.2011",
            mib_type=MIBType.ENTERPRISE,
            vendor="huawei",
            version="1.0",
            description="Huawei equipment MIB definitions",
            enterprise_oid="1.3.6.1.4.1.2011",
        )
        
        # Add Huawei-specific traps
        mib.add_trap(TrapDefinition(
            trap_oid="1.3.6.1.4.1.2011.1.1.1",
            name="hwEntityFault",
            description="Entity fault detected",
            alarm_category=AlarmCategory.EQUIPMENT,
            default_severity="critical",
            enterprise_oid="1.3.6.1.4.1.2011",
        ))
        
        mib.add_trap(TrapDefinition(
            trap_oid="1.3.6.1.4.1.2011.1.1.2",
            name="hwBoardFault",
            description="Board fault detected",
            alarm_category=AlarmCategory.EQUIPMENT,
            default_severity="major",
            enterprise_oid="1.3.6.1.4.1.2011",
        ))
        
        mib.add_trap(TrapDefinition(
            trap_oid="1.3.6.1.4.1.2011.1.1.3",
            name="hwPowerSupplyFault",
            description="Power supply fault detected",
            alarm_category=AlarmCategory.EQUIPMENT,
            default_severity="critical",
            enterprise_oid="1.3.6.1.4.1.2011",
        ))
        
        mib.add_trap(TrapDefinition(
            trap_oid="1.3.6.1.4.1.2011.1.1.4",
            name="hwFanFault",
            description="Fan fault detected",
            alarm_category=AlarmCategory.ENVIRONMENTAL,
            default_severity="warning",
            enterprise_oid="1.3.6.1.4.1.2011",
        ))
        
        # Add Huawei OIDs
        mib.add_oid(OIDDefinition(
            oid="1.3.6.1.4.1.2011.1.1.1.1",
            name="hwEntityStatus",
            description="Entity operational status",
            syntax="INTEGER",
            alarm_category=AlarmCategory.EQUIPMENT,
        ))
        
        return mib
    
    @classmethod
    def create_nokia_mib(cls) -> MIBDefinition:
        """Create Nokia enterprise MIB.
        
        Returns:
            MIBDefinition for Nokia equipment.
        """
        mib = MIBDefinition(
            name="NOKIA-TC-MIB",
            oid="1.3.6.1.4.1.637",
            mib_type=MIBType.ENTERPRISE,
            vendor="nokia",
            version="1.0",
            description="Nokia Telecom MIB definitions",
            enterprise_oid="1.3.6.1.4.1.637",
        )
        
        mib.add_trap(TrapDefinition(
            trap_oid="1.3.6.1.4.1.637.1.1.1",
            name="nokiaEquipmentAlarm",
            description="Equipment alarm detected",
            alarm_category=AlarmCategory.EQUIPMENT,
            default_severity="major",
            enterprise_oid="1.3.6.1.4.1.637",
        ))
        
        return mib
    
    @classmethod
    def create_cisco_mib(cls) -> MIBDefinition:
        """Create Cisco enterprise MIB.
        
        Returns:
            MIBDefinition for Cisco equipment.
        """
        mib = MIBDefinition(
            name="CISCO-GENERAL-TRAPS-MIB",
            oid="1.3.6.1.4.1.9",
            mib_type=MIBType.ENTERPRISE,
            vendor="cisco",
            version="1.0",
            description="Cisco general trap MIB definitions",
            enterprise_oid="1.3.6.1.4.1.9",
        )
        
        # Add Cisco-specific traps
        mib.add_trap(TrapDefinition(
            trap_oid="1.3.6.1.4.1.9.9.41.2.0.1",
            name="clogMessageGenerated",
            description="Cisco log message generated",
            alarm_category=AlarmCategory.PROCESSING,
            default_severity="warning",
            enterprise_oid="1.3.6.1.4.1.9",
        ))
        
        mib.add_trap(TrapDefinition(
            trap_oid="1.3.6.1.4.1.9.0.1",
            name="tcpConnectionClose",
            description="TCP connection closed",
            alarm_category=AlarmCategory.COMMUNICATIONS,
            default_severity="warning",
            enterprise_oid="1.3.6.1.4.1.9",
        ))
        
        return mib


class OIDMapper:
    """OID to name and alarm type mapper.
    
    This class provides functionality for resolving OIDs to
    human-readable names and determining alarm types based
    on MIB definitions.
    
    Attributes:
        mibs: Dictionary of loaded MIB definitions.
        oid_index: Index for fast OID lookup.
        trap_index: Index for fast trap lookup.
    """
    
    def __init__(self, mib_definitions: Optional[List[MIBDefinition]] = None) -> None:
        """Initialize the OID mapper.
        
        Args:
            mib_definitions: Optional list of MIB definitions to load.
        """
        self._mibs: Dict[str, MIBDefinition] = {}
        self._oid_index: Dict[str, OIDDefinition] = {}
        self._trap_index: Dict[str, TrapDefinition] = {}
        self._name_index: Dict[str, str] = {}  # name -> oid
        
        # Load standard MIBs
        self._load_standard_mibs()
        
        # Load provided MIBs
        if mib_definitions:
            for mib in mib_definitions:
                self.add_mib(mib)
        
        logger.info(f"OIDMapper initialized with {len(self._oid_index)} OIDs and {len(self._trap_index)} traps")
    
    def _load_standard_mibs(self) -> None:
        """Load standard MIB-II definitions."""
        # Create MIB-II
        mib2 = MIBDefinition(
            name="RFC1213-MIB",
            oid="1.3.6.1.2.1",
            mib_type=MIBType.STANDARD,
            description="MIB-II as defined in RFC 1213",
        )
        
        # System group
        mib2.add_oid(OIDDefinition(
            oid="1.3.6.1.2.1.1.1.0",
            name="sysDescr",
            description="A textual description of the entity",
            syntax="DisplayString",
        ))
        mib2.add_oid(OIDDefinition(
            oid="1.3.6.1.2.1.1.3.0",
            name="sysUpTime",
            description="Time since the network management portion was re-initialized",
            syntax="TimeTicks",
        ))
        mib2.add_oid(OIDDefinition(
            oid="1.3.6.1.2.1.1.5.0",
            name="sysName",
            description="Administratively-assigned name for this managed node",
            syntax="DisplayString",
        ))
        mib2.add_oid(OIDDefinition(
            oid="1.3.6.1.2.1.1.6.0",
            name="sysLocation",
            description="Physical location of this node",
            syntax="DisplayString",
        ))
        mib2.add_oid(OIDDefinition(
            oid="1.3.6.1.2.1.1.7.0",
            name="sysServices",
            description="Value indicating set of services this entity offers",
            syntax="INTEGER",
        ))
        
        # SNMPv2 trap OIDs
        mib2.add_oid(OIDDefinition(
            oid="1.3.6.1.6.3.1.1.4.1.0",
            name="snmpTrapOID",
            description="OID of the trap being sent",
            syntax="OBJECT IDENTIFIER",
        ))
        mib2.add_oid(OIDDefinition(
            oid="1.3.6.1.6.3.1.1.4.3.0",
            name="snmpTrapEnterprise",
            description="Enterprise OID for the trap",
            syntax="OBJECT IDENTIFIER",
        ))
        
        # Interface group
        mib2.add_oid(OIDDefinition(
            oid="1.3.6.1.2.1.2.1.0",
            name="ifNumber",
            description="Number of network interfaces",
            syntax="INTEGER",
        ))
        
        # Standard traps
        mib2.add_trap(TrapDefinition(
            trap_oid="1.3.6.1.6.3.1.1.5.1",
            name="coldStart",
            description="Cold start trap - device reinitialized",
            alarm_category=AlarmCategory.PROCESSING,
            default_severity="critical",
        ))
        mib2.add_trap(TrapDefinition(
            trap_oid="1.3.6.1.6.3.1.1.5.2",
            name="warmStart",
            description="Warm start trap - device reinitialized",
            alarm_category=AlarmCategory.PROCESSING,
            default_severity="warning",
        ))
        mib2.add_trap(TrapDefinition(
            trap_oid="1.3.6.1.6.3.1.1.5.3",
            name="linkDown",
            description="Link down trap",
            alarm_category=AlarmCategory.COMMUNICATIONS,
            default_severity="major",
        ))
        mib2.add_trap(TrapDefinition(
            trap_oid="1.3.6.1.6.3.1.1.5.4",
            name="linkUp",
            description="Link up trap",
            alarm_category=AlarmCategory.COMMUNICATIONS,
            default_severity="cleared",
        ))
        mib2.add_trap(TrapDefinition(
            trap_oid="1.3.6.1.6.3.1.1.5.5",
            name="authenticationFailure",
            description="Authentication failure trap",
            alarm_category=AlarmCategory.SECURITY,
            default_severity="warning",
        ))
        
        self.add_mib(mib2)
        
        # Load enterprise MIBs
        self.add_mib(EnterpriseMIB.create_ericsson_mib())
        self.add_mib(EnterpriseMIB.create_huawei_mib())
        self.add_mib(EnterpriseMIB.create_nokia_mib())
        self.add_mib(EnterpriseMIB.create_cisco_mib())
    
    def add_mib(self, mib: MIBDefinition) -> None:
        """Add a MIB definition.
        
        Args:
            mib: MIB definition to add.
        """
        self._mibs[mib.name] = mib
        
        # Index OIDs
        for oid, oid_def in mib.oids.items():
            self._oid_index[oid] = oid_def
            self._name_index[oid_def.name] = oid
        
        # Index traps
        for trap_oid, trap_def in mib.traps.items():
            self._trap_index[trap_oid] = trap_def
        
        logger.debug(f"Added MIB: {mib.name} with {len(mib.oids)} OIDs and {len(mib.traps)} traps")
    
    def get_mib(self, name: str) -> Optional[MIBDefinition]:
        """Get a MIB by name.
        
        Args:
            name: MIB name.
            
        Returns:
            MIB definition or None if not found.
        """
        return self._mibs.get(name)
    
    def resolve_oid(self, oid: str) -> str:
        """Resolve an OID to a human-readable name.
        
        Args:
            oid: Object identifier string.
            
        Returns:
            Human-readable name or the OID itself if not found.
        """
        # Try exact match
        if oid in self._oid_index:
            return self._oid_index[oid].name
        
        # Try trap match
        if oid in self._trap_index:
            return self._trap_index[oid].name
        
        # Try partial match (for instance OIDs)
        for known_oid, oid_def in self._oid_index.items():
            if oid.startswith(known_oid.rstrip(".0")):
                return f"{oid_def.name}.{oid.split(known_oid.rstrip('.0'))[-1].lstrip('.')}"
        
        return oid
    
    def resolve_name(self, name: str) -> str:
        """Resolve a name to an OID.
        
        Args:
            name: MIB name.
            
        Returns:
            OID string or empty string if not found.
        """
        return self._name_index.get(name, "")
    
    def get_trap_definition(self, trap_oid: str) -> Optional[TrapDefinition]:
        """Get trap definition by OID.
        
        Args:
            trap_oid: Trap object identifier.
            
        Returns:
            Trap definition or None if not found.
        """
        return self._trap_index.get(trap_oid)
    
    def get_alarm_info(self, oid: str) -> Tuple[str, AlarmCategory]:
        """Get alarm severity and category for an OID.
        
        Args:
            oid: Object identifier.
            
        Returns:
            Tuple of (severity, category).
        """
        # Check trap first
        trap_def = self._trap_index.get(oid)
        if trap_def:
            return trap_def.default_severity, trap_def.alarm_category
        
        # Check OID definition
        oid_def = self._oid_index.get(oid)
        if oid_def:
            return oid_def.alarm_severity, oid_def.alarm_category
        
        return "indeterminate", AlarmCategory.UNKNOWN
    
    def parse_varbind(self, oid: str, value: Any) -> VarBind:
        """Parse a variable binding.
        
        Args:
            oid: Object identifier.
            value: Variable value.
            
        Returns:
            VarBind object with resolved name.
        """
        resolved_name = self.resolve_oid(oid)
        oid_def = self._oid_index.get(oid)
        value_type = oid_def.syntax if oid_def else "unknown"
        
        return VarBind(
            oid=oid,
            value=value,
            resolved_name=resolved_name,
            value_type=value_type,
        )
    
    def get_vendor_for_oid(self, oid: str) -> str:
        """Determine vendor from OID.
        
        Args:
            oid: Object identifier.
            
        Returns:
            Vendor name or "unknown".
        """
        for vendor, enterprise_oid in EnterpriseMIB.ENTERPRISE_OIDS.items():
            if oid.startswith(enterprise_oid):
                return vendor
        
        return "unknown"
    
    def get_all_mibs(self) -> List[str]:
        """Get list of all loaded MIB names.
        
        Returns:
            List of MIB names.
        """
        return list(self._mibs.keys())
    
    def get_stats(self) -> Dict[str, Any]:
        """Get mapper statistics.
        
        Returns:
            Dictionary of statistics.
        """
        return {
            "total_mibs": len(self._mibs),
            "total_oids": len(self._oid_index),
            "total_traps": len(self._trap_index),
            "mibs": self.get_all_mibs(),
        }
