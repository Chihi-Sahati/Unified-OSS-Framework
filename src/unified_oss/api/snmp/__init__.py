"""
SNMP API Module for Unified OSS Framework.

This module provides SNMP trap handling and MIB management functionality
for the Unified OSS Framework. It supports both SNMPv2c and SNMPv3 protocols
with full integration with the FCAPS fault management system.

Components:
    - SNMPTrapHandler: Main trap handler for receiving and processing traps
    - TrapReceiver: Async UDP receiver for trap messages
    - TrapProcessor: Multi-threaded trap processor
    - MIBDefinition: MIB module definitions
    - OIDMapper: OID to name resolution
    - EnterpriseMIB: Factory for vendor-specific MIBs

Example:
    >>> from unified_oss.api.snmp import SNMPTrapHandler, OIDMapper
    >>> 
    >>> # Create and start trap handler
    >>> handler = SNMPTrapHandler(alarm_manager=alarm_manager)
    >>> await handler.start()
    >>> 
    >>> # Use OID mapper for resolution
    >>> mapper = OIDMapper()
    >>> name = mapper.resolve_oid("1.3.6.1.2.1.1.1.0")
    >>> print(name)  # sysDescr

Supported Features:
    - SNMPv2c trap reception with community string validation
    - SNMPv3 trap reception with USM authentication
    - Standard MIB-II definitions
    - Enterprise MIBs (Ericsson, Huawei, Nokia, Cisco)
    - OID to alarm type mapping
    - Integration with alarm normalization
    - Multi-threaded processing for high throughput
"""

from unified_oss.api.snmp.trap_handler import (
    # Main handler
    SNMPTrapHandler,
    TrapHandlerConfig,
    TrapReceiver,
    TrapProcessor,
    
    # Trap data structures
    SNMPTrap,
    SNMPVersion,
    TrapType,
    
    # Security
    USMUser,
    USMAuthProtocol,
    USMPrivProtocol,
    USMSecurityLevel,
    CommunityConfig,
    
    # Exceptions
    SNMPError,
    TrapParsingError,
    AuthenticationError as SNMPAuthenticationError,
    CommunityStringError,
)

from unified_oss.api.snmp.mib_definitions import (
    # MIB definitions
    MIBDefinition,
    MIBType,
    OIDDefinition,
    TrapDefinition,
    OIDMapper,
    EnterpriseMIB,
    VarBind,
    AlarmCategory,
)

__all__ = [
    # Main handler
    "SNMPTrapHandler",
    "TrapHandlerConfig",
    "TrapReceiver",
    "TrapProcessor",
    
    # Trap data structures
    "SNMPTrap",
    "SNMPVersion",
    "TrapType",
    
    # Security
    "USMUser",
    "USMAuthProtocol",
    "USMPrivProtocol",
    "USMSecurityLevel",
    "CommunityConfig",
    
    # Exceptions
    "SNMPError",
    "TrapParsingError",
    "SNMPAuthenticationError",
    "CommunityStringError",
    
    # MIB definitions
    "MIBDefinition",
    "MIBType",
    "OIDDefinition",
    "TrapDefinition",
    "OIDMapper",
    "EnterpriseMIB",
    "VarBind",
    "AlarmCategory",
]
