"""
Unified OSS Framework for Multi-Vendor Network Element Management.

This package provides comprehensive FCAPS management capabilities for
Ericsson ENM and Huawei U2000 network elements, with YANG-based data
modeling and NETCONF protocol support.

Copyright (c) 2024 Unified OSS Framework Consortium.
All rights reserved.
"""

__version__ = "1.0.0"
__author__ = "Unified OSS Framework Consortium"
__license__ = "Apache 2.0"

from .version import get_version, get_version_info

__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "get_version",
    "get_version_info",
]
