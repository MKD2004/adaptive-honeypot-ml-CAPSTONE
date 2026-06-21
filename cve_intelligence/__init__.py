"""
cve_intelligence/__init__.py

Adaptive Honeypot Gateway — CVE Intelligence Package
═════════════════════════════════════════════════════

Fetches trending vulnerabilities from NVD, CISA KEV, ExploitDB, and MITRE,
scores them by exploitability, and generates dynamic honeypot configurations.

Quick usage:
    from cve_intelligence.pipeline import CVEIntelligencePipeline
    result = CVEIntelligencePipeline().run()

Individual clients:
    from cve_intelligence.clients import NVDClient, CISAClient
    from cve_intelligence.clients import ExploitDBClient, MITREClient

Analytics / generators:
    from cve_intelligence import analyzers, config_generator
"""

__version__  = "1.0.0"
__author__   = "Adaptive Honeypot Team — UE23CS320A"

from cve_intelligence.pipeline         import CVEIntelligencePipeline
from cve_intelligence.config_generator import HoneypotConfigGenerator
from cve_intelligence.clients          import (
    NVDClient,
    CVEOrgClient,
    CISAClient,
    ExploitDBClient,
    MITREClient,
)

__all__ = [
    "CVEIntelligencePipeline",
    "HoneypotConfigGenerator",
    "NVDClient",
    "CVEOrgClient",
    "CISAClient",
    "ExploitDBClient",
    "MITREClient",
]
