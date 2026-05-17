"""JanusGuard - Defensive static analyzer for Android Janus risk indicators (CVE-2017-13156).

This package provides a static, non-executing analyzer for Android APK files.
It inspects signing scheme presence and file structure to flag APKs that exhibit
indicators consistent with the Janus vulnerability or weak legacy signing.

The tool never installs, executes, or modifies the APKs it analyzes.
"""

__version__ = "1.0.0"
__author__ = "David-Tudor Anghel, Omar Hossam Abdelmonem Mahmoud"
__license__ = "MIT"

from janusguard.apk_reader import ApkReadResult, read_apk
from janusguard.signature_analyzer import SignatureFindings, analyze_signatures
from janusguard.structure_analyzer import StructureFindings, analyze_structure
from janusguard.risk_engine import RiskAssessment, RiskLevel, assess_risk
from janusguard.report_generator import render_markdown, render_html

__all__ = [
    "__version__",
    "ApkReadResult",
    "read_apk",
    "SignatureFindings",
    "analyze_signatures",
    "StructureFindings",
    "analyze_structure",
    "RiskAssessment",
    "RiskLevel",
    "assess_risk",
    "render_markdown",
    "render_html",
]
