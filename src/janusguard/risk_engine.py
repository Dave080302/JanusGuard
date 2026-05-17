"""Risk engine.

Combines the outputs of :mod:`janusguard.signature_analyzer` and
:mod:`janusguard.structure_analyzer` together with optional target
environment context (Android version, security patch level) and produces
a :class:`RiskAssessment` containing:

* an overall :class:`RiskLevel`,
* a flat list of human-readable :class:`Finding` records,
* a list of mitigation strings tailored to those findings.

Janus background used by these rules
------------------------------------

CVE-2017-13156 lets an attacker prepend a malicious DEX file to an APK and
have older Android versions execute that DEX while still treating the APK
signature as valid. The vulnerability was fixed by:

* the APK Signature Scheme v2 (Android 7.0+), which signs the entire APK
  byte stream from offset 0 to the start of the APK Signing Block, and
* a 2017-12-01 Android security patch, which closed the runtime side of the
  bug on devices that only verified v1.

Affected: Android 5.0 through 8.0 with a pre-2017-12 patch level, running
an APK signed only with v1. Apps signed with both v1 and v2 are still
vulnerable on Android 5.x/6.x devices, because those devices fall back to
v1 verification (which ignores prepended bytes).

The rules below encode that knowledge.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from janusguard.signature_analyzer import SignatureFindings
from janusguard.structure_analyzer import StructureFindings


class RiskLevel(str, Enum):
    """Coarse risk buckets used in the report."""

    OK = "OK"
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def severity(self) -> int:
        """Numeric severity used for max() comparisons."""
        return _LEVEL_ORDER[self.value]


_LEVEL_ORDER = {
    "OK": 0,
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}


def _max_level(a: RiskLevel, b: RiskLevel) -> RiskLevel:
    return a if a.severity >= b.severity else b


@dataclass
class Finding:
    """One classified observation produced by the risk engine."""

    code: str
    level: RiskLevel
    title: str
    detail: str


@dataclass
class TargetContext:
    """Optional information about the device an APK will run on.

    Both fields are optional. When supplied, they sharpen the risk verdict.

    Attributes
    ----------
    android_version : str | None
        Marketing version string such as ``"6.0"``, ``"7.1"``, ``"8.0"``.
    patch_level : str | None
        Android security patch level in ``YYYY-MM-DD`` form, e.g.
        ``"2017-11-05"``.
    """

    android_version: Optional[str] = None
    patch_level: Optional[str] = None


@dataclass
class RiskAssessment:
    """Final risk verdict and supporting evidence."""

    overall: RiskLevel = RiskLevel.OK
    findings: List[Finding] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    target: TargetContext = field(default_factory=TargetContext)


# ---------------------------------------------------------------------------
# Helpers for evaluating target context
# ---------------------------------------------------------------------------


def _is_vulnerable_android_version(version: str) -> bool:
    """Return True when ``version`` falls inside the Janus-affected window.

    Janus affects Android 5.0 through 8.0 inclusive. Anything outside that
    range (older than 5.0 or 8.1+) is not vulnerable from the OS side.
    """
    try:
        major_str, *_ = version.strip().split(".")
        major = int(major_str)
    except (ValueError, AttributeError):
        return False
    return 5 <= major <= 8


def _patch_predates_fix(patch_level: str) -> bool:
    """Return True when ``patch_level`` is older than the 2017-12-01 fix.

    Accepts ``YYYY-MM-DD``, ``YYYY-MM``, or ``YYYY``. Anything that doesn't
    parse is conservatively treated as "predates the fix".
    """
    parts = patch_level.strip().split("-")
    try:
        year = int(parts[0])
        month = int(parts[1]) if len(parts) > 1 else 1
        day = int(parts[2]) if len(parts) > 2 else 1
    except (ValueError, IndexError):
        return True
    return (year, month, day) < (2017, 12, 1)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def assess_risk(
    signatures: SignatureFindings,
    structure: StructureFindings,
    target: Optional[TargetContext] = None,
) -> RiskAssessment:
    """Combine analyzer outputs into a :class:`RiskAssessment`."""
    target = target or TargetContext()
    assessment = RiskAssessment(target=target)

    # ------------------------------------------------------------------
    # Structural Janus indicator - highest priority.
    # ------------------------------------------------------------------
    if structure.janus_pattern_detected:
        assessment.findings.append(
            Finding(
                code="STRUCT-JANUS-PATTERN",
                level=RiskLevel.CRITICAL,
                title="File starts with DEX magic and is also a valid ZIP",
                detail=(
                    "The file simultaneously parses as a DEX file (magic "
                    "'dex\\n' at offset 0) and as a ZIP archive. This is "
                    "the exact structural signature of a CVE-2017-13156 "
                    "(Janus) injected APK. Do not install. Do not execute. "
                    "Treat as malicious until proven otherwise."
                ),
            )
        )
        assessment.mitigations.append(
            "Discard this file. Re-download the APK from an authoritative "
            "source. Verify the publisher's signing certificate hash before "
            "installing."
        )
    elif structure.starts_with_dex_magic:
        assessment.findings.append(
            Finding(
                code="STRUCT-DEX-PREFIX",
                level=RiskLevel.HIGH,
                title="File starts with DEX magic but is not a valid ZIP",
                detail=(
                    "The first bytes are 'dex\\n'. The file did not parse "
                    "as a ZIP, so it is not an installable APK in its "
                    "current state, but the layout is suspicious."
                ),
            )
        )
    elif structure.starts_with_cdex_magic:
        assessment.findings.append(
            Finding(
                code="STRUCT-CDEX-PREFIX",
                level=RiskLevel.HIGH,
                title="File starts with compact-DEX (cdex) magic",
                detail=(
                    "Compact DEX is an internal ART format and should not "
                    "appear at the start of a distributable APK. This is "
                    "highly anomalous."
                ),
            )
        )
    elif not structure.starts_with_zip_magic:
        assessment.findings.append(
            Finding(
                code="STRUCT-NO-ZIP-MAGIC",
                level=RiskLevel.MEDIUM,
                title="File does not begin with a ZIP local file header",
                detail=(
                    "The first four bytes are not 'PK\\x03\\x04'. Normal "
                    "APKs always begin with the ZIP local file header. "
                    "Manual inspection is recommended."
                ),
            )
        )

    # ------------------------------------------------------------------
    # Signature-based findings.
    # ------------------------------------------------------------------
    if signatures.is_unsigned:
        assessment.findings.append(
            Finding(
                code="SIG-NONE",
                level=RiskLevel.MEDIUM,
                title="No APK signing scheme detected",
                detail=(
                    "Neither v1 META-INF artefacts nor an APK Signing Block "
                    "were found. Android will refuse to install this file."
                ),
            )
        )
    elif signatures.v1_only:
        v1_level = RiskLevel.MEDIUM
        v1_detail = (
            "Only the legacy JAR (v1) signing scheme is present. v1 signs "
            "individual ZIP entries and ignores extra bytes before the ZIP "
            "data, which is exactly the gap exploited by Janus on "
            "Android 5.0-8.0 with pre-2017-12 patch levels."
        )

        # Sharpen the verdict with target context, if supplied.
        if target.android_version and _is_vulnerable_android_version(target.android_version):
            patch_old = (
                target.patch_level is None
                or _patch_predates_fix(target.patch_level)
            )
            if patch_old:
                v1_level = RiskLevel.HIGH
                v1_detail += (
                    f" Target Android version {target.android_version} "
                    "is within the Janus-affected window and the supplied "
                    "patch level is at or before the 2017-12-01 fix - "
                    "an installed Janus-style APK would be exploitable."
                )
            else:
                v1_detail += (
                    f" Target Android version {target.android_version} "
                    "is within the affected window, but the supplied patch "
                    "level is after the 2017-12-01 fix."
                )

        assessment.findings.append(
            Finding(
                code="SIG-V1-ONLY",
                level=v1_level,
                title="APK is signed only with the legacy v1 (JAR) scheme",
                detail=v1_detail,
            )
        )
        assessment.mitigations.append(
            "Re-sign the APK with at least APK Signature Scheme v2 using "
            "the apksigner tool from the Android SDK build-tools "
            "(``apksigner sign --v1-signing-enabled true --v2-signing-enabled true ...``)."
        )

    elif signatures.has_v1 and (signatures.has_v2 or signatures.has_v3 or signatures.has_v3_1):
        assessment.findings.append(
            Finding(
                code="SIG-V1-PLUS-MODERN",
                level=RiskLevel.LOW,
                title="APK is signed with v1 and at least one modern scheme",
                detail=(
                    f"Detected schemes: {signatures.scheme_summary()}. "
                    "Modern devices will verify with v2/v3 and reject Janus "
                    "injections. Note that Android 5.x and 6.x devices "
                    "still fall back to v1 and remain exposed unless they "
                    "have the 2017-12-01 patch installed."
                ),
            )
        )
        # If a vulnerable target Android version was supplied, escalate.
        if target.android_version:
            try:
                major = int(target.android_version.strip().split(".")[0])
            except ValueError:
                major = None
            if major is not None and major in (5, 6):
                patch_old = (
                    target.patch_level is None
                    or _patch_predates_fix(target.patch_level)
                )
                if patch_old:
                    assessment.findings.append(
                        Finding(
                            code="SIG-V1-FALLBACK-TARGET",
                            level=RiskLevel.HIGH,
                            title="Target device will fall back to v1 verification",
                            detail=(
                                f"Android {target.android_version} only "
                                "verifies v1 signatures, so the v2 protection "
                                "on this APK is not enforced on this target. "
                                "Combined with a pre-2017-12 patch level, "
                                "Janus is exploitable."
                            ),
                        )
                    )
                    assessment.mitigations.append(
                        "Refuse to install on Android 5.x/6.x devices below "
                        "the 2017-12-01 security patch, or upgrade the device."
                    )

    elif signatures.has_v2 or signatures.has_v3 or signatures.has_v3_1:
        assessment.findings.append(
            Finding(
                code="SIG-MODERN-ONLY",
                level=RiskLevel.OK,
                title=f"APK is signed with modern scheme(s): {signatures.scheme_summary()}",
                detail=(
                    "No legacy v1 META-INF artefacts were detected. The APK "
                    "Signing Block covers the entire file, so Janus-style "
                    "prepended bytes would invalidate the signature."
                ),
            )
        )

    # ------------------------------------------------------------------
    # Add neutral context for any signing-block parsing notes.
    # ------------------------------------------------------------------
    for note in signatures.notes:
        assessment.findings.append(
            Finding(
                code="SIG-NOTE",
                level=RiskLevel.INFO,
                title="Signing-block parser note",
                detail=note,
            )
        )
    for note in structure.notes:
        assessment.findings.append(
            Finding(
                code="STRUCT-NOTE",
                level=RiskLevel.INFO,
                title="Structure parser note",
                detail=note,
            )
        )

    # ------------------------------------------------------------------
    # Compute overall level.
    # ------------------------------------------------------------------
    overall = RiskLevel.OK
    for f in assessment.findings:
        overall = _max_level(overall, f.level)
    assessment.overall = overall

    # General mitigation always worth surfacing.
    if assessment.overall.severity >= RiskLevel.MEDIUM.severity:
        assessment.mitigations.append(
            "Inspect the APK in an isolated environment (e.g. a sandboxed "
            "emulator with no sensitive accounts) before any further action."
        )

    # De-duplicate mitigations while preserving order.
    seen = set()
    deduped: List[str] = []
    for m in assessment.mitigations:
        if m not in seen:
            seen.add(m)
            deduped.append(m)
    assessment.mitigations = deduped

    return assessment
