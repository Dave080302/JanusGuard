"""Tests for :mod:`janusguard.risk_engine`."""

from __future__ import annotations

from janusguard.apk_reader import read_apk
from janusguard.risk_engine import (
    RiskLevel,
    TargetContext,
    _is_vulnerable_android_version,
    _patch_predates_fix,
    assess_risk,
)
from janusguard.signature_analyzer import analyze_signatures
from janusguard.structure_analyzer import analyze_structure


def _assess(path: str, target: TargetContext = None):
    apk = read_apk(path)
    return assess_risk(
        analyze_signatures(apk),
        analyze_structure(apk),
        target=target,
    )


# ---------------------------------------------------------------------------
# End-to-end verdicts on synthetic samples.
# ---------------------------------------------------------------------------


def test_modern_apk_is_ok(write_bytes, sample_modern_bytes):
    risk = _assess(write_bytes("modern.apk", sample_modern_bytes))
    assert risk.overall == RiskLevel.OK


def test_v1_v2_apk_is_low(write_bytes, sample_v1_v2_bytes):
    risk = _assess(write_bytes("v1v2.apk", sample_v1_v2_bytes))
    assert risk.overall == RiskLevel.LOW


def test_v1_only_apk_is_medium(write_bytes, sample_v1_only_bytes):
    risk = _assess(write_bytes("v1only.apk", sample_v1_only_bytes))
    assert risk.overall == RiskLevel.MEDIUM


def test_unsigned_apk_is_medium(write_bytes, sample_unsigned_bytes):
    risk = _assess(write_bytes("unsigned.apk", sample_unsigned_bytes))
    assert risk.overall == RiskLevel.MEDIUM


def test_janus_style_apk_is_critical(write_bytes, sample_janus_bytes):
    risk = _assess(write_bytes("janus.apk", sample_janus_bytes))
    assert risk.overall == RiskLevel.CRITICAL
    codes = [f.code for f in risk.findings]
    assert "STRUCT-JANUS-PATTERN" in codes


# ---------------------------------------------------------------------------
# Target-context escalation.
# ---------------------------------------------------------------------------


def test_v1_only_on_vulnerable_target_is_high(write_bytes, sample_v1_only_bytes):
    path = write_bytes("v1only.apk", sample_v1_only_bytes)
    target = TargetContext(android_version="6.0", patch_level="2017-11-05")
    risk = _assess(path, target=target)
    assert risk.overall == RiskLevel.HIGH


def test_v1_only_on_patched_target_stays_medium(write_bytes, sample_v1_only_bytes):
    path = write_bytes("v1only.apk", sample_v1_only_bytes)
    target = TargetContext(android_version="6.0", patch_level="2018-01-05")
    risk = _assess(path, target=target)
    # The base v1-only finding stays MEDIUM when the patch covers the fix.
    assert risk.overall == RiskLevel.MEDIUM


def test_v1_only_on_modern_android_stays_medium(write_bytes, sample_v1_only_bytes):
    path = write_bytes("v1only.apk", sample_v1_only_bytes)
    target = TargetContext(android_version="9.0")
    risk = _assess(path, target=target)
    assert risk.overall == RiskLevel.MEDIUM


def test_v1_v2_on_vulnerable_target_escalates(write_bytes, sample_v1_v2_bytes):
    """v1+v2 still gets HIGH when the target is Android 5.x/6.x with old patch
    because those devices only verify v1."""
    path = write_bytes("v1v2.apk", sample_v1_v2_bytes)
    target = TargetContext(android_version="6.0", patch_level="2017-10-01")
    risk = _assess(path, target=target)
    assert risk.overall == RiskLevel.HIGH
    codes = [f.code for f in risk.findings]
    assert "SIG-V1-FALLBACK-TARGET" in codes


# ---------------------------------------------------------------------------
# Helper function tests.
# ---------------------------------------------------------------------------


def test_is_vulnerable_android_version_window():
    assert _is_vulnerable_android_version("5.0") is True
    assert _is_vulnerable_android_version("5.1.1") is True
    assert _is_vulnerable_android_version("6.0.1") is True
    assert _is_vulnerable_android_version("7.1") is True
    assert _is_vulnerable_android_version("8.0") is True
    # Just outside the window.
    assert _is_vulnerable_android_version("4.4") is False
    assert _is_vulnerable_android_version("9") is False
    assert _is_vulnerable_android_version("13.0") is False
    # Garbage input.
    assert _is_vulnerable_android_version("garbage") is False


def test_patch_predates_fix():
    # Fix shipped 2017-12-01.
    assert _patch_predates_fix("2017-11-30") is True
    assert _patch_predates_fix("2017-12-01") is False
    assert _patch_predates_fix("2017-12-05") is False
    assert _patch_predates_fix("2018-01-01") is False
    assert _patch_predates_fix("2017") is True
    # Unparseable - conservative answer is True (predates).
    assert _patch_predates_fix("not-a-date") is True


# ---------------------------------------------------------------------------
# Mitigation messages.
# ---------------------------------------------------------------------------


def test_v1_only_yields_resign_mitigation(write_bytes, sample_v1_only_bytes):
    risk = _assess(write_bytes("v1only.apk", sample_v1_only_bytes))
    text = " ".join(risk.mitigations).lower()
    assert "apksigner" in text


def test_janus_yields_discard_mitigation(write_bytes, sample_janus_bytes):
    risk = _assess(write_bytes("janus.apk", sample_janus_bytes))
    text = " ".join(risk.mitigations).lower()
    assert "discard" in text


def test_mitigations_are_deduplicated(write_bytes, sample_janus_bytes):
    risk = _assess(write_bytes("janus.apk", sample_janus_bytes))
    assert len(risk.mitigations) == len(set(risk.mitigations))
