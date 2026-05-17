"""Tests for :mod:`janusguard.structure_analyzer`."""

from __future__ import annotations

from janusguard.apk_reader import read_apk
from janusguard.structure_analyzer import analyze_structure


def _analyze(path: str):
    return analyze_structure(read_apk(path))


def test_modern_apk_starts_with_zip_magic(write_bytes, sample_modern_bytes):
    path = write_bytes("modern.apk", sample_modern_bytes)
    findings = _analyze(path)

    assert findings.starts_with_zip_magic is True
    assert findings.starts_with_dex_magic is False
    assert findings.janus_pattern_detected is False


def test_v1_v2_apk_starts_with_zip_magic(write_bytes, sample_v1_v2_bytes):
    path = write_bytes("v1v2.apk", sample_v1_v2_bytes)
    findings = _analyze(path)
    assert findings.starts_with_zip_magic is True
    assert findings.janus_pattern_detected is False


def test_janus_style_apk_triggers_pattern(write_bytes, sample_janus_bytes):
    """The decisive test: DEX magic at offset 0 AND valid ZIP behind."""
    path = write_bytes("janus.apk", sample_janus_bytes)
    findings = _analyze(path)

    assert findings.starts_with_dex_magic is True
    assert findings.dex_version == "035"
    assert findings.starts_with_zip_magic is False
    assert findings.janus_pattern_detected is True
    assert findings.dex_declared_file_size == 112


def test_random_file_no_janus(write_bytes):
    path = write_bytes("random.bin", b"\x00" * 4096)
    findings = _analyze(path)
    assert findings.starts_with_dex_magic is False
    assert findings.starts_with_zip_magic is False
    assert findings.janus_pattern_detected is False


def test_dex_only_file_no_zip_so_no_janus_pattern(write_bytes):
    """DEX magic without a working ZIP must not trigger the Janus pattern.

    The pattern requires *both* DEX magic at offset 0 and a parseable ZIP.
    """
    dex_only = b"dex\n035\x00" + b"\x00" * 200
    path = write_bytes("dex_only.bin", dex_only)
    findings = _analyze(path)
    assert findings.starts_with_dex_magic is True
    assert findings.janus_pattern_detected is False


def test_tiny_file_is_handled_gracefully(write_bytes):
    path = write_bytes("tiny.bin", b"\x00")
    findings = _analyze(path)
    assert findings.starts_with_dex_magic is False
    assert findings.notes  # parser left a note
