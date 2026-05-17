"""Tests for :mod:`janusguard.signature_analyzer`."""

from __future__ import annotations

from janusguard.apk_reader import read_apk
from janusguard.signature_analyzer import (
    APK_SIG_BLOCK_MAGIC,
    SIGNING_BLOCK_IDS,
    analyze_signatures,
)


def _analyze(path: str):
    return analyze_signatures(read_apk(path))


def test_modern_apk_has_only_v2(write_bytes, sample_modern_bytes):
    path = write_bytes("modern.apk", sample_modern_bytes)
    findings = _analyze(path)

    assert findings.has_v1 is False
    assert findings.has_v2 is True
    assert findings.has_v3 is False
    assert findings.has_v3_1 is False
    assert findings.has_signing_block is True
    assert findings.v1_only is False
    assert findings.is_unsigned is False
    # 0x7109871a (v2) and 0x42726577 (verity padding) were inserted.
    assert 0x7109871A in findings.signing_block_ids
    assert 0x42726577 in findings.signing_block_ids
    assert findings.scheme_summary() == "v2"


def test_v1_v2_apk_has_both(write_bytes, sample_v1_v2_bytes):
    path = write_bytes("v1v2.apk", sample_v1_v2_bytes)
    findings = _analyze(path)

    assert findings.has_v1 is True
    assert findings.has_v2 is True
    assert findings.has_v3 is True
    assert findings.v1_only is False
    assert "META-INF/MANIFEST.MF" in findings.v1_files
    # SF and RSA file too.
    assert any(name.endswith(".SF") for name in findings.v1_files)
    assert any(name.endswith(".RSA") for name in findings.v1_files)
    assert findings.scheme_summary() == "v1+v2+v3"


def test_v1_only_apk(write_bytes, sample_v1_only_bytes):
    path = write_bytes("v1only.apk", sample_v1_only_bytes)
    findings = _analyze(path)

    assert findings.has_v1 is True
    assert findings.has_v2 is False
    assert findings.has_v3 is False
    assert findings.has_v3_1 is False
    assert findings.has_signing_block is False
    assert findings.v1_only is True
    assert findings.scheme_summary() == "v1"


def test_unsigned_apk(write_bytes, sample_unsigned_bytes):
    path = write_bytes("unsigned.apk", sample_unsigned_bytes)
    findings = _analyze(path)

    assert findings.has_v1 is False
    assert findings.has_v2 is False
    assert findings.is_unsigned is True
    assert findings.scheme_summary() == "none"


def test_janus_style_apk_is_v1_only(write_bytes, sample_janus_bytes):
    """Janus prepends DEX, but the embedded APK is still v1-signed."""
    path = write_bytes("janus.apk", sample_janus_bytes)
    findings = _analyze(path)

    assert findings.has_v1 is True
    assert findings.has_v2 is False  # no signing block embedded
    assert findings.v1_only is True


def test_signing_block_magic_bytes_are_correct():
    """Sanity check: the constant matches the canonical 16-byte magic."""
    assert APK_SIG_BLOCK_MAGIC == b"APK Sig Block 42"
    assert len(APK_SIG_BLOCK_MAGIC) == 16


def test_known_signing_block_ids_include_v2_v3():
    """Sanity check: well-known block IDs are present in the mapping."""
    assert 0x7109871A in SIGNING_BLOCK_IDS  # v2
    assert 0xF05368C0 in SIGNING_BLOCK_IDS  # v3
    assert 0x1B93AD61 in SIGNING_BLOCK_IDS  # v3.1


def test_manifest_mf_alone_is_not_v1(write_bytes):
    """A file with MANIFEST.MF but no SF/RSA must NOT be classified as v1."""
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\n\r\n")
        zf.writestr("AndroidManifest.xml", b"<manifest/>")

    path = write_bytes("manifest_only.apk", buf.getvalue())
    findings = _analyze(path)
    assert findings.has_v1 is False
