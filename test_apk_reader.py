"""Tests for :mod:`janusguard.apk_reader`."""

from __future__ import annotations

import os

import pytest

from janusguard.apk_reader import ApkReadError, read_apk


def test_read_modern_apk(write_bytes, sample_modern_bytes):
    path = write_bytes("modern.apk", sample_modern_bytes)
    result = read_apk(path)

    assert result.path == path
    assert result.file_size == len(sample_modern_bytes)
    assert result.is_valid_zip is True
    assert result.first_bytes[:4] == b"PK\x03\x04"
    assert "AndroidManifest.xml" in result.entry_names
    assert "classes.dex" in result.entry_names
    assert result.read_errors == []
    # SHA-256 is a 64-char lowercase hex string.
    assert len(result.sha256) == 64
    int(result.sha256, 16)  # raises if not hex


def test_read_janus_style_apk_is_still_a_valid_zip(
    write_bytes, sample_janus_bytes
):
    """Janus-style files have prepended bytes but a backward-scanning ZIP
    reader (which is what Python's zipfile uses) still finds the EOCD."""
    path = write_bytes("janus.apk", sample_janus_bytes)
    result = read_apk(path)

    assert result.is_valid_zip is True
    assert result.first_bytes[:4] == b"dex\n"
    assert "META-INF/MANIFEST.MF" in result.entry_names


def test_read_nonexistent_file_raises():
    with pytest.raises(ApkReadError):
        read_apk("/nonexistent/path/does-not-exist.apk")


def test_read_empty_file_raises(tmp_path):
    p = tmp_path / "empty.apk"
    p.write_bytes(b"")
    with pytest.raises(ApkReadError):
        read_apk(str(p))


def test_read_non_zip_file(write_bytes):
    """A random non-ZIP file must read without crashing, with errors recorded."""
    path = write_bytes("junk.bin", b"this is not a zip" * 32)
    result = read_apk(path)
    assert result.is_valid_zip is False
    assert result.read_errors  # some error recorded
    assert result.entry_names == []


def test_read_apk_records_zip_entries_metadata(
    write_bytes, sample_v1_only_bytes
):
    path = write_bytes("v1.apk", sample_v1_only_bytes)
    result = read_apk(path)
    by_name = {e.name: e for e in result.entries}
    assert "AndroidManifest.xml" in by_name
    assert by_name["AndroidManifest.xml"].uncompressed_size > 0
