"""End-to-end tests for the CLI."""

from __future__ import annotations

import os

import pytest

from janusguard.cli import (
    EXIT_CRITICAL,
    EXIT_MEDIUM,
    EXIT_OK,
    EXIT_READ_ERROR,
    main,
)


def test_cli_modern_returns_ok(write_bytes, sample_modern_bytes, tmp_path):
    apk_path = write_bytes("modern.apk", sample_modern_bytes)
    out_dir = tmp_path / "out"
    rc = main(
        [
            apk_path,
            "--format",
            "all",
            "--output-dir",
            str(out_dir),
            "--quiet",
        ]
    )
    assert rc == EXIT_OK
    assert (out_dir / "modern.report.md").is_file()
    assert (out_dir / "modern.report.html").is_file()


def test_cli_janus_returns_critical(write_bytes, sample_janus_bytes, tmp_path):
    apk_path = write_bytes("janus.apk", sample_janus_bytes)
    out_dir = tmp_path / "out"
    rc = main(
        [apk_path, "--format", "markdown", "--output-dir", str(out_dir), "--quiet"]
    )
    assert rc == EXIT_CRITICAL


def test_cli_v1_only_returns_medium(write_bytes, sample_v1_only_bytes, tmp_path):
    apk_path = write_bytes("v1.apk", sample_v1_only_bytes)
    out_dir = tmp_path / "out"
    rc = main(
        [apk_path, "--format", "markdown", "--output-dir", str(out_dir), "--quiet"]
    )
    assert rc == EXIT_MEDIUM


def test_cli_missing_file_returns_read_error(tmp_path):
    rc = main(
        [
            str(tmp_path / "does-not-exist.apk"),
            "--format",
            "markdown",
            "--output-dir",
            str(tmp_path / "out"),
            "--quiet",
        ]
    )
    assert rc == EXIT_READ_ERROR


def test_cli_writes_markdown_only_by_default(
    write_bytes, sample_modern_bytes, tmp_path
):
    apk_path = write_bytes("modern.apk", sample_modern_bytes)
    out_dir = tmp_path / "out"
    rc = main(
        [apk_path, "--output-dir", str(out_dir), "--quiet"]
    )
    assert rc == EXIT_OK
    assert (out_dir / "modern.report.md").is_file()
    assert not (out_dir / "modern.report.html").exists()


def test_cli_android_version_escalates_v1_only(
    write_bytes, sample_v1_only_bytes, tmp_path
):
    """Passing a vulnerable target context bumps v1-only from MEDIUM to HIGH."""
    from janusguard.cli import EXIT_HIGH

    apk_path = write_bytes("v1.apk", sample_v1_only_bytes)
    out_dir = tmp_path / "out"
    rc = main(
        [
            apk_path,
            "--android-version",
            "6.0",
            "--patch-level",
            "2017-09-01",
            "--output-dir",
            str(out_dir),
            "--quiet",
        ]
    )
    assert rc == EXIT_HIGH
