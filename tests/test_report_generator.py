"""Tests for :mod:`janusguard.report_generator`."""

from __future__ import annotations

from janusguard.apk_reader import read_apk
from janusguard.report_generator import render_html, render_markdown
from janusguard.risk_engine import assess_risk
from janusguard.signature_analyzer import analyze_signatures
from janusguard.structure_analyzer import analyze_structure


def _pipeline(path: str):
    apk = read_apk(path)
    sig = analyze_signatures(apk)
    struct = analyze_structure(apk)
    risk = assess_risk(sig, struct)
    return apk, sig, struct, risk


def test_markdown_contains_required_sections(write_bytes, sample_modern_bytes):
    path = write_bytes("modern.apk", sample_modern_bytes)
    md = render_markdown(*_pipeline(path))
    for section in (
        "# JanusGuard Report",
        "## Summary",
        "## Signing schemes",
        "## File structure",
        "## Findings",
        "## Mitigations",
        "## Background",
    ):
        assert section in md


def test_markdown_records_overall_risk(write_bytes, sample_janus_bytes):
    path = write_bytes("janus.apk", sample_janus_bytes)
    md = render_markdown(*_pipeline(path))
    assert "**Overall risk:** CRITICAL" in md
    assert "STRUCT-JANUS-PATTERN" in md


def test_markdown_records_sha256(write_bytes, sample_modern_bytes):
    path = write_bytes("modern.apk", sample_modern_bytes)
    apk, sig, struct, risk = _pipeline(path)
    md = render_markdown(apk, sig, struct, risk)
    assert apk.sha256 in md


def test_html_is_well_formed(write_bytes, sample_v1_v2_bytes):
    path = write_bytes("v1v2.apk", sample_v1_v2_bytes)
    html = render_html(*_pipeline(path))
    assert html.startswith("<!DOCTYPE html>")
    assert "<title>JanusGuard Report" in html
    assert "</html>" in html
    # Tag balance for the basic structural tags.
    for tag in ("html", "body", "table"):
        assert html.count(f"<{tag}") == html.count(f"</{tag}>")


def test_html_escapes_filename(write_bytes, sample_modern_bytes):
    """Filenames with HTML-special characters must be escaped in the report."""
    # Write to a normal path, then manually override apk.path so the render
    # function sees the special characters without needing to create an
    # invalid filename on Windows (where <, >, & are forbidden).
    import dataclasses

    path = write_bytes("normal.apk", sample_modern_bytes)
    apk, sig, struct, risk = _pipeline(path)
    apk = dataclasses.replace(apk, path="/fake/<weird&name>.apk")
    html = render_html(apk, sig, struct, risk)
    assert "<weird&name>" not in html
    assert "&lt;weird&amp;name&gt;" in html


def test_markdown_lists_v1_files(write_bytes, sample_v1_only_bytes):
    path = write_bytes("v1.apk", sample_v1_only_bytes)
    md = render_markdown(*_pipeline(path))
    assert "META-INF/MANIFEST.MF" in md
    assert "META-INF/CERT.SF" in md
    assert "META-INF/CERT.RSA" in md


def test_markdown_lists_signing_block_ids(write_bytes, sample_v1_v2_bytes):
    path = write_bytes("v1v2.apk", sample_v1_v2_bytes)
    md = render_markdown(*_pipeline(path))
    assert "0x7109871a" in md.lower()
    assert "0xf05368c0" in md.lower()
