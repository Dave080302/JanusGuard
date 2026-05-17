"""Report generator.

Produces Markdown and HTML reports from the analysis results. Both
formats present exactly the same information; HTML adds light styling so
the report is readable when opened in a browser.
"""

from __future__ import annotations

import datetime
import html
import json
import os
from typing import Iterable, List

from janusguard.apk_reader import ApkReadResult
from janusguard.risk_engine import Finding, RiskAssessment, RiskLevel
from janusguard.signature_analyzer import SIGNING_BLOCK_IDS, SignatureFindings
from janusguard.structure_analyzer import StructureFindings


# ---------------------------------------------------------------------------
# Common helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


def _scheme_table(sig: SignatureFindings) -> List[tuple]:
    """Rows for the 'detected signing schemes' table."""
    return [
        ("v1 (JAR signing)", "yes" if sig.has_v1 else "no"),
        ("v2 (APK Signature Scheme)", "yes" if sig.has_v2 else "no"),
        ("v3 (APK Signature Scheme)", "yes" if sig.has_v3 else "no"),
        ("v3.1 (APK Signature Scheme)", "yes" if sig.has_v3_1 else "no"),
        ("APK Signing Block present", "yes" if sig.has_signing_block else "no"),
    ]


def _block_id_label(raw_id: int) -> str:
    """Human label for a signing-block ID, with a fallback for unknowns."""
    name = SIGNING_BLOCK_IDS.get(raw_id)
    return f"0x{raw_id:08x} - {name}" if name else f"0x{raw_id:08x} - (unknown)"


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


_MD_LEVEL_BADGE = {
    RiskLevel.OK: "OK",
    RiskLevel.INFO: "INFO",
    RiskLevel.LOW: "LOW",
    RiskLevel.MEDIUM: "MEDIUM",
    RiskLevel.HIGH: "HIGH",
    RiskLevel.CRITICAL: "CRITICAL",
}


def render_markdown(
    apk: ApkReadResult,
    signatures: SignatureFindings,
    structure: StructureFindings,
    risk: RiskAssessment,
) -> str:
    """Render the analysis as a Markdown report."""
    lines: List[str] = []
    out = lines.append

    out("# JanusGuard Report")
    out("")
    out(f"_Generated {_now_iso()}_")
    out("")

    out("## Summary")
    out("")
    out(f"- **Overall risk:** {_MD_LEVEL_BADGE[risk.overall]}")
    out(f"- **File:** `{os.path.basename(apk.path)}`")
    out(f"- **Size:** {apk.file_size} bytes")
    out(f"- **SHA-256:** `{apk.sha256}`")
    out(f"- **Detected schemes:** {signatures.scheme_summary()}")
    if risk.target.android_version:
        out(f"- **Target Android version:** {risk.target.android_version}")
    if risk.target.patch_level:
        out(f"- **Target patch level:** {risk.target.patch_level}")
    out("")

    out("## Signing schemes")
    out("")
    out("| Scheme | Detected |")
    out("|---|---|")
    for name, value in _scheme_table(signatures):
        out(f"| {name} | {value} |")
    out("")
    if signatures.v1_files:
        out("**v1 META-INF artefacts:**")
        out("")
        for entry in signatures.v1_files:
            out(f"- `{entry}`")
        out("")
    if signatures.signing_block_ids:
        out("**APK Signing Block IDs:**")
        out("")
        for raw_id in signatures.signing_block_ids:
            out(f"- {_block_id_label(raw_id)}")
        if signatures.signing_block_offset is not None:
            out("")
            out(f"_Signing block starts at file offset {signatures.signing_block_offset}._")
        out("")

    out("## File structure")
    out("")
    out(f"- First 4 bytes (hex): `{apk.first_bytes[:4].hex()}`")
    out(f"- Starts with ZIP local file header: {structure.starts_with_zip_magic}")
    out(f"- Starts with DEX magic: {structure.starts_with_dex_magic}")
    if structure.dex_version:
        out(f"- Embedded DEX version: `{structure.dex_version}`")
    if structure.dex_declared_file_size is not None:
        out(f"- DEX header `file_size` field: {structure.dex_declared_file_size}")
    out(f"- Starts with compact-DEX magic: {structure.starts_with_cdex_magic}")
    out(f"- Janus dual-format pattern detected: {structure.janus_pattern_detected}")
    out(f"- Valid ZIP archive: {apk.is_valid_zip}")
    if apk.read_errors:
        out("")
        out("**ZIP read errors:**")
        for err in apk.read_errors:
            out(f"- {err}")
    out("")

    out("## Findings")
    out("")
    if not risk.findings:
        out("_No findings produced._")
    else:
        for f in risk.findings:
            out(f"### [{_MD_LEVEL_BADGE[f.level]}] {f.title}")
            out("")
            out(f"_Code: `{f.code}`_")
            out("")
            out(f.detail)
            out("")

    out("## Mitigations")
    out("")
    if not risk.mitigations:
        out("_No mitigations recommended._")
    else:
        for m in risk.mitigations:
            out(f"- {m}")
    out("")

    out("## Background")
    out("")
    out(
        "CVE-2017-13156 (\"Janus\") allows an attacker to prepend a malicious "
        "DEX file to an APK without invalidating the v1 (JAR) signature. "
        "Affected: Android 5.0-8.0 with pre-2017-12-01 security patch level, "
        "when verifying APKs signed only with v1. The APK Signature Scheme "
        "v2 (Android 7.0+) signs the entire APK byte stream and closes the "
        "structural gap."
    )
    out("")
    out("---")
    out("")
    out("_This report is the output of a static analyzer. It flags indicators, not proven exploits._")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------


_HTML_LEVEL_CLASS = {
    RiskLevel.OK: "ok",
    RiskLevel.INFO: "info",
    RiskLevel.LOW: "low",
    RiskLevel.MEDIUM: "medium",
    RiskLevel.HIGH: "high",
    RiskLevel.CRITICAL: "critical",
}


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>JanusGuard Report - {filename}</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      max-width: 900px;
      margin: 2rem auto;
      padding: 0 1.5rem;
      color: #1f2933;
      line-height: 1.5;
    }}
    h1, h2, h3 {{ color: #102a43; }}
    h1 {{ border-bottom: 2px solid #102a43; padding-bottom: 0.3rem; }}
    h2 {{ border-bottom: 1px solid #cbd2d9; padding-bottom: 0.2rem; margin-top: 2rem; }}
    code, pre {{ background: #f0f4f8; padding: 0.1rem 0.3rem; border-radius: 3px; font-size: 0.9em; }}
    pre {{ padding: 0.75rem; overflow-x: auto; }}
    table {{ border-collapse: collapse; margin: 1rem 0; }}
    th, td {{ border: 1px solid #cbd2d9; padding: 0.4rem 0.8rem; text-align: left; }}
    th {{ background: #f0f4f8; }}
    .badge {{
      display: inline-block;
      padding: 0.15rem 0.6rem;
      border-radius: 999px;
      font-weight: 600;
      font-size: 0.85em;
      color: white;
    }}
    .badge.ok {{ background: #2f855a; }}
    .badge.info {{ background: #4a5568; }}
    .badge.low {{ background: #2b6cb0; }}
    .badge.medium {{ background: #b7791f; }}
    .badge.high {{ background: #c05621; }}
    .badge.critical {{ background: #9b2c2c; }}
    .finding {{
      border-left: 4px solid #cbd2d9;
      padding: 0.6rem 1rem;
      margin: 0.75rem 0;
      background: #f7fafc;
    }}
    .finding.ok {{ border-color: #2f855a; }}
    .finding.info {{ border-color: #4a5568; }}
    .finding.low {{ border-color: #2b6cb0; }}
    .finding.medium {{ border-color: #b7791f; }}
    .finding.high {{ border-color: #c05621; }}
    .finding.critical {{ border-color: #9b2c2c; background: #fff5f5; }}
    .small {{ color: #627d98; font-size: 0.85em; }}
    footer {{ margin-top: 3rem; color: #627d98; font-size: 0.85em; }}
  </style>
</head>
<body>
  <h1>JanusGuard Report</h1>
  <p class="small">Generated {generated_at}</p>

  <h2>Summary</h2>
  <p><strong>Overall risk:</strong>
    <span class="badge {overall_class}">{overall_label}</span></p>
  <table>
    <tr><th>File</th><td><code>{filename}</code></td></tr>
    <tr><th>Size</th><td>{file_size} bytes</td></tr>
    <tr><th>SHA-256</th><td><code>{sha256}</code></td></tr>
    <tr><th>Detected schemes</th><td>{scheme_summary}</td></tr>
    {target_rows}
  </table>

  <h2>Signing schemes</h2>
  <table>
    <tr><th>Scheme</th><th>Detected</th></tr>
    {scheme_rows}
  </table>
  {v1_files_block}
  {block_ids_block}

  <h2>File structure</h2>
  <table>
    <tr><th>First 4 bytes (hex)</th><td><code>{first_bytes_hex}</code></td></tr>
    <tr><th>Starts with ZIP local file header</th><td>{starts_zip}</td></tr>
    <tr><th>Starts with DEX magic</th><td>{starts_dex}</td></tr>
    <tr><th>Embedded DEX version</th><td>{dex_version}</td></tr>
    <tr><th>DEX header file_size</th><td>{dex_file_size}</td></tr>
    <tr><th>Starts with compact-DEX magic</th><td>{starts_cdex}</td></tr>
    <tr><th>Janus dual-format pattern</th><td>{janus_pattern}</td></tr>
    <tr><th>Valid ZIP archive</th><td>{is_zip}</td></tr>
  </table>
  {read_errors_block}

  <h2>Findings</h2>
  {findings_block}

  <h2>Mitigations</h2>
  {mitigations_block}

  <h2>Background</h2>
  <p>CVE-2017-13156 (&quot;Janus&quot;) allows an attacker to prepend a malicious
  DEX file to an APK without invalidating the v1 (JAR) signature.
  Affected: Android 5.0&ndash;8.0 with pre-2017-12-01 security patch level,
  when verifying APKs signed only with v1. The APK Signature Scheme v2
  (Android 7.0+) signs the entire APK byte stream and closes the
  structural gap.</p>

  <footer>This report is the output of a static analyzer. It flags indicators, not proven exploits.</footer>
</body>
</html>
"""


def _html_finding(f: Finding) -> str:
    css_class = _HTML_LEVEL_CLASS[f.level]
    return (
        f'<div class="finding {css_class}">'
        f'<p><span class="badge {css_class}">{_MD_LEVEL_BADGE[f.level]}</span> '
        f"<strong>{html.escape(f.title)}</strong></p>"
        f'<p class="small">Code: <code>{html.escape(f.code)}</code></p>'
        f"<p>{html.escape(f.detail)}</p>"
        f"</div>"
    )


def render_json(
    apk: ApkReadResult,
    signatures: SignatureFindings,
    structure: StructureFindings,
    risk: RiskAssessment,
) -> str:
    """Render the analysis as a JSON string (pretty-printed)."""
    from janusguard import __version__

    doc = {
        "janusguard_version": __version__,
        "generated_at": _now_iso(),
        "apk": {
            "filename": os.path.basename(apk.path),
            "path": apk.path,
            "size_bytes": apk.file_size,
            "sha256": apk.sha256,
            "is_valid_zip": apk.is_valid_zip,
            "read_errors": apk.read_errors,
        },
        "signatures": {
            "has_v1": signatures.has_v1,
            "has_v2": signatures.has_v2,
            "has_v3": signatures.has_v3,
            "has_v3_1": signatures.has_v3_1,
            "has_signing_block": signatures.has_signing_block,
            "v1_only": signatures.v1_only,
            "is_unsigned": signatures.is_unsigned,
            "scheme_summary": signatures.scheme_summary(),
            "v1_files": signatures.v1_files,
            "signing_block_ids": [
                {"id": f"0x{rid:08x}", "label": SIGNING_BLOCK_IDS.get(rid, "unknown")}
                for rid in signatures.signing_block_ids
            ],
            "signing_block_offset": signatures.signing_block_offset,
            "notes": signatures.notes,
        },
        "structure": {
            "starts_with_dex_magic": structure.starts_with_dex_magic,
            "dex_version": structure.dex_version,
            "starts_with_cdex_magic": structure.starts_with_cdex_magic,
            "starts_with_zip_magic": structure.starts_with_zip_magic,
            "janus_pattern_detected": structure.janus_pattern_detected,
            "dex_declared_file_size": structure.dex_declared_file_size,
            "notes": structure.notes,
        },
        "risk": {
            "overall": risk.overall.value,
            "target": {
                "android_version": risk.target.android_version,
                "patch_level": risk.target.patch_level,
            },
            "findings": [
                {
                    "code": f.code,
                    "level": f.level.value,
                    "title": f.title,
                    "detail": f.detail,
                }
                for f in risk.findings
            ],
            "mitigations": risk.mitigations,
        },
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def render_html(
    apk: ApkReadResult,
    signatures: SignatureFindings,
    structure: StructureFindings,
    risk: RiskAssessment,
) -> str:
    """Render the analysis as a standalone HTML document."""
    target_rows = ""
    if risk.target.android_version:
        target_rows += (
            f"<tr><th>Target Android version</th><td>"
            f"{html.escape(risk.target.android_version)}</td></tr>"
        )
    if risk.target.patch_level:
        target_rows += (
            f"<tr><th>Target patch level</th><td>"
            f"{html.escape(risk.target.patch_level)}</td></tr>"
        )

    scheme_rows = "".join(
        f"<tr><td>{html.escape(name)}</td><td>{value}</td></tr>"
        for name, value in _scheme_table(signatures)
    )

    if signatures.v1_files:
        items = "".join(
            f"<li><code>{html.escape(name)}</code></li>"
            for name in signatures.v1_files
        )
        v1_files_block = f"<p><strong>v1 META-INF artefacts:</strong></p><ul>{items}</ul>"
    else:
        v1_files_block = ""

    if signatures.signing_block_ids:
        items = "".join(
            f"<li><code>{html.escape(_block_id_label(rid))}</code></li>"
            for rid in signatures.signing_block_ids
        )
        offset_note = ""
        if signatures.signing_block_offset is not None:
            offset_note = (
                f'<p class="small">Signing block starts at file offset '
                f"{signatures.signing_block_offset}.</p>"
            )
        block_ids_block = (
            f"<p><strong>APK Signing Block IDs:</strong></p>"
            f"<ul>{items}</ul>{offset_note}"
        )
    else:
        block_ids_block = ""

    read_errors_block = ""
    if apk.read_errors:
        items = "".join(
            f"<li>{html.escape(err)}</li>" for err in apk.read_errors
        )
        read_errors_block = (
            f"<p><strong>ZIP read errors:</strong></p><ul>{items}</ul>"
        )

    if risk.findings:
        findings_block = "\n".join(_html_finding(f) for f in risk.findings)
    else:
        findings_block = "<p><em>No findings produced.</em></p>"

    if risk.mitigations:
        items = "".join(
            f"<li>{html.escape(m)}</li>" for m in risk.mitigations
        )
        mitigations_block = f"<ul>{items}</ul>"
    else:
        mitigations_block = "<p><em>No mitigations recommended.</em></p>"

    return _HTML_TEMPLATE.format(
        filename=html.escape(os.path.basename(apk.path)),
        generated_at=_now_iso(),
        overall_class=_HTML_LEVEL_CLASS[risk.overall],
        overall_label=_MD_LEVEL_BADGE[risk.overall],
        file_size=apk.file_size,
        sha256=html.escape(apk.sha256),
        scheme_summary=html.escape(signatures.scheme_summary()),
        target_rows=target_rows,
        scheme_rows=scheme_rows,
        v1_files_block=v1_files_block,
        block_ids_block=block_ids_block,
        first_bytes_hex=html.escape(apk.first_bytes[:4].hex()),
        starts_zip=str(structure.starts_with_zip_magic),
        starts_dex=str(structure.starts_with_dex_magic),
        dex_version=html.escape(structure.dex_version) if structure.dex_version else "&mdash;",
        dex_file_size=(
            str(structure.dex_declared_file_size)
            if structure.dex_declared_file_size is not None
            else "&mdash;"
        ),
        starts_cdex=str(structure.starts_with_cdex_magic),
        janus_pattern=str(structure.janus_pattern_detected),
        is_zip=str(apk.is_valid_zip),
        read_errors_block=read_errors_block,
        findings_block=findings_block,
        mitigations_block=mitigations_block,
    )
