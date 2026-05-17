"""Command-line entry point for JanusGuard."""

from __future__ import annotations

import argparse
import os
import re
import sys
from typing import List, Optional

from janusguard import __version__
from janusguard.apk_reader import ApkReadError, read_apk
from janusguard.report_generator import render_html, render_json, render_markdown
from janusguard.risk_engine import RiskLevel, TargetContext, assess_risk
from janusguard.signature_analyzer import analyze_signatures
from janusguard.structure_analyzer import analyze_structure


# Exit codes are picked to be useful in CI.
EXIT_OK = 0
EXIT_LOW = 0
EXIT_MEDIUM = 10
EXIT_HIGH = 20
EXIT_CRITICAL = 30
EXIT_USAGE = 2
EXIT_READ_ERROR = 3

_PATCH_LEVEL_RE = re.compile(r"^\d{4}(-\d{2}(-\d{2})?)?$")

_EXIT_BY_LEVEL = {
    RiskLevel.OK: EXIT_OK,
    RiskLevel.INFO: EXIT_OK,
    RiskLevel.LOW: EXIT_LOW,
    RiskLevel.MEDIUM: EXIT_MEDIUM,
    RiskLevel.HIGH: EXIT_HIGH,
    RiskLevel.CRITICAL: EXIT_CRITICAL,
}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="janusguard",
        description=(
            "Static, non-executing analyzer for Janus (CVE-2017-13156) "
            "risk indicators in Android APK files."
        ),
        epilog=(
            "JanusGuard never installs or runs the APK. It only inspects "
            "raw bytes and ZIP layout. Use the generated report as input "
            "for human review."
        ),
    )
    parser.add_argument(
        "apk_paths",
        nargs="+",
        metavar="apk_path",
        help="Path(s) to APK file(s) to analyze. Multiple paths are accepted.",
    )
    parser.add_argument(
        "--android-version",
        default=None,
        help=(
            "Optional target Android version, e.g. '6.0' or '8.0'. "
            "Used to sharpen the v1-only verdict."
        ),
    )
    parser.add_argument(
        "--patch-level",
        default=None,
        help=(
            "Optional Android security patch level in YYYY-MM-DD form, "
            "e.g. '2017-11-05'. Combined with --android-version."
        ),
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "html", "json", "all"),
        default="markdown",
        help="Report format(s) to write. 'all' writes markdown, html, and json. Default: markdown.",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default="reports",
        help="Directory to write reports into. Default: ./reports",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Also print the Markdown report to stdout (or JSON when --format json).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress the human summary written to stderr.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"janusguard {__version__}",
    )
    return parser


def _summary_for_stderr(apk_path: str, risk_level: RiskLevel, scheme_summary: str) -> str:
    return (
        f"[janusguard] {os.path.basename(apk_path)}: "
        f"risk={risk_level.value} schemes={scheme_summary}"
    )


def _analyze_one(
    apk_path: str, args: argparse.Namespace, target: TargetContext
) -> Optional[RiskLevel]:
    """Analyze a single APK and write report(s). Returns None on read error."""
    try:
        apk = read_apk(apk_path)
    except ApkReadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return None

    signatures = analyze_signatures(apk)
    structure = analyze_structure(apk)
    risk = assess_risk(signatures, structure, target=target)

    os.makedirs(args.output_dir, exist_ok=True)
    base = os.path.splitext(os.path.basename(apk_path))[0]
    fmt = args.format

    if fmt in ("markdown", "all"):
        md_text = render_markdown(apk, signatures, structure, risk)
        md_path = os.path.join(args.output_dir, f"{base}.report.md")
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write(md_text)
        if not args.quiet:
            print(f"[janusguard] wrote {md_path}", file=sys.stderr)
        if args.stdout and fmt == "markdown":
            print(md_text)

    if fmt in ("html", "all"):
        html_text = render_html(apk, signatures, structure, risk)
        html_path = os.path.join(args.output_dir, f"{base}.report.html")
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(html_text)
        if not args.quiet:
            print(f"[janusguard] wrote {html_path}", file=sys.stderr)

    if fmt in ("json", "all"):
        json_text = render_json(apk, signatures, structure, risk)
        json_path = os.path.join(args.output_dir, f"{base}.report.json")
        with open(json_path, "w", encoding="utf-8") as fh:
            fh.write(json_text)
        if not args.quiet:
            print(f"[janusguard] wrote {json_path}", file=sys.stderr)
        if args.stdout and fmt == "json":
            print(json_text, end="")

    if not args.quiet:
        print(
            _summary_for_stderr(apk_path, risk.overall, signatures.scheme_summary()),
            file=sys.stderr,
        )

    return risk.overall


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Validate --patch-level format early so users get a clear error.
    if args.patch_level and not _PATCH_LEVEL_RE.match(args.patch_level):
        print(
            f"error: --patch-level must be in YYYY-MM-DD form, got: {args.patch_level!r}",
            file=sys.stderr,
        )
        return EXIT_USAGE

    target = TargetContext(
        android_version=args.android_version,
        patch_level=args.patch_level,
    )

    # Batch: collect the worst risk level across all APKs.
    worst = RiskLevel.OK
    had_read_error = False
    for apk_path in args.apk_paths:
        level = _analyze_one(apk_path, args, target)
        if level is None:
            had_read_error = True
        elif level.severity > worst.severity:
            worst = level

    if len(args.apk_paths) > 1 and not args.quiet:
        print(
            f"[janusguard] {len(args.apk_paths)} files analyzed — "
            f"worst risk: {worst.value}",
            file=sys.stderr,
        )

    # If nothing was readable and no successful risk was found, report the read error.
    if had_read_error and worst == RiskLevel.OK:
        return EXIT_READ_ERROR
    return _EXIT_BY_LEVEL[worst]


if __name__ == "__main__":
    sys.exit(main())
