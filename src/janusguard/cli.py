"""Command-line entry point for JanusGuard."""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from janusguard import __version__
from janusguard.apk_reader import ApkReadError, read_apk
from janusguard.report_generator import render_html, render_markdown
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
        "apk_path",
        help="Path to the APK file to analyze.",
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
        choices=("markdown", "html", "both"),
        default="markdown",
        help="Report format(s) to write. Default: markdown.",
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
        help="Also print the Markdown report to stdout.",
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


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        apk = read_apk(args.apk_path)
    except ApkReadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_READ_ERROR

    signatures = analyze_signatures(apk)
    structure = analyze_structure(apk)
    target = TargetContext(
        android_version=args.android_version,
        patch_level=args.patch_level,
    )
    risk = assess_risk(signatures, structure, target=target)

    os.makedirs(args.output_dir, exist_ok=True)
    base = os.path.splitext(os.path.basename(args.apk_path))[0]

    md_text = render_markdown(apk, signatures, structure, risk)
    if args.format in ("markdown", "both"):
        md_path = os.path.join(args.output_dir, f"{base}.report.md")
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write(md_text)
        if not args.quiet:
            print(f"[janusguard] wrote {md_path}", file=sys.stderr)

    if args.format in ("html", "both"):
        html_text = render_html(apk, signatures, structure, risk)
        html_path = os.path.join(args.output_dir, f"{base}.report.html")
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(html_text)
        if not args.quiet:
            print(f"[janusguard] wrote {html_path}", file=sys.stderr)

    if args.stdout:
        print(md_text)

    if not args.quiet:
        print(
            _summary_for_stderr(args.apk_path, risk.overall, signatures.scheme_summary()),
            file=sys.stderr,
        )

    return _EXIT_BY_LEVEL[risk.overall]


if __name__ == "__main__":
    sys.exit(main())
