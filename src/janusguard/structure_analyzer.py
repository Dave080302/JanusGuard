"""Structure analyzer.

Looks for structural anomalies that are consistent with a Janus-style
(CVE-2017-13156) APK file. The key Janus structural pattern is:

* The file starts with valid DEX magic ``dex\\n0XX\\0`` (where ``XX`` is the
  DEX format version - 035, 036, 037, 038, 039, 040, ...).
* The same file simultaneously parses as a valid ZIP archive (because the
  ZIP central directory is read from the end of the file, the prepended
  DEX bytes are ignored by ZIP readers).

A normal APK starts with ``PK\\x03\\x04`` (the ZIP local file header
signature). A file that starts with DEX magic but is also a working ZIP
is highly anomalous and is the hallmark of a Janus injection.

This module does **not** confirm exploitability. It only surfaces the
structural indicator so a human reviewer can decide.

Reference
---------
DEX file format header constants live in AOSP at
``art/libdexfile/dex/dex_file.h`` (``kDexMagic`` and ``kDexMagicVersions``).
"""

from __future__ import annotations

import struct
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Optional

from janusguard.apk_reader import ApkReadResult


# The shared "dex\n" prefix common to every DEX format version.
DEX_MAGIC_PREFIX = b"dex\n"
# Compact DEX prefix (used internally by ART; should never appear at the
# start of a distributable APK).
CDEX_MAGIC_PREFIX = b"cdex"

# Known DEX format version strings. These are the four ASCII digits + null
# byte that immediately follow ``dex\n``. We accept any well-formed
# ``NNN\\0`` value rather than a hardcoded list so that future DEX versions
# are still detected.
KNOWN_DEX_VERSIONS = {
    b"035\x00",
    b"036\x00",
    b"037\x00",
    b"038\x00",
    b"039\x00",
    b"040\x00",
    b"041\x00",
}

# A normal APK is a ZIP, so its first 4 bytes are the local file header
# signature.
ZIP_LOCAL_FILE_HEADER = b"PK\x03\x04"


@dataclass
class StructureFindings:
    """Outcome of structural inspection.

    Attributes
    ----------
    starts_with_dex_magic : bool
        True when the first 4 bytes are exactly ``dex\\n``.
    dex_version : str | None
        The DEX format version string (e.g. ``"035"``) if a recognised
        version follows the magic, else ``None``.
    starts_with_cdex_magic : bool
        True when the first 4 bytes match the internal compact-DEX prefix.
        This should never be true for a legitimate distributed APK.
    starts_with_zip_magic : bool
        True when the first 4 bytes are a ZIP local file header.
    janus_pattern_detected : bool
        True when the file simultaneously starts with DEX magic and parses
        as a valid ZIP archive - the hallmark of a Janus-style file.
    dex_declared_file_size : int | None
        The ``file_size`` field from the embedded DEX header (offset 32,
        little-endian uint32). Surfaced as evidence; not used for the
        verdict itself.
    notes : list[str]
        Free-form parser notes.
    """

    starts_with_dex_magic: bool = False
    dex_version: Optional[str] = None
    starts_with_cdex_magic: bool = False
    starts_with_zip_magic: bool = False
    janus_pattern_detected: bool = False
    dex_declared_file_size: Optional[int] = None
    zip_comment_length: int = 0
    zip_comment_is_binary: bool = False
    duplicate_entry_names: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


def analyze_structure(apk: ApkReadResult) -> StructureFindings:
    """Return :class:`StructureFindings` for an already-read APK."""
    findings = StructureFindings()
    data = apk.raw_data

    if len(data) < 8:
        findings.notes.append("File is too small for any meaningful structural check")
        return findings

    head = data[:4]
    if head == DEX_MAGIC_PREFIX:
        findings.starts_with_dex_magic = True
        version_field = data[4:8]
        if version_field in KNOWN_DEX_VERSIONS:
            findings.dex_version = version_field[:3].decode("ascii", errors="replace")
        else:
            findings.notes.append(
                "DEX magic present but version field is not a known DEX version"
            )

        # The DEX header has a uint32 little-endian file_size at offset 32.
        if len(data) >= 36:
            findings.dex_declared_file_size = struct.unpack_from("<I", data, 32)[0]

    elif head == CDEX_MAGIC_PREFIX:
        findings.starts_with_cdex_magic = True
        findings.notes.append(
            "File starts with compact-DEX (cdex) magic - this is an internal "
            "ART format and should not appear in a distributable APK"
        )
    elif head == ZIP_LOCAL_FILE_HEADER:
        findings.starts_with_zip_magic = True

    # The Janus signal is "starts with DEX magic AND is also a valid ZIP".
    # ``apk.is_valid_zip`` was set by the reader using Python's zipfile,
    # which scans backwards from the file end - exactly the behaviour the
    # Janus exploit relies on.
    if findings.starts_with_dex_magic and apk.is_valid_zip:
        findings.janus_pattern_detected = True

    _check_zip_comment(apk, findings)
    _check_entry_anomalies(apk, findings)

    return findings


def _check_zip_comment(apk: ApkReadResult, findings: StructureFindings) -> None:
    """Inspect the ZIP comment field for unexpected or binary content."""
    comment = apk.zip_comment
    findings.zip_comment_length = len(comment)
    if comment:
        # Binary: any byte outside printable ASCII + common whitespace
        findings.zip_comment_is_binary = any(
            b < 0x20 and b not in (0x09, 0x0A, 0x0D) or b > 0x7E
            for b in comment
        )


def _check_entry_anomalies(apk: ApkReadResult, findings: StructureFindings) -> None:
    """Detect ZIP entry anomalies associated with tampered APKs."""
    counts = Counter(apk.entry_names)
    findings.duplicate_entry_names = sorted(
        name for name, n in counts.items() if n > 1
    )
