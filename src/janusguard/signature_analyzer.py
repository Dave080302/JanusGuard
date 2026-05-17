"""Signature analyzer.

Detects the APK signing schemes present in an APK:

* APK Signature Scheme v1 (JAR signing) - identified by presence of the
  classic META-INF files: ``MANIFEST.MF``, a ``*.SF`` signature file, and a
  ``*.RSA`` / ``*.DSA`` / ``*.EC`` certificate file.
* APK Signature Scheme v2/v3/v3.1 - identified by parsing the *APK Signing
  Block* that sits between the last local ZIP file header and the central
  directory. Each known scheme has a well-known ID inside that block.

The analyzer only locates schemes; it does **not** verify cryptographic
signatures. That is intentional: this is an educational defensive scanner,
not an installer.

References
----------
* https://source.android.com/docs/security/features/apksigning/v2 (APK Signing
  Block layout and v2 block ID ``0x7109871a``).
* https://source.android.com/docs/security/features/apksigning/v3 (v3 block
  ID ``0xf05368c0``).
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import List, Optional

from janusguard.apk_reader import ApkReadResult


# ---------------------------------------------------------------------------
# Constants - APK Signing Block
# ---------------------------------------------------------------------------

# The 16-byte magic that marks the *end* of the APK Signing Block.
APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"

# Known ID values inside the APK Signing Block. The list is intentionally
# kept short: only the IDs that are useful to surface in a defensive report.
SIGNING_BLOCK_IDS = {
    0x7109871A: "APK Signature Scheme v2",
    0xF05368C0: "APK Signature Scheme v3",
    0x1B93AD61: "APK Signature Scheme v3.1",
    0x42726577: "Verity padding block",
    0x2146444E: "Google Play frosting (proprietary)",
}

# The smallest theoretically valid signing block: 8 bytes size + 8 bytes size
# + 16 bytes magic = 32 bytes. We require at least one ID-value pair on top
# of that to consider the block meaningful (length 8 + at least 4 byte ID),
# i.e. 44 bytes total; but we don't enforce that strictly - we just parse.
APK_SIG_BLOCK_MIN_SIZE = 32


# ---------------------------------------------------------------------------
# Constants - ZIP End of Central Directory
# ---------------------------------------------------------------------------

ZIP_EOCD_MAGIC = b"PK\x05\x06"
ZIP_EOCD_MIN_SIZE = 22  # fixed-size portion of EOCD record
ZIP_EOCD_MAX_COMMENT = 0xFFFF  # ZIP comment is uint16


# ---------------------------------------------------------------------------
# Constants - v1 (JAR) signing files in META-INF
# ---------------------------------------------------------------------------

V1_MANIFEST_PATH = "META-INF/MANIFEST.MF"
V1_SF_RE = re.compile(r"^META-INF/[^/]+\.SF$", re.IGNORECASE)
V1_CERT_RE = re.compile(r"^META-INF/[^/]+\.(RSA|DSA|EC)$", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class SignatureFindings:
    """Outcome of signature inspection.

    Attributes
    ----------
    has_v1 : bool
        True when META-INF contains the three classic JAR-signing artefacts
        (``MANIFEST.MF``, a ``*.SF`` file, and at least one ``*.RSA``,
        ``*.DSA`` or ``*.EC`` file).
    has_v2 : bool
        True when the APK Signing Block contains an entry with the
        v2 ID ``0x7109871a``.
    has_v3 : bool
        True when the block contains an entry with the v3 ID ``0xf05368c0``.
    has_v3_1 : bool
        True when the block contains an entry with the v3.1 ID
        ``0x1b93ad61``.
    has_signing_block : bool
        True when an APK Signing Block was located at all (even if its
        contents are unknown).
    v1_files : list[str]
        Concrete META-INF filenames that triggered ``has_v1``.
    signing_block_ids : list[int]
        Raw IDs parsed out of the APK Signing Block. May contain IDs that
        are not in :data:`SIGNING_BLOCK_IDS`.
    signing_block_offset : int | None
        Byte offset of the start of the APK Signing Block, or ``None``.
    notes : list[str]
        Free-form parser notes (e.g. malformed block).
    """

    has_v1: bool = False
    has_v2: bool = False
    has_v3: bool = False
    has_v3_1: bool = False
    has_signing_block: bool = False
    v1_files: List[str] = field(default_factory=list)
    signing_block_ids: List[int] = field(default_factory=list)
    signing_block_offset: Optional[int] = None
    notes: List[str] = field(default_factory=list)

    @property
    def v1_only(self) -> bool:
        """True when v1 is present and no v2/v3/v3.1 was detected."""
        return self.has_v1 and not (self.has_v2 or self.has_v3 or self.has_v3_1)

    @property
    def is_unsigned(self) -> bool:
        """True when no signing scheme indicators were found at all."""
        return not (
            self.has_v1 or self.has_v2 or self.has_v3 or self.has_v3_1
        )

    def scheme_summary(self) -> str:
        """One-line human-readable summary of detected schemes."""
        schemes = []
        if self.has_v1:
            schemes.append("v1")
        if self.has_v2:
            schemes.append("v2")
        if self.has_v3:
            schemes.append("v3")
        if self.has_v3_1:
            schemes.append("v3.1")
        return "+".join(schemes) if schemes else "none"


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def analyze_signatures(apk: ApkReadResult) -> SignatureFindings:
    """Return the :class:`SignatureFindings` for an already-read APK."""
    findings = SignatureFindings()

    _detect_v1(apk, findings)
    _detect_signing_block(apk, findings)

    return findings


# ---------------------------------------------------------------------------
# v1 detection
# ---------------------------------------------------------------------------


def _detect_v1(apk: ApkReadResult, findings: SignatureFindings) -> None:
    """Set ``has_v1`` and ``v1_files`` based on META-INF entries."""
    has_manifest = False
    has_sf = False
    has_cert = False

    for name in apk.entry_names:
        if name.upper() == V1_MANIFEST_PATH:
            has_manifest = True
            findings.v1_files.append(name)
        elif V1_SF_RE.match(name):
            has_sf = True
            findings.v1_files.append(name)
        elif V1_CERT_RE.match(name):
            has_cert = True
            findings.v1_files.append(name)

    # The classic JAR signing scheme requires all three. Detecting only
    # MANIFEST.MF (which any aapt-built APK has) is not a v1 signature.
    findings.has_v1 = has_manifest and has_sf and has_cert


# ---------------------------------------------------------------------------
# APK Signing Block detection
# ---------------------------------------------------------------------------


def _find_eocd_offset(data: bytes) -> Optional[int]:
    """Locate the End of Central Directory record.

    A ZIP comment can push the EOCD up to ``ZIP_EOCD_MAX_COMMENT`` bytes
    away from the end of the file. We scan backwards from the end looking
    for the magic, ignoring any earlier occurrences (the magic is short and
    could legitimately appear inside compressed data, so we always search
    from the end).
    """
    if len(data) < ZIP_EOCD_MIN_SIZE:
        return None

    # Earliest position where a valid EOCD could start.
    earliest = max(0, len(data) - ZIP_EOCD_MIN_SIZE - ZIP_EOCD_MAX_COMMENT)
    # Search window includes everything from earliest to end-of-file.
    window_start = earliest
    window = data[window_start:]
    # Find the rightmost occurrence of the magic inside the window.
    rel = window.rfind(ZIP_EOCD_MAGIC)
    if rel == -1:
        return None
    return window_start + rel


def _read_cd_offset(data: bytes, eocd_offset: int) -> Optional[int]:
    """Read the central directory offset from the EOCD record."""
    if eocd_offset + ZIP_EOCD_MIN_SIZE > len(data):
        return None
    # Layout (little-endian):
    #   0: 4 bytes magic
    #   4: 2 bytes disk number
    #   6: 2 bytes disk where CD starts
    #   8: 2 bytes records on this disk
    #  10: 2 bytes total records
    #  12: 4 bytes size of CD
    #  16: 4 bytes offset of CD
    #  20: 2 bytes comment length
    cd_offset = struct.unpack_from("<I", data, eocd_offset + 16)[0]
    if cd_offset == 0xFFFFFFFF:
        # ZIP64 sentinel - we do not parse ZIP64 in this educational tool.
        return None
    if cd_offset > len(data):
        return None
    return cd_offset


def _locate_signing_block(data: bytes, cd_offset: int) -> Optional[int]:
    """Return the start offset of the APK Signing Block, or ``None``.

    The block ends immediately before the central directory. Its last 16
    bytes are the magic. The 8 bytes before the magic are the block size,
    and the block size is repeated as the first 8 bytes of the block. The
    block size value covers everything *except* the very first size field.
    """
    if cd_offset < APK_SIG_BLOCK_MIN_SIZE:
        return None

    magic_offset = cd_offset - 16
    if data[magic_offset:cd_offset] != APK_SIG_BLOCK_MAGIC:
        return None

    trailing_size = struct.unpack_from("<Q", data, magic_offset - 8)[0]
    # trailing_size covers: id-value pairs + final size (8) + magic (16) =
    # everything after the leading size field.
    if trailing_size < 24 or trailing_size > cd_offset:
        return None

    block_start = cd_offset - trailing_size - 8
    if block_start < 0:
        return None

    leading_size = struct.unpack_from("<Q", data, block_start)[0]
    if leading_size != trailing_size:
        # Sizes must agree. If they don't, treat the block as malformed.
        return None

    return block_start


def _parse_signing_block_ids(data: bytes, block_start: int) -> List[int]:
    """Parse the ID-value pairs inside the APK Signing Block.

    Returns the list of IDs in the order they appear. The values themselves
    are ignored.
    """
    ids: List[int] = []
    if block_start + 8 > len(data):
        return ids

    leading_size = struct.unpack_from("<Q", data, block_start)[0]
    # Pairs region runs from block_start + 8 up to the trailing size
    # field. The trailing size field starts at block_start + 8 +
    # leading_size - 24 (size of trailing-size + magic).
    pairs_end = block_start + 8 + leading_size - 24
    cursor = block_start + 8

    # Hard cap iteration count to defend against pathological inputs.
    max_iterations = 4096

    while cursor + 8 <= pairs_end and max_iterations > 0:
        max_iterations -= 1
        pair_length = struct.unpack_from("<Q", data, cursor)[0]
        if pair_length < 4:
            break
        if cursor + 8 + pair_length > pairs_end + 8:
            # Pair would run past the pairs region; malformed.
            break
        pair_id = struct.unpack_from("<I", data, cursor + 8)[0]
        ids.append(pair_id)
        cursor += 8 + pair_length

    return ids


def _detect_signing_block(apk: ApkReadResult, findings: SignatureFindings) -> None:
    """Populate v2/v3/v3.1 fields by parsing the APK Signing Block."""
    data = apk.raw_data
    eocd_offset = _find_eocd_offset(data)
    if eocd_offset is None:
        findings.notes.append("ZIP End of Central Directory record not found")
        return

    cd_offset = _read_cd_offset(data, eocd_offset)
    if cd_offset is None:
        findings.notes.append(
            "Central directory offset not readable (possibly ZIP64)"
        )
        return

    block_start = _locate_signing_block(data, cd_offset)
    if block_start is None:
        # No APK Signing Block. The APK either uses only v1 or is unsigned.
        return

    findings.has_signing_block = True
    findings.signing_block_offset = block_start

    ids = _parse_signing_block_ids(data, block_start)
    findings.signing_block_ids = ids

    for raw_id in ids:
        if raw_id == 0x7109871A:
            findings.has_v2 = True
        elif raw_id == 0xF05368C0:
            findings.has_v3 = True
        elif raw_id == 0x1B93AD61:
            findings.has_v3_1 = True
