"""Generate synthetic sample APK files for testing JanusGuard.

This script produces a small set of *non-installable* APK-shaped files
that exercise every code path in the analyzer. Each file is a real ZIP
archive with carefully crafted metadata; none of them carries valid
cryptographic signatures, so none of them can be installed on a real
Android device. That is deliberate: the goal is to feed the *static*
analyzer, not to attack anything.

Files produced
--------------

``sample_modern.apk``
    Clean APK structure: ZIP local file header at offset 0, no v1
    META-INF artefacts, an APK Signing Block containing only the v2
    block ID and verity padding. Expected verdict: ``OK``.

``sample_v1_v2.apk``
    A mixed-signing APK: full v1 META-INF artefacts *and* an APK
    Signing Block carrying v2 + v3 block IDs. Expected verdict:
    ``LOW``.

``sample_v1_only.apk``
    A legacy APK with only v1 META-INF artefacts and no APK Signing
    Block. Expected verdict: ``MEDIUM`` (or ``HIGH`` with a vulnerable
    target Android version supplied).

``sample_unsigned.apk``
    An APK ZIP with no signing artefacts at all. Expected verdict:
    ``MEDIUM``.

``sample_janus_style.apk``
    A Janus-style file: a DEX header is prepended to a valid v1-signed
    APK. The file simultaneously parses as DEX (magic ``dex\\n035\\0``)
    and as a ZIP. Expected verdict: ``CRITICAL``.

Run from the project root::

    python samples/generate_samples.py

All files land in ``samples/`` next to this script.
"""

from __future__ import annotations

import io
import os
import struct
import zipfile
from typing import Iterable, List, Tuple

SAMPLES_DIR = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------------------
# Building blocks
# ---------------------------------------------------------------------------

# Minimal valid DEX file header (112 bytes) for format version 035. This
# is *not* executable code; it is just a header with zeroed-out sections
# so that the structure analyzer can read ``file_size`` from offset 32.
def _build_minimal_dex_header(file_size: int) -> bytes:
    header = bytearray(112)
    # Magic + version: "dex\n035\0"
    header[0:8] = b"dex\n035\x00"
    # Checksum (offset 8, 4 bytes) - leave as zero; we are not installing.
    # SHA-1 signature (offset 12, 20 bytes) - leave as zero.
    # file_size (offset 32, uint32 LE)
    struct.pack_into("<I", header, 32, file_size)
    # header_size (offset 36, uint32 LE) - 0x70 = 112 for v035.
    struct.pack_into("<I", header, 36, 0x70)
    # endian_tag (offset 40, uint32 LE) - 0x12345678 = little-endian.
    struct.pack_into("<I", header, 40, 0x12345678)
    # The rest stays zero.
    return bytes(header)


# Minimal AndroidManifest.xml placeholder. Real APKs carry the binary AXML
# form; we just need a file with that name for realism.
_FAKE_AXML = (
    b"<?xml version='1.0' encoding='utf-8'?>\n"
    b"<!-- JanusGuard test fixture; not a real AndroidManifest -->\n"
    b"<manifest package=\"com.example.janusguard.sample\"/>\n"
)


# v1 (JAR) signing artefacts. The content of these files is not what the
# JanusGuard analyzer checks; the analyzer only looks at the filenames in
# META-INF and ensures all three artefact types are present.
_FAKE_MANIFEST_MF = (
    b"Manifest-Version: 1.0\r\n"
    b"Created-By: JanusGuard sample generator\r\n"
    b"\r\n"
    b"Name: AndroidManifest.xml\r\n"
    b"SHA-256-Digest: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n"
    b"\r\n"
)
_FAKE_CERT_SF = (
    b"Signature-Version: 1.0\r\n"
    b"Created-By: JanusGuard sample generator\r\n"
    b"SHA-256-Digest-Manifest: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n"
    b"\r\n"
)
# 64 bytes of placeholder PKCS#7 bytes - just enough to make the file non-empty.
_FAKE_CERT_RSA = bytes(64)


def _add_basic_entries(zf: zipfile.ZipFile) -> None:
    """Add the entries every sample APK has."""
    zf.writestr("AndroidManifest.xml", _FAKE_AXML)
    # A short stub classes.dex (its content is irrelevant; only the name is).
    zf.writestr("classes.dex", _build_minimal_dex_header(112))
    zf.writestr("resources.arsc", b"FAKE_ARSC")


def _add_v1_meta_inf(zf: zipfile.ZipFile) -> None:
    """Add the three META-INF artefacts that trigger v1 detection."""
    zf.writestr("META-INF/MANIFEST.MF", _FAKE_MANIFEST_MF)
    zf.writestr("META-INF/CERT.SF", _FAKE_CERT_SF)
    zf.writestr("META-INF/CERT.RSA", _FAKE_CERT_RSA)


def _build_signing_block(block_ids: Iterable[int]) -> bytes:
    """Build a synthetic APK Signing Block carrying the given IDs.

    Each ID is given a tiny placeholder value so the block parses cleanly.
    The block layout matches the spec:

        size_of_block        : uint64 LE
        repeated id-value pairs
            length_of_pair   : uint64 LE  (>= 4)
            id               : uint32 LE
            value            : bytes      (length_of_pair - 4)
        size_of_block        : uint64 LE  (same value as above)
        magic                : 16 bytes   ("APK Sig Block 42")
    """
    pairs = bytearray()
    placeholder_value = b"\x00" * 16  # 16-byte placeholder value per pair
    for raw_id in block_ids:
        pair_length = 4 + len(placeholder_value)  # ID + value
        pairs += struct.pack("<Q", pair_length)
        pairs += struct.pack("<I", raw_id)
        pairs += placeholder_value

    # Block size excludes the leading size field itself.
    size_of_block = len(pairs) + 8 + 16  # pairs + trailing size + magic
    block = (
        struct.pack("<Q", size_of_block)
        + bytes(pairs)
        + struct.pack("<Q", size_of_block)
        + b"APK Sig Block 42"
    )
    return block


def _insert_signing_block(zip_bytes: bytes, block: bytes) -> bytes:
    """Insert ``block`` between the last local entry and the central directory.

    The End of Central Directory record's "offset of central directory"
    field is rewritten to point at the shifted central directory.
    """
    eocd_offset = zip_bytes.rfind(b"PK\x05\x06")
    if eocd_offset == -1:
        raise RuntimeError("EOCD not found in synthetic ZIP")

    cd_offset = struct.unpack_from("<I", zip_bytes, eocd_offset + 16)[0]
    cd_size = struct.unpack_from("<I", zip_bytes, eocd_offset + 12)[0]

    # Some ZIP writers include a comment; we do not, so the EOCD ends 22
    # bytes after eocd_offset.
    new_zip = (
        zip_bytes[:cd_offset]
        + block
        + zip_bytes[cd_offset : cd_offset + cd_size]
        + zip_bytes[cd_offset + cd_size :]
    )

    new_cd_offset = cd_offset + len(block)
    # Rewrite the EOCD's CD offset field. The EOCD has shifted by len(block)
    # bytes inside ``new_zip``.
    new_eocd_offset = eocd_offset + len(block)
    out = bytearray(new_zip)
    struct.pack_into("<I", out, new_eocd_offset + 16, new_cd_offset)
    return bytes(out)


def _write_zip(entries_fn, signing_block_ids: List[int] = None) -> bytes:
    """Build an in-memory ZIP and optionally inject an APK Signing Block."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        entries_fn(zf)
    raw = buffer.getvalue()
    if signing_block_ids:
        block = _build_signing_block(signing_block_ids)
        raw = _insert_signing_block(raw, block)
    return raw


# ---------------------------------------------------------------------------
# Sample definitions
# ---------------------------------------------------------------------------


def build_modern_apk() -> bytes:
    """v2-only APK: no META-INF v1 artefacts, signing block with v2 ID."""
    return _write_zip(_add_basic_entries, signing_block_ids=[0x7109871A, 0x42726577])


def build_v1_v2_apk() -> bytes:
    """v1 + v2 + v3 APK: full META-INF and a signing block with v2 and v3 IDs."""

    def entries(zf: zipfile.ZipFile) -> None:
        _add_basic_entries(zf)
        _add_v1_meta_inf(zf)

    return _write_zip(entries, signing_block_ids=[0x7109871A, 0xF05368C0, 0x42726577])


def build_v1_only_apk() -> bytes:
    """v1-only APK: META-INF artefacts present, no APK Signing Block."""

    def entries(zf: zipfile.ZipFile) -> None:
        _add_basic_entries(zf)
        _add_v1_meta_inf(zf)

    return _write_zip(entries, signing_block_ids=None)


def build_unsigned_apk() -> bytes:
    """Plain APK ZIP with no signing artefacts of any kind."""
    return _write_zip(_add_basic_entries, signing_block_ids=None)


def build_janus_style_apk() -> bytes:
    """A Janus-style file: DEX header prepended to a v1-signed APK.

    The resulting file:

    * starts with ``dex\\n035\\0``,
    * is still a valid ZIP archive (because ``zipfile`` finds the EOCD by
      scanning backwards from the end of the file).
    """
    inner_apk = build_v1_only_apk()
    # Prepend a DEX header that *declares* a file_size matching the
    # length of the DEX header itself. The real Janus exploit ships a
    # functional DEX with real code; the structural indicator we care
    # about is the magic at offset 0.
    dex_header = _build_minimal_dex_header(112)
    return dex_header + inner_apk


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

_SAMPLES: List[Tuple[str, "callable[[], bytes]", str]] = [
    ("sample_modern.apk", build_modern_apk, "Modern (v2-only) signing - expected OK"),
    ("sample_v1_v2.apk", build_v1_v2_apk, "v1 + v2 + v3 signing - expected LOW"),
    ("sample_v1_only.apk", build_v1_only_apk, "v1-only signing - expected MEDIUM"),
    ("sample_unsigned.apk", build_unsigned_apk, "No signing artefacts - expected MEDIUM"),
    ("sample_janus_style.apk", build_janus_style_apk, "Janus-style DEX-prepended - expected CRITICAL"),
]


def main() -> int:
    os.makedirs(SAMPLES_DIR, exist_ok=True)
    print("Writing sample APK fixtures to", SAMPLES_DIR)
    for name, builder, description in _SAMPLES:
        data = builder()
        out_path = os.path.join(SAMPLES_DIR, name)
        with open(out_path, "wb") as fh:
            fh.write(data)
        print(f"  {name:30s}  {len(data):>8d} bytes  {description}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
