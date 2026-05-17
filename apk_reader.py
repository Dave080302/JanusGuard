"""APK reader.

Reads an APK file's raw bytes and inspects its ZIP layout without ever
installing or executing it. Produces a normalized result object consumed
by downstream analyzers.
"""

from __future__ import annotations

import hashlib
import os
import zipfile
from dataclasses import dataclass, field
from typing import List, Optional


# Hard cap on file size we are willing to load into memory. APKs larger than
# this are rejected to keep the tool predictable on small machines. Real-world
# APKs are almost always well under this limit.
MAX_APK_SIZE_BYTES = 512 * 1024 * 1024  # 512 MiB


class ApkReadError(Exception):
    """Raised when the APK file cannot be read or is not a valid archive."""


@dataclass
class ZipEntryInfo:
    """Lightweight description of one ZIP entry inside the APK."""

    name: str
    compressed_size: int
    uncompressed_size: int


@dataclass
class ApkReadResult:
    """Everything the reader extracted from an APK file.

    No analysis is performed here; the downstream analyzers consume this object.
    """

    path: str
    file_size: int
    sha256: str
    first_bytes: bytes
    raw_data: bytes
    is_valid_zip: bool
    zip_comment: bytes
    entry_names: List[str] = field(default_factory=list)
    entries: List[ZipEntryInfo] = field(default_factory=list)
    read_errors: List[str] = field(default_factory=list)


def _sha256(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def read_apk(path: str) -> ApkReadResult:
    """Read an APK file from disk and return its raw facts.

    Parameters
    ----------
    path : str
        Filesystem path to the APK file.

    Returns
    -------
    ApkReadResult
        Container holding the raw bytes and ZIP metadata.

    Raises
    ------
    ApkReadError
        If the file does not exist, is not readable, is empty, or exceeds
        ``MAX_APK_SIZE_BYTES``.
    """
    if not os.path.isfile(path):
        raise ApkReadError(f"File does not exist or is not a regular file: {path}")

    file_size = os.path.getsize(path)
    if file_size == 0:
        raise ApkReadError(f"File is empty: {path}")
    if file_size > MAX_APK_SIZE_BYTES:
        raise ApkReadError(
            f"File is larger than the {MAX_APK_SIZE_BYTES} byte safety limit: "
            f"{path} ({file_size} bytes)"
        )

    try:
        with open(path, "rb") as fh:
            raw_data = fh.read()
    except OSError as exc:
        raise ApkReadError(f"Could not read file: {path}: {exc}") from exc

    first_bytes = raw_data[:16]
    sha = _sha256(raw_data)

    is_valid_zip = False
    zip_comment = b""
    entry_names: List[str] = []
    entries: List[ZipEntryInfo] = []
    read_errors: List[str] = []

    # zipfile may still parse files that have prepended bytes (such as a Janus
    # style DEX header) because it scans backwards for the End of Central
    # Directory record. That is precisely what we want: even when the file
    # is malformed at the front, we still get the ZIP view.
    try:
        with zipfile.ZipFile(path, "r") as zf:
            is_valid_zip = True
            zip_comment = zf.comment or b""
            for info in zf.infolist():
                entry_names.append(info.filename)
                entries.append(
                    ZipEntryInfo(
                        name=info.filename,
                        compressed_size=info.compress_size,
                        uncompressed_size=info.file_size,
                    )
                )
    except zipfile.BadZipFile as exc:
        read_errors.append(f"Not a valid ZIP archive: {exc}")
    except Exception as exc:  # pragma: no cover - defensive
        read_errors.append(f"Unexpected error while parsing ZIP: {exc}")

    return ApkReadResult(
        path=path,
        file_size=file_size,
        sha256=sha,
        first_bytes=first_bytes,
        raw_data=raw_data,
        is_valid_zip=is_valid_zip,
        zip_comment=zip_comment,
        entry_names=entry_names,
        entries=entries,
        read_errors=read_errors,
    )
