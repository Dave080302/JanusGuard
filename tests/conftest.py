"""Shared pytest fixtures.

We import the sample builders directly so the test suite does not depend
on the on-disk sample files. This lets ``pytest`` run from a clean clone
without first running ``generate_samples.py``.
"""

from __future__ import annotations

import os
import sys

import pytest

# Make sure ``src`` is on the import path when running pytest from the
# project root. ``pip install -e .`` would also do this, but we want the
# tests to work without it.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SRC_DIR = os.path.join(_PROJECT_ROOT, "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

_SAMPLES_DIR = os.path.join(_PROJECT_ROOT, "samples")
if _SAMPLES_DIR not in sys.path:
    sys.path.insert(0, _SAMPLES_DIR)

# Imported after sys.path manipulation.
import generate_samples  # noqa: E402


@pytest.fixture
def sample_modern_bytes() -> bytes:
    return generate_samples.build_modern_apk()


@pytest.fixture
def sample_v1_v2_bytes() -> bytes:
    return generate_samples.build_v1_v2_apk()


@pytest.fixture
def sample_v1_only_bytes() -> bytes:
    return generate_samples.build_v1_only_apk()


@pytest.fixture
def sample_unsigned_bytes() -> bytes:
    return generate_samples.build_unsigned_apk()


@pytest.fixture
def sample_janus_bytes() -> bytes:
    return generate_samples.build_janus_style_apk()


@pytest.fixture
def write_bytes(tmp_path):
    """Return a callable that writes bytes to ``tmp_path`` and returns the path."""

    def _write(name: str, data: bytes) -> str:
        p = tmp_path / name
        p.write_bytes(data)
        return str(p)

    return _write
