"""Unit tests for tests/conftest.py's own helper logic (not the embed
tests themselves), run on every platform since no compiler is needed.
"""

import subprocess
from types import SimpleNamespace

import pytest

from conftest import _msvc_target_bits, _require_msvc_bits


def _fake_run(banner_line):
    def run(cmd, capture_output=True, text=True):
        return SimpleNamespace(stdout=banner_line, stderr="")
    return run


# ---------------------------------------------------------------------------
# _msvc_target_bits
# ---------------------------------------------------------------------------


def test_msvc_target_bits_detects_x64(monkeypatch):
    monkeypatch.setattr(
        subprocess, "run",
        _fake_run("Microsoft (R) C/C++ Optimizing Compiler Version 19.38.33130 for x64"),
    )
    _msvc_target_bits.cache_clear()
    assert _msvc_target_bits("cl.exe") == 64


def test_msvc_target_bits_detects_x86(monkeypatch):
    monkeypatch.setattr(
        subprocess, "run",
        _fake_run("Microsoft (R) C/C++ Optimizing Compiler Version 19.38.33130 for x86"),
    )
    _msvc_target_bits.cache_clear()
    assert _msvc_target_bits("cl.exe") == 32


def test_msvc_target_bits_unknown_banner_is_none(monkeypatch):
    monkeypatch.setattr(subprocess, "run", _fake_run("not a recognizable banner"))
    _msvc_target_bits.cache_clear()
    assert _msvc_target_bits("cl.exe") is None


# ---------------------------------------------------------------------------
# _require_msvc_bits
# ---------------------------------------------------------------------------


def test_require_msvc_bits_skips_on_mismatch(monkeypatch):
    monkeypatch.setattr(
        subprocess, "run",
        _fake_run("Microsoft (R) C/C++ Optimizing Compiler Version 19.38.33130 for x64"),
    )
    _msvc_target_bits.cache_clear()
    with pytest.raises(pytest.skip.Exception):
        _require_msvc_bits("cl.exe", 32)


def test_require_msvc_bits_passes_on_match(monkeypatch):
    monkeypatch.setattr(
        subprocess, "run",
        _fake_run("Microsoft (R) C/C++ Optimizing Compiler Version 19.38.33130 for x64"),
    )
    _msvc_target_bits.cache_clear()
    _require_msvc_bits("cl.exe", 64)  # does not raise/skip
