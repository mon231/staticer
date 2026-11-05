"""Tests for the ELF-track fix for a finding dropped from both the PE and
ELF fix-wave dispatches and only caught at whole-branch close-out: the
path-traversal (CWE-22) gap in `resolve_elf` itself.

ELF counterpart of tests/windows/test_pe_final_review_fixes.py's
`test_resolve_pe_rejects_path_traversal_name`.
"""

import platform

import pytest

from staticer.elf_embedder import resolve_elf

pytestmark = pytest.mark.skipif(platform.system() != "Linux", reason="ELF embedding is Linux-only")


def test_resolve_elf_rejects_path_traversal_name(tmp_path):
    """`name` in `resolve_elf` comes straight from the TARGET BINARY's own
    DT_NEEDED entries -- attacker-controlled, if the input binary being
    processed is untrusted. A crafted dependency name carrying
    path-traversal components must not be allowed to escape the
    search_dirs entry it's matched against; it must behave exactly like
    "not found" (fall through to None / the next dir), never resolve to a
    file genuinely sitting outside the intended directory, even though
    such a file genuinely exists on disk at that escaped location."""
    search_dir = tmp_path / "libs"
    search_dir.mkdir()

    # A real file sitting OUTSIDE search_dir, at exactly the location the
    # crafted traversal name points at.
    outside = tmp_path / "evil.so"
    outside.write_bytes(b"not a real so")

    assert resolve_elf("../evil.so", [search_dir]) is None
    assert resolve_elf("../../etc/passwd", [search_dir]) is None
    assert resolve_elf("..", [search_dir]) is None
    assert resolve_elf(str(outside), [search_dir]) is None  # absolute path

    # A legitimate same-directory match must still resolve normally --
    # the fix must not break the ordinary, non-malicious case.
    legit = search_dir / "lib.so"
    legit.write_bytes(b"legit")
    assert resolve_elf("lib.so", [search_dir]) == legit

    # Falls through to a legitimate match in a LATER search dir when an
    # earlier dir's candidate escapes it.
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    (other_dir / "legit2.so").write_bytes(b"legit2")
    assert resolve_elf("legit2.so", [search_dir, other_dir]) == other_dir / "legit2.so"
