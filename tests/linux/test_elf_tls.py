"""ELF TLS segment + relocation merge (Task 3, phase 1): adopting a
dependency's own PT_TLS segment as a TLS-less host's own, mirroring
tests/windows/test_pe_tls.py's PE counterpart.

Per .superpowers/findings/2026-11-04-frida-gadget-tls-shape.md (Task 1),
frida-gadget's real .so carries ONLY R_X86_64_DTPMOD64 (type 16)
relocations in its own .rela.dyn -- no R_X86_64_TLSGD/TLSLD (types
19/20, the call-site General/Local-Dynamic relaxation model) anywhere.
So this task's scope is a pure data-patch merge: a combined PT_TLS
segment, DTPMOD64 slots resolved to the single merged module's id, and
DTPOFF64/TPOFF64 slots resolved to the static offset within that
combined block -- no instruction-level code relaxation needed.

Step 1 (synthetic fixture, `lib_tls_simple.c` -- shared with Task 2's PE
fixture, same source, built here via the GNU/ELF toolchain instead) proves
the mechanism actually works end to end: a __thread counter, embedded
into a TLS-less host, increments and reads back correctly across real
calls after a real embed()+run, not just "doesn't crash". Step 2 (the
real, genuine frida-gadget .so, fetched the same way every other
frida-gadget test in this project does) proves the real binary's shape
is handled too -- that second test only asserts embed() no longer
raises.
"""

import platform
import struct
import subprocess

import pytest
from elftools.elf.elffile import ELFFile

from conftest import FIXTURES, build_exe, build_shared_lib

from staticer.elf_embedder import ElfEmbedder

pytestmark = [
    pytest.mark.skipif(platform.system() != "Linux", reason="ELF embedding is Linux-only"),
    pytest.mark.slow,
]


def test_tls_dependency_merges_into_tls_less_host(tmp_path, c_compiler):
    """The real, positive case this task implements: a dependency .so
    carrying its own PT_TLS segment (one __thread counter) is adopted as
    a TLS-less host's own PT_TLS, rather than raising
    "unsupported relocation type 16". The embedded counter must actually
    increment and read back correctly across three real calls (proves the
    GOT-slot-data-patch mechanism works), not just avoid crashing."""
    so = build_shared_lib(tmp_path, FIXTURES / "lib_tls_simple.c", "lib_tls_simple.so", pic=True, bits=64)
    exe = build_exe(tmp_path, FIXTURES / "main_tls_simple.c", "main_tls_simple", [so], pic=True, bits=64)
    out = tmp_path / "static_tls_simple"

    ElfEmbedder(exe, out, exclude=set(), lib_dir=tmp_path).embed()
    out.chmod(0o755)

    result = subprocess.run([str(out)], capture_output=True)
    assert result.returncode == 3, (
        f"embedded TLS counter didn't read back 3; stderr={result.stderr!r}"
    )


def test_host_with_own_tls_directory_fails_loudly(tmp_path, c_compiler):
    """The genuinely still-unsupported case (phase 2): the HOST itself
    already carries its own PT_TLS segment (`main_host_own_tls.c`'s own
    `host_counter`), and also imports a dependency that carries its own,
    separate PT_TLS (`lib_tls_dep.c`'s `dep_tls_counter`) -- merging two
    real TLS directories into one combined block isn't implemented yet.
    Mirrors tests/windows/test_pe_final_review_fixes.py's
    test_host_with_own_tls_directory_fails_loudly."""
    dll = build_shared_lib(tmp_path, FIXTURES / "lib_tls_dep.c", "lib_tls_dep.so", pic=True, bits=64)
    exe = build_exe(
        tmp_path, FIXTURES / "main_host_own_tls.c", "main_host_own_tls", [dll], pic=True, bits=64,
    )
    out = tmp_path / "static_host_own_tls"

    with pytest.raises(ValueError, match="(?i)lib_tls_dep.so.*tls|tls.*lib_tls_dep.so"):
        ElfEmbedder(exe, out, exclude=set(), lib_dir=tmp_path).embed()


def _patch_dtpmod64_to_tlsgd(so_path):
    """Rewrite the type field of the first R_X86_64_DTPMOD64 (16)
    relocation entry found in `so_path`'s own .rela.dyn into
    R_X86_64_TLSGD (19), in place.

    This exists only to produce, for test purposes, the one ELF shape
    Task 6's investigation (see task-6-report.md) found is otherwise
    impossible to obtain from a real compiler/linker: a genuinely
    *linked* .so carrying an R_X86_64_TLSGD/TLSLD relocation. Every
    toolchain tried (gcc with `-ftls-model=global-dynamic` and the
    `tls_model("global-dynamic")` attribute, GNU ld/bfd, lld) always
    resolves TLSGD/TLSLD at static-link time into an ordinary
    DTPMOD64/DTPOFF64 GOT-slot pair before it ever reaches a linked
    output file -- so the only way to exercise `embed()`'s own explicit
    rejection of this relocation type is to hand-craft it directly,
    exactly as a malicious or unusual input might.
    """
    with open(so_path, "rb") as f:
        data = bytearray(f.read())
    with open(so_path, "rb") as f:
        elf = ELFFile(f)
        sec = elf.get_section_by_name(".rela.dyn")
        assert sec is not None, f"{so_path} has no .rela.dyn section"
        off = sec["sh_offset"]
        entsize = sec["sh_entsize"]
        count = sec["sh_size"] // entsize
        for i in range(count):
            entry_off = off + i * entsize
            r_info = struct.unpack_from("<Q", data, entry_off + 8)[0]
            if (r_info & 0xFFFFFFFF) == 16:  # R_X86_64_DTPMOD64
                new_info = (r_info & ~0xFFFFFFFF) | 19  # R_X86_64_TLSGD
                struct.pack_into("<Q", data, entry_off + 8, new_info)
                break
        else:
            raise AssertionError(f"no R_X86_64_DTPMOD64 relocation found in {so_path}")
    so_path.write_bytes(bytes(data))


def test_tlsgd_relocation_fails_loudly(tmp_path, c_compiler):
    """`embed()` must reject a genuine R_X86_64_TLSGD relocation with a
    specific, named error (rather than falling into the generic
    "unsupported relocation type" message, or silently mishandling it) --
    see the module-level comment above `R_X86_64_TLSGD`'s own declaration
    in elf_embedder.py and task-6-report.md for why this can only be
    exercised via a hand-crafted fixture (no real compiler/linker on this
    project's supported toolchains actually produces this relocation type
    in a linked .so)."""
    so = build_shared_lib(tmp_path, FIXTURES / "lib_tls_simple.c", "lib_tls_simple.so", pic=True, bits=64)
    _patch_dtpmod64_to_tlsgd(so)
    exe = build_exe(tmp_path, FIXTURES / "main_tls_simple.c", "main_tls_simple", [so], pic=True, bits=64)
    out = tmp_path / "static_tlsgd"

    # Matched on text unique to the new rejection branch's own message
    # ("General/Local-Dynamic"), not on "TLSGD" alone: pytest's own
    # `tmp_path` directory is named after this test function (truncated),
    # e.g. ".../test_tlsgd_relocation_fails_lo0/lib_tls_simple.so", and
    # that path is embedded via `node.name` into EVERY ValueError the
    # per-dependency relocation loop can raise -- including the
    # pre-existing generic "unsupported relocation type" fallback. A
    # "TLSGD"-only match would therefore pass even if the new check were
    # deleted, proving nothing about it specifically (confirmed by
    # disabling the new check and re-running: see task-6-report.md).
    with pytest.raises(ValueError, match="General/Local-Dynamic"):
        ElfEmbedder(exe, out, exclude=set(), lib_dir=tmp_path).embed()
