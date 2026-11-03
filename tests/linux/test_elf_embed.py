import os
import platform
import subprocess
from pathlib import Path

import pytest

from conftest import FIXTURES, build_exe, build_shared_lib

from staticer.elf_embedder import ElfEmbedder, list_elf_imports

pytestmark = pytest.mark.skipif(platform.system() != "Linux", reason="ELF embedding is Linux-only")


# NOTE on `lib_dir`: as with test_pe_embed.py, the task brief's example
# uses `lib_dir=None`. Per the design doc, that makes *every* resolvable
# import embeddable -- including the host's real libc.so.6 (resolved via
# the /lib,/usr/lib,... fallback). Embedding real system shared objects
# needs the non-PIC/unwind-preservation work from Tasks 6/8 and is
# exercised deliberately in Task 10 against real system binaries. For
# this task's synthetic-fixture tests we scope embedding to `tmp_path`
# (where the fixture .so lives) via `lib_dir=tmp_path`, so only our own
# fixture dependency is embedded and libc.so.6 stays an ordinary dynamic
# import, exactly as `--lib-dir` is documented to behave.


@pytest.mark.parametrize("bits", [32, 64])
def test_embed_pic_so_into_exe(tmp_path, c_compiler, bits):
    so = build_shared_lib(tmp_path, FIXTURES / "lib.c", "lib.so", pic=True, bits=bits)
    exe = build_exe(tmp_path, FIXTURES / "main.c", "main", [so], pic=True, bits=bits)
    out = tmp_path / "static"

    ElfEmbedder(exe, out, exclude=set(), lib_dir=tmp_path).embed()
    out.chmod(0o755)

    result = subprocess.run([str(out)], capture_output=True)
    assert result.returncode == 42


@pytest.mark.parametrize("bits", [32, 64])
def test_embedded_output_no_longer_needs_embedded_so(tmp_path, c_compiler, bits):
    so = build_shared_lib(tmp_path, FIXTURES / "lib.c", "lib.so", pic=True, bits=bits)
    exe = build_exe(tmp_path, FIXTURES / "main.c", "main", [so], pic=True, bits=bits)
    out = tmp_path / "static"

    ElfEmbedder(exe, out, exclude=set(), lib_dir=tmp_path).embed()
    out.chmod(0o755)

    assert "lib.so" not in list_elf_imports(out)

    result = subprocess.run([str(out)], capture_output=True)
    assert result.returncode == 42


@pytest.mark.parametrize("bits", [32, 64])
def test_architecture_mismatch_fails_loudly(tmp_path, c_compiler, bits):
    other_bits = 32 if bits == 64 else 64

    so_same_arch = build_shared_lib(tmp_path, FIXTURES / "lib.c", "lib.so", pic=True, bits=bits)
    exe = build_exe(tmp_path, FIXTURES / "main.c", "main", [so_same_arch], pic=True, bits=bits)

    so_other_arch = build_shared_lib(tmp_path, FIXTURES / "lib.c", "lib_other.so", pic=True, bits=other_bits)
    # manually place the mismatched-arch build where exe's DT_NEEDED entry
    # for "lib.so" will resolve to it (search_dirs == [lib_dir] == [tmp_path])
    (tmp_path / "lib.so").write_bytes(so_other_arch.read_bytes())

    with pytest.raises(ValueError):
        ElfEmbedder(exe, tmp_path / "out", set(), lib_dir=tmp_path).embed()


@pytest.mark.parametrize("bits", [32, 64])
def test_embedded_output_preserves_host_tls(tmp_path, c_compiler, bits):
    """Regression test for a bug where embed() relocated the host's
    program header table into a new PT_LOAD segment with a different
    p_vaddr-p_offset skew than the host's first PT_LOAD segment. The
    kernel computes AT_PHDR = load_bias + e_phoff using *that first
    segment's* skew unconditionally; a skew mismatch sends AT_PHDR to a
    bogus address still inside the original image, which glibc's
    _dl_aux_init then misreads while hunting for this executable's own
    PT_TLS entry -- silently skipping static TLS setup (or crashing) for
    `main_tls.c`'s `tls_counter`. `lib.c`/`main.c` alone (used by the
    other tests above) have no TLS and can't catch this class of bug:
    embed() currently (correctly) never touches e_phoff/e_phnum at all,
    so AT_PHDR's computation is untouched and TLS keeps working."""
    so = build_shared_lib(tmp_path, FIXTURES / "lib.c", "lib.so", pic=True, bits=bits)
    exe = build_exe(tmp_path, FIXTURES / "main_tls.c", "main_tls", [so], pic=True, bits=bits)
    out = tmp_path / "static_tls"

    ElfEmbedder(exe, out, exclude=set(), lib_dir=tmp_path).embed()
    out.chmod(0o755)

    result = subprocess.run([str(out)], capture_output=True)
    assert result.returncode == 49  # tls_counter(7) + lib_value()(42)


@pytest.mark.parametrize("bits", [32, 64])
def test_embed_handles_trailing_debug_info(tmp_path, c_compiler, bits):
    """Regression test for a bug where the new content's placement was
    derived purely from the host's own extended PT_LOAD segment rounding
    up past its *own* p_memsz -- silently assuming that rounding slack
    always happens to cover whatever ordinary trailing, non-segment-
    covered content a binary has (.comment/.symtab/.strtab/.shstrtab/the
    section header table, present on any binary that isn't built with
    `-s`/stripped, which none of this suite's fixtures are). When that
    trailing content is bigger than the segment's own rounding slack --
    completely normal for an unstripped binary with real debug info, not
    an adversarial case -- embed() spuriously raised "would overlap
    existing file content" on an otherwise perfectly ordinary host. `-g`
    here is enough to reliably push a plain host past one page of slack
    (confirmed against this suite's own minimal fixtures, which clear it
    by only a couple hundred bytes without `-g`); embed() must place new
    content past the *actual* end of the file, not just past where its
    chosen segment's own memsz happens to round up to."""
    so = build_shared_lib(tmp_path, FIXTURES / "lib.c", "lib.so", pic=True, bits=bits, extra_flags=["-g"])
    exe = build_exe(
        tmp_path, FIXTURES / "main.c", "main", [so], pic=True, bits=bits, extra_flags=["-g"]
    )
    out = tmp_path / "static_debug"

    ElfEmbedder(exe, out, exclude=set(), lib_dir=tmp_path).embed()
    out.chmod(0o755)

    assert "lib.so" not in list_elf_imports(out)

    result = subprocess.run([str(out)], capture_output=True)
    assert result.returncode == 42


@pytest.mark.parametrize("bits", [32, 64])
def test_embedded_deps_own_further_dependency_gets_host_dt_needed(tmp_path, c_compiler, bits):
    """B2 regression test: lib_needs_further.so gets embedded into the
    host, but it itself links against lib_further.so, which is kept
    entirely out of `lib_dir` (so it's unresolved/out-of-scope from the
    dependency graph's point of view -- never a node at all, let alone an
    embedded one). The bug: embed() forwarded lib_needs_further.so's own
    remaining reference to further_value() as a plain external GLOB_DAT
    symbol, resolved by name at runtime -- but never added lib_further.so
    itself to the host's own DT_NEEDED, so ld.so never loads the module
    that actually defines that symbol. The fix must grow the host's
    DT_NEEDED to include lib_further.so, and the embedded output must
    actually run correctly (not just embed() not crashing) once
    lib_further.so is reachable via LD_LIBRARY_PATH at runtime."""
    further_dir = tmp_path / "further"
    further_dir.mkdir()
    embed_dir = tmp_path / "embed"
    embed_dir.mkdir()

    so_further = build_shared_lib(
        further_dir, FIXTURES / "lib_further.c", "lib_further.so", pic=True, bits=bits,
        extra_flags=["-Wl,-soname,lib_further.so"],
    )
    so_needs_further = build_shared_lib(
        embed_dir, FIXTURES / "lib_needs_further.c", "lib_needs_further.so", pic=True, bits=bits,
        extra_flags=[str(so_further), "-Wl,-soname,lib_needs_further.so"],
    )
    exe = build_exe(
        tmp_path, FIXTURES / "main_needs_further.c", "main_needs_further",
        [so_needs_further], pic=True, bits=bits,
        # -rpath-link only helps the *linker* locate lib_further.so to
        # resolve lib_needs_further.so's own undefined symbol at link
        # time; it leaves no runtime search path in the output at all
        # (unlike -rpath), so this doesn't give the final host binary
        # any way to find lib_further.so by itself -- the whole point
        # of this test.
        extra_flags=[f"-Wl,-rpath-link,{further_dir}"],
    )
    out = tmp_path / "static_needs_further"

    # lib_dir=embed_dir only -- lib_further.so (in a sibling directory) is
    # never a candidate for embedding, matching an "excluded/out of
    # scope" sub-dependency.
    ElfEmbedder(exe, out, exclude=set(), lib_dir=embed_dir).embed()
    out.chmod(0o755)

    remaining = list_elf_imports(out)
    assert "lib_needs_further.so" not in remaining  # embedded
    assert "lib_further.so" in remaining  # B2: must now be a host DT_NEEDED

    env = dict(os.environ, LD_LIBRARY_PATH=str(further_dir))
    result = subprocess.run([str(out)], capture_output=True, env=env)
    assert result.returncode == 8  # further_value()(7) + 1
