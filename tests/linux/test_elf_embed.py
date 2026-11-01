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
