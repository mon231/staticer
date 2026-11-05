import platform
import subprocess

import pytest

from conftest import FIXTURES, build_exe, build_shared_lib

from staticer.pe_embedder import PortableExecutableEmbedder, list_pe_imports

pytestmark = pytest.mark.skipif(platform.system() != "Windows", reason="PE embedding is Windows-only")


# NOTE on `lib_dir`: the task brief's example uses `lib_dir=None`. Per the
# design doc ("every dependency resolvable anywhere on disk is a candidate
# for embedding ... including system libraries"), `lib_dir=None` makes
# *every* resolvable import embeddable -- including the host's real
# KERNEL32.dll/msvcrt.dll imports (resolved via the System32 fallback).
# Embedding real system DLLs needs the non-PIC/unwind-preservation work from
# Tasks 5-8 and is exercised deliberately in Task 10 against real system
# binaries. For this task's synthetic-fixture tests we scope embedding to
# `tmp_path` (where the fixture DLL lives) via `lib_dir=tmp_path`, so only
# our own fixture dependency is embedded and KERNEL32.dll/msvcrt.dll stay
# ordinary dynamic imports, exactly as `--lib-dir` is documented to behave.


@pytest.mark.parametrize("bits", [32, 64])
def test_embed_pic_dll_into_exe(tmp_path, c_compiler, bits):
    dll = build_shared_lib(tmp_path, FIXTURES / "lib.c", "lib.dll", pic=True, bits=bits)
    exe = build_exe(tmp_path, FIXTURES / "main.c", "main.exe", [dll], pic=True, bits=bits)
    out = tmp_path / "static.exe"

    PortableExecutableEmbedder(exe, out, exclude=set(), lib_dir=tmp_path).embed()

    result = subprocess.run([str(out)], capture_output=True)
    assert result.returncode == 42


@pytest.mark.parametrize("bits", [32, 64])
def test_embedded_output_no_longer_imports_embedded_dll(tmp_path, c_compiler, bits):
    dll = build_shared_lib(tmp_path, FIXTURES / "lib.c", "lib.dll", pic=True, bits=bits)
    exe = build_exe(tmp_path, FIXTURES / "main.c", "main.exe", [dll], pic=True, bits=bits)
    out = tmp_path / "static.exe"

    PortableExecutableEmbedder(exe, out, exclude=set(), lib_dir=tmp_path).embed()

    assert "lib.dll" not in list_pe_imports(out)

    result = subprocess.run([str(out)], capture_output=True)
    assert result.returncode == 42


@pytest.mark.parametrize("bits", [32, 64])
def test_architecture_mismatch_fails_loudly(tmp_path, c_compiler, bits):
    other_bits = 32 if bits == 64 else 64

    dll_same_arch = build_shared_lib(tmp_path, FIXTURES / "lib.c", "lib.dll", pic=True, bits=bits)
    exe = build_exe(tmp_path, FIXTURES / "main.c", "main.exe", [dll_same_arch], pic=True, bits=bits)

    dll_other_arch = build_shared_lib(tmp_path, FIXTURES / "lib.c", "lib_other.dll", pic=True, bits=other_bits)
    # manually place the mismatched-arch build where exe's import of
    # "lib.dll" will resolve to it (search_dirs == [lib_dir] == [tmp_path])
    (tmp_path / "lib.dll").write_bytes(dll_other_arch.read_bytes())

    with pytest.raises(ValueError):
        PortableExecutableEmbedder(exe, tmp_path / "out.exe", set(), lib_dir=tmp_path).embed()


# NOTE: a dependency with no relocation data at all used to fail loudly
# unconditionally here (Task 3's interim guard). Task 5 replaced that with
# real base-address-reservation handling -- see
# tests/windows/test_pe_no_reloc.py for the no-reloc-data success path and
# the (reservation-conflict) failure path.
