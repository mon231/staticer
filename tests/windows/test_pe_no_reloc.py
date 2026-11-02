import platform
import subprocess
from pathlib import Path

import pefile
import pytest

from conftest import FIXTURES, build_exe, build_shared_lib

from staticer.pe_embedder import PortableExecutableEmbedder

pytestmark = pytest.mark.skipif(platform.system() != "Windows", reason="PE embedding is Windows-only")


# NOTE on `lib_dir`: as in test_pe_embed.py, scope embedding to `tmp_path`
# (via `lib_dir=tmp_path`) rather than the task brief's illustrative
# `lib_dir=None`, so only our own fixture dependency/dependencies are
# embedded and real system DLLs (KERNEL32.dll/msvcrt.dll) stay ordinary
# dynamic imports -- embedding *those* needs work from later tasks (10).


@pytest.mark.parametrize("bits", [32, 64])
def test_embed_non_pic_dll_without_relocs(tmp_path, c_compiler, bits):
    dll = build_shared_lib(tmp_path, FIXTURES / "lib.c", "lib.dll", pic=False, bits=bits, strip_relocs=True)
    exe = build_exe(tmp_path, FIXTURES / "main.c", "main.exe", [dll], pic=True, bits=bits)
    out = tmp_path / "static.exe"

    PortableExecutableEmbedder(exe, out, set(), tmp_path).embed()

    result = subprocess.run([str(out)], capture_output=True)
    assert result.returncode == 42


def _set_pe_image_base(path: Path, image_base: int) -> None:
    """Overwrite a PE's OPTIONAL_HEADER.ImageBase in place, so two
    independently-built no-reloc DLLs can be forced to claim the exact
    same preferred base -- deterministically exercising the embedder's
    conflict check rather than relying on the toolchain's default base
    happening to collide."""
    pe = pefile.PE(str(path))
    is64 = pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]
    off = pe.OPTIONAL_HEADER.get_field_absolute_offset("ImageBase")
    pe.close()

    size = 8 if is64 else 4
    data = bytearray(path.read_bytes())
    data[off:off + size] = image_base.to_bytes(size, "little")
    path.write_bytes(bytes(data))


@pytest.mark.parametrize("bits", [32, 64])
def test_base_address_conflict_fails_loudly(tmp_path, c_compiler, bits):
    dll_a = build_shared_lib(tmp_path, FIXTURES / "lib.c", "lib.dll", pic=False, bits=bits, strip_relocs=True)
    dll_b = build_shared_lib(tmp_path, FIXTURES / "lib_b.c", "lib_b.dll", pic=False, bits=bits, strip_relocs=True)

    shared_base = 0x10000000
    _set_pe_image_base(dll_a, shared_base)
    _set_pe_image_base(dll_b, shared_base)

    exe = build_exe(tmp_path, FIXTURES / "main_two_libs.c", "main_two_libs.exe", [dll_a, dll_b], pic=True, bits=bits)

    with pytest.raises(ValueError):
        PortableExecutableEmbedder(exe, tmp_path / "out.exe", set(), tmp_path).embed()
