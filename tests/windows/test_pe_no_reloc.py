import platform
import subprocess
from pathlib import Path

import pefile
import pytest

from conftest import FIXTURES, build_exe, build_shared_lib

from staticer.pe_embedder import PortableExecutableEmbedder, list_pe_imports

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


@pytest.mark.parametrize("bits", [32, 64])
def test_base_address_conflict_inside_alignment_gap_filler_fails_loudly(tmp_path, c_compiler, bits):
    """Regression test: a no-reloc dependency placed far from the host's
    own sections is bridged by a ".bss"-style filler section covering the
    RVA gap in between (see embed()'s comments on why -- the Windows PE
    loader rejects an image whose sections don't cover its RVA space
    contiguously). That filler section is a real entry in the final
    section table and physically claims its RVA range, exactly like any
    other section -- so a *second*, independent no-reloc dependency whose
    own reserved address falls inside that filler's range (not inside the
    host's own range, and not inside the first dependency's own data
    range) is just as real a collision as any other, and must be rejected
    the same way.

    `main_two_libs.c` calls `lib_value()` then `lib_b_value()`; which of
    `lib.dll`/`lib_b.dll` the linker lists first in the host's own import
    table (and so which `list_pe_imports`/`embed_order` process first)
    isn't guaranteed stable across linkers/toolchain versions -- confirmed
    via a real CI run where it flipped from what local testing had seen,
    silently turning this regression test into a no-op (neither dependency's
    address collided with anything, so `embed()` raised nothing). Query the
    host's own actual import order instead of hardcoding which name is
    "first", so the far/wide-filler address always lands on whichever
    dependency the real embed() processes first, regardless of toolchain.
    """
    dll_a = build_shared_lib(tmp_path, FIXTURES / "lib.c", "lib.dll", pic=False, bits=bits, strip_relocs=True)
    dll_b = build_shared_lib(tmp_path, FIXTURES / "lib_b.c", "lib_b.dll", pic=False, bits=bits, strip_relocs=True)
    exe = build_exe(tmp_path, FIXTURES / "main_two_libs.c", "main_two_libs.exe", [dll_a, dll_b], pic=True, bits=bits)

    exe_pe = pefile.PE(str(exe))
    exe_image_base = exe_pe.OPTIONAL_HEADER.ImageBase
    exe_pe.close()

    # Whichever of lib.dll/lib_b.dll the host's own import table lists
    # first is the one embed_order() processes first -- give *that* one
    # the far address (wide enough to need a filler bridging the gap from
    # the host's own sections) and the other the address that lands
    # inside that filler's range, well clear of both the host's own range
    # and the first dependency's own data range.
    import_order = [name.lower() for name in list_pe_imports(exe)]
    dlls_by_name = {"lib.dll": dll_a, "lib_b.dll": dll_b}
    first_name, second_name = sorted(dlls_by_name, key=lambda n: import_order.index(n))
    _set_pe_image_base(dlls_by_name[first_name], exe_image_base + 0x40000000)
    _set_pe_image_base(dlls_by_name[second_name], exe_image_base + 0x20000000)

    with pytest.raises(ValueError):
        PortableExecutableEmbedder(exe, tmp_path / "out.exe", set(), tmp_path).embed()
