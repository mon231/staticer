"""Shared fixture-building helpers for Windows (PE) and Linux (ELF) embed
tests: locate a C compiler and compile the small synthetic fixtures in
``tests/fixtures`` into shared libs / executables with the requested
bitness and PIC-ness.
"""

import functools
import lzma
import platform
import re
import shutil
import struct
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import List, Optional, Tuple

import pefile
import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def _align_up(value: int, alignment: int) -> int:
    if alignment <= 1:
        return value
    return (value + alignment - 1) // alignment * alignment


def _find_compiler() -> Optional[Tuple[str, Optional[str]]]:
    """Returns ('msvc', path-to-cl) or ('gnu', None) or None."""
    cl = shutil.which("cl.exe") or shutil.which("cl")
    if cl:
        return ("msvc", cl)
    if shutil.which("gcc") or shutil.which("clang"):
        return ("gnu", None)
    return None


@functools.lru_cache(maxsize=None)
def _msvc_target_bits(cl_path: str) -> Optional[int]:
    """The bitness `cl_path` actually compiles for, read from its own
    version banner ("... for x64" / "... for x86"), or None if that can't
    be determined.

    There's no portable way to make a single `cl.exe` on PATH build for a
    *different* bitness than the one it was set up for (that's a property
    of which Developer Command Prompt / vcvarsall.bat environment is
    active, not a compiler flag) -- so callers must check this and skip
    rather than silently building the wrong bitness.
    """
    result = subprocess.run([cl_path], capture_output=True, text=True)
    banner = (result.stdout or "") + (result.stderr or "")
    if re.search(r"\bfor x64\b", banner):
        return 64
    if re.search(r"\bfor x86\b", banner):
        return 32
    return None


def _require_msvc_bits(cl_path: str, bits: int) -> None:
    active = _msvc_target_bits(cl_path)
    if active != bits:
        pytest.skip(
            f"active cl.exe targets {active if active else 'an unknown'}-bit; "
            f"this fixture can't select a {bits}-bit MSVC toolchain on its own "
            f"(that needs a different vcvarsall.bat/Developer Command Prompt "
            f"environment)"
        )


@pytest.fixture(scope="session")
def c_compiler():
    found = _find_compiler()
    if found is None:
        pytest.skip("no C compiler (cl.exe/gcc/clang) found on PATH")
    return found


def _gnu_cpp_compiler_for_bits(bits: int) -> str:
    """g++/clang++ equivalent of ``_gnu_compiler_for_bits``, for fixtures
    that need real C++ exception handling (``throw``/``catch``) -- a plain
    C compiler can't compile those. Same Windows-mingw-prefix preference
    and native-ELF-target caveat as the C path; see its docstring."""
    if platform.system() == "Windows":
        prefixed = "x86_64-w64-mingw32-g++" if bits == 64 else "i686-w64-mingw32-g++"
        exe = shutil.which(prefixed)
        if exe:
            return exe
    exe = shutil.which("g++") or shutil.which("clang++")
    if exe:
        return exe
    raise RuntimeError(f"no usable GNU-style C++ compiler found for {bits}-bit")


def _gnu_compiler_for_bits(bits: int) -> str:
    """A gcc/clang binary that actually targets the requested bitness.

    On Windows (the cl.exe-less fallback for the PE/mingw path), a plain
    'gcc' on PATH is frequently a single-target MinGW build with no
    -m32/-m64 multilib support, so prefer the architecture-prefixed
    mingw-w64 binary name when one is on PATH there.

    Elsewhere (native ELF target), *never* prefer that prefixed name even
    if it happens to be on PATH (e.g. a dev box with mingw-w64 installed
    for cross-building Windows binaries) -- "x86_64-w64-mingw32-gcc" is a
    Windows (PE) cross-compiler, not a Linux-targeting one, and would
    silently produce a `foo.exe` PE binary instead of the requested ELF
    one. Just use the generic name plus -m32/-m64 (works for toolchains
    that support multilib, e.g. most Linux distro gccs targeting x86).
    """
    if platform.system() == "Windows":
        prefixed = "x86_64-w64-mingw32-gcc" if bits == 64 else "i686-w64-mingw32-gcc"
        exe = shutil.which(prefixed)
        if exe:
            return exe
    exe = shutil.which("gcc") or shutil.which("clang")
    if exe:
        return exe
    raise RuntimeError(f"no usable GNU-style C compiler found for {bits}-bit")


def _run(cmd: List[str]) -> None:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(cmd)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )


def _strip_pe_relocations(path: Path) -> None:
    """Zero out a PE's Base Relocation data directory in place, producing a
    dependency that carries no relocation data at all -- simulates a
    fixed-base/non-PIC build without needing to find a compiler/linker flag
    combination that reliably omits relocations on every toolchain."""
    pe = pefile.PE(str(path))
    reloc_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]]
    va_off = reloc_dir.get_field_absolute_offset("VirtualAddress")
    sz_off = reloc_dir.get_field_absolute_offset("Size")
    pe.close()  # release the file handle before rewriting it (Windows locking)

    data = bytearray(path.read_bytes())
    data[va_off:va_off + 4] = b"\x00\x00\x00\x00"
    data[sz_off:sz_off + 4] = b"\x00\x00\x00\x00"
    path.write_bytes(bytes(data))


def shrink_pe_section_header_slack(path: Path) -> None:
    """Doctors a built PE in place so its section-header table has almost
    no slack left -- simulating the "original linker packed this region
    tight" real-world case (see ``docs/limitations.md``'s entry on PE
    section-header-table growth, found via local testing against a real
    Qt6-based application) without needing a specific third-party linker
    on hand.

    Every real compiler/linker leaves the gap between the end of the
    (existing) section-header table and the first section's own raw file
    data as plain zero padding, there purely because ``PointerToRawData``
    must be a multiple of ``FileAlignment`` and the header table itself
    rarely lands exactly on such a boundary. That gap can't be shrunk by
    moving ``PointerToRawData`` earlier without violating that alignment
    rule (and real binaries just leave it as slack) -- so this doesn't
    touch any raw file data at all. Instead it fills that existing slack
    with harmless *dummy* section-header entries, consuming the slack
    down to less than one more 40-byte entry's worth -- exactly the
    "nowhere near enough for even one dependency's worth of new
    sections" scenario ``embed()``'s "not enough slack" check guards
    against. Each dummy also bumps ``NumberOfSections``, so the file
    stays internally consistent.

    Each dummy is given its own non-overlapping virtual-address range
    (one ``SectionAlignment`` page past wherever the real sections end)
    and the same ``IMAGE_SCN_CNT_UNINITIALIZED_DATA | MEM_READ |
    MEM_WRITE`` characteristics real ``.bss`` sections carry, with no
    raw file backing (``PointerToRawData``/``SizeOfRawData`` both 0, the
    same convention this project's own embedder uses for a "no raw file
    backing" filler section) -- an all-zero section-header entry
    (0 VirtualAddress, 0 Characteristics) is not a section Windows'
    real loader accepts (confirmed directly: a host doctored that way
    fails to start at all, with ``%1 is not a valid Win32
    application``), so this mimics a real, loader-valid empty section
    instead.
    """
    pe = pefile.PE(str(path))
    fh = pe.FILE_HEADER
    section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
    section_table_offset = fh.get_file_offset() + fh.sizeof() + fh.SizeOfOptionalHeader
    existing_section_count = fh.NumberOfSections
    first_raw_data_offset = min(s.PointerToRawData for s in pe.sections if s.PointerToRawData)
    slack = first_raw_data_offset - (section_table_offset + existing_section_count * 40)
    num_dummies = slack // 40
    noff = fh.get_field_absolute_offset("NumberOfSections")

    last_section = max(pe.sections, key=lambda s: s.VirtualAddress)
    next_rva = _align_up(
        last_section.VirtualAddress + max(last_section.Misc_VirtualSize, last_section.SizeOfRawData),
        section_alignment,
    )
    size_off = pe.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfImage")
    pe.close()

    if num_dummies <= 0:
        raise RuntimeError(
            f"'{path}' already has less than one section-header entry's "
            f"worth of slack ({slack} bytes) -- nothing to shrink"
        )

    data = bytearray(path.read_bytes())
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
    IMAGE_SCN_MEM_READ = 0x40000000
    IMAGE_SCN_MEM_WRITE = 0x80000000
    characteristics = IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
    dummies_offset = section_table_offset + existing_section_count * 40
    for i in range(num_dummies):
        va = next_rva + i * section_alignment
        header = struct.pack(
            "<8sIIIIIIHHI", b".pad\x00\x00\x00\x00", section_alignment, va,
            0, 0, 0, 0, 0, 0, characteristics,
        )
        data[dummies_offset + i * 40:dummies_offset + (i + 1) * 40] = header
    data[noff:noff + 2] = struct.pack("<H", existing_section_count + num_dummies)
    new_size_of_image = _align_up(next_rva + num_dummies * section_alignment, section_alignment)
    data[size_off:size_off + 4] = struct.pack("<I", new_size_of_image)
    path.write_bytes(bytes(data))


def build_shared_lib(
    tmp_path: Path, source: Path, name: str, *, pic: bool, bits: int,
    extra_flags: Optional[List[str]] = None, strip_relocs: bool = False, cpp: bool = False,
) -> Path:
    kind, cl_path = _find_compiler()
    out = tmp_path / name

    if kind == "msvc":
        _require_msvc_bits(cl_path, bits)
        obj = tmp_path / (Path(name).stem + ".obj")
        if cpp:
            # /TP ("treat every file on this command line as C++ source")
            # applies to *every* argument, not just the primary source --
            # mixing it into the same invocation as /LD's link inputs
            # (extra_flags may contain more .lib/.obj paths) makes cl.exe
            # try to *compile* those too, producing garbage syntax errors.
            # Compile-only first (plain object file, no /LD -- that flag's
            # DLL-building behavior belongs to the link step), then link
            # separately with no /TP in sight.
            _run([cl_path, "/nologo", "/c", "/TP", str(source), f"/Fo{obj}"])
            _run([cl_path, "/nologo", "/LD", str(obj), f"/Fe{out}"] + list(extra_flags or []))
        else:
            _run([cl_path, "/nologo", "/LD", str(source), f"/Fe{out}", f"/Fo{obj}"] + list(extra_flags or []))
        if strip_relocs:
            _strip_pe_relocations(out)
        return out

    compiler = _gnu_cpp_compiler_for_bits(bits) if cpp else _gnu_compiler_for_bits(bits)
    bits_flag = "-m64" if bits == 64 else "-m32"
    pic_flag = "-fPIC" if pic else "-fno-pic"
    cmd = [compiler, "-shared", bits_flag, pic_flag, "-o", str(out), str(source)] + list(extra_flags or [])
    if platform.system() == "Windows":
        # mingw-w64 cross/native compiler, producing a PE DLL (used as a
        # cl.exe-less fallback for the Windows/PE embed tests).
        cmd.append("-Wl,--export-all-symbols")
        if not pic:
            cmd.append("-Wl,--disable-dynamicbase")
            # --disable-dynamicbase only clears the runtime ASLR flag; the
            # linker still picks a high-entropy *link-time* preferred base
            # unless told otherwise, which for a real fixed-base/non-PIC
            # DLL would defeat the purpose (and, for our purposes, tends to
            # land far enough from the host's own base to overflow a
            # 32-bit RVA). Pin it to a conventional default instead -- one
            # that's comfortably above a typical 64-bit EXE's own default
            # base (0x140000000) so the two don't collide by coincidence.
            image_base = 0x180000000 if bits == 64 else 0x10000000
            cmd.append(f"-Wl,--image-base=0x{image_base:x}")
    # Elsewhere (Linux), this produces a native ELF .so: default symbol
    # visibility already exports lib.c's function, so no extra flag is
    # needed there.
    _run(cmd)
    if strip_relocs:
        if platform.system() == "Windows":
            _strip_pe_relocations(out)
        else:
            # ELF-side relocation stripping is a different task's concern
            # (see the ELF embedder's own no-reloc-data handling); nothing
            # here does it yet.
            raise NotImplementedError("strip_relocs isn't implemented for ELF output yet")
    return out


def _msvc_import_lib_for(dll_path: Path) -> Path:
    """The sibling .lib import library that MSVC's ``/LD`` produces
    alongside a DLL it just built, for linking against that DLL from
    cl.exe/link.exe -- a .dll is itself a PE image, not a COFF object
    file or import library, so passing it directly as a link input is
    invalid (link.exe will reject it)."""
    lib_path = dll_path.with_suffix(".lib")
    if not lib_path.is_file():
        raise RuntimeError(
            f"no MSVC import library found for '{dll_path}' (expected "
            f"'{lib_path}' alongside it); /LD produces this automatically "
            "when the DLL is built, so its absence means the DLL wasn't "
            "built via that path and can't be linked against here"
        )
    return lib_path


def build_exe(
    tmp_path: Path, source: Path, name: str, libs: List[Path], *, pic: bool, bits: int,
    extra_flags: Optional[List[str]] = None, cpp: bool = False,
) -> Path:
    kind, cl_path = _find_compiler()
    out = tmp_path / name

    if kind == "msvc":
        _require_msvc_bits(cl_path, bits)
        obj = tmp_path / (Path(name).stem + ".obj")
        link_libs = [_msvc_import_lib_for(lib) for lib in libs]
        if cpp:
            # See build_shared_lib's identical comment: /TP applies to
            # every argument on the command line, so it can't be mixed
            # into the same invocation as the .lib link inputs below --
            # compile-only first, then link with no /TP at all.
            _run([cl_path, "/nologo", "/c", "/TP", str(source), f"/Fo{obj}"])
            _run(
                [cl_path, "/nologo", str(obj), f"/Fe{out}"]
                + [str(lib) for lib in link_libs] + list(extra_flags or [])
            )
        else:
            _run(
                [cl_path, "/nologo", str(source), f"/Fe{out}", f"/Fo{obj}"]
                + [str(lib) for lib in link_libs] + list(extra_flags or [])
            )
        return out

    compiler = _gnu_cpp_compiler_for_bits(bits) if cpp else _gnu_compiler_for_bits(bits)
    bits_flag = "-m64" if bits == 64 else "-m32"
    pic_flag = "-fPIC" if pic else "-fno-pic"
    cmd = (
        [compiler, bits_flag, pic_flag, "-o", str(out), str(source)]
        + [str(lib) for lib in libs] + list(extra_flags or [])
    )
    if platform.system() == "Windows":
        if not pic:
            cmd.append("-Wl,--disable-dynamicbase")
    else:
        # Native ELF target: make PIC-ness of the *executable* explicit
        # (modern distro gcc defaults to PIE already, but don't rely on
        # that default) rather than relying on -fPIC alone, which only
        # affects code generation, not whether the linker emits an ET_DYN
        # (PIE) vs ET_EXEC (fixed-base) binary.
        cmd.append("-pie" if pic else "-no-pie")
    _run(cmd)
    return out


# ---------------------------------------------------------------------------
# frida-gadget real-binary test support (tests/windows/test_pe_frida_gadget.py,
# tests/linux/test_elf_frida_gadget.py)
# ---------------------------------------------------------------------------

#: Pinned, exact Frida release used by those tests -- see this constant's
#: own callers for why: the two helpers below hardcode the dependency's own
#: baked-in module name ("libfrida-gadget-raw.dll"/".so", read from its PE
#: export-directory Name field / ELF DT_SONAME, confirmed for real against
#: this exact release), which only stays accurate for pinning one specific
#: version rather than always tracking "latest".
FRIDA_GADGET_VERSION = "17.25.2"

#: frida-gadget's own module name, as baked into its PE export directory's
#: Name field / ELF DT_SONAME (confirmed for real by inspecting the
#: FRIDA_GADGET_VERSION release assets with pefile/readelf) -- NOT the
#: filename of the GitHub release asset, which is just
#: "frida-gadget-<version>-<platform>-x86_64.<ext>". A GNU/mingw-w64 `ld`
#: direct-DLL-link, and any ELF `DT_NEEDED` entry, both resolve/record a
#: dependency by *this* name rather than whatever a caller names the file
#: on disk -- so a lib_dir copy of the gadget must use this exact name
#: for PortableExecutableEmbedder/ElfEmbedder's by-name resolution to find
#: it at all.
FRIDA_GADGET_MODULE_NAME = {"windows": "libfrida-gadget-raw.dll", "linux": "libfrida-gadget-raw.so"}

FRIDA_CACHE_DIR = FIXTURES / ".frida-cache"

_FRIDA_GADGET_ASSET_NAME = {
    "windows": f"frida-gadget-{FRIDA_GADGET_VERSION}-windows-x86_64.dll.xz",
    "linux": f"frida-gadget-{FRIDA_GADGET_VERSION}-linux-x86_64.so.xz",
}
_FRIDA_GADGET_EXT = {"windows": ".dll", "linux": ".so"}


class FridaGadgetUnavailable(Exception):
    """Raised by fetch_frida_gadget() when the real, genuine third-party
    frida-gadget binary can't be obtained -- no network access, GitHub
    unreachable, a truncated/corrupt download, etc. Callers should catch
    this and pytest.skip() with its message: an inability to fetch a
    third-party binary is an environment/infra concern, not a bug in
    staticer itself, and shouldn't fail CI on that basis."""


def fetch_frida_gadget(platform_name: str) -> Path:
    """Downloads (or reuses a previously cached copy of) the real
    frida-gadget shared library for `platform_name` ("windows" or
    "linux"), fetched for real from Frida's own GitHub release assets --
    never synthesized; see the real-binary test modules that call this
    for why a genuine third-party binary matters here specifically.

    Cached under tests/fixtures/.frida-cache/ (gitignored) so repeated
    test runs don't re-download the ~9MB compressed asset every time.

    Raises FridaGadgetUnavailable (never a bare network/OS exception) if
    the real binary can't be obtained for any reason.
    """
    asset_name = _FRIDA_GADGET_ASSET_NAME[platform_name]
    ext = _FRIDA_GADGET_EXT[platform_name]
    FRIDA_CACHE_DIR.mkdir(parents=True, exist_ok=True)

    extracted = FRIDA_CACHE_DIR / f"frida-gadget-{FRIDA_GADGET_VERSION}-{platform_name}-x86_64{ext}"
    if extracted.is_file() and extracted.stat().st_size > 0:
        return extracted

    compressed = FRIDA_CACHE_DIR / asset_name
    if not (compressed.is_file() and compressed.stat().st_size > 0):
        url = f"https://github.com/frida/frida/releases/download/{FRIDA_GADGET_VERSION}/{asset_name}"
        try:
            with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310 (real asset, pinned host)
                data = response.read()
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise FridaGadgetUnavailable(
                f"could not download real frida-gadget from {url}: {exc}"
            ) from exc
        if not data:
            raise FridaGadgetUnavailable(f"empty download from {url}")
        compressed.write_bytes(data)

    try:
        extracted_bytes = lzma.decompress(compressed.read_bytes())
    except lzma.LZMAError as exc:
        # Don't leave a corrupt cache entry behind to keep failing every
        # subsequent run the same way -- let a retry re-download instead.
        compressed.unlink(missing_ok=True)
        raise FridaGadgetUnavailable(
            f"corrupt cached/downloaded frida-gadget archive ({compressed}): {exc}"
        ) from exc

    extracted.write_bytes(extracted_bytes)
    return extracted


def build_exe_importing_prebuilt_dll(
    tmp_path: Path, source: Path, name: str, dll_path: Path, exported_symbol: str, *, bits: int,
) -> Path:
    """Like build_exe, but for linking against a prebuilt *third-party*
    DLL that has no sibling MSVC import library of its own (e.g. a
    downloaded release binary such as frida-gadget, as opposed to one of
    this project's own fixtures built via build_shared_lib's `/LD` step,
    which always produces one). `source` must reference `exported_symbol`
    (e.g. as an unused function-pointer value) for either toolchain to
    actually emit an import-table entry for it at all -- unlike ELF,
    where a bare `--no-as-needed` is enough with zero symbols used.

    MSVC's link.exe has no way to link directly against a bare DLL; one
    is generated on the fly via lib.exe from a minimal .def file naming
    just the one symbol this test needs, with the .def's `LIBRARY` line
    set to `dll_path.name` so the generated import descriptor records
    that exact name.

    GNU/mingw-w64's `ld` *can* link directly against the DLL file itself
    (reading its real export table) -- but the import descriptor name it
    emits in the output comes from the DLL's own baked-in PE
    export-directory Name field, not from the path/filename given on the
    command line (confirmed for real against a downloaded frida-gadget
    release build, whose own declared name differs from its release
    asset's file name) -- so this only produces a *consistent* result
    across both toolchains if `dll_path.name` already matches that
    baked-in name.
    """
    kind, cl_path = _find_compiler()
    out = tmp_path / name

    if kind == "msvc":
        _require_msvc_bits(cl_path, bits)
        def_path = tmp_path / (Path(name).stem + "_prebuilt.def")
        lib_path = tmp_path / (Path(name).stem + "_prebuilt.lib")
        def_path.write_text(f"LIBRARY {dll_path.name}\nEXPORTS\n{exported_symbol}\n")
        lib_exe = str(Path(cl_path).with_name("lib.exe"))
        _run([lib_exe, f"/DEF:{def_path}", f"/OUT:{lib_path}", f"/MACHINE:{'X64' if bits == 64 else 'X86'}"])
        obj = tmp_path / (Path(name).stem + ".obj")
        _run([cl_path, "/nologo", str(source), f"/Fe{out}", f"/Fo{obj}", str(lib_path)])
        return out

    compiler = _gnu_compiler_for_bits(bits)
    bits_flag = "-m64" if bits == 64 else "-m32"
    _run([compiler, bits_flag, "-fno-pic", "-o", str(out), str(source), str(dll_path), "-Wl,--disable-dynamicbase"])
    return out


def build_exe_importing_prebuilt_so(
    tmp_path: Path, source: Path, name: str, so_path: Path, *, bits: int,
) -> Path:
    """ELF counterpart of build_exe_importing_prebuilt_dll: links `source`
    against the real, prebuilt `so_path` so the output's dynamic section
    carries a DT_NEEDED entry naming it, recorded under `so_path`'s own
    DT_SONAME (not its filename on disk, same caveat as the PE helper
    above's docstring) -- `-Wl,--no-as-needed` forces the entry even
    though, unlike the PE case, `source` references no symbol from it at
    all (modern distro `ld` otherwise drops an unused direct `.so` link
    input silently, confirmed for real against this exact Ubuntu
    toolchain)."""
    compiler = _gnu_compiler_for_bits(bits)
    bits_flag = "-m64" if bits == 64 else "-m32"
    out = tmp_path / name
    _run([compiler, bits_flag, "-fpie", "-pie", "-o", str(out), str(source), "-Wl,--no-as-needed", str(so_path)])
    return out
