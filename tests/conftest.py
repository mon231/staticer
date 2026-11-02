"""Shared fixture-building helpers for Windows (PE) and Linux (ELF) embed
tests: locate a C compiler and compile the small synthetic fixtures in
``tests/fixtures`` into shared libs / executables with the requested
bitness and PIC-ness.
"""

import functools
import platform
import re
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

import pefile
import pytest

FIXTURES = Path(__file__).parent / "fixtures"


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


def build_shared_lib(
    tmp_path: Path, source: Path, name: str, *, pic: bool, bits: int,
    extra_flags: Optional[List[str]] = None, strip_relocs: bool = False,
) -> Path:
    kind, cl_path = _find_compiler()
    out = tmp_path / name

    if kind == "msvc":
        _require_msvc_bits(cl_path, bits)
        obj = tmp_path / (Path(name).stem + ".obj")
        _run([cl_path, "/nologo", "/LD", str(source), f"/Fe{out}", f"/Fo{obj}"] + list(extra_flags or []))
        if strip_relocs:
            _strip_pe_relocations(out)
        return out

    compiler = _gnu_compiler_for_bits(bits)
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


def build_exe(
    tmp_path: Path, source: Path, name: str, libs: List[Path], *, pic: bool, bits: int,
    extra_flags: Optional[List[str]] = None,
) -> Path:
    kind, cl_path = _find_compiler()
    out = tmp_path / name

    if kind == "msvc":
        _require_msvc_bits(cl_path, bits)
        obj = tmp_path / (Path(name).stem + ".obj")
        _run(
            [cl_path, "/nologo", str(source), f"/Fe{out}", f"/Fo{obj}"]
            + [str(lib) for lib in libs] + list(extra_flags or [])
        )
        return out

    compiler = _gnu_compiler_for_bits(bits)
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
