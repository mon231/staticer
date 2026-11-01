"""Shared fixture-building helpers for Windows (PE) and Linux (ELF) embed
tests: locate a C compiler and compile the small synthetic fixtures in
``tests/fixtures`` into shared libs / executables with the requested
bitness and PIC-ness.
"""

import shutil
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

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


@pytest.fixture(scope="session")
def c_compiler():
    found = _find_compiler()
    if found is None:
        pytest.skip("no C compiler (cl.exe/gcc/clang) found on PATH")
    return found


def _gnu_compiler_for_bits(bits: int) -> str:
    """A gcc/clang binary that actually targets the requested bitness.

    A plain 'gcc' on PATH is frequently a single-target MinGW build with no
    -m32/-m64 multilib support, so prefer the architecture-prefixed binary
    name when one is on PATH, and fall back to the generic name plus
    -m32/-m64 (works for toolchains that do support multilib, e.g. many
    Linux distro gccs targeting x86).
    """
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


def build_shared_lib(tmp_path: Path, source: Path, name: str, *, pic: bool, bits: int) -> Path:
    kind, cl_path = _find_compiler()
    out = tmp_path / name

    if kind == "msvc":
        obj = tmp_path / (Path(name).stem + ".obj")
        _run([cl_path, "/nologo", "/LD", str(source), f"/Fe{out}", f"/Fo{obj}"])
        return out

    compiler = _gnu_compiler_for_bits(bits)
    bits_flag = "-m64" if bits == 64 else "-m32"
    pic_flag = "-fPIC" if pic else "-fno-pic"
    cmd = [
        compiler, "-shared", bits_flag, pic_flag,
        "-Wl,--export-all-symbols",
        "-o", str(out), str(source),
    ]
    if not pic:
        cmd.append("-Wl,--disable-dynamicbase")
    _run(cmd)
    return out


def build_exe(tmp_path: Path, source: Path, name: str, libs: List[Path], *, pic: bool, bits: int) -> Path:
    kind, cl_path = _find_compiler()
    out = tmp_path / name

    if kind == "msvc":
        obj = tmp_path / (Path(name).stem + ".obj")
        _run([cl_path, "/nologo", str(source), f"/Fe{out}", f"/Fo{obj}"] + [str(lib) for lib in libs])
        return out

    compiler = _gnu_compiler_for_bits(bits)
    bits_flag = "-m64" if bits == 64 else "-m32"
    pic_flag = "-fPIC" if pic else "-fno-pic"
    cmd = [compiler, bits_flag, pic_flag, "-o", str(out), str(source)] + [str(lib) for lib in libs]
    if not pic:
        cmd.append("-Wl,--disable-dynamicbase")
    _run(cmd)
    return out
