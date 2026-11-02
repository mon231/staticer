import platform
import subprocess

import pytest

from conftest import FIXTURES, build_exe, build_shared_lib

from staticer.elf_embedder import ElfEmbedder

pytestmark = pytest.mark.skipif(platform.system() != "Linux", reason="ELF embedding is Linux-only")


# See tests/linux/test_elf_embed.py's own NOTE on `lib_dir` for why these
# tests pass `lib_dir=tmp_path`: it scopes embedding to just the fixture
# .so's built into tmp_path, leaving libc/libstdc++/libgcc_s as ordinary
# dynamic imports rather than trying to embed real system shared objects
# (that's Task 10's concern).


@pytest.mark.parametrize("bits", [32, 64])
def test_exception_crosses_embedded_boundary(tmp_path, c_compiler, bits):
    """A C++ exception thrown inside an embedded dependency's code must
    still be catchable on the host side of what used to be a dynamic-
    linking boundary -- which only works if the embedded function's
    .eh_frame/.eh_frame_hdr unwind info is still reachable by the
    unwinder after embedding (ElfEmbedder.embed() must merge it into the
    host's own PT_GNU_EH_FRAME table, since the dependency no longer has
    a PT_GNU_EH_FRAME segment -- or module -- of its own once merged into
    the host image)."""
    so = build_shared_lib(tmp_path, FIXTURES / "exc_lib.cpp", "exc.so", pic=True, bits=bits, cpp=True)
    exe = build_exe(
        tmp_path, FIXTURES / "exc_main.cpp", "excmain", [so], pic=True, bits=bits, cpp=True
    )
    out = tmp_path / "excmain_static"

    ElfEmbedder(exe, out, exclude=set(), lib_dir=tmp_path).embed()
    out.chmod(0o755)

    result = subprocess.run([str(out)], capture_output=True)
    assert result.returncode == 7, (
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )


@pytest.mark.parametrize("bits", [32, 64])
def test_dependency_initializer_runs_before_dependent(tmp_path, c_compiler, bits):
    """The generated entrypoint stub must call each embedded module's
    .init_array constructors in dependencies-first order: lib_ctor_b's
    constructor sets a flag; lib_ctor_a (which depends on lib_ctor_b)
    reads it in its *own* constructor. The combined exit code only comes
    out 42 if lib_ctor_b's constructor already ran by the time
    lib_ctor_a's constructor runs."""
    libb = build_shared_lib(tmp_path, FIXTURES / "lib_ctor_b.c", "libctorb.so", pic=True, bits=bits)
    liba = build_shared_lib(
        tmp_path, FIXTURES / "lib_ctor_a.c", "libctora.so", pic=True, bits=bits,
        # --no-as-needed: liba.c makes no actual symbol reference to
        # libctorb.so (see lib_ctor_b.c's comment for why), so without
        # this flag the linker would drop the DT_NEEDED entry entirely
        # as "unused" -- and with it gone, ElfEmbedder's dependency
        # graph would never see the A-depends-on-B edge this test
        # exists to exercise.
        extra_flags=["-Wl,--no-as-needed", str(libb)],
    )
    exe = build_exe(
        tmp_path, FIXTURES / "main_ctor_order.c", "main_ctor", [liba, libb], pic=True, bits=bits
    )
    out = tmp_path / "main_ctor_static"

    ElfEmbedder(exe, out, exclude=set(), lib_dir=tmp_path).embed()
    out.chmod(0o755)

    result = subprocess.run([str(out)], capture_output=True)
    assert result.returncode == 42, (
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
