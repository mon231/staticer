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


@pytest.mark.parametrize("bits", [32, 64])
def test_constructor_sse_alignment_survives_stub(tmp_path, c_compiler, bits):
    """Regression test for the generated entrypoint stub's own stack-
    realignment code (staticer/stubs/linux/elf_stub.py's docstring has
    the full history): a wrong version of that code can leave %rsp/%esp
    mis-aligned by exactly one pointer width going into each init call,
    with *no* symptom unless the called constructor itself executes an
    alignment-sensitive instruction -- lib_ctor_a.c/lib_ctor_b.c's own
    rdtsc-plus-integer-store constructors don't, so they can't catch
    this. ctor_sse_align.c's constructor does: a local, 16-byte-aligned
    stack array, loaded/stored via `_mm_load_ps`/`_mm_store_ps`, which
    GCC compiles to the *aligned* `movaps` (trusting, by default, that
    the incoming stack is already 16-byte aligned -- exactly the
    assumption a misaligned stub call would violate) rather than the
    alignment-tolerant `movups`. `movaps` raises #GP (-> SIGSEGV) on a
    misaligned address; this constructor completing normally, and the
    host reading back the correct computed value afterwards, is only
    possible if the stub handed it a correctly call-site-aligned stack.

    `-mincoming-stack-boundary=4 -msse2` makes gcc actually emit
    `movaps` for the i386 build too (its default assumption is more
    conservative there, degrading to alignment-tolerant moves
    otherwise) -- harmless on x86-64, where that's already the default.
    """
    so = build_shared_lib(
        tmp_path, FIXTURES / "ctor_sse_align.c", "sse.so", pic=True, bits=bits,
        extra_flags=["-msse2", "-mincoming-stack-boundary=4"],
    )
    exe = build_exe(tmp_path, FIXTURES / "main_sse_align.c", "main_sse", [so], pic=True, bits=bits)
    out = tmp_path / "main_sse_static"

    ElfEmbedder(exe, out, exclude=set(), lib_dir=tmp_path).embed()
    out.chmod(0o755)

    result = subprocess.run([str(out)], capture_output=True)
    assert result.returncode == 42, (
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
