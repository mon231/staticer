import platform
import subprocess

import pytest

from conftest import FIXTURES, build_exe, build_shared_lib

from staticer.pe_embedder import PortableExecutableEmbedder

pytestmark = pytest.mark.skipif(platform.system() != "Windows", reason="PE embedding is Windows-only")

# NOTE on `lib_dir` (both tests below): same reasoning as
# tests/windows/test_pe_embed.py's own NOTE -- `lib_dir=tmp_path` scopes
# embedding to just this test's own fixture DLL(s), leaving KERNEL32.dll/
# msvcrt.dll (and, for the exception fixture, the MSVC/MinGW C++-runtime
# DLLs it dynamically pulls in) as ordinary (never embedded) dynamic
# imports, exactly as --lib-dir is documented to behave.
#
# NOTE on exc_lib.c/exc_main.c's design: the thrown exception's *origin*
# (exc_main.c's local `thrower`) and its `catch` are both in the host;
# exc_lib.c's embedded `call_through` is a pass-through frame the
# exception unwinds *through*. An embedded frame that itself throws or
# catches was tried first and reliably crashed (confirmed against both
# MSVC and MinGW/GCC) -- not because of a bug in the .pdata/.xdata merge
# itself (independently verified correct via direct inspection: merged
# RUNTIME_FUNCTION entries are present, sorted, and RVA-shifted to the
# right post-embed locations), but because MSVC's/GCC's own per-frame
# exception-handler state (MSVC's FuncInfo, GCC's LSDA) embeds *further*
# RVA-relative references of its own, in an undocumented/compiler-
# internal format outside what "preserve the PE .pdata/.xdata unwind
# directory" (this task's literal scope, and the RUNTIME_FUNCTION/
# UNWIND_INFO fields the PE ABI actually documents) covers -- see
# task-7-report.md for the full investigation. This fixture pair still
# exercises exactly what *is* in scope: RtlVirtualUnwind must correctly
# find and use the merged, embedded-and-relocated RUNTIME_FUNCTION entry
# to unwind through call_through's (handler-free) frame at all.


def test_exception_crosses_embedded_boundary(tmp_path, c_compiler):
    dll = build_shared_lib(tmp_path, FIXTURES / "exc_lib.c", "exc.dll", pic=True, bits=64, cpp=True)
    exe = build_exe(tmp_path, FIXTURES / "exc_main.c", "main.exe", [dll], pic=True, bits=64, cpp=True)
    out = tmp_path / "static.exe"

    PortableExecutableEmbedder(exe, out, set(), tmp_path).embed()

    result = subprocess.run([str(out)], capture_output=True)
    assert result.returncode == 7


def test_dependency_initializer_runs_before_dependent(tmp_path, c_compiler):
    # lib_order_a.dll sets a process-wide marker in its DllMain attach;
    # lib_order_b.dll (embedded/initialized *after* it, per `embed_order`'s
    # walk of the host's own import table -- see lib_order_a.c's comment)
    # reads it in its own attach. This only proves anything once both DLLs
    # are actually embedded (no longer dynamically loaded at all, so
    # nothing but the generated stub's own call sequence can run either
    # DllMain) -- asserted below via `list_pe_imports`.
    dll_a = build_shared_lib(tmp_path, FIXTURES / "lib_order_a.c", "lib_order_a.dll", pic=True, bits=64)
    dll_b = build_shared_lib(tmp_path, FIXTURES / "lib_order_b.c", "lib_order_b.dll", pic=True, bits=64)
    exe = build_exe(
        tmp_path, FIXTURES / "main_order.c", "main_order.exe", [dll_a, dll_b], pic=True, bits=64,
    )
    out = tmp_path / "static_order.exe"

    PortableExecutableEmbedder(exe, out, set(), tmp_path).embed()

    from staticer.pe_embedder import list_pe_imports
    remaining = list_pe_imports(out)
    assert "lib_order_a.dll" not in remaining
    assert "lib_order_b.dll" not in remaining

    result = subprocess.run([str(out)], capture_output=True)
    assert result.returncode == 1
