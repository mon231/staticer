"""PE TLS-directory merge (Task 2, phase 1): adopting a dependency's own
IMAGE_DIRECTORY_ENTRY_TLS as the host's, when the host has none of its
own.

Step 1 (synthetic fixture) proves the mechanism actually works end to
end -- a __declspec(thread)/__thread counter, embedded into a TLS-less
host, increments and reads back correctly across real calls after a real
embed()+run, not just "doesn't crash". Step 2 (the real, genuine
frida-gadget DLL, fetched the same way every other frida-gadget test in
this project does -- never synthesized) proves the callback-array
handling this merge needs actually works against frida-gadget's real,
more complex shape (a non-null AddressOfCallBacks with 3 real callback
entries -- see .superpowers/findings/2026-11-04-frida-gadget-tls-
shape.md), not just the synthetic callback-free case above. That second
test only asserts embed() no longer raises -- running the embedded
gadget's config-driven script flow end to end is Task 4, after both this
task and Task 3 (ELF) land.
"""

import ctypes
import platform
import shutil
import subprocess

import pytest

from conftest import (
    FIXTURES,
    FRIDA_GADGET_MODULE_NAME,
    FridaGadgetUnavailable,
    build_exe,
    build_exe_importing_prebuilt_dll,
    build_shared_lib,
    fetch_frida_gadget,
)

from staticer.pe_embedder import PortableExecutableEmbedder, list_pe_imports

pytestmark = [
    pytest.mark.skipif(platform.system() != "Windows", reason="PE embedding is Windows-only"),
    pytest.mark.slow,
]


def test_tls_dependency_merges_into_tls_less_host(tmp_path, c_compiler):
    """The real, positive case this task implements: a dependency DLL
    carrying its own TLS directory (one __declspec(thread)/__thread
    counter, AddressOfCallBacks == 0 -- the simplest sub-case) is adopted
    as a TLS-less host's own TLS directory, rather than raising. The
    embedded counter must actually increment and read back correctly
    (proves the raw-data/index mechanism works), not just avoid
    crashing."""
    dll = build_shared_lib(tmp_path, FIXTURES / "lib_tls_simple.c", "lib_tls_simple.dll", pic=True, bits=64)
    exe = build_exe(tmp_path, FIXTURES / "main_tls_simple.c", "main_tls_simple.exe", [dll], pic=True, bits=64)
    out = tmp_path / "static_tls_simple.exe"

    PortableExecutableEmbedder(exe, out, set(), tmp_path).embed()
    assert "lib_tls_simple.dll" not in list_pe_imports(out)

    result = subprocess.run([str(out)], capture_output=True)
    assert result.returncode == 3


def test_tls_dependency_merge_survives_multiple_threads(tmp_path, c_compiler):
    """A correct TLS merge must give each OS thread its own slot (that's
    the entire point of thread-local storage) -- not alias every thread
    onto one shared counter. Embeds the same TLS-bearing dependency into
    a host DLL and calls its bump function from several real OS threads,
    each starting its own count from 0."""
    dll = build_shared_lib(tmp_path, FIXTURES / "lib_tls_simple.c", "lib_tls_simple.dll", pic=True, bits=64)
    kind, _ = c_compiler
    link_arg = str(dll.with_suffix(".lib")) if kind == "msvc" else str(dll)
    host_dll = build_shared_lib(
        tmp_path, FIXTURES / "host_tls_wrapper.c", "host_tls_wrapper.dll", pic=True, bits=64,
        extra_flags=[link_arg],
    )
    out = tmp_path / "static_host_tls_wrapper.dll"

    PortableExecutableEmbedder(host_dll, out, set(), tmp_path).embed()

    lib = ctypes.WinDLL(str(out))
    lib.host_bump.restype = ctypes.c_int

    results = []

    def run():
        results.append(lib.host_bump())
        results.append(lib.host_bump())

    import threading

    threads = [threading.Thread(target=run) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Each thread's own two calls must read back 1 then 2 -- never
    # anything higher, which would mean threads are sharing one slot.
    assert sorted(results) == [1, 1, 1, 2, 2, 2]


def test_embedding_real_frida_gadget_no_longer_raises_on_its_tls_directory(tmp_path, c_compiler):
    """frida-gadget's real TLS directory has a non-null AddressOfCallBacks
    pointing at a 3-entry callback array (confirmed against the real,
    genuine downloaded DLL -- see .superpowers/findings/2026-11-04-frida-
    gadget-tls-shape.md). This is the case this task's merge must handle
    correctly, not just the synthetic callback-free fixture above --
    embed() must no longer raise ValueError naming it."""
    try:
        gadget_dll = fetch_frida_gadget("windows")
    except FridaGadgetUnavailable as exc:
        pytest.skip(str(exc))

    lib_dir = tmp_path / "gadget_libdir"
    lib_dir.mkdir()
    gadget_copy = lib_dir / FRIDA_GADGET_MODULE_NAME["windows"]
    shutil.copy(gadget_dll, gadget_copy)

    exe = build_exe_importing_prebuilt_dll(
        tmp_path, FIXTURES / "looper_gadget_win.c", "looper.exe",
        gadget_copy, "frida_gadget_load", bits=64,
    )
    assert FRIDA_GADGET_MODULE_NAME["windows"] in list_pe_imports(exe)

    out = tmp_path / "looper_frida.exe"
    # Must not raise -- this is the whole point of this test. If it does,
    # pytest reports the failure with the real traceback/message.
    PortableExecutableEmbedder(exe, out, exclude=set(), lib_dir=lib_dir).embed()
    assert FRIDA_GADGET_MODULE_NAME["windows"] not in list_pe_imports(out)
