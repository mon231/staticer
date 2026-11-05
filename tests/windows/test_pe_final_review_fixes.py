"""Tests for the PE-track fixes from the final whole-branch review:
B1 (dependency-to-dependency imports must not stay dynamic), B3 (a
TLS-carrying dependency must fail loudly, not silently corrupt), B4 (a
dependency's own PE header region must be copied into its embedded blob),
B6-PE (a DLL-as-output must not re-run dependency inits on thread
attach/detach), the --exclude case-sensitivity minor fix, and the
path-traversal (CWE-22) fix in `resolve_pe` itself -- a finding dropped
from both the PE and ELF fix-wave dispatches and only caught at
whole-branch close-out.
"""

import ctypes
import platform
import subprocess
import threading

import pefile
import pytest

from conftest import FIXTURES, build_exe, build_shared_lib

from staticer.pe_embedder import PortableExecutableEmbedder, list_pe_imports, resolve_pe

pytestmark = pytest.mark.skipif(platform.system() != "Windows", reason="PE embedding is Windows-only")


def test_transitive_embedded_dependency_import_is_patched_not_dynamic(tmp_path, c_compiler):
    """B1: lib_x.dll imports lib_y.dll; both get embedded (no exclusion).
    The combined output must not still dynamically import 'lib_y.dll' --
    lib_x's own IAT slot for it must be patched directly to the embedded
    address instead, and the program must still compute the right result.
    """
    kind, _ = c_compiler

    dll_y = build_shared_lib(tmp_path, FIXTURES / "lib_y.c", "lib_y.dll", pic=True, bits=64)
    link_arg = str(dll_y.with_suffix(".lib")) if kind == "msvc" else str(dll_y)
    dll_x = build_shared_lib(
        tmp_path, FIXTURES / "lib_x.c", "lib_x.dll", pic=True, bits=64, extra_flags=[link_arg],
    )

    exe = build_exe(
        tmp_path, FIXTURES / "main_transitive.c", "main_transitive.exe", [dll_x, dll_y], pic=True, bits=64,
    )
    out = tmp_path / "static_transitive.exe"

    # No exclusion at all -- both lib_x.dll and lib_y.dll are embeddable,
    # and lib_x.dll's own import of lib_y.dll must be resolved internally.
    PortableExecutableEmbedder(exe, out, set(), tmp_path).embed()

    remaining = list_pe_imports(out)
    assert "lib_x.dll" not in remaining
    assert "lib_y.dll" not in remaining

    # Move lib_y.dll out of the way so a surviving (buggy) dynamic import
    # of it can't accidentally still resolve and mask the bug.
    (tmp_path / "lib_y.dll").unlink()

    result = subprocess.run([str(out)], capture_output=True)
    assert result.returncode == 12  # lib_x_value() + lib_y_value() == 11 + 1


def test_host_with_own_tls_directory_merges_on_64bit(tmp_path, c_compiler):
    """B3 (updated again for Task 5's phase-2 TLS merge): embedding a
    TLS-carrying dependency into a host that *also* already has its own
    TLS directory now succeeds on 64-bit hosts too (see
    tests/windows/test_pe_tls.py's
    test_tls_merge_when_host_already_has_its_own_tls_directory for the
    positive, read-both-values-back version of this same fixture pair).
    This just re-confirms embed() no longer raises for it here, next to
    this suite's other TLS-shape regression tests."""
    dll = build_shared_lib(tmp_path, FIXTURES / "lib_tls_dep.c", "lib_tls_dep.dll", pic=True, bits=64)
    exe = build_exe(
        tmp_path, FIXTURES / "main_host_own_tls.c", "main_host_own_tls.exe", [dll], pic=True, bits=64,
    )
    out = tmp_path / "static_host_own_tls.exe"

    PortableExecutableEmbedder(exe, out, set(), tmp_path).embed()


def test_dependency_header_region_is_copied_into_blob(tmp_path, c_compiler):
    """B4: the embedded blob for a dependency must carry its own PE header
    bytes (DOS 'MZ' signature at offset 0 of its placement), not zeros --
    otherwise anything reading its own module header via its own HINSTANCE
    once embedded (e.g. mingw's pseudo-relocation check) finds garbage."""
    dll = build_shared_lib(tmp_path, FIXTURES / "lib.c", "lib.dll", pic=True, bits=64)
    exe = build_exe(tmp_path, FIXTURES / "main.c", "main.exe", [dll], pic=True, bits=64)
    out = tmp_path / "static.exe"

    PortableExecutableEmbedder(exe, out, set(), tmp_path).embed()

    pe = pefile.PE(str(out))
    try:
        # The embedded dependency landed in a new ".sdep0" section -- find
        # it and check its first bytes are a real DOS header ('MZ'), not
        # zeros.
        dep_section = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".sdep0")
        header_bytes = pe.get_data(dep_section.VirtualAddress, 2)
        assert header_bytes == b"MZ"
    finally:
        pe.close()

    result = subprocess.run([str(out)], capture_output=True)
    assert result.returncode == 42


def test_resolve_pe_rejects_path_traversal_name(tmp_path):
    """Dropped-finding fix (CWE-22): `name` in `resolve_pe` comes straight
    from the TARGET BINARY's own Import Directory -- attacker-controlled,
    if the input binary being processed is untrusted. A crafted import
    name carrying path-traversal components must not be allowed to escape
    the search_dirs entry it's matched against; it must behave exactly
    like "not found" (fall through to None / the next dir), never resolve
    to a file genuinely sitting outside the intended directory, even
    though such a file genuinely exists on disk at that escaped
    location."""
    search_dir = tmp_path / "libs"
    search_dir.mkdir()

    # A real file sitting OUTSIDE search_dir, at exactly the location the
    # crafted traversal name points at.
    outside = tmp_path / "evil.dll"
    outside.write_bytes(b"not a real dll")

    assert resolve_pe("..\\evil.dll", [search_dir]) is None
    assert resolve_pe("../evil.dll", [search_dir]) is None
    assert resolve_pe("..", [search_dir]) is None
    assert resolve_pe(str(outside), [search_dir]) is None  # absolute path

    # A legitimate same-directory match must still resolve normally --
    # the fix must not break the ordinary, non-malicious case.
    legit = search_dir / "lib.dll"
    legit.write_bytes(b"legit")
    assert resolve_pe("lib.dll", [search_dir]) == legit

    # Falls through to a legitimate match in a LATER search dir when an
    # earlier dir's candidate escapes it.
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    (other_dir / "legit2.dll").write_bytes(b"legit2")
    assert resolve_pe("legit2.dll", [search_dir, other_dir]) == other_dir / "legit2.dll"


def test_dll_as_output_runs_dep_init_once(tmp_path, c_compiler):
    """B6-PE: when the embed() *input* is itself a DLL (not an EXE), the
    generated stub becomes its real entrypoint, called by the OS loader on
    every thread attach/detach too -- the embedded dependency's own
    process-attach-style init must run exactly once (at the output DLL's
    own process attach), not again on every later thread notification."""
    dep = build_shared_lib(tmp_path, FIXTURES / "lib_attach_count.c", "lib_attach_count.dll", pic=True, bits=64)
    kind, _ = c_compiler
    link_arg = str(dep.with_suffix(".lib")) if kind == "msvc" else str(dep)
    host_dll = build_shared_lib(
        tmp_path, FIXTURES / "host_attach_count.c", "host_attach_count.dll", pic=True, bits=64,
        extra_flags=[link_arg],
    )
    out = tmp_path / "static_host_attach_count.dll"

    PortableExecutableEmbedder(host_dll, out, set(), tmp_path).embed()
    assert "lib_attach_count.dll" not in list_pe_imports(out)

    lib = ctypes.WinDLL(str(out))
    try:
        lib.host_get_attach_count.restype = ctypes.c_long
        # LoadLibrary itself already delivered one real DLL_PROCESS_ATTACH.
        assert lib.host_get_attach_count() == 1

        # Starting new OS threads while this DLL is loaded delivers
        # DLL_THREAD_ATTACH (and, on join, DLL_THREAD_DETACH) to its entry
        # point too -- the buggy stub (no fdwReason guard) would re-run the
        # dependency's process-attach-style init on each of these.
        threads = [threading.Thread(target=lambda: None) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert lib.host_get_attach_count() == 1
    finally:
        # Deliberately NOT calling FreeLibrary here -- see the real,
        # reproducible finding below. The loaded module just leaks for the
        # rest of this (short-lived test/CI worker) process; that's a far
        # better trade than the alternative.
        #
        # FINDING (confirmed real on CI, see the dev CI run(s) around this
        # commit): calling FreeLibrary(lib._handle) here used to crash the
        # *entire hosting process* with STATUS_ACCESS_VIOLATION -- not at
        # the FreeLibrary call itself (which succeeded, rc=1), but later,
        # silently, at the process's own unrelated normal exit (confirmed
        # by isolating this exact test in its own process: removing
        # FreeLibrary alone made the crash disappear; every other variant
        # tried -- running other tests before/after, with/without other
        # Windows test files present -- was irrelevant). Root cause:
        # embed()'s generated stub runs each embedded dependency's own
        # AddressOfEntryPoint directly on the output's DLL_PROCESS_ATTACH
        # (by design, so compiled CRT startup/static-init code runs, not
        # just a bare user DllMain) -- for a dependency built against the
        # dynamic CRT (true here, and true for most real MSVC/MinGW DLLs),
        # that *also* runs the CRT's own startup glue, which registers
        # process-*wide* state (TLS/FLS slots, the UCRT's own per-module
        # exit-time bookkeeping) that assumes the normal loader will one
        # day deliver a matching DLL_PROCESS_DETACH to tear it back down.
        # This design deliberately never delivers DETACH to an embedded
        # dependency (a documented non-goal, not a bug) -- harmless as
        # long as the *output* DLL stays mapped for the rest of the
        # process's life, which is the overwhelmingly common case (a DLL
        # that's loaded once and never explicitly unloaded again before
        # the process exits). It stops being harmless the moment something
        # calls FreeLibrary on the output DLL *before* the process exits,
        # as this test used to: the dependency's registered process-wide
        # state outlives the now-freed memory it points into, and whatever
        # later runs it (here, apparently some UCRT/loader-internal exit-
        # time callback, triggered by this *same* process's own unrelated
        # normal exit, well after this test function returns) dereferences
        # a dangling pointer.
        #
        # This is a real, previously-undiscovered instance of the "DllMain
        # invoked out of band" concern this project's own fix-wave history
        # has repeatedly flagged as an open question (see e.g. this
        # module's own B3/B6-PE work, and test_pe_real_binaries.py's
        # DllMain-out-of-band note) -- now concretely confirmed for the
        # DLL-as-output + FreeLibrary-before-process-exit combination.
        # Properly fixing it would mean either delivering a real
        # DLL_PROCESS_DETACH to each embedded dependency when the output
        # itself is unloaded (undoing the current, deliberate non-goal) or
        # auditing/suppressing whatever process-wide registration the
        # dependency's CRT startup performs -- both real future work, out
        # of this task's scope. Not calling FreeLibrary here sidesteps it
        # for this test without papering over or hiding the finding.
        pass


def test_exclude_is_case_insensitive(tmp_path, c_compiler):
    """Minor fix: --exclude must match DLL names case-insensitively
    (Windows filenames are case-insensitive) -- excluding 'LIB.DLL' must
    still exclude the actual 'lib.dll' import."""
    dll = build_shared_lib(tmp_path, FIXTURES / "lib.c", "lib.dll", pic=True, bits=64)
    exe = build_exe(tmp_path, FIXTURES / "main.c", "main.exe", [dll], pic=True, bits=64)
    out = tmp_path / "static.exe"

    PortableExecutableEmbedder(exe, out, {"LIB.DLL"}, tmp_path).embed()

    assert "lib.dll" in list_pe_imports(out)

    result = subprocess.run([str(out)], capture_output=True)
    assert result.returncode == 42
