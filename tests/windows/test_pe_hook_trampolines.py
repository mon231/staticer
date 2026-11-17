"""Direct-execution regression tests for the LoadLibraryW/LoadLibraryA/
GetProcAddress runtime-hook machine code in
``staticer/stubs/windows/pe_stub.py`` (``build_windows_loadlibrary_
trampoline``, ``build_windows_getprocaddress_trampoline``,
``build_windows_hook_install``).

Unlike ``test_pe_stub_keystone.py`` (byte-for-byte parity against a
hand-encoded reference) or the full-embed tests in ``test_pe_embed.py``
(exercising the mechanism end-to-end through a real compiled binary),
these tests validate the generated code's actual *runtime behavior*
directly: the assembled bytes are copied into real executable memory
(``VirtualAlloc`` with ``PAGE_EXECUTE_READWRITE``) and invoked through
``ctypes``, with hand-built match/module tables and fake "real API"
stand-ins. This is deliberately the most direct way to pin down x64
calling-convention correctness (the task's own highest-risk area) without
needing a full PE embed + process launch per case.
"""

import ctypes
import platform
import struct
from ctypes import wintypes

import pytest

from staticer.stubs.windows.pe_stub import (
    build_windows_getprocaddress_trampoline,
    build_windows_hook_install,
    build_windows_loadlibrary_trampoline,
)

pytestmark = pytest.mark.skipif(platform.system() != "Windows", reason="x64 machine code is Windows-only")

_MEM_COMMIT_RESERVE = 0x1000 | 0x2000
_PAGE_EXECUTE_READWRITE = 0x40
_PAGE_READONLY = 0x02
_ORD_SENTINEL = 0xFFFFFFFFFFFFFFFF


def _real_virtualprotect_slot_va() -> int:
    """An 8-byte cell holding the real, genuine `kernel32!VirtualProtect`
    address -- `build_windows_hook_install` calls *through* a slot like
    this (`call qword ptr [slot]`), never through a bare function address
    directly, mirroring every other real-API call-through slot elsewhere
    in this module (`loadlibrarya_iat_slot_va`/`getprocaddress_iat_slot_
    va` for the delay-import lazy thunk)."""
    kernel32 = ctypes.windll.kernel32
    real_addr = ctypes.cast(kernel32.VirtualProtect, ctypes.c_void_p).value
    cell = (ctypes.c_uint64 * 1)(real_addr)
    # Keep the ctypes buffer alive for the module's lifetime (a leak, but
    # this is test-only scratch memory) -- its own address is what's
    # actually used as the "slot".
    _KEEPALIVE.append(cell)
    return ctypes.addressof(cell)


_KEEPALIVE: list = []


class _Scratch:
    """A single large RWX region, hand-laid-out like a tiny bump
    allocator -- mirrors how `pe_embedder.py` lays every hook-related
    structure (strings, tables, trampolines, saved-original cells) into
    one contiguous section, just without any of the PE-specific
    plumbing."""

    def __init__(self, size: int = 0x20000):
        kernel32 = ctypes.windll.kernel32
        kernel32.VirtualAlloc.restype = ctypes.c_void_p
        kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
        addr = kernel32.VirtualAlloc(None, size, _MEM_COMMIT_RESERVE, _PAGE_EXECUTE_READWRITE)
        assert addr, "VirtualAlloc failed"
        self._base = addr
        self._cursor = addr

    def alloc(self, n: int, align: int = 8) -> int:
        if self._cursor % align:
            self._cursor += align - (self._cursor % align)
        addr = self._cursor
        self._cursor += n
        return addr

    def write(self, addr: int, data: bytes) -> None:
        ctypes.memmove(addr, data, len(data))

    def write_u64(self, addr: int, value: int) -> None:
        self.write(addr, struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF))

    def read_u64(self, addr: int) -> int:
        return struct.unpack("<Q", ctypes.string_at(addr, 8))[0]

    def write_str(self, s: str, wide: bool) -> int:
        data = s.encode("utf-16-le") + b"\x00\x00" if wide else s.encode("ascii") + b"\x00"
        addr = self.alloc(len(data), align=2)
        self.write(addr, data)
        return addr

    def write_sentinel_fn(self, return_value: int) -> int:
        """A tiny `mov rax, return_value; ret` function standing in for
        a real API -- lets the fallthrough path be asserted on by its
        own distinct return value rather than merely "didn't crash"."""
        import keystone

        ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
        code, _count = ks.asm(f"mov rax, {return_value}\nret")
        addr = self.alloc(len(code))
        self.write(addr, bytes(code))
        return addr

    def place(self, code: bytes) -> int:
        addr = self.alloc(len(code))
        self.write(addr, code)
        return addr

    def alloc_readonly_page(self, values: list) -> int:
        """A dedicated, genuinely `PAGE_READONLY` page pre-filled with
        `values` (a list of u64s, one per 8-byte slot) -- for proving the
        hook-install code's `VirtualProtect`-wrap actually matters (a
        plain write here, without it, reproduces the real
        `STATUS_ACCESS_VIOLATION` this mechanism was built to avoid; see
        `build_windows_hook_install`'s own docstring)."""
        kernel32 = ctypes.windll.kernel32
        kernel32.VirtualProtect.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
        ]
        kernel32.VirtualProtect.restype = wintypes.BOOL
        page = kernel32.VirtualAlloc(None, 0x1000, _MEM_COMMIT_RESERVE, _PAGE_EXECUTE_READWRITE)
        assert page
        for i, v in enumerate(values):
            self.write_u64(page + i * 8, v)
        old = wintypes.DWORD(0)
        ok = kernel32.VirtualProtect(ctypes.c_void_p(page), ctypes.c_size_t(0x1000), _PAGE_READONLY, ctypes.byref(old))
        assert ok
        return page


@pytest.fixture
def scratch():
    return _Scratch()


def test_loadlibraryw_trampoline_matches_case_insensitively(scratch):
    fake_base = 0x7FFF00000000
    real_fn = scratch.write_sentinel_fn(0xDEAD0001)
    saved = scratch.alloc(8)
    scratch.write_u64(saved, 0)

    name_va = scratch.write_str("foo.dll", wide=True)
    table = scratch.alloc(32)
    scratch.write(table, name_va.to_bytes(8, "little") + fake_base.to_bytes(8, "little") + b"\x00" * 16)

    code, offsets = build_windows_loadlibrary_trampoline(is_wide=True, match_table_va=table, saved_original_va=saved)
    assert len(offsets) == 2
    tramp = scratch.place(code)

    # Install: saved cell holds the real function's own address (what a
    # genuine IAT slot would have held), matching `build_windows_hook_
    # install`'s own contract -- the trampoline treats it as a function
    # pointer to tail-jump to, not a value to return directly.
    scratch.write_u64(saved, real_fn)

    fn = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_wchar_p)(tramp)
    assert fn("FOO.DLL") == fake_base
    assert fn("fOo.DlL") == fake_base
    assert fn("foo.dll") == fake_base
    # No match -> falls through to the real (saved) function, called,
    # not just returned as a value.
    assert fn("bar.dll") == 0xDEAD0001


def test_loadlibrarya_trampoline_matches_case_insensitively(scratch):
    fake_base = 0x7FFF00001000
    real_fn = scratch.write_sentinel_fn(0xDEAD0002)
    saved = scratch.alloc(8)
    scratch.write_u64(saved, real_fn)

    name_va = scratch.write_str("foo.dll", wide=False)
    table = scratch.alloc(32)
    scratch.write(table, name_va.to_bytes(8, "little") + fake_base.to_bytes(8, "little") + b"\x00" * 16)

    code, offsets = build_windows_loadlibrary_trampoline(is_wide=False, match_table_va=table, saved_original_va=saved)
    assert len(offsets) == 2
    tramp = scratch.place(code)

    fn = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_char_p)(tramp)
    assert fn(b"Foo.DLL") == fake_base
    assert fn(b"bar.dll") == 0xDEAD0002


def test_loadlibrary_trampoline_walks_past_non_matching_entries(scratch):
    """A match table with several entries: confirms the per-entry
    advance (`add r11, 16` / `jmp try_entry`) actually walks the whole
    table rather than only ever checking the first entry."""
    fake_base_a = 0x7FFF00002000
    fake_base_c = 0x7FFF00004000
    real_fn = scratch.write_sentinel_fn(0xDEAD0003)
    saved = scratch.alloc(8)
    scratch.write_u64(saved, real_fn)

    name_a = scratch.write_str("aaa.dll", wide=True)
    name_b = scratch.write_str("bbb.dll", wide=True)
    name_c = scratch.write_str("ccc.dll", wide=True)
    table = scratch.alloc(16 * 4)
    scratch.write(
        table,
        name_a.to_bytes(8, "little") + fake_base_a.to_bytes(8, "little")
        + name_b.to_bytes(8, "little") + (0x7FFF00003000).to_bytes(8, "little")
        + name_c.to_bytes(8, "little") + fake_base_c.to_bytes(8, "little")
        + b"\x00" * 16,
    )

    code, _offsets = build_windows_loadlibrary_trampoline(is_wide=True, match_table_va=table, saved_original_va=saved)
    tramp = scratch.place(code)
    fn = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_wchar_p)(tramp)
    assert fn("ccc.dll") == fake_base_c
    assert fn("aaa.dll") == fake_base_a
    assert fn("zzz.dll") == 0xDEAD0003


def test_getprocaddress_trampoline_by_name_and_ordinal(scratch):
    fake_base = 0x7FFF00005000
    real_fn = scratch.write_sentinel_fn(0xDEAD0004)
    saved = scratch.alloc(8)
    scratch.write_u64(saved, real_fn)

    export_name = scratch.write_str("DoThing", wide=False)
    resolved_va = 0x7FFF11112222

    name_table = scratch.alloc(32)
    scratch.write(name_table, export_name.to_bytes(8, "little") + resolved_va.to_bytes(8, "little") + b"\x00" * 16)

    ord_table = scratch.alloc(32)
    scratch.write(
        ord_table,
        (5).to_bytes(8, "little") + resolved_va.to_bytes(8, "little")
        + _ORD_SENTINEL.to_bytes(8, "little") + b"\x00" * 8,
    )

    module_table = scratch.alloc(48)
    scratch.write(
        module_table,
        fake_base.to_bytes(8, "little") + name_table.to_bytes(8, "little") + ord_table.to_bytes(8, "little")
        + b"\x00" * 24,
    )

    code, offsets = build_windows_getprocaddress_trampoline(module_table_va=module_table, saved_original_va=saved)
    assert len(offsets) == 2
    tramp = scratch.place(code)

    fn = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, ctypes.c_char_p)(tramp)
    assert fn(fake_base, b"DoThing") == resolved_va
    assert fn(fake_base, ctypes.cast(5, ctypes.c_char_p)) == resolved_va
    # Matched module, but no such export -> NULL, not a fallthrough call.
    assert fn(fake_base, b"NoSuchExport") == 0
    assert fn(fake_base, ctypes.cast(999, ctypes.c_char_p)) == 0
    # Module itself doesn't match any hooked base -> real fallthrough.
    assert fn(0x1234, b"DoThing") == 0xDEAD0004


def test_hook_install_saves_original_and_overwrites_every_slot(scratch):
    """`build_windows_hook_install` must: (1) read the real value from
    only the *first* listed slot per API, (2) store it into that API's
    saved-original cell, and (3) overwrite *every* listed slot --
    including more than one, the multi-importer case -- with the
    trampoline address. An API entry with an empty slot list must be
    skipped without affecting any other entry.

    Every slot lives on a genuinely `PAGE_READONLY` page (via
    `alloc_readonly_page`) -- a plain, unprotected write to any of them
    reproduces the real `STATUS_ACCESS_VIOLATION` this mechanism exists
    to avoid (confirmed against a real embed() output via `cdb`, see
    `build_windows_hook_install`'s own docstring), so this only passes if
    the generated `VirtualProtect`-wrap genuinely works."""
    real_loadlibw = scratch.write_sentinel_fn(0xAAAA0001)
    real_loadliba = scratch.write_sentinel_fn(0xAAAA0002)
    real_getproc = scratch.write_sentinel_fn(0xAAAA0003)

    saved_w = scratch.alloc(8)
    saved_a = scratch.alloc(8)
    saved_gpa = scratch.alloc(8)
    for cell in (saved_w, saved_a, saved_gpa):
        scratch.write_u64(cell, 0)

    ro_page = scratch.alloc_readonly_page([real_loadlibw, real_loadlibw, real_loadliba, real_getproc])
    slot_w1 = ro_page
    slot_w2 = ro_page + 8
    slot_a = ro_page + 16
    slot_gpa = ro_page + 24

    tramp_w = 0x7FFF0A000000
    tramp_a = 0x7FFF0B000000
    tramp_gpa = 0x7FFF0C000000

    code, offsets = build_windows_hook_install(
        [
            (saved_w, [slot_w1, slot_w2], tramp_w),
            (saved_a, [], 0x7FFF0D000000),  # empty slot list -> must be a no-op
            (saved_gpa, [slot_gpa], tramp_gpa),
        ],
        virtualprotect_iat_slot_va=_real_virtualprotect_slot_va(),
        scratch_dword_va=scratch.alloc(8),
    )
    assert offsets  # some relocation-worthy immediates were emitted
    install = scratch.place(code)

    ctypes.CFUNCTYPE(None)(install)()

    assert scratch.read_u64(saved_w) == real_loadlibw
    assert scratch.read_u64(saved_gpa) == real_getproc
    # The skipped (empty-slots) entry's own saved cell must be untouched.
    assert scratch.read_u64(saved_a) == 0

    assert scratch.read_u64(slot_w1) == tramp_w
    assert scratch.read_u64(slot_w2) == tramp_w
    assert scratch.read_u64(slot_gpa) == tramp_gpa
    # `slot_a` was never passed to this call at all (empty list) -- still
    # holds the real function's address, confirming the skip really
    # emitted nothing for that entry rather than silently writing it too.
    assert scratch.read_u64(slot_a) == real_loadliba


def test_hook_install_with_no_slots_anywhere_emits_nothing():
    code, offsets = build_windows_hook_install(
        [(0x1000, [], 0x2000), (0x1008, [], 0x2008)],
        virtualprotect_iat_slot_va=0x3000,
        scratch_dword_va=0x4000,
    )
    assert code == b""
    assert offsets == []
