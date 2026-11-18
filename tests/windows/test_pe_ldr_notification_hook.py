"""Direct-execution regression tests for the LdrRegisterDllNotification-
based IAT-redirect callback in ``staticer/stubs/windows/pe_stub.py``
(``build_windows_ldr_notification_callback``,
``build_windows_ldr_notification_register``).

Like ``test_pe_hook_trampolines.py`` (its closest sibling), this invokes
the generated machine code directly, with a hand-built fake "newly loaded
module" image (a minimal PE header fragment plus one import descriptor and
its thunk arrays) rather than a real PE file -- the point is pinning down
the callback's own memory-walking and calling-convention correctness in
isolation, not re-proving the whole embed() pipeline (see
``tests/windows/test_pe_hook_runtime.py``'s new
``test_third_dll_statically_importing_embedded_dependency_resolves_against_
embedded_copy`` for the real end-to-end fixture matching 010 Editor's own
qwindows.dll shape).
"""

import ctypes
import platform
import struct
from ctypes import wintypes

import pytest

from staticer.stubs.windows.pe_stub import (
    build_windows_ldr_notification_callback,
    build_windows_ldr_notification_register,
)

pytestmark = pytest.mark.skipif(platform.system() != "Windows", reason="x64 machine code is Windows-only")

_MEM_COMMIT_RESERVE = 0x1000 | 0x2000
_PAGE_EXECUTE_READWRITE = 0x40
_PAGE_READONLY = 0x02
_ORD_SENTINEL = 0xFFFFFFFFFFFFFFFF
_LDR_DLL_NOTIFICATION_REASON_LOADED = 1
_LDR_DLL_NOTIFICATION_REASON_UNLOADED = 2


def _real_virtualprotect_slot_va() -> int:
    kernel32 = ctypes.windll.kernel32
    real_addr = ctypes.cast(kernel32.VirtualProtect, ctypes.c_void_p).value
    cell = (ctypes.c_uint64 * 1)(real_addr)
    _KEEPALIVE.append(cell)
    return ctypes.addressof(cell)


_KEEPALIVE: list = []


class _Scratch:
    """Same bump-allocator helper as ``test_pe_hook_trampolines.py``'s own
    ``_Scratch`` -- duplicated rather than imported across test modules
    (deliberately: these two files are independent regression suites, and
    this one additionally needs a genuinely page-aligned IAT region, see
    ``alloc_aligned_readonly_page`` below)."""

    def __init__(self, size: int = 0x40000):
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

    def write_u32(self, addr: int, value: int) -> None:
        self.write(addr, struct.pack("<I", value & 0xFFFFFFFF))

    def write_u64(self, addr: int, value: int) -> None:
        self.write(addr, struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF))

    def read_u64(self, addr: int) -> int:
        return struct.unpack("<Q", ctypes.string_at(addr, 8))[0]

    def write_str(self, s: str) -> int:
        data = s.encode("ascii") + b"\x00"
        addr = self.alloc(len(data), align=1)
        self.write(addr, data)
        return addr

    def place(self, code: bytes) -> int:
        addr = self.alloc(len(code))
        self.write(addr, code)
        return addr


@pytest.fixture
def scratch():
    return _Scratch()


def _build_fake_module(
    *,
    import_dll_name: str,
    by_name_import: str = None,
    by_ordinal_import: int = None,
    make_readonly: bool = False,
):
    """Builds a minimal, hand-laid-out fake "newly loaded module" image:
    a PE header fragment (just enough for the callback's own header walk:
    e_lfanew at +0x3C, the import-directory RVA at the PE32+ NT-headers
    offset +0x90) plus one `IMAGE_IMPORT_DESCRIPTOR` (terminated by one
    all-zero entry) and its `OriginalFirstThunk`/`FirstThunk` arrays --
    exactly the shape a real `qwindows.dll`-style plugin's own static
    import table has, just synthesized by hand instead of compiled.

    Lives on its own dedicated page (never the shared `_Scratch` region)
    so the *whole* fake module can be made genuinely `PAGE_READONLY` when
    `make_readonly=True` -- proving the callback's own `VirtualProtect`
    wrap actually matters (same reasoning as
    `test_pe_hook_trampolines.py`'s `alloc_readonly_page`) -- while every
    offset inside it (header fields, the descriptor, the IAT slot) stays
    a small, real RVA relative to this same page's own base, exactly like
    a real module's own `FirstThunk` RVA is always relative to its own
    `DllBase`. Only the IAT slot (the one thing the callback ever writes)
    needs to be writable at all; making the entire small page read-only
    is simpler than carving out a second one and is harmless, since
    nothing else here is ever written to after setup.

    Returns (module_base, iat_slot_va) -- `iat_slot_va` is where the
    callback is expected to write the redirected address (or leave
    untouched, for the no-match/no-match-in-table cases).
    """
    kernel32 = ctypes.windll.kernel32
    kernel32.VirtualAlloc.restype = ctypes.c_void_p
    kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
    base = kernel32.VirtualAlloc(None, 0x1000, _MEM_COMMIT_RESERVE, _PAGE_EXECUTE_READWRITE)
    assert base

    def w32(off: int, val: int) -> None:
        ctypes.memmove(base + off, struct.pack("<I", val & 0xFFFFFFFF), 4)

    def w64(off: int, val: int) -> None:
        ctypes.memmove(base + off, struct.pack("<Q", val & 0xFFFFFFFFFFFFFFFF), 8)

    def wbytes(off: int, data: bytes) -> None:
        ctypes.memmove(base + off, data, len(data))

    e_lfanew = 0x80
    w32(0x3C, e_lfanew)
    import_dir_rva = 0x200
    w32(e_lfanew + 0x90, import_dir_rva)

    descriptor_rva = import_dir_rva
    name_rva = descriptor_rva + 40  # two 20-byte descriptor slots (real + terminator)
    wbytes(name_rva, import_dll_name.encode("ascii") + b"\x00")

    orig_thunk_rva = name_rva + 32
    # Generous headroom past the one thunk slot + terminator (16 bytes)
    # for the by-name case's own IMAGE_IMPORT_BY_NAME (Hint + name string)
    # before the IAT slot itself -- comfortably fits every name used in
    # this file's own tests.
    iat_rva = orig_thunk_rva + 64

    # IMAGE_IMPORT_DESCRIPTOR: OriginalFirstThunk, TimeDateStamp,
    # ForwarderChain, Name, FirstThunk.
    w32(descriptor_rva + 0, orig_thunk_rva)
    w32(descriptor_rva + 4, 0)
    w32(descriptor_rva + 8, 0)
    w32(descriptor_rva + 12, name_rva)
    w32(descriptor_rva + 16, iat_rva)
    wbytes(descriptor_rva + 20, b"\x00" * 20)  # terminator descriptor

    if by_name_import is not None:
        ibn_rva = orig_thunk_rva + 16
        hint_and_name = struct.pack("<H", 0) + by_name_import.encode("ascii") + b"\x00"
        wbytes(ibn_rva, hint_and_name)
        w64(orig_thunk_rva, ibn_rva)
    else:
        w64(orig_thunk_rva, 0x8000000000000000 | (by_ordinal_import & 0xFFFF))
    w64(orig_thunk_rva + 8, 0)  # terminator

    # Pre-fill the IAT slot with a "real loader already snapped this"
    # stand-in value, distinguishable from both 0 and any resolved VA used
    # in these tests.
    w64(iat_rva, 0xBAD5EED5BAD5EED5)

    if make_readonly:
        kernel32.VirtualProtect.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
        ]
        kernel32.VirtualProtect.restype = wintypes.BOOL
        old = wintypes.DWORD(0)
        ok = kernel32.VirtualProtect(ctypes.c_void_p(base), ctypes.c_size_t(0x1000), _PAGE_READONLY, ctypes.byref(old))
        assert ok

    return base, base + iat_rva


def _build_dep_table(scratch: _Scratch, entries):
    """`entries` is a list of (dll_name, [(export_name_or_None, ordinal_or_None, resolved_va), ...])."""
    table_rows = []
    for dll_name, exports in entries:
        ansi_va = scratch.write_str(dll_name)

        name_rows = [(scratch.write_str(n), va) for n, o, va in exports if n is not None]
        name_table = scratch.alloc(16 * (len(name_rows) + 1), align=8)
        off = name_table
        for nva, va in name_rows:
            scratch.write_u64(off, nva)
            scratch.write_u64(off + 8, va)
            off += 16
        scratch.write_u64(off, 0)
        scratch.write_u64(off + 8, 0)

        ord_rows = [(o, va) for n, o, va in exports if o is not None]
        ord_table = scratch.alloc(16 * (len(ord_rows) + 1), align=8)
        off = ord_table
        for ordv, va in ord_rows:
            scratch.write_u64(off, ordv)
            scratch.write_u64(off + 8, va)
            off += 16
        scratch.write_u64(off, _ORD_SENTINEL)
        scratch.write_u64(off + 8, 0)

        table_rows.append((ansi_va, name_table, ord_table))

    table = scratch.alloc(24 * (len(table_rows) + 1), align=8)
    off = table
    for ansi_va, name_table, ord_table in table_rows:
        scratch.write_u64(off, ansi_va)
        scratch.write_u64(off + 8, name_table)
        scratch.write_u64(off + 16, ord_table)
        off += 24
    scratch.write_u64(off, 0)
    scratch.write_u64(off + 8, 0)
    scratch.write_u64(off + 16, 0)
    return table


class _NotificationData(ctypes.Structure):
    _fields_ = [
        ("Flags", ctypes.c_uint32),
        ("_pad", ctypes.c_uint32),
        ("FullDllName", ctypes.c_void_p),
        ("BaseDllName", ctypes.c_void_p),
        ("DllBase", ctypes.c_void_p),
        ("SizeOfImage", ctypes.c_uint32),
    ]


def test_callback_redirects_by_name_import_in_newly_loaded_module(scratch):
    resolved_va = 0x7FFF22223333
    dep_table = _build_dep_table(scratch, [("lib.dll", [("lib_value", None, resolved_va)])])
    module_base, iat_slot_va = _build_fake_module(
        import_dll_name="lib.dll", by_name_import="lib_value", make_readonly=True,
    )

    code, _offsets = build_windows_ldr_notification_callback(
        dep_table_va=dep_table,
        virtualprotect_iat_slot_va=_real_virtualprotect_slot_va(),
        scratch_qword_va=scratch.alloc(8),
    )
    callback = scratch.place(code)

    fn = ctypes.CFUNCTYPE(None, ctypes.c_uint32, ctypes.POINTER(_NotificationData), ctypes.c_void_p)(callback)
    data = _NotificationData(Flags=0, DllBase=module_base, SizeOfImage=0x1000)
    fn(_LDR_DLL_NOTIFICATION_REASON_LOADED, ctypes.byref(data), None)

    assert scratch.read_u64(iat_slot_va) == resolved_va


def test_callback_redirects_by_ordinal_import(scratch):
    resolved_va = 0x7FFF44445555
    dep_table = _build_dep_table(scratch, [("lib.dll", [(None, 7, resolved_va)])])
    module_base, iat_slot_va = _build_fake_module(
        import_dll_name="LIB.DLL", by_ordinal_import=7,
    )

    code, _offsets = build_windows_ldr_notification_callback(
        dep_table_va=dep_table,
        virtualprotect_iat_slot_va=_real_virtualprotect_slot_va(),
        scratch_qword_va=scratch.alloc(8),
    )
    callback = scratch.place(code)

    fn = ctypes.CFUNCTYPE(None, ctypes.c_uint32, ctypes.POINTER(_NotificationData), ctypes.c_void_p)(callback)
    data = _NotificationData(Flags=0, DllBase=module_base, SizeOfImage=0x1000)
    # Case-insensitive DLL-name match ("LIB.DLL" vs the table's "lib.dll").
    fn(_LDR_DLL_NOTIFICATION_REASON_LOADED, ctypes.byref(data), None)

    assert scratch.read_u64(iat_slot_va) == resolved_va


def test_callback_leaves_non_matching_module_untouched(scratch):
    dep_table = _build_dep_table(scratch, [("lib.dll", [("lib_value", None, 0x7FFF99990000)])])
    module_base, iat_slot_va = _build_fake_module(
        import_dll_name="unrelated.dll", by_name_import="whatever",
    )

    code, _offsets = build_windows_ldr_notification_callback(
        dep_table_va=dep_table,
        virtualprotect_iat_slot_va=_real_virtualprotect_slot_va(),
        scratch_qword_va=scratch.alloc(8),
    )
    callback = scratch.place(code)

    fn = ctypes.CFUNCTYPE(None, ctypes.c_uint32, ctypes.POINTER(_NotificationData), ctypes.c_void_p)(callback)
    data = _NotificationData(Flags=0, DllBase=module_base, SizeOfImage=0x1000)
    fn(_LDR_DLL_NOTIFICATION_REASON_LOADED, ctypes.byref(data), None)

    assert scratch.read_u64(iat_slot_va) == 0xBAD5EED5BAD5EED5


def test_callback_leaves_unresolvable_name_untouched(scratch):
    """A matched DLL whose specific imported name isn't in our own
    export-match table (e.g. a forward this project couldn't resolve at
    embed time) must leave that one slot alone -- never a NULL write,
    matching this project's existing fallback convention elsewhere."""
    dep_table = _build_dep_table(scratch, [("lib.dll", [("some_other_export", None, 0x7FFF88880000)])])
    module_base, iat_slot_va = _build_fake_module(
        import_dll_name="lib.dll", by_name_import="lib_value",
    )

    code, _offsets = build_windows_ldr_notification_callback(
        dep_table_va=dep_table,
        virtualprotect_iat_slot_va=_real_virtualprotect_slot_va(),
        scratch_qword_va=scratch.alloc(8),
    )
    callback = scratch.place(code)

    fn = ctypes.CFUNCTYPE(None, ctypes.c_uint32, ctypes.POINTER(_NotificationData), ctypes.c_void_p)(callback)
    data = _NotificationData(Flags=0, DllBase=module_base, SizeOfImage=0x1000)
    fn(_LDR_DLL_NOTIFICATION_REASON_LOADED, ctypes.byref(data), None)

    assert scratch.read_u64(iat_slot_va) == 0xBAD5EED5BAD5EED5


def test_callback_ignores_unload_reason(scratch):
    resolved_va = 0x7FFF11112222
    dep_table = _build_dep_table(scratch, [("lib.dll", [("lib_value", None, resolved_va)])])
    module_base, iat_slot_va = _build_fake_module(
        import_dll_name="lib.dll", by_name_import="lib_value",
    )

    code, _offsets = build_windows_ldr_notification_callback(
        dep_table_va=dep_table,
        virtualprotect_iat_slot_va=_real_virtualprotect_slot_va(),
        scratch_qword_va=scratch.alloc(8),
    )
    callback = scratch.place(code)

    fn = ctypes.CFUNCTYPE(None, ctypes.c_uint32, ctypes.POINTER(_NotificationData), ctypes.c_void_p)(callback)
    data = _NotificationData(Flags=0, DllBase=module_base, SizeOfImage=0x1000)
    fn(_LDR_DLL_NOTIFICATION_REASON_UNLOADED, ctypes.byref(data), None)

    assert scratch.read_u64(iat_slot_va) == 0xBAD5EED5BAD5EED5


def test_register_calls_ldrregisterdllnotification_for_real(scratch):
    """`build_windows_ldr_notification_register` makes a real call into
    ntdll -- confirms it doesn't crash and the real `LdrRegisterDllNotification`
    accepts the call (NTSTATUS >= 0, i.e. success) and writes a real,
    non-NULL cookie, through the exact IAT-slot-call-through convention
    this module uses for every other real-API call."""
    ntdll = ctypes.WinDLL("ntdll.dll")
    real_addr = ctypes.cast(ntdll.LdrRegisterDllNotification, ctypes.c_void_p).value
    slot_cell = (ctypes.c_uint64 * 1)(real_addr)
    slot_va = ctypes.addressof(slot_cell)

    def fake_callback(reason, data, context):
        pass

    callback_proto = ctypes.CFUNCTYPE(None, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p)
    callback_fn = callback_proto(fake_callback)
    callback_va = ctypes.cast(callback_fn, ctypes.c_void_p).value

    cookie_va = scratch.alloc(8)
    scratch.write_u64(cookie_va, 0)

    code, _offsets = build_windows_ldr_notification_register(
        ldrregisterdllnotification_iat_slot_va=slot_va,
        callback_va=callback_va,
        cookie_scratch_va=cookie_va,
    )
    installer = scratch.place(code)
    ctypes.CFUNCTYPE(None)(installer)()

    cookie = scratch.read_u64(cookie_va)
    assert cookie != 0

    # Clean up: unregister via the real API directly (not generated code)
    # so this test doesn't leave a dangling callback pointing at memory
    # that may later be reused/freed.
    ntdll.LdrUnregisterDllNotification.restype = ctypes.c_long
    ntdll.LdrUnregisterDllNotification.argtypes = [ctypes.c_void_p]
    status = ntdll.LdrUnregisterDllNotification(ctypes.c_void_p(cookie))
    assert status == 0
