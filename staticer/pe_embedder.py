"""PE (Windows) dependency embedding.

Implements both the reloc-bearing ("PIC") case -- a dependency DLL that
carries a base relocation table is appended into the host EXE/DLL as new
section(s), its own relocations are applied against the new addresses --
and the no-relocation-data ("fixed-base"/non-PIC) case -- the dependency is
instead placed at the fixed address its own preferred ImageBase demands,
reserved against the host's own image and every other such dependency.
Either way, the host's references to it are patched to the embedded
addresses and its import-table entry is removed. Each dependency's own
``.pdata``/``.xdata`` (x64 unwind metadata) is merged into the host's own
exception directory, and the generated entrypoint stub (see
``staticer/stubs/windows/pe_stub.py``) runs each embedded dependency's own
entry point before handing off to the host's original one. On an x64
host with at least one embedded dependency, that same stub also installs
a runtime LoadLibraryW/LoadLibraryA/GetProcAddress hook (see
``pe_stub.py``'s own module docstring's "Hook mechanism" section, and
this module's own long comment near ``build_windows_stub``'s call site),
so anything in the process that later asks to load one of this run's
embedded dependencies *by name* at runtime gets back its already-
initialized embedded address instead of triggering a real, separate,
duplicate load -- see ``embed()``'s docstring for this mechanism's own
documented scope limits.
"""

import os
import struct
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import pefile

from .common.depgraph import build_dependency_graph, embed_order
from .stubs.windows.pe_stub import (
    build_windows_delay_import_lazy_thunk,
    build_windows_getprocaddress_trampoline,
    build_windows_hook_install,
    build_windows_loadlibrary_trampoline,
    build_windows_stub,
    build_windows_tls_index_fixup,
)

IMAGE_REL_BASED_ABSOLUTE = 0
IMAGE_REL_BASED_HIGHLOW = 3
IMAGE_REL_BASED_DIR64 = 10

_IMAGE_DIRECTORY_ENTRY_IMPORT = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]
_IMAGE_DIRECTORY_ENTRY_BASERELOC = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]
_IMAGE_DIRECTORY_ENTRY_EXCEPTION = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]
_IMAGE_DIRECTORY_ENTRY_TLS = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"]
_IMAGE_DIRECTORY_ENTRY_SECURITY = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
_IMAGE_FILE_DLL = 0x2000  # FILE_HEADER.Characteristics bit: this image is a DLL

# Mirrors elf_embedder.py's _SUPPORTED_MACHINES: only architectures this
# project has actually been exercised against, not merely "host and
# dependency agree with each other" (a separate, pre-existing mismatch
# guard below). Without this, e.g. an untested ARM64 PE pair would be
# silently accepted.
_SUPPORTED_MACHINES = (
    pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"],
    pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"],
)

# x64 UNWIND_INFO flags (IMAGE_DIRECTORY_ENTRY_EXCEPTION's RUNTIME_FUNCTION
# entries point at one of these per function) -- see _adjust_unwind_info.
_UNW_FLAG_EHANDLER = 0x1
_UNW_FLAG_UHANDLER = 0x2
_UNW_FLAG_CHAININFO = 0x4

_SCN_CODE_RWX = 0x60000020 | 0x80000000  # CNT_CODE|MEM_EXECUTE|MEM_READ|MEM_WRITE
_SCN_DATA_R = 0x40000040  # CNT_INITIALIZED_DATA|MEM_READ
_SCN_UNINIT_RW = 0xC0000080  # CNT_UNINITIALIZED_DATA|MEM_READ|MEM_WRITE (".bss"-style)

# Byte offsets of IMAGE_TLS_DIRECTORY64's own fields, relative to its own
# start (StartAddressOfRawData, EndAddressOfRawData, AddressOfIndex,
# AddressOfCallBacks -- each a QWORD -- then SizeOfZeroFill, a DWORD).
# Used by the N-way TLS merge (see embed()'s TLS-directory handling) to
# patch a merge *authority* struct's fields when that authority is a
# dependency's own (adopted) directory living inside its own mutable
# blob at a relative offset, rather than the host's own, which instead
# uses pefile's `get_field_absolute_offset` against `output` directly.
_TLS64_FIELD_OFFSET = {"start": 0, "end": 8, "callbacks": 24, "zero_fill": 32}


# pefile's own `max_symbol_exports` default (8192) silently truncates a
# dependency's own export-table PARSE once past that many distinct
# symbols -- NOT a corruption guard tripping on a malicious file (that's
# `max_repeated_symbol`'s/the separate (name, address)-repeat check's job,
# both unaffected by this), just an overly conservative default for a
# real, large, legitimate module: confirmed via a genuine commercial Qt6
# application's own Qt6Gui.dll (9255 real exports) -- `embed()` reported
# a specific exported symbol the host's own import table needed as
# "does not export" it, even though the real Windows loader resolves it
# fine (the DLL unmodified by this project runs correctly) -- because
# pefile's parse silently stopped at the 8192nd symbol and the needed
# one happened to sit past that cut-off. Same bug *class* as the already-
# fixed import-table re-parse truncation documented in `list_pe_imports`
# below (a pefile internal safety limit, not file corruption, silently
# dropping real data for a sufficiently large real-world binary) -- just
# a different cap on a different directory. Comfortably above any real
# module's export count (even large system DLLs like combase.dll/
# shell32.dll stay well under this); raising it costs nothing but a
# larger loop bound, since genuine corruption is still caught by the
# unrelated repeated-(name, address) check regardless of this value.
_MAX_SYMBOL_EXPORTS = 65536


def list_pe_imports(path: Path) -> List[str]:
    """Names of the DLLs a PE file imports, read from its IMPORT_DESCRIPTOR
    directory (empty list if it has none)."""
    # `pefile.PE(path)` (fast_load=False, the default) already parses every
    # data directory -- including imports -- during construction. A second,
    # redundant `parse_data_directories()` call on an already-parsed object
    # is not a no-op: for at least one real, densely-importing binary (a
    # Qt6 application found via local testing) it corrupted the re-walk of
    # the import descriptor array, silently truncating it from 26 real
    # entries down to 3 (pefile's own `parse_import_directory` gives up
    # after too many descriptors it fails to resolve imports for). That
    # truncation cascaded into `build_dependency_graph` only ever seeing
    # the input's first 3 imports, and a corrupted/crashing final binary.
    # Never re-parse an already-constructed PE object.
    pe = pefile.PE(str(path), max_symbol_exports=_MAX_SYMBOL_EXPORTS)
    try:
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return []
        return [entry.dll.decode("ascii") for entry in pe.DIRECTORY_ENTRY_IMPORT]
    finally:
        pe.close()


def _list_pe_import_graph_edges(path: Path) -> List[str]:
    """Like `list_pe_imports`, but also includes forwarder-TARGET DLL names
    from this PE's own export table, so the dependency graph can discover
    and embed a DLL that nothing in the closure directly imports but that
    IS needed purely as a forward target of some embedded dependency's own
    export (a real, observed shape: e.g. SHLWAPI.dll forwards some exports
    to SHCORE.dll, which SHLWAPI.dll's own import table never mentions at
    all). Without this, `_resolve_raw_export`'s finalize pass can only ever
    resolve a forward whose target DLL happens to ALSO be reachable via an
    ordinary import edge from somewhere in the closure -- a forward-only
    target was previously an unconditional dead end ("isn't an
    already-embedded dependency"), even though it's perfectly embeddable
    once added to the graph the exact same way as any other dependency.

    Deliberately NOT folded into `list_pe_imports` itself: that function's
    contract (used directly by tests to assert on a PE file's *actual*
    import table) must keep meaning exactly that, not "every DLL name this
    graph might want to visit." Only used as `build_dependency_graph`'s
    `list_imports` callback.

    Re-implements (rather than calls) `list_pe_imports`'s own import-table
    scan to do both scans against one `pefile.PE()` construction -- see
    `list_pe_imports`'s own docstring for why a *second*, independent
    parse of the same already-parsed object is unsafe; two independent
    `pefile.PE()` constructions from the same path are fine, just wasteful
    I/O-wise for every node in a large graph, avoided here instead."""
    pe = pefile.PE(str(path), max_symbol_exports=_MAX_SYMBOL_EXPORTS)
    try:
        names: List[str] = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            names.extend(entry.dll.decode("ascii") for entry in pe.DIRECTORY_ENTRY_IMPORT)
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            own_name_lower = path.name.lower()
            seen_lower = {n.lower() for n in names}
            for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if not sym.forwarder:
                    continue
                forwarder = sym.forwarder.decode("ascii")
                fwd_dll, _, _ = forwarder.rpartition(".")
                if not fwd_dll.lower().endswith(".dll"):
                    fwd_dll += ".dll"
                fwd_dll_lower = fwd_dll.lower()
                # A self-forward (a real, observed shape -- e.g. RPCRT4.dll
                # forwards some of its own ANSI exports to its own wide-
                # string ones) needs no graph edge at all: it's already
                # its own node, and `_resolve_raw_export`'s finalize pass
                # resolves it trivially once this same dependency's own
                # raw export table is populated. An edge here would be a
                # self-loop, which `embed_order`'s cycle detector (rightly)
                # rejects as a cycle even though no real ordering
                # constraint exists.
                if fwd_dll_lower == own_name_lower or fwd_dll_lower in seen_lower:
                    continue
                seen_lower.add(fwd_dll_lower)
                names.append(fwd_dll)
        return names
    finally:
        pe.close()


class _CaseInsensitiveNameSet:
    """A read-only, case-insensitive view over a set of DLL names, for
    passing as ``build_dependency_graph``'s ``exclude`` argument from the
    PE embedder only.

    Windows filenames (and so DLL import names) are case-insensitive, but
    ``build_dependency_graph`` itself (shared with the ELF embedder, where
    filenames *are* case-sensitive) does a plain ``name in exclude`` set
    membership test -- it can't be made case-insensitive for everyone
    without changing ELF's correct case-sensitive semantics. Scoping the
    fix to this wrapper, used only here, keeps that shared module
    untouched. (``--exclude ws2_32.dll`` must exclude ``WS2_32.dll``.)
    """

    def __init__(self, names: Set[str]):
        self._lower = {n.lower() for n in names}

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name.lower() in self._lower


def resolve_pe(name: str, search_dirs: List[Path]) -> Optional[Path]:
    """Scan search_dirs in order for a file literally named `name`.

    `name` comes straight from the PE file being processed's own Import
    Directory (an attacker-controlled DLL name, if the input binary is
    untrusted) -- it must never be allowed to escape the `search_dirs`
    entry it's being matched against via path-traversal components
    (``..``) or an absolute path (CWE-22), or `--lib-dir`'s whole purpose
    (scoping embedding to one chosen folder) is defeated. A `name` that
    isn't a bare filename is rejected outright before any join is even
    attempted (cheap first-line defense); as a second, independent check,
    any resulting candidate that resolves outside `directory` is also
    rejected. Either way this behaves exactly like "not found in this
    directory" -- falling through to the next search_dirs entry, or
    returning None if none match -- never a hard error."""
    if not name or "/" in name or "\\" in name or name == ".." or Path(name).is_absolute():
        return None
    for directory in search_dirs:
        candidate = directory / name
        try:
            resolved = candidate.resolve()
            if not resolved.is_relative_to(directory.resolve()):
                continue
        except (OSError, ValueError):
            continue
        if candidate.is_file():
            return candidate
    return None




def _align_up(value: int, alignment: int) -> int:
    if alignment <= 1:
        return value
    return (value + alignment - 1) // alignment * alignment


def _pack_section_header(name: bytes, virtual_size: int, virtual_address: int,
                          size_of_raw_data: int, pointer_to_raw_data: int,
                          characteristics: int) -> bytes:
    name8 = name[:8].ljust(8, b"\x00")
    return struct.pack(
        "<8sIIIIIIHHI", name8, virtual_size, virtual_address, size_of_raw_data,
        pointer_to_raw_data, 0, 0, 0, 0, characteristics,
    )


class _FH4ParseError(Exception):
    """Raised internally by the ``_fh4_parse_*`` helpers below when the
    bytes at some offset don't decode as a plausible __CxxFrameHandler4
    structure (out-of-bounds read, an implausible entry count, a header
    byte with its documented-always-zero 'reserved' bit set, ...).
    Caught by ``_adjust_cxx_frame_handler4_funcinfo``, which then leaves
    that function's FuncInfo4 data completely unpatched rather than risk
    writing a wrong address over real data -- the same fail-safe,
    leave-it-alone behavior this module already falls back to for any
    other not-confidently-understood case."""


#: Upper bound on any single compressed-int *count* field (NumEntries,
#: number of try blocks, number of handlers, ...) __CxxFrameHandler4 data
#: is ever expected to contain for a real, compiler-generated function.
#: Purely a sanity backstop against treating garbage/unrelated bytes as a
#: huge entry count and looping far past anything a real function would
#: need -- every real read is already bounds-checked against `len(blob)`
#: regardless, so this can never cause an out-of-bounds access by itself.
_FH4_MAX_ENTRIES = 1 << 16


def _fh4_read_compressed_uint(blob: bytearray, pos: int) -> "tuple[int, int]":
    """Decode one of __CxxFrameHandler4's own variable-length ("compressed")
    unsigned integers starting at byte offset `pos` in `blob`, returning
    ``(value, new_pos)``.

    This is the format MSVC's own ``FH4::ReadUnsigned``/
    ``FH4::Compress::getNETencoded`` (see ``ehdata4_export.h``, shipped
    with MSVC under ``VC/Tools/MSVC/<ver>/include/`` -- the project's own
    semi-public header for this exact on-disk format, confirmed present
    and readable on this machine) implement: the low bits of the first
    byte, read as a unary prefix, give the total encoded length in bytes
    (1-5); the remaining bits (spread across however many bytes that is)
    hold the actual value, least-significant byte first:

        bit0=0                     -> 1 byte,  7 value bits (byte0>>1)
        bit0=1, bit1=0             -> 2 bytes, 14 value bits
        bit0=1, bit1=1, bit2=0     -> 3 bytes, 21 value bits
        bits0-2=1, bit3=0 (0x07)   -> 4 bytes, 28 value bits
        bits0-3=1 (0x0F)           -> 5 bytes, 32 value bits (raw LE)

    Confirmed against MSVC 19.51's own compiled output by decoding a real
    FuncInfo4 blob both this way and via a tiny harness that calls the
    real ``FH4::DecompFuncInfo``/``FH4::ReadUnsigned`` from
    ``ehdata4_export.h`` directly (LoadLibraryExA'd with
    ``LOAD_LIBRARY_AS_IMAGE_RESOURCE`` so RVA-based pointer arithmetic
    inside those inline functions is valid) -- the two gave identical
    results. Never embeds an RVA itself (it's used only for counts,
    state-transition deltas, and bit-packed type tags), so nothing this
    function decodes ever needs ``+shift`` treatment -- it only needs to
    be decoded accurately enough to find *where the next field starts*.
    """
    if pos >= len(blob):
        raise _FH4ParseError("compressed-int read starts past end of buffer")
    b0 = blob[pos]
    if b0 & 1 == 0:
        return b0 >> 1, pos + 1
    if b0 & 3 == 1:
        if pos + 2 > len(blob):
            raise _FH4ParseError("2-byte compressed-int read past end of buffer")
        return (b0 >> 2) | (blob[pos + 1] << 6), pos + 2
    if b0 & 7 == 3:
        if pos + 3 > len(blob):
            raise _FH4ParseError("3-byte compressed-int read past end of buffer")
        return (b0 >> 3) | (blob[pos + 1] << 5) | (blob[pos + 2] << 13), pos + 3
    if b0 & 0xF == 7:
        if pos + 4 > len(blob):
            raise _FH4ParseError("4-byte compressed-int read past end of buffer")
        return (
            (b0 >> 4) | (blob[pos + 1] << 4) | (blob[pos + 2] << 12) | (blob[pos + 3] << 20),
            pos + 4,
        )
    if pos + 5 > len(blob):
        raise _FH4ParseError("5-byte compressed-int read past end of buffer")
    value = blob[pos + 1] | (blob[pos + 2] << 8) | (blob[pos + 3] << 16) | (blob[pos + 4] << 24)
    return value, pos + 5


def _fh4_read_count(blob: bytearray, pos: int) -> "tuple[int, int]":
    """Like ``_fh4_read_compressed_uint``, but for a *NumEntries*-style
    count field specifically -- rejects an implausibly large result (see
    ``_FH4_MAX_ENTRIES``) rather than looping that many times below."""
    count, pos = _fh4_read_compressed_uint(blob, pos)
    if count > _FH4_MAX_ENTRIES:
        raise _FH4ParseError(f"implausible entry count {count}")
    return count, pos


def _fh4_rva_in_module(rva: int, module_ranges: List["tuple[int, int]"]) -> bool:
    """True if `rva` falls within some real section of the module (i.e.
    some ``[VirtualAddress, VirtualAddress + size)`` range reported by the
    dependency's own section table) -- false for an RVA that lands in the
    PE header/DOS-stub region before the first section, past the end of
    the image, or in an inter-section alignment gap no section claims.

    This is the key discriminator that keeps ``_fh4_parse_func_info4`` and
    friends from treating some *other* personality routine's unrelated
    data (plain SEH scope tables, __CxxFrameHandler3's legacy format,
    ...) as __CxxFrameHandler4's -- confirmed necessary, not theoretical:
    an early version of this patch, validating only "in-bounds of `blob`"
    plus FuncInfoHeader's reserved-bit, happily accepted small
    coincidentally-reserved-bit-clear values (1, 2, 3, 4, ...) read out of
    plain-SEH scope-table bytes for a non-C++, DllMain-only MSVC-built
    dependency (see ``tests/fixtures/lib_order_a.c``) as "valid" FuncInfo4
    RVAs and corrupted unrelated bytes near the start of the image -- a
    real, reproduced false positive, not a hypothetical one. Every one of
    those bogus values landed below the dependency's first section's own
    ``VirtualAddress`` (i.e. in the header region); real FuncInfo4 data,
    being ordinary comdat'd .xdata/.rdata content, never does.
    """
    return any(lo <= rva < hi for lo, hi in module_ranges)


def _fh4_rva_field(blob: bytearray, pos: int,
                    module_ranges: List["tuple[int, int]"]) -> "tuple[int, int]":
    """Reads one plain 4-byte image-relative-offset ("RVA") field at `pos`
    -- one of FuncInfo4's own fixed-size fields (dispUnwindMap,
    dispTryBlockMap, an UnwindMapEntry4's `action`, a TryBlockMapEntry4's
    dispHandlerArray, a HandlerType4's dispType/dispOfHandler/
    continuation address, ...) -- unlike every other field in this format,
    these are NOT compressed-int-encoded (see ehdata4_export.h's own
    on-disk-format comment: each is spelled out as "4 bytes, RVA to ...").
    Returns ``(value, pos + 4)``; `pos` itself is the field's own offset,
    which the caller collects for patching.

    A nonzero value failing ``_fh4_rva_in_module`` raises, exactly like an
    out-of-bounds read -- see that function's docstring for why this
    check earns its place on every single RVA field this format has, not
    just the ones this module recurses through."""
    if pos + 4 > len(blob):
        raise _FH4ParseError("RVA field read past end of buffer")
    (value,) = struct.unpack_from("<I", blob, pos)
    if value and not _fh4_rva_in_module(value, module_ranges):
        raise _FH4ParseError(f"RVA 0x{value:x} outside every known module section")
    return value, pos + 4


def _fh4_parse_handler_map4(blob: bytearray, rva: int,
                             module_ranges: List["tuple[int, int]"]) -> List[int]:
    """Parses a HandlerMap4 blob (the per-try-block array of catch-handler
    descriptors a TryBlockMapEntry4's ``dispHandlerArray`` points at --
    see ehdata4_export.h's "HandlerMap4" on-disk-format comment and
    ``FH4::HandlerMap4::DecompHandler``), returning the list of byte
    offsets *within* `blob` that hold a 4-byte RVA needing ``+shift``:
    each entry's optional ``dispType`` (the RTTI type descriptor the
    thrown object is matched against), its always-present
    ``dispOfHandler`` (the catch handler's own entry point), and, only
    when ``contIsRVA`` is set (used for POGO/BBT-separated code), its 1-2
    continuation addresses."""
    if rva >= len(blob):
        raise _FH4ParseError("HandlerMap4 RVA out of bounds")
    pos = rva
    count, pos = _fh4_read_count(blob, pos)
    patches = []
    for _ in range(count):
        if pos >= len(blob):
            raise _FH4ParseError("HandlerMap4 entry header read past end of buffer")
        header = blob[pos]
        pos += 1
        has_adjectives = header & 1
        has_disp_type = (header >> 1) & 1
        has_catch_obj = (header >> 2) & 1
        cont_is_rva = (header >> 3) & 1
        cont_addr = (header >> 4) & 0b11
        if has_adjectives:
            _, pos = _fh4_read_compressed_uint(blob, pos)
        if has_disp_type:
            _, pos2 = _fh4_rva_field(blob, pos, module_ranges)
            patches.append(pos)
            pos = pos2
        if has_catch_obj:
            _, pos = _fh4_read_compressed_uint(blob, pos)
        _, pos2 = _fh4_rva_field(blob, pos, module_ranges)  # dispOfHandler: always present
        patches.append(pos)
        pos = pos2
        if cont_is_rva:
            if cont_addr == 1:
                _, pos2 = _fh4_rva_field(blob, pos, module_ranges)
                patches.append(pos)
                pos = pos2
            elif cont_addr == 2:
                _, pos2 = _fh4_rva_field(blob, pos, module_ranges)
                patches.append(pos)
                pos = pos2
                _, pos2 = _fh4_rva_field(blob, pos, module_ranges)
                patches.append(pos)
                pos = pos2
            # cont_addr == 0 (none) or 3 (reserved): no continuation field at all.
        else:
            # Function-relative (not RVA), used for non-separated code --
            # no adjustment needed.
            if cont_addr == 1:
                _, pos = _fh4_read_compressed_uint(blob, pos)
            elif cont_addr == 2:
                _, pos = _fh4_read_compressed_uint(blob, pos)
                _, pos = _fh4_read_compressed_uint(blob, pos)
    return patches


def _fh4_parse_try_block_map4(blob: bytearray, rva: int,
                               module_ranges: List["tuple[int, int]"]) -> List[int]:
    """Parses a TryBlockMap4 blob (FuncInfo4's own ``dispTryBlockMap``
    points here -- see ehdata4_export.h's "TryBlockMap4" comment and
    ``FH4::TryBlockMap4::DecompTryBlock``): one entry per try block, each
    giving the EH-state range it covers and an RVA (``dispHandlerArray``)
    to that try's own HandlerMap4 (recursed into here). Returns every byte
    offset found needing ``+shift``."""
    if rva >= len(blob):
        raise _FH4ParseError("TryBlockMap4 RVA out of bounds")
    pos = rva
    count, pos = _fh4_read_count(blob, pos)
    patches = []
    for _ in range(count):
        _, pos = _fh4_read_compressed_uint(blob, pos)  # tryLow
        _, pos = _fh4_read_compressed_uint(blob, pos)  # tryHigh
        _, pos = _fh4_read_compressed_uint(blob, pos)  # catchHigh
        disp_handler_array, pos = _fh4_rva_field(blob, pos, module_ranges)
        patches.append(pos - 4)
        if disp_handler_array:
            patches.extend(_fh4_parse_handler_map4(blob, disp_handler_array, module_ranges))
    return patches


def _fh4_parse_unwind_map4(blob: bytearray, rva: int,
                            module_ranges: List["tuple[int, int]"]) -> List[int]:
    """Parses an UWMap4 blob (FuncInfo4's own ``dispUnwindMap`` points
    here -- see ehdata4_export.h's "UWMap4" comment and
    ``FH4::UWMap4::ReadEntry``): one entry per unwind-map state, each a
    compressed ``nextOffset<<2|type`` tag followed by an ``action`` RVA
    (to the destructor/cleanup thunk to run) for every type *except*
    ``NoUW`` (0) -- a state with nothing to unwind has no further data at
    all. Returns every byte offset found needing ``+shift``."""
    if rva >= len(blob):
        raise _FH4ParseError("UWMap4 RVA out of bounds")
    pos = rva
    count, pos = _fh4_read_count(blob, pos)
    patches = []
    for _ in range(count):
        packed, pos = _fh4_read_compressed_uint(blob, pos)
        entry_type = packed & 0b11
        if entry_type in (1, 2):  # DtorWithObj, DtorWithPtrToObj
            _, pos = _fh4_rva_field(blob, pos, module_ranges)
            patches.append(pos - 4)
            _, pos = _fh4_read_compressed_uint(blob, pos)  # object (frame offset, not an RVA)
        elif entry_type == 3:  # RVA
            _, pos = _fh4_rva_field(blob, pos, module_ranges)
            patches.append(pos - 4)
        # entry_type == 0 (NoUW): no further data for this entry.
    return patches


def _fh4_parse_sep_ip2state_map4(blob: bytearray, rva: int,
                                  module_ranges: List["tuple[int, int]"]) -> List[int]:
    """Parses a SepIPtoStateMap4 blob (only present for POGO/BBT-separated
    functions, pointed at by FuncInfo4's ``dispUnwindMap``-slot field when
    ``header.isSeparated`` is set -- see ehdata4_export.h's
    "SepIPtoStateMap4" comment): one ``(addrStartRVA, dispOfIPMap)`` pair
    per code segment, both real RVAs (the segment's own start address,
    and the RVA to *that* segment's own IPtoStateMap4 -- which, like the
    non-separated IPtoStateMap4, has no RVA fields of its own and so
    needs no further recursion)."""
    if rva >= len(blob):
        raise _FH4ParseError("SepIPtoStateMap4 RVA out of bounds")
    pos = rva
    count, pos = _fh4_read_count(blob, pos)
    patches = []
    for _ in range(count):
        _, pos = _fh4_rva_field(blob, pos, module_ranges)  # addrStartRVA
        patches.append(pos - 4)
        _, pos = _fh4_rva_field(blob, pos, module_ranges)  # dispOfIPMap
        patches.append(pos - 4)
    return patches


def _fh4_parse_func_info4(blob: bytearray, rva: int,
                           module_ranges: List["tuple[int, int]"]) -> List[int]:
    """Parses a FuncInfo4 blob (__CxxFrameHandler4's own top-level
    per-function metadata structure -- see ehdata4_export.h's "FuncInfo4"
    comment and ``FH4::DecompFuncInfo``) and everything it transitively
    points to (its UnwindMap, TryBlockMap and, for POGO/BBT-separated
    code, per-segment IP-to-state map), returning every byte offset
    within `blob` found to hold a 4-byte RVA needing ``+shift``.

    Raises ``_FH4ParseError`` -- caught by this module's one caller,
    ``_adjust_cxx_frame_handler4_funcinfo`` -- the moment anything stops
    looking like a real, well-formed FuncInfo4 (an out-of-bounds read, an
    implausible entry count, or ``header``'s documented-always-zero
    'reserved' bit being set): that's the signal this *isn't* actually
    __CxxFrameHandler4 data after all (see that function's docstring for
    why a plain RVA can't be told apart from one on sight alone), and the
    caller leaves it completely unpatched rather than risk doing this
    wrong."""
    if rva >= len(blob):
        raise _FH4ParseError("FuncInfo4 RVA out of bounds")
    pos = rva
    header = blob[pos]
    if header & 0x80:  # FuncInfoHeader.reserved: "Have to be 0"
        raise _FH4ParseError("FuncInfoHeader.reserved bit set")
    is_catch = header & 1
    is_separated = (header >> 1) & 1
    has_bbt = (header >> 2) & 1
    has_unwind_map = (header >> 3) & 1
    has_try_block_map = (header >> 4) & 1
    pos += 1

    if has_bbt:
        _, pos = _fh4_read_compressed_uint(blob, pos)  # bbtFlags

    disp_unwind_map = 0
    disp_unwind_map_off = None
    if has_unwind_map:
        disp_unwind_map, pos = _fh4_rva_field(blob, pos, module_ranges)
        disp_unwind_map_off = pos - 4

    disp_try_block_map = 0
    disp_try_block_map_off = None
    if has_try_block_map:
        disp_try_block_map, pos = _fh4_rva_field(blob, pos, module_ranges)
        disp_try_block_map_off = pos - 4

    # dispIPtoStateMap (non-separated) / dispToSegMap (separated) is
    # unconditional -- see ehdata4_export.h: "always assumed to exist".
    disp_ip_or_seg_map, pos = _fh4_rva_field(blob, pos, module_ranges)
    disp_ip_or_seg_map_off = pos - 4

    if is_catch:
        _, pos = _fh4_read_compressed_uint(blob, pos)  # dispFrame

    patches = []
    if disp_unwind_map_off is not None:
        patches.append(disp_unwind_map_off)
    if disp_try_block_map_off is not None:
        patches.append(disp_try_block_map_off)
    patches.append(disp_ip_or_seg_map_off)

    if disp_unwind_map:
        patches.extend(_fh4_parse_unwind_map4(blob, disp_unwind_map, module_ranges))
    if disp_try_block_map:
        patches.extend(_fh4_parse_try_block_map4(blob, disp_try_block_map, module_ranges))
    if is_separated and disp_ip_or_seg_map:
        patches.extend(_fh4_parse_sep_ip2state_map4(blob, disp_ip_or_seg_map, module_ranges))
    # Non-separated IPtoStateMap4 (the common case) has no RVA fields of
    # its own at all (Ip is function-relative *and* delta-encoded, State
    # is a small compressed state index) -- nothing further to patch.

    return patches


def _adjust_cxx_frame_handler4_funcinfo(blob: bytearray, disp_off: int, shift: int,
                                         patched: Set[int],
                                         module_ranges: List["tuple[int, int]"]) -> None:
    """__CxxFrameHandler4 -- the personality routine VS2019+ emits by
    default for x64 C++ EH, and the one case this module's general
    UNWIND_INFO handling (see ``_adjust_unwind_info``) does NOT cover --
    embeds one more RVA field immediately after its own (already-patched)
    handler-RVA field: an indirection to a separately-comdat'd
    ``FuncInfo4``/"cppxdata" blob (apparently so the linker can
    fold/dedup identical FuncInfo4 data shared by multiple functions),
    rather than inlining that data directly the way the public x64 ABI
    docs describe for a generic "exception handler data" blob.

    This is a *confirmed-real* finding, not a guess: reverse-engineered
    by cross-referencing MSVC's own real (and realistically-public --
    shipped in ``VC/Tools/MSVC/<ver>/include/ehdata4_export.h`` alongside
    cl.exe itself) struct/format definitions for ``FuncInfo4``,
    ``UnwindMapEntry4``, ``TryBlockMapEntry4`` and ``HandlerType4`` against
    (a) ``dumpbin /unwindinfo`` and ``/disasm`` on a real MSVC-14.51
    (VS2026)-compiled self-contained-throw/catch fixture, (b) the exact
    COMDAT-relocation list (``dumpbin /relocations``) of several
    deliberately differently-shaped EH functions compiled fresh for this
    investigation, and (c) a tiny harness calling MSVC's own
    ``FH4::DecompFuncInfo``/``ReadUnsigned`` (from that same header)
    directly against the compiled bytes via
    ``LoadLibraryExA(..., LOAD_LIBRARY_AS_IMAGE_RESOURCE)``. All three
    agree on the exact byte layout implemented by ``_fh4_parse_func_info4``
    and its helpers above.

    Deliberately does NOT try to identify __CxxFrameHandler4 (or its
    stack-cookie-checking wrapper, __GSHandlerCheck_EH4, which has the
    exact same FuncInfo4-pointer-after-handler layout) by name/import --
    this fixture's own build statically links it in with no
    vcruntime140.dll dependency at all, so there's no import entry to
    resolve against. Instead, it *structurally* validates the data at
    `disp_off` before touching anything: `_fh4_parse_func_info4` and its
    helpers bounds-check every read, cap every entry count, and check
    FuncInfoHeader's documented-always-zero reserved bit; if any of that
    comes back wrong, this is firmly NOT __CxxFrameHandler4-shaped data
    (e.g. it's __CxxFrameHandler3's magic-number-prefixed legacy format,
    plain SEH, or something else again), and this function leaves it
    completely untouched -- the same fail-safe behavior this module
    already has for anything it doesn't confidently understand. Patches
    are collected into a full list *before* any byte is written, so a
    failure partway through a function's FuncInfo4 can't leave it
    half-patched either.

    `patched` is the set of absolute `blob` byte-offsets already shifted
    by this dependency's unwind-info pass (shared across every
    RUNTIME_FUNCTION entry via `_collect_and_patch_dep_unwind`): the
    linker can comdat-fold an identical FuncInfo4 (or a shared
    sub-structure within it) across multiple distinct functions, so
    without this guard a shared blob reachable from more than one
    RUNTIME_FUNCTION entry would get `+shift` applied once per entry that
    reaches it, corrupting it.

    `module_ranges` (this dependency's own section VA ranges, built once
    by `_collect_and_patch_dep_unwind`) backs the one validation check
    that turned out to matter most in practice -- see
    `_fh4_rva_in_module`'s docstring for the real false-positive this
    caught on a plain (non-C++) MSVC-built dependency: bounds-checking
    against `len(blob)` and FuncInfoHeader's reserved bit alone was
    nowhere near enough to reject other personality routines' data.
    """
    if disp_off + 4 > len(blob):
        return
    (fi_rva,) = struct.unpack_from("<I", blob, disp_off)
    if not fi_rva or not _fh4_rva_in_module(fi_rva, module_ranges):
        return
    try:
        patches = [disp_off] + _fh4_parse_func_info4(blob, fi_rva, module_ranges)
    except _FH4ParseError:
        return
    for off in patches:
        if off in patched:
            continue
        (value,) = struct.unpack_from("<I", blob, off)
        if value:
            struct.pack_into("<I", blob, off, value + shift)
        patched.add(off)


def _adjust_unwind_info(blob: bytearray, unwind_rva: int, shift: int,
                         module_ranges: List["tuple[int, int]"], _depth: int = 0,
                         _patched: Optional[Set[int]] = None) -> None:
    """Patch the RVA-relative fields *inside* an x64 UNWIND_INFO structure
    (and any chained UNWIND_INFO it references) by `shift`, in place
    within `blob`, at the structure's *original* (pre-shift) offset.

    Two kinds of fields inside UNWIND_INFO proper are themselves RVAs (and
    so need the same "+shift" treatment as the RUNTIME_FUNCTION entries
    that point at them -- see _collect_and_patch_dep_unwind): a trailing
    exception-handler RVA (present when UNW_FLAG_EHANDLER/UHANDLER is set
    -- this is what the OS actually calls to run a C++ personality
    routine/__except filter when an exception unwinds through the
    function) and a chained RUNTIME_FUNCTION record (when
    UNW_FLAG_CHAININFO is set, itself recursed into). The unwind-code
    array itself is already correct after a flat block move, needing no
    adjustment.

    Language-specific exception data following the handler RVA is, for
    most personality routines (e.g. GCC/MinGW's LSDA/call-site table,
    which encodes everything self-relative/pcrel), *also* already correct
    unmodified -- but NOT univerally: see
    ``_adjust_cxx_frame_handler4_funcinfo`` for the one confirmed
    exception, MSVC's __CxxFrameHandler4, whose own further data this
    function hands off to it for every EHANDLER/UHANDLER entry (a no-op,
    confirmed by that function's own structural validation, for any
    personality routine that isn't __CxxFrameHandler4-shaped).
    """
    if _patched is None:
        _patched = set()
    if unwind_rva == 0 or unwind_rva + 4 > len(blob) or _depth > 32:
        return
    if unwind_rva in _patched:
        # Already visited via another RUNTIME_FUNCTION entry that shares
        # this exact UNWIND_INFO -- the linker's comdat folding can (and,
        # confirmed against frida-gadget's own real, large x64 DLL, in
        # practice does) make many distinct functions' entries all point
        # at one shared UNWIND_INFO, directly or by chaining to it. Without
        # this check, every one of those entries would re-run the `+shift`
        # patch below on the exact same bytes -- not a no-op repeat (unlike
        # ordinary relocation, which is idempotent by nature), but a
        # second, third, ... genuine additional `+shift`, so a
        # sufficiently-shared chain eventually overflows its own DWORD
        # field (`struct.error: 'I' format requires 0 <= number <=
        # 4294967295`) once the repeat count is high enough -- exactly
        # the real crash this guards against, not a hypothetical one.
        return
    _patched.add(unwind_rva)
    version_flags = blob[unwind_rva]
    flags = (version_flags >> 3) & 0x1F
    count_of_codes = blob[unwind_rva + 2]
    codes_size = ((count_of_codes + 1) & ~1) * 2
    extra_off = unwind_rva + 4 + codes_size

    if flags & _UNW_FLAG_CHAININFO:
        if extra_off + 12 > len(blob):
            return
        cbegin, cend, cunwind = struct.unpack_from("<III", blob, extra_off)
        _adjust_unwind_info(blob, cunwind, shift, module_ranges, _depth + 1, _patched)
        struct.pack_into(
            "<III", blob, extra_off,
            cbegin + shift, cend + shift, (cunwind + shift) if cunwind else 0,
        )
    elif flags & (_UNW_FLAG_EHANDLER | _UNW_FLAG_UHANDLER):
        if extra_off + 4 > len(blob):
            return
        (handler,) = struct.unpack_from("<I", blob, extra_off)
        if handler:
            struct.pack_into("<I", blob, extra_off, handler + shift)
        _adjust_cxx_frame_handler4_funcinfo(blob, extra_off + 4, shift, _patched, module_ranges)


#: Fixed on-disk sizes (bytes) of the x64 (``_EH_RELATIVE_TYPEINFO=1``)
#: ``_s_ThrowInfo``/``_s_CatchableType`` structs -- see
#: ``ehdata_forceinclude.h`` (shipped with MSVC, force-included into
#: every C++ TU it compiles -- about as public as this project's own
#: on-disk-format references get) for the real struct definitions these
#: mirror. Both are fixed-size (``#pragma pack(push, ehdata, 4)``, no
#: compressed-int fields at all, unlike FuncInfo4) so no parser is needed
#: beyond plain offsets.
_THROWINFO_SIZE = 16  # attributes(4) + pmfnUnwind(4) + pForwardCompat(4) + pCatchableTypeArray(4)
_CATCHABLE_TYPE_SIZE = 28  # properties(4) + pType(4) + thisDisplacement[3](12) + sizeOrOffset(4) + copyFunction(4)
_CATCHABLE_TYPE_PTYPE_OFF = 4
_CATCHABLE_TYPE_COPYFUNC_OFF = 24
_MAX_CATCHABLE_TYPES = 256  # a real throw site lists a small handful at most (one per qualifier variant)


def _fh4_relocate_throw_info(blob: bytearray, rva: int, shift: int, patched: Set[int],
                              module_ranges: List["tuple[int, int]"]) -> bool:
    """Validates and, if it checks out, relocates one ``_ThrowInfo`` blob
    (MSVC's per-throw-site "description of the thrown object" -- see
    ``ehdata_forceinclude.h``'s own long comment on it) and the
    ``CatchableTypeArray``/``CatchableType`` chain it points to, all of
    which embed further module-relative RVAs needing the same ``+shift``
    treatment as everything else this module patches.

    This is a *second*, independent gap from __CxxFrameHandler4's
    FuncInfo4 (see ``_adjust_cxx_frame_handler4_funcinfo``), discovered
    by debugging *why* a self-contained throw/catch still crashed after
    FuncInfo4 relocation alone: real-execution debugging (WinDbg/cdb
    against the actual embedded, crashing binary -- breakpointing
    __CxxFrameHandler4 itself, confirming it ran exactly once on the
    exception's first (search) pass and declined to handle it) showed
    the *search* itself failing, not the unwind/invoke step FuncInfo4
    governs. __CxxFrameHandler4's ``TypeMatch`` compares the thrown
    type's ``CatchableType.pType``-pointed ``TypeDescriptor`` against the
    catch's (correctly-relocated) ``HandlerType4.dispType``-pointed one --
    by *dereferencing both and comparing the decorated name string*, not
    by raw pointer identity (consistent with needing to match identical
    types declared in different modules/DLLs). Since nothing relocated
    ``_ThrowInfo``/``CatchableTypeArray``/``CatchableType`` before this,
    the thrown side's ``pType`` was still the dependency's *original*
    (pre-embed) RVA -- which, in the merged image, now points at
    unrelated bytes -- so the name comparison read garbage and never
    matched, exactly reproducing the observed "search pass declines, no
    second invocation, unhandled exception" behavior.

    Unlike FuncInfo4, ``_ThrowInfo`` has no directory anywhere that lists
    every instance -- it's pure ``.rdata``, reachable only from the
    *code* at each throw site (as the 2nd argument to
    ``_CxxThrowException``), so there's no clean, directory-driven way to
    enumerate every one the way ``_adjust_unwind_info`` enumerates
    RUNTIME_FUNCTION entries. `rva` here is only ever a *candidate*,
    handed in by a narrow instruction-pattern scan (see
    ``_fh4_scan_for_throw_info_candidates``) that itself can misfire on
    coincidental byte sequences -- so, same spirit as
    ``_fh4_parse_func_info4``, every field is structurally validated
    (bounds, a plausible small ``nCatchableTypes``, every nested RVA
    landing inside some real module section) *before* anything is
    trusted enough to patch; a candidate that doesn't fully check out is
    left completely untouched and this returns False.
    """
    if not rva or not _fh4_rva_in_module(rva, module_ranges) or rva + _THROWINFO_SIZE > len(blob):
        return False
    _attributes, pmfn_unwind, p_forward_compat, p_catchable_array = struct.unpack_from("<Iiii", blob, rva)
    if pmfn_unwind and not _fh4_rva_in_module(pmfn_unwind, module_ranges):
        return False
    if p_forward_compat and not _fh4_rva_in_module(p_forward_compat, module_ranges):
        return False
    if not p_catchable_array or not _fh4_rva_in_module(p_catchable_array, module_ranges):
        return False
    if p_catchable_array + 4 > len(blob):
        return False
    (num_catchable,) = struct.unpack_from("<i", blob, p_catchable_array)
    if not (0 < num_catchable <= _MAX_CATCHABLE_TYPES):
        return False
    array_off = p_catchable_array + 4
    if array_off + 4 * num_catchable > len(blob):
        return False
    catchable_rvas = struct.unpack_from(f"<{num_catchable}i", blob, array_off)
    for ct_rva in catchable_rvas:
        if not ct_rva or not _fh4_rva_in_module(ct_rva, module_ranges):
            return False
        if ct_rva + _CATCHABLE_TYPE_SIZE > len(blob):
            return False
        (p_type,) = struct.unpack_from("<i", blob, ct_rva + _CATCHABLE_TYPE_PTYPE_OFF)
        if not p_type or not _fh4_rva_in_module(p_type, module_ranges):
            return False

    patches = [rva + 4, rva + 8, rva + 12, p_catchable_array]  # pmfnUnwind, pForwardCompat, pCatchableTypeArray, nCatchableTypes's array
    for i, ct_rva in enumerate(catchable_rvas):
        patches.append(array_off + i * 4)
        patches.append(ct_rva + _CATCHABLE_TYPE_PTYPE_OFF)
        patches.append(ct_rva + _CATCHABLE_TYPE_COPYFUNC_OFF)
    for off in patches:
        if off in patched:
            continue
        (value,) = struct.unpack_from("<i", blob, off)
        if value:
            struct.pack_into("<i", blob, off, value + shift)
        patched.add(off)
    return True


def _fh4_scan_for_throw_info_candidates(blob: bytearray, begin: int, end: int) -> List[int]:
    """Scans the narrow, already-known ``[begin, end)`` byte range of one
    function (a RUNTIME_FUNCTION entry's own BeginAddress/EndAddress --
    this is always called with those, never a blind whole-section scan)
    for `_CxxThrowException(void* object, _ThrowInfo* pThrowInfo)`'s
    exact, unambiguous x64-calling-convention call shape: ``pThrowInfo``
    (the 2nd argument -- RDX in the Microsoft x64 calling convention) is
    always loaded via a RIP-relative LEA, since it's always a static,
    per-throw-site ``.rdata`` blob, never a computed/dynamic address --
    ``48 8D 15 <disp32>`` (``LEA RDX, [RIP+disp32]``, the only encoding of
    "load RDX via RIP-relative LEA": REX.W + opcode 0x8D + ModRM 0x15 is
    mod=00/reg=010(RDX)/rm=101(RIP-relative), and REX.R would change the
    destination register away from RDX) -- followed, within a short
    window, by a direct ``E8 <rel32>`` CALL.

    Same spirit, and the same honestly-documented caveat, as this
    module's existing ``_patch_dep_tls_access_offsets``: this recognizes
    one exact, real, MSVC-x64-compiler-generated byte shape via a plain
    byte scan (no disassembler, so no instruction-boundary awareness --
    a coincidental match inside a longer, unrelated instruction is
    possible in principle), not a general-purpose instruction decoder.
    It is deliberately narrow in scope, not a generic "find every throw
    in this module" scanner: restricting it to one already-known
    function's own byte range (rather than scanning the whole section)
    both keeps false positives rare in practice and keeps this cheap.
    Every resulting candidate is independently, structurally validated
    by ``_fh4_relocate_throw_info`` before anything is trusted -- a
    misfire here (a coincidental 3-byte match that isn't really this
    instruction) fails that validation and is silently skipped, same as
    any other not-confidently-understood data in this module.
    """
    window = 24
    candidates = []
    i = begin
    limit = min(end, len(blob))
    while i + 7 <= limit:
        if blob[i] == 0x48 and blob[i + 1] == 0x8D and blob[i + 2] == 0x15:
            (disp,) = struct.unpack_from("<i", blob, i + 3)
            target = i + 7 + disp
            j = i + 7
            window_end = min(j + window, limit - 5, len(blob) - 5)
            found_call = False
            while j <= window_end:
                if blob[j] == 0xE8:
                    found_call = True
                    break
                j += 1
            if found_call and 0 <= target < len(blob):
                candidates.append(target)
            i += 7
        else:
            i += 1
    return candidates


def _collect_and_patch_dep_unwind(dep: "pefile.PE", blob: bytearray, shift: int) -> List[tuple]:
    """Returns this dependency's own RUNTIME_FUNCTION entries (the
    IMAGE_DIRECTORY_ENTRY_EXCEPTION/".pdata" table x64 PE images carry,
    one per function with unwind info), each of the 3 RVA fields -- start,
    end, unwind-info -- shifted by `shift` to match where `blob`'s bytes
    end up once placed at host RVA `shift` (mirroring the reloc-delta
    treatment applied to the dependency's own base relocations elsewhere
    in embed(), but for these never-base-relocation-listed, pure-RVA
    references -- see _adjust_unwind_info's docstring for why that's
    needed at all). Also patches `blob`'s own copy of these fields (and
    whatever _adjust_unwind_info finds past each UnwindInfoAddress) in
    place, so `blob`'s internal .pdata/.xdata stay consistent too -- not
    just the merged copy this returns, which the caller appends into the
    host's own (combined) exception directory.

    No-op (returns []) for a dependency with no exception directory at
    all -- the common case for x86 (32-bit) PE images, which don't use
    this table-based unwind mechanism.

    One `_patched` offset-set is shared across every RUNTIME_FUNCTION
    entry processed here (not just within one call to
    ``_adjust_unwind_info``): the linker can comdat-fold a UNWIND_INFO's
    chained parent, or a __CxxFrameHandler4 FuncInfo4 (or one of its own
    sub-structures), across multiple distinct functions, so a single
    shared blob reachable from more than one entry in this loop must
    still only ever get `+shift` applied to it once.

    Also builds this dependency's own section VA-range table once here
    (rather than inside ``_adjust_unwind_info``'s recursion, which may
    visit many entries) and threads it down to
    ``_adjust_cxx_frame_handler4_funcinfo`` -- see
    ``_fh4_rva_in_module``'s docstring for what it's for and why it's
    load-bearing, not an extra nice-to-have.

    Also, for every entry here (regardless of its own UNWIND_INFO flags
    -- a function can call ``_CxxThrowException`` without having any
    try/catch of its own), scans that function's own byte range for a
    throw site and relocates its ``_ThrowInfo`` -- see
    ``_fh4_scan_for_throw_info_candidates``/``_fh4_relocate_throw_info``
    for why that's a second, independent gap from FuncInfo4 and a
    necessary one for a self-contained throw+catch to actually work once
    embedded, not an optional extra.
    """
    excdir = dep.OPTIONAL_HEADER.DATA_DIRECTORY[_IMAGE_DIRECTORY_ENTRY_EXCEPTION]
    if not excdir.Size:
        return []
    entries = []
    base = excdir.VirtualAddress
    patched: Set[int] = set()
    module_ranges = [
        (section.VirtualAddress, section.VirtualAddress + max(section.Misc_VirtualSize, section.SizeOfRawData))
        for section in dep.sections
        if section.Misc_VirtualSize or section.SizeOfRawData
    ]
    for i in range(excdir.Size // 12):
        off = base + i * 12
        if off + 12 > len(blob):
            break
        begin, end, unwind = struct.unpack_from("<III", blob, off)
        if begin == 0 and end == 0 and unwind == 0:
            continue
        _adjust_unwind_info(blob, unwind, shift, module_ranges, _patched=patched)
        for throw_info_rva in _fh4_scan_for_throw_info_candidates(blob, begin, end):
            _fh4_relocate_throw_info(blob, throw_info_rva, shift, patched, module_ranges)
        new_begin, new_end = begin + shift, end + shift
        new_unwind = (unwind + shift) if unwind else 0
        struct.pack_into("<III", blob, off, new_begin, new_end, new_unwind)
        entries.append((new_begin, new_end, new_unwind))
    return entries


def _try_patch_mingw_style_tls_access(
    blob: bytearray, anchor_begin: int, tls_index_load_end: int, limit: int, shift: int
) -> bool:
    """mingw-w64's compiled idiom for the final, variable-specific part of
    a `__declspec(thread)`/`__thread` access: once `_tls_index`'s value
    has been loaded and combined with `TEB.ThreadLocalStoragePointer`
    into this module's own per-thread block pointer, the link-time
    constant offset to this one specific TLS variable is baked directly
    into *this* access instruction's own disp32 field:

        mov/  r32, [r64+disp32]      ; <- disp32 is the one to shift
         mov      [r64+disp32], r32

    Scans forward from `tls_index_load_end` (where the `_tls_index` load
    matched by the caller ends) through a short, bounded window for the
    first instruction matching that exact shape (``8B``/``89`` opcode,
    ModRM mod=10 i.e. disp32-sized displacement, rm!=100 i.e. a plain
    base register with no SIB byte) and shifts its disp32 in place.
    `anchor_begin` is unused here (mingw's idiom never needs to look
    behind the `_tls_index` load) -- it's only part of this function's
    signature so every entry in `_KNOWN_DEP_TLS_ACCESS_PATTERNS` shares
    one call shape. Returns whether a match was found and patched.
    """
    j = tls_index_load_end
    window_end = min(j + 32, limit - 6, len(blob) - 6)
    while j <= window_end:
        op = blob[j]
        if op in (0x8B, 0x89) and (blob[j + 1] & 0xC0) == 0x80 and (blob[j + 1] & 0x07) != 0x04:
            disp_off = j + 2
            cur = int.from_bytes(blob[disp_off:disp_off + 4], "little", signed=True)
            blob[disp_off:disp_off + 4] = (cur + shift).to_bytes(4, "little", signed=True)
            return True
        j += 1
    return False


# The fixed tail of `mov r64, qword ptr gs:[0x58]` (TEB.ThreadLocalStoragePointer,
# a 9-byte instruction: `65` GS-segment prefix, REX.W (`48`/`4C`), `8B`, a ModRM
# selecting the destination register with rm=100 (SIB follows), then this SIB
# byte (`25` = scale 00, index 100 "none", base 101 "disp32 only, no base reg")
# and the little-endian disp32 `0x58`). This exact tail is identical no matter
# which register is the destination, and -- unlike `_tls_index`'s own load --
# identical across every compiler: it's the one truly compiler-independent
# instruction in a compiled `__declspec(thread)`/`__thread` access, so it's
# used below purely as corroboration (never as the thing being patched).
_TEB_TLS_POINTER_GS_TAIL = b"\x25\x58\x00\x00\x00"


def _try_patch_msvc_style_tls_access(
    blob: bytearray, anchor_begin: int, tls_index_load_end: int, limit: int, shift: int
) -> bool:
    """MSVC's compiled idiom for the same final, variable-specific part
    of a `__declspec(thread)`/`__thread` access -- confirmed against
    real `cl.exe`-compiled x64 output (both an unoptimized and an `/O2`
    build), and genuinely different from mingw-w64's, above: MSVC never
    bakes the offset into the final access instruction's own disp32 at
    all. Instead, the final access is SIB-addressed with no
    displacement at all (`mov r32, [base_reg + offset_reg]` / `inc
    dword ptr [base_reg + offset_reg]`, etc.), and the offset constant
    instead lives in a separate, nearby `mov r32, imm32` (opcode
    0xB8-0xBF, optionally preceded by a single REX prefix byte with
    REX.W clear -- REX.W set would make this a different, 10-byte
    `mov r64, imm64` instruction, not this one) that loads it into the
    register later used as that SIB offset. For example (`/O2`,
    this project's own locally-compiled test case):

        mov   edx, [rip+disp32]      ; load _tls_index's current value
        mov   rcx, gs:0x58           ; TEB.ThreadLocalStoragePointer
        mov   r8d, 4                 ; <- the offset to shift lives here
        mov   rax, [rcx+rdx*8]       ; this module's own per-thread block
        inc   dword ptr [rax+r8]     ; no disp32 at all -- r8 carries it

    and, unoptimized, the same `mov r32, imm32` can instead appear
    *before* the `_tls_index` load rather than after it -- so this
    searches a bounded window on both sides of the anchor
    (`anchor_begin`/`tls_index_load_end`), not just forward like the
    mingw-w64 pattern above. The gap between the anchor (or the TEB load)
    and the real offset-load varies in practice -- sometimes zero bytes,
    sometimes several other instructions -- so position relative to the
    anchor or the TEB load alone is *not* trustworthy corroboration (see
    below for why).

    `mov r32, imm32` alone is far too generic a byte shape to trust on
    its own (it's an extremely common instruction for entirely unrelated
    reasons) -- and neither is "exists somewhere near a `mov r64,
    gs:[0x58]` access", which was this function's original corroboration
    and is still too weak: real-world testing (both against SHLWAPI.dll
    and SHELL32.dll's own compiled TLS access) found false matches on
    coincidental 0xB8-0xBF bytes inside *other*, unrelated instructions'
    own encoding sitting in the same window, well before a scan ever
    reached the real offset-load. Instead, a candidate is only accepted
    when it's immediately (zero-gap) followed by the one instruction
    shape every real compiled access in every case actually observed
    shares right after loading the offset: a scale-8 SIB-addressed load
    using that offset's register as part of the per-thread-block address
    computation --
    `REX.W [40+8] 8B modrm(mod=00,rm=100=SIB) sib(scale=11)` -- e.g.
    `48 8B 04 C8` (`mov rax, [rax+rcx*8]`) or `4C 8B 04 D0`
    (`mov r8, [rax+rdx*8]`). This is a far stronger, local signal than
    "a `gs:[0x58]` access somewhere in a wide window" (which, since real
    functions often reuse an already-loaded per-thread-block pointer
    across several variable accesses without re-fetching it, isn't even
    always present near a given real call site -- confirmed for real:
    one of SHELL32.dll's own TLS accesses has no `gs:[0x58]` load
    anywhere nearby at all) and, empirically, is never satisfied by
    either confirmed false match.

    Re-reviewed and confirmed NOT a gap: an extended-register load of
    `_tls_index` (r8d-r15d, via a REX prefix immediately before the `8B`
    opcode) still matches the caller's own anchor check -- that check
    masks only the ModRM reg-field bits (`blob[i+1] & 0xC7 == 0x05`),
    which is unaffected by a preceding REX byte, and the disp32-relative
    target-RVA math is REX-position-independent too. Hand-verified by
    encoding `mov r9d,[rip+disp32]` (`44 8B 0D <disp32>`) and tracing it
    through the matcher. Every real-world and locally compiled case seen
    so far loads it into eax/ecx/edx anyway, but the extended-register
    case was never actually unreachable.
    """
    win_begin = max(0, anchor_begin - 32)
    win_end = min(limit, tls_index_load_end + 32, len(blob))

    def _is_scale8_sib_load(pos: int) -> bool:
        """True if `blob[pos:pos+4]` is `REX.W 8B modrm sib` with the
        ModRM selecting a SIB byte and no displacement (mod=00, rm=100)
        and that SIB byte's own scale field selecting *8 (its top two
        bits, `0b11`) -- the "index this module's own per-thread block by
        (register)*8" instruction every real offset-load observed so far
        is immediately followed by, regardless of which registers it
        uses (R/X/B extension bits in the REX byte, or the SIB's own
        index/base register fields, are deliberately not checked here --
        irrelevant to this specific shape)."""
        if pos + 4 > len(blob):
            return False
        return (
            0x48 <= blob[pos] <= 0x4F  # REX.W set (bit 0x08), R/X/B don't matter
            and blob[pos + 1] == 0x8B
            and (blob[pos + 2] & 0xC7) == 0x04  # ModRM: mod=00, rm=100 (SIB follows)
            and (blob[pos + 3] & 0xC0) == 0xC0  # SIB: scale=11 (*8)
        )

    j = win_begin
    while j <= win_end - 5:
        # Never start decoding inside the anchor's own 6 bytes (opcode +
        # ModRM + disp32) -- that disp32 is an arbitrary RIP-relative
        # displacement with no structural meaning as machine code, yet a
        # byte-level scan walking straight through it can still land on a
        # byte that happens to fall in 0xB8-0xBF. Confirmed for real
        # against SHLWAPI.dll: a disp32 of 0x0005bde2 has 0xbd as its
        # second byte, squarely in range, and the resulting false match's
        # 4 "immediate" bytes straddled the anchor's own trailing disp32
        # bytes *and* the start of the next real instruction, corrupting
        # both when shifted.
        if anchor_begin <= j < tls_index_load_end:
            j = tls_index_load_end
            continue
        op = blob[j]
        rex_len = 0
        opcode = op
        if 0x40 <= op <= 0x47:  # REX prefix, W clear (W set -> imm64, a different instruction)
            if j + 1 >= len(blob):
                break
            rex_len = 1
            opcode = blob[j + 1]
        if 0xB8 <= opcode <= 0xBF:
            imm_off = j + rex_len + 1
            imm_end = imm_off + 4
            if imm_end <= len(blob) and _is_scale8_sib_load(imm_end):
                cur = int.from_bytes(blob[imm_off:imm_off + 4], "little", signed=True)
                blob[imm_off:imm_off + 4] = (cur + shift).to_bytes(4, "little", signed=True)
                return True
        j += 1
    return False


# Tried, in order, for every `_tls_index`-load call site found below. Each
# entry recognizes one compiler's own compiled shape for the final,
# variable-specific part of a `__declspec(thread)`/`__thread` access (see
# each one's own docstring); a third compiler's idiom, if one is ever found
# to differ from both of these, belongs here as a new entry, not as a
# special case folded into either existing function.
_KNOWN_DEP_TLS_ACCESS_PATTERNS = [
    _try_patch_mingw_style_tls_access,
    _try_patch_msvc_style_tls_access,
]


def _patch_dep_tls_access_offsets(
    blob: bytearray, dep_index_rva: int, shift: int
) -> Tuple[int, int]:
    """TLS phase 2's last remaining piece of real byte-level surgery:
    find every compiled access to *this dependency's own* TLS variable(s)
    inside `blob` and shift its embedded, compile-time-fixed offset (into
    the per-thread TLS block) by `shift` -- the size of the host's own
    raw TLS data, now prepended ahead of this dependency's own in the
    combined raw-data range pe_embedder.py's phase-2 block builds (see
    its own long comment for the full picture).

    Why this can't be avoided (and isn't covered by any ordinary PE base
    relocation, unlike nearly everything else this module patches): the
    x64/x86 mingw-w64 and MSVC compiled idiom for `__declspec(thread)`/
    `__thread` access reads the *value* of a global `_tls_index`
    variable (that part *is* just an ordinary pointer-sized global, fully
    handled by `build_windows_tls_index_fixup`), but the *offset* added
    to the resulting per-thread block pointer to reach any one specific
    TLS variable is a small link-time constant -- (that variable's own
    RVA) minus (its *own* module's TLS directory's own
    StartAddressOfRawData), baked directly into the instruction as an
    immediate, by design *not* relocation-covered (it doesn't change
    when the whole module is relocated by a uniform delta, which is
    exactly why it normally needs no fixup at all -- just not in this
    one case, where the per-thread block's own *layout* is being changed
    out from under it).

    Both mingw-w64 and MSVC load `_tls_index`'s current value the same
    way -- a RIP-relative 32-bit load, `mov r32, [rip+disp32]`, where
    `disp32` resolves to `_tls_index`'s own RVA -- and this still walks
    `blob` for exactly that instruction (an exact, unambiguous match,
    not a heuristic) as the shared anchor for both compilers' idioms.
    From there, the two compilers diverge in how the *variable-specific*
    offset itself is encoded -- see `_try_patch_mingw_style_tls_access`
    and `_try_patch_msvc_style_tls_access`'s own docstrings for each
    compiler's real, locally-confirmed compiled shape. Each entry in
    `_KNOWN_DEP_TLS_ACCESS_PATTERNS` is tried in order per anchor match;
    the first one that finds and shifts its offset wins. This is still a
    real, if narrow, binary-pattern dependency -- it recognizes exactly
    these compiler-generated shapes and nothing else; a third compiler's
    codegen for the same source-level construct would need its own
    pattern added to that list. Returns `(patched, anchors_found)` --
    `anchors_found` is how many `_tls_index` load sites exist at all,
    `patched` is how many of those this function was confident enough to
    actually shift. The caller should treat `patched < anchors_found`
    (not just `patched == 0`) as the merge being unsupported for this
    dependency: every anchor found genuinely does need its own offset
    shifted somewhere, and silently leaving even one unshifted means that
    one specific TLS variable's access reads/writes the wrong location
    after the merge -- just as real a correctness bug as patching the
    wrong bytes, only quieter. Deliberately conservative on purpose: each
    pattern in `_KNOWN_DEP_TLS_ACCESS_PATTERNS` only accepts a candidate
    it has real, strong, local corroboration for (see each one's own
    docstring), so a genuine compiled shape neither pattern recognizes
    yet fails this count rather than risk a wrong guess.
    """
    patched = 0
    anchors_found = 0
    n = len(blob)
    i = 0
    while i + 6 <= n:
        if blob[i] == 0x8B and (blob[i + 1] & 0xC7) == 0x05:
            disp = int.from_bytes(blob[i + 2:i + 6], "little", signed=True)
            if i + 6 + disp == dep_index_rva:
                anchors_found += 1
                j = i + 6
                for try_pattern in _KNOWN_DEP_TLS_ACCESS_PATTERNS:
                    if try_pattern(blob, i, j, n, shift):
                        patched += 1
                        break
                i = j
                continue
        i += 1
    return patched, anchors_found


class PortableExecutableEmbedder:
    def __init__(self, input_path: Path, output_path: Path, exclude: Set[str], lib_dir: Optional[Path]):
        self.input_path = Path(input_path)
        self.output_path = Path(output_path)
        self.exclude = exclude
        self.lib_dir = lib_dir

    def _search_dirs(self) -> List[Path]:
        if self.lib_dir is not None:
            return [self.lib_dir]
        windir = Path(os.environ.get("WINDIR", r"C:\Windows"))
        return [self.input_path.parent, windir / "System32", windir / "SysWOW64"]

    def embed(self) -> None:
        """Embed every embeddable dependency (per Task 1's dependency graph)
        into the host, reloc-bearing (PIC) path only.

        Mechanism, per dependency (in dependencies-first order):
          1. Copy its mapped image (all sections, laid out at their own
             relative offsets) into a new host section at a freshly chosen
             RVA `X`.
          2. Apply the dependency's own base relocations against that new
             placement (delta = (host ImageBase + X) - dep ImageBase).
          3. For each of the host's imports of this dependency, resolve the
             matching export and patch the host's IAT slot in place with the
             resolved absolute address; record that slot (and every
             relocation applied in step 2) as a *new* host relocation entry,
             so the whole thing stays correct if the final image is itself
             relocated at load time.
          4. Remove the dependency's IMAGE_IMPORT_DESCRIPTOR from the host's
             import directory (building a fresh combined descriptor array
             in a new section and repointing the data directory, rather than
             editing the original array in place, since growing it in place
             isn't generally safe).
          5. Merge the dependency's own *remaining* (external, not-embedded)
             imports into that same fresh combined import directory, so its
             own runtime needs (e.g. CRT startup calling KERNEL32/msvcrt)
             keep resolving correctly.
          6. Copy the dependency's own IMAGE_DIRECTORY_ENTRY_EXCEPTION
             (".pdata"/x64 unwind-info) entries alongside its relocated
             code, with every RVA field they (and the UNWIND_INFO
             structures in ".xdata" they point at) carry rewritten to
             match -- see ``_collect_and_patch_dep_unwind`` -- then merge
             them into the host's own exception directory (combined with
             its existing entries, sorted by start RVA, as the ABI
             requires), so unwinding (a C++ exception, or SEH) still works
             correctly across the newly embedded code.
          7. Generate the new entrypoint stub (``build_windows_stub``):
             one DllMain-style process-attach call per embedded dependency
             with an entry point, in dependencies-first order, then a
             tail-jump to the host's original entrypoint.

        For a dependency that carries no relocation data at all (a fixed-
        base/non-PIC build), step 1's placement differs: instead of
        appending it at the next free RVA, it's placed at the one RVA that
        makes ``host ImageBase + RVA`` exactly equal to that dependency's
        own preferred ``ImageBase`` -- so none of its hardcoded absolute
        addresses need step 2's relocation-application at all. That address
        range is checked first against the host's own image (and anything
        already placed there) and against every other dependency reserved
        the same way, raising ``ValueError`` on any overlap. Steps 3-7
        proceed identically either way (including step 6's +RVA-shift
        unwind-info patching, which is independent of whether the
        dependency's *other* references needed delta-relocation at all --
        see ``_adjust_unwind_info``'s docstring).

        Step 7's stub also installs the design doc's LoadLibraryW/
        LoadLibraryA/GetProcAddress interception mechanism, on an x64 host
        with at least one embedded dependency that has its own entry
        point (see ``staticer/stubs/windows/pe_stub.py``'s module
        docstring's "Hook mechanism" section for the full design, and this
        method's own long comment just above its ``build_windows_stub``
        call site for exactly how the data/trampolines/install code are
        built here). Known, deliberate scope limits -- not yet fixed,
        tracked in ``docs/limitations.md``:

        * 32-bit (x86) hosts get no hook at all -- this mechanism's
          trampolines and install code are x64 machine code only, matching
          every other recently-added stub in ``pe_stub.py``.
        * This intercepts explicit, application-level LoadLibrary*/
          GetProcAddress calls, not the OS loader's own *internal*
          resolution of a module's statically-compiled import table while
          mapping that module -- a module loaded dynamically by name
          (which this hook does see) that itself statically imports one of
          this run's embedded dependencies by name is NOT thereby
          redirected to the embedded copy; the loader's own internal
          import-table walk never calls through any IAT slot this hook can
          see or overwrite. See ``docs/limitations.md`` for the real-world
          case (010 Editor's Qt platform plugin) this was confirmed
          against.
        * A hooked GetProcAddress only resolves exports this project could
          already resolve at embed time -- a forwarded export whose target
          DLL isn't itself embedded this run is left out of that module's
          own runtime table (returning ``NULL``, matching a real "not
          found"), mirroring this project's existing delay-import forward-
          resolution fallback elsewhere.
        """
        search_dirs = self._search_dirs()
        graph = build_dependency_graph(
            self.input_path, _list_pe_import_graph_edges, resolve_pe, search_dirs, self.lib_dir,
            _CaseInsensitiveNameSet(self.exclude),
        )
        # allow_cycles=True: a real, confirmed cycle can exist among
        # embeddable PE dependencies purely through export forwarding (see
        # `global_raw_exports_by_dll`'s own comment below, and
        # test_second_real_binary_full_closure) -- e.g. WS2_32.dll's own
        # import table imports MSWSOCK.dll, while WS2_32.dll ALSO forwards
        # some exports TO MSWSOCK.dll. The per-dependency loop below never
        # reads another not-yet-processed node's blob/export table/
        # placement inline -- every cross-dependency need (host-IAT
        # patches, dependency-to-dependency IAT patches, export-forward
        # resolution) is deferred to a finalize pass that runs only after
        # every node in `order` has been placed -- so there is no real
        # correctness requirement on a strict total order here, just
        # determinism. `elf_embedder.py` calls the same shared
        # `embed_order` without this flag and keeps the strict, cycle-
        # raising default.
        order = embed_order(graph, allow_cycles=True)

        if not order:
            self.output_path.write_bytes(self.input_path.read_bytes())
            return

        pe = pefile.PE(str(self.input_path), max_symbol_exports=_MAX_SYMBOL_EXPORTS)
        try:
            # See `list_pe_imports`'s comment: `pefile.PE(...)` already fully
            # parses every data directory at construction -- re-parsing
            # here would silently corrupt the import-descriptor walk for
            # some real-world binaries (confirmed via local testing against
            # 010 Editor, a dense Qt6 PE).

            host_machine = pe.FILE_HEADER.Machine
            if host_machine not in _SUPPORTED_MACHINES:
                raise ValueError(
                    f"unsupported host architecture {hex(host_machine)}; only "
                    f"{tuple(hex(m) for m in _SUPPORTED_MACHINES)} are supported"
                )
            is64 = host_machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]
            ptr_size = 8 if is64 else 4
            image_base = pe.OPTIONAL_HEADER.ImageBase
            section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
            file_alignment = pe.OPTIONAL_HEADER.FileAlignment
            original_entry_va = image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
            host_tlsdir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[_IMAGE_DIRECTORY_ENTRY_TLS]
            # The real Windows loader keys TLS-directory presence off
            # VirtualAddress, not Size -- but every "does the host already
            # have its own TLS directory" branch below used `.Size` as a
            # presence proxy (true for every real compiler's output, where
            # the two fields are always either both zero or both
            # non-zero). A hand-crafted/malformed PE could set them
            # inconsistently; checked once, here, up front, with a clean
            # ValueError, rather than letting that disagreement silently
            # route to the wrong merge path or surface as an unrelated
            # AttributeError further down.
            if bool(host_tlsdir.VirtualAddress) != bool(host_tlsdir.Size):
                raise ValueError(
                    f"host '{self.input_path}' has a malformed TLS directory: "
                    f"VirtualAddress={host_tlsdir.VirtualAddress:#x} but "
                    f"Size={host_tlsdir.Size:#x} -- these must be either both "
                    f"zero or both non-zero"
                )
            host_has_tls = bool(host_tlsdir.VirtualAddress)

            output = bytearray(self.input_path.read_bytes())

            last_section = max(pe.sections, key=lambda s: s.VirtualAddress)
            next_rva = _align_up(
                last_section.VirtualAddress + max(last_section.Misc_VirtualSize, last_section.SizeOfRawData),
                section_alignment,
            )

            section_table_offset = (
                pe.FILE_HEADER.get_file_offset() + pe.FILE_HEADER.sizeof() + pe.FILE_HEADER.SizeOfOptionalHeader
            )
            existing_section_count = pe.FILE_HEADER.NumberOfSections
            first_raw_data_offset = min(
                s.PointerToRawData for s in pe.sections if s.PointerToRawData
            )

            new_sections: List[tuple] = []  # (name, data, rva, characteristics, virtual_size)
            new_reloc_entries: List[tuple] = []  # (host_rva, type)
            dep_entry_calls: List[tuple] = []  # (name, hinst_va, entry_va), in embed order
            dep_pdata_entries: List[tuple] = []  # (begin_rva, end_rva, unwind_rva), host-relative
            removed_dll_names_lower: Set[str] = set()
            merged_descriptors: List[Dict[str, int]] = []
            # (start_rva, end_rva, name) of the host's own image and every
            # dependency (reloc-bearing or not) placed so far, host-relative
            # -- used to attribute a base-address conflict to whichever of
            # those a no-reloc dependency's reserved range collides with.
            occupied_ranges: List[tuple] = [(0, next_rva, self.input_path.name)]
            reserved_base_ranges: List[tuple] = []
            # Every embedded dependency's own *raw* export table (see the
            # per-dependency `raw_exports` comment below for what each
            # entry holds), keyed by lowercased DLL name -- populated once
            # per dependency in the main loop below, consulted only in the
            # finalize pass that resolves `pending_host_iat_patches` after
            # the loop (so a forward's target DLL doesn't need to already
            # be embedded at the point the forward itself is processed --
            # see that pass for why that matters).
            global_raw_exports_by_dll: Dict[str, Dict[object, object]] = {}
            # (ordinal, name_va_or_None, raw_entry) per exported symbol of
            # every embedded dependency, keyed by lowercased DLL name --
            # collected in the very same per-symbol loop that populates
            # `global_raw_exports_by_dll` above (so there's no duplicate
            # work or double-counting from that dict's own by-name *and*
            # by-ordinal keys both pointing at one real symbol), consumed
            # only by the runtime GetProcAddress-hook table builder below
            # (near `build_windows_stub`), which needs one row per actual
            # symbol rather than per dict key. `raw_entry` is exactly
            # `global_raw_exports_by_dll[dll][ordinal]` -- an absolute VA,
            # or an unresolved ("fwd", ...) marker resolved the same way
            # (`_resolve_raw_export`, defined below) when this is consumed.
            pending_hook_export_syms: Dict[str, List[Tuple[int, Optional[int], object]]] = {}
            # Absolute VAs of every discovered KERNEL32.dll LoadLibraryA/
            # LoadLibraryW/GetProcAddress IAT slot this run finds -- the
            # host's own (collected after the main loop below, directly
            # from `pe.DIRECTORY_ENTRY_IMPORT`) and each embedded
            # dependency's own *remaining* (non-embedded-target) KERNEL32
            # import of one of these three (collected inline in the main
            # loop below, in the same place `entry_dll_lower == "kernel32.
            # dll"` is already special-cased for the merged-descriptor
            # path). Consulted by the runtime LoadLibraryW/LoadLibraryA/
            # GetProcAddress hook-install step below (near
            # `build_windows_stub`) -- see that section for why *every*
            # discovered slot (there can be more than one per API, since
            # each embedded dependency keeps its own distinct FirstThunk
            # array rather than sharing the host's) must be overwritten,
            # and for what happens if a given API has none at all (a
            # fresh, synthetic KERNEL32 import is added for it, mirroring
            # the existing delay-import lazy-thunk's own synthetic
            # KERNEL32 import just below).
            # "virtualprotect" is discovered/synthesized via the exact
            # same mechanism as the other three (below), but is never
            # itself a hook *target* -- it's purely internal plumbing
            # `build_windows_hook_install` needs to temporarily make a
            # possibly-read-only discovered IAT slot writable before
            # patching it (see that function's own docstring); only
            # `kernel32_hook_slot_vas["virtualprotect"][0]` is ever read
            # (as a call-through address), never the whole list, and it's
            # never passed to `build_windows_hook_install` as something
            # to overwrite.
            kernel32_hook_slot_vas: Dict[str, List[int]] = {
                "loadlibrarya": [], "loadlibraryw": [], "getprocaddress": [], "virtualprotect": [],
            }
            # (iat_slot_rva, dll_name_lower, name_or_ordinal) for every host
            # import of an embedded dependency, deferred until every
            # dependency's raw export table (and X placement) is known --
            # see `global_raw_exports_by_dll` above.
            pending_host_iat_patches: List[tuple] = []
            # Lowercased names of every dependency this embed() run is
            # actually embedding (== every node in `order`) -- used below to
            # tell whether one dependency's own import of another dependency
            # must be patched out (see `pending_dep_iat_patches`) rather than
            # merged into the combined dynamic import directory as-is (B1:
            # leaving it dynamic would mean the final image both embeds the
            # target DLL's code *and* still dynamically loads a second, disk-
            # resident copy of it at runtime -- the duplicate-live-copy case
            # the design spec's transitive-exclusion anti-goal forbids).
            embedded_names_lower: Set[str] = {n.name.lower() for n in order}
            # (dep_name_lower, slot_offset_in_dep_blob, target_dll_lower,
            # name_or_ordinal) for every *dependency's own* import of another
            # embedded dependency -- resolved in the same finalize pass as
            # `pending_host_iat_patches` (a forward chain's ultimate target
            # may not be known until every dependency has been placed), then
            # patched directly into that dependency's own blob (looked up via
            # `dep_blobs_by_name_lower`) rather than left as a live import
            # descriptor.
            pending_dep_iat_patches: List[tuple] = []
            # Same tuple shape as `pending_dep_iat_patches` immediately
            # above, but for a *delay*-import (`/DELAYLOAD`) whose target
            # happens to itself be one of this run's embedded dependencies
            # -- kept in its own list, resolved by its own finalize pass,
            # specifically so a resolution failure there can fall back to
            # leaving that one entry's original, genuinely-lazy delay-load
            # bytes untouched instead of hard-failing the whole embed (an
            # ordinary import has no such fallback available -- its target
            # DLL's own live descriptor was already unconditionally removed
            # -- but a delay import's target DLL is still a real, loadable
            # file on disk even once embedded, so "leave it exactly as the
            # original binary had it" is always a safe, if imperfect,
            # fallback here). See the delay-import handling below for why
            # this distinction matters for a real, observed case (SHLWAPI.
            # dll delay-importing SHELL32.dll's ordinal 102, which SHELL32
            # itself can only re-export as a forward to a virtual API-set
            # DLL with no real host at all -- a separate, pre-existing,
            # out-of-scope limitation around forward resolution, not
            # something this delay-import fix should turn into a hard
            # failure).
            pending_dep_delay_iat_patches: List[tuple] = []
            # (dep_name_lower, slot_offset_in_dep_blob, dll_name_va,
            # func_key_va_or_ordinal, func_key_is_ordinal) for every delay
            # import whose target is a real, external DLL that ISN'T
            # embedded this run -- the common case. Even though nothing
            # about *this* target needs resolving at embed time, the
            # compiler's own delay-load thunk still cannot be left in
            # place (see the long comment on `build_windows_delay_import_
            # lazy_thunk` for the real, confirmed crash this causes once
            # the *owning* dependency, not the target, is embedded), so
            # each of these needs a generated per-function lazy-resolution
            # thunk instead -- deferred to its own finalize pass (after
            # every dependency has an `X` placement, and after the merged
            # import directory below adds the two fresh KERNEL32.dll
            # IAT slots every such thunk calls through).
            pending_dep_delay_lazy_thunks: List[tuple] = []
            # Every embedded dependency's own blob (bytearray, mutable even
            # once referenced from `new_sections`) and host RVA placement,
            # keyed by lowercased name -- so the finalize pass above can
            # patch a dependency's own IAT slot in place and compute the
            # right host-relative RVA for the accompanying relocation entry.
            dep_blobs_by_name_lower: Dict[str, bytearray] = {}
            dep_X_by_name_lower: Dict[str, int] = {}
            # N-way TLS merge state -- generalizes the former single-
            # dependency-only `merged_tls`/`tls_phase2` trackers to any
            # number of TLS-bearing dependencies in one embed() run (see
            # the long comment where this is used, in the main loop
            # below, for the full chained-merge mechanism).
            #
            # `tls_authority` is None until the first TLS-bearing
            # dependency is seen, then holds a dict describing *where*
            # the one real, loader-assigned TLS index slot and directory
            # struct live:
            #   'is_host': True if the host's own pre-existing TLS
            #       directory is the authority (it never moves -- only
            #       its field *values* change), False if a dependency's
            #       own (adopted) directory is instead.
            #   'name' / 'index_va': the authority's own name (for
            #       diagnostics) and the one real `_tls_index` VA every
            #       other TLS-bearing dependency gets fixed up to match
            #       at process start. Fixed forever once set.
            #   'struct_abs_off': (is_host True only) a dict of absolute
            #       file offsets, in `output`, of the host's own TLS
            #       directory struct's start/end/callbacks/zero_fill
            #       fields -- computed once, stays valid forever since
            #       the struct's own location never moves.
            #   'dep_blob' / 'struct_rel_off': (is_host False only) the
            #       authority dependency's own mutable blob and the TLS
            #       directory struct's offset within it -- same
            #       stays-valid-forever reasoning, relative to that blob.
            #   'adopted_cheap': True only for the single-TLS-dependency,
            #       host-had-none case, for as long as no second
            #       TLS-bearing dependency has shown up yet (see the
            #       "cheap adopt" vs. "retroactive conversion" split
            #       where this is consumed).
            #   'own_raw_bytes' / 'own_cb_vas' / 'own_zero_fill': (only
            #       while 'adopted_cheap' is True) this authority
            #       dependency's own already-computed raw bytes/callback
            #       VA list/zero-fill size, kept around purely so a later
            #       second TLS-bearing dependency can retroactively seed
            #       `tls_pieces`/`tls_cb_vas`/`tls_zero_fill_total` from
            #       them without re-deriving anything.
            tls_authority: Optional[Dict[str, object]] = None
            # (rva, size) of the TLS directory to adopt as the host's own
            # DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_TLS] entry, set once,
            # the moment the *first* TLS-bearing dependency is merged into
            # a host that had no TLS directory of its own -- stays
            # correct even after a later dependency triggers "retroactive
            # conversion" above, since that only ever rewrites this same
            # struct's field *values*, never its on-disk location.
            adopted_tls_directory: Optional[tuple] = None
            # Combined raw-data pieces / callback VA list / zero-fill
            # total accumulated so far, in final on-disk order (piece 0 is
            # whichever TLS-bearing entity -- host or a dependency --
            # became the authority first). Only populated once a *real*
            # byte-level merge (as opposed to the single-dependency cheap-
            # adopt shortcut) actually happens.
            tls_pieces: List[bytes] = []
            tls_cb_vas: List[int] = []
            tls_zero_fill_total = 0

            for node in order:
                dep = pefile.PE(str(node.path), max_symbol_exports=_MAX_SYMBOL_EXPORTS)
                try:
                    if dep.FILE_HEADER.Machine != host_machine:
                        raise ValueError(
                            f"architecture mismatch embedding '{node.name}': host "
                            f"'{self.input_path}' is {hex(host_machine)}, dependency "
                            f"'{node.path}' is {hex(dep.FILE_HEADER.Machine)}"
                        )

                    # TLS-directory handling (Task 2 phase 1 + Task 5 phase
                    # 2, generalized to N dependencies -- see the long
                    # comment just below `dep_tlsdir.Size`'s own `else`
                    # branch for the full chained-merge mechanism): a
                    # dependency carrying its own non-empty
                    # IMAGE_DIRECTORY_ENTRY_TLS (any __declspec(thread)/
                    # thread_local variable) can now be merged in, in any
                    # number, in the same embed() run, in either of two
                    # ways: *adopted* as the host's own TLS directory when
                    # the host had none of its own (phase 1), or -- when
                    # the host *also* already has its own non-empty TLS
                    # directory, or once a second TLS-bearing dependency
                    # shows up -- merged into one combined raw-data range
                    # sharing the host's own (real, loader-assigned) index
                    # slot (phase 2; see `_patch_dep_tls_access_offsets`'s
                    # and `build_windows_tls_index_fixup`'s own docstrings
                    # for why: Windows' real PE loader only natively
                    # processes *one* TLS directory per image).
                    #
                    # The byte-level merge mechanism (phase 2) is 64-bit
                    # only (the synthesized index-fixup callback is x64
                    # machine code) -- guard against it up front, covering
                    # both ways it can become necessary: the host already
                    # having its own TLS directory, or this being the
                    # second (or later) TLS-bearing dependency in this run
                    # (`tls_authority` already set -- see its declaration
                    # above).
                    dep_tlsdir = dep.OPTIONAL_HEADER.DATA_DIRECTORY[_IMAGE_DIRECTORY_ENTRY_TLS]
                    if dep_tlsdir.Size:
                        if not is64 and (host_has_tls or tls_authority is not None):
                            reason = (
                                "the host already carries its own Thread Local "
                                "Storage (TLS) directory too"
                                if host_has_tls else
                                "another dependency's TLS directory was already "
                                "merged into the host's earlier in this same run"
                            )
                            raise ValueError(
                                f"cannot embed dependency '{node.name}': it has its "
                                f"own Thread Local Storage (TLS) directory, and "
                                f"{reason} -- merging two or more real TLS "
                                f"directories into one is only implemented for "
                                f"64-bit hosts so far (phase 2 / Task 5)"
                            )

                    dep_image_base = dep.OPTIONAL_HEADER.ImageBase
                    blob_size = _align_up(dep.OPTIONAL_HEADER.SizeOfImage, section_alignment)
                    # SizeOfImage is attacker-controlled (read directly from
                    # the dependency file, no sanity check of its own) and
                    # used directly as `bytearray(blob_size)`'s size below.
                    # It's a DWORD (max ~4 GiB), so it can't reach ELF
                    # embedder's 16 GiB `_MAX_SANE_BLOB_SIZE` threshold for
                    # `p_memsz` (a 64-bit field) -- but a multi-gigabyte
                    # allocation per dependency is still a real DoS lever no
                    # genuine PE module ever needs; cap it well below the
                    # field's own ceiling instead.
                    _MAX_SANE_BLOB_SIZE = 1 << 31  # 2 GiB
                    if blob_size > _MAX_SANE_BLOB_SIZE:
                        raise ValueError(
                            f"dependency '{node.name}' declares an implausibly large mapped "
                            f"size ({blob_size} bytes); refusing to allocate it"
                        )
                    blob = bytearray(blob_size)

                    # B4: the dependency's own PE header region (DOS header
                    # through its section headers, i.e. everything before
                    # its first section's raw data) is never covered by
                    # `dep.sections`' own data -- without copying it too,
                    # that region of the embedded blob stays all zeros, and
                    # anything that reads its own module header via its own
                    # HINSTANCE (which, once embedded, *is* this blob's
                    # placement address) -- e.g. mingw's pseudo-relocation
                    # startup check, or any lookup through its own DOS/PE
                    # header -- finds zeros instead of a real header and
                    # fails before any of the dependency's own code runs.
                    # Every field in this region is either a plain RVA
                    # (unaffected by where the blob is ultimately placed --
                    # that's the entire point of an RVA) or not consulted at
                    # all once we're not going through the real PE loader,
                    # so a verbatim byte copy (no further patching) is
                    # sufficient.
                    dep_raw = node.path.read_bytes()
                    size_of_headers = min(dep.OPTIONAL_HEADER.SizeOfHeaders, blob_size, len(dep_raw))
                    blob[0:size_of_headers] = dep_raw[0:size_of_headers]

                    for sec in dep.sections:
                        raw = sec.get_data()
                        start = sec.VirtualAddress
                        if start >= blob_size:
                            continue
                        n = min(len(raw), blob_size - start)
                        blob[start:start + n] = raw[:n]

                    has_reloc = bool(getattr(dep, "DIRECTORY_ENTRY_BASERELOC", None))

                    if has_reloc:
                        X = next_rva
                        delta = (image_base + X) - dep_image_base

                        def apply_delta(offset: int, size: int) -> None:
                            mask = (1 << (size * 8)) - 1
                            val = int.from_bytes(blob[offset:offset + size], "little")
                            val = (val + delta) & mask
                            blob[offset:offset + size] = val.to_bytes(size, "little")

                        for block in dep.DIRECTORY_ENTRY_BASERELOC:
                            for entry in block.entries:
                                if entry.type == IMAGE_REL_BASED_ABSOLUTE:
                                    continue
                                if entry.type == IMAGE_REL_BASED_HIGHLOW:
                                    apply_delta(entry.rva, 4)
                                elif entry.type == IMAGE_REL_BASED_DIR64:
                                    apply_delta(entry.rva, 8)
                                else:
                                    raise ValueError(
                                        f"unsupported relocation type {entry.type} in "
                                        f"dependency '{node.name}'"
                                    )
                                new_reloc_entries.append((X + entry.rva, entry.type))
                    else:
                        # No relocation data at all means this dependency is
                        # fixed-base/non-PIC: none of its internal absolute
                        # addresses can be fixed up, so it can only be
                        # embedded by reserving its own preferred ImageBase
                        # as a fixed RVA within the host's image (such that
                        # image_base + X == dep_image_base exactly, making
                        # every one of its hardcoded addresses already
                        # correct). Fail loudly if that address range is
                        # already claimed by the host's own image (plus
                        # anything already placed there) or by another
                        # dependency reserved the same way -- rather than
                        # silently overlapping two live mappings.
                        X = dep_image_base - image_base
                        if X < 0:
                            raise ValueError(
                                f"cannot reserve base address 0x{dep_image_base:x} for "
                                f"dependency '{node.name}': it is below the host "
                                f"image's own base 0x{image_base:x}"
                            )
                        for other_start, other_end, other_name in occupied_ranges:
                            if X < other_end and other_start < X + blob_size:
                                raise ValueError(
                                    f"base address conflict at 0x{dep_image_base:x} "
                                    f"between '{node.name}' and '{other_name}'"
                                )
                        reserved_base_ranges.append((X, X + blob_size, node.name))

                        if X > next_rva:
                            # The Windows PE loader requires sections to
                            # cover the image's RVA space contiguously (no
                            # gaps between them), so bridge the distance
                            # between the append cursor and this
                            # dependency's reserved address with a
                            # ".bss"-style filler section: no raw file
                            # backing needed, just a VirtualSize claiming
                            # that range.
                            new_sections.append((
                                f".sgap{len(new_sections)}".encode("ascii"), b"", next_rva,
                                _SCN_UNINIT_RW, X - next_rva,
                            ))
                            # The filler's own bridging range is now a real
                            # section in the final section table too (it
                            # physically claims those RVAs even though it
                            # has no raw content) -- a later dependency
                            # landing inside it would be just as malformed
                            # a collision as landing inside the host's or
                            # another dependency's actual data, so it must
                            # be checked against too.
                            occupied_ranges.append((next_rva, X, f"{node.name}'s alignment-gap filler"))

                    # Unwind-metadata (.pdata/.xdata) preservation: collect
                    # this dependency's own RUNTIME_FUNCTION entries,
                    # shifted (and, where needed, their UNWIND_INFO's own
                    # RVA fields patched) to match where `blob`'s bytes end
                    # up once placed at host RVA X -- regardless of
                    # whether this dependency's *other* references needed
                    # has_reloc's delta-relocation treatment above, since
                    # these are pure-RVA references no base relocation
                    # entry ever covers (see _adjust_unwind_info's
                    # docstring). No-op for a dependency with no exception
                    # directory at all (e.g. any x86/32-bit dependency).
                    dep_pdata_entries.extend(_collect_and_patch_dep_unwind(dep, blob, X))

                    # Adopt or merge this dependency's TLS directory (see
                    # the 64-bit-only guard above): the struct's own
                    # fields (StartAddressOfRawData/EndAddressOfRawData/
                    # AddressOfIndex/AddressOfCallBacks, and every callback
                    # VA in the null-terminated array AddressOfCallBacks
                    # points at) live inside `blob` at their original
                    # (dep-relative) locations -- already byte-copied above
                    # by the generic per-section copy, and, for the
                    # has_reloc case, already rewritten to host-relative
                    # VAs by the ordinary base-relocation loop above (every
                    # one of those fields is itself an absolute VA the
                    # dependency's own linker emitted a base relocation
                    # entry for, same as any other absolute pointer in its
                    # data -- confirmed against the real frida-gadget DLL's
                    # TLS directory and 3-entry callback array; see
                    # .superpowers/findings/2026-11-04-frida-gadget-tls-
                    # shape.md). So nothing about the struct's *contents*
                    # needs patching here for the cheap-adopt case -- only
                    # the new DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_TLS]
                    # entry itself (an ordinary RVA+Size pair, like every
                    # other data directory, not a VA) needs to point at
                    # it, applied once, after the loop, alongside the
                    # other directory patches (`adopted_tls_directory`).
                    #
                    # For every other case (host already has its own TLS
                    # directory, or this is the second-or-later TLS-
                    # bearing dependency in this run), this dependency's
                    # own raw-data template VA/size, zero-fill size,
                    # `_tls_index` variable's VA, and its own (already
                    # host-relative, already-correct) callback VA list can
                    # all be read directly out of `blob` right now, while
                    # `dep`/`blob`/`X` are still in scope.
                    if dep_tlsdir.Size:
                        tls_off = dep_tlsdir.VirtualAddress
                        final_start, final_end, final_index_va, final_cb_va = struct.unpack_from(
                            "<4Q", blob, tls_off
                        )
                        final_zero_fill = struct.unpack_from("<I", blob, tls_off + 32)[0]
                        raw_size = final_end - final_start
                        dep_raw_off_in_blob = (final_start - image_base) - X
                        dep_raw_bytes = (
                            bytes(blob[dep_raw_off_in_blob:dep_raw_off_in_blob + raw_size])
                            if raw_size else b""
                        )
                        dep_index_blob_rva = (final_index_va - image_base) - X
                        dep_cb_vas: List[int] = []
                        if final_cb_va:
                            cb_off = (final_cb_va - image_base) - X
                            idx = 0
                            while 0 <= cb_off + idx * ptr_size < blob_size:
                                entry_off = cb_off + idx * ptr_size
                                entry = int.from_bytes(blob[entry_off:entry_off + ptr_size], "little")
                                if entry == 0:
                                    break
                                dep_cb_vas.append(entry)
                                idx += 1

                        if tls_authority is None and not host_has_tls:
                            # Phase 1's original cheap shortcut, unchanged:
                            # the host had no TLS directory of its own at
                            # all, so this dependency's own directory --
                            # already fully self-consistent in `blob`,
                            # untouched -- is adopted as-is, no byte-level
                            # copying at all. Everything a later *second*
                            # TLS-bearing dependency would need to
                            # "retroactively convert" this into a real
                            # merge target is kept around too (see the
                            # 'adopted_cheap' branch below), since the
                            # cheapness of this path must not foreclose
                            # that later possibility.
                            adopted_tls_directory = (X + tls_off, dep_tlsdir.Size)
                            tls_authority = {
                                "is_host": False,
                                "name": node.name,
                                "index_va": final_index_va,
                                "dep_blob": blob,
                                "struct_rel_off": tls_off,
                                "adopted_cheap": True,
                                "own_raw_bytes": dep_raw_bytes,
                                "own_cb_vas": dep_cb_vas,
                                "own_zero_fill": final_zero_fill,
                            }
                        else:
                            # Phase 2's real mechanism (an earlier design
                            # tried giving this dependency a fully
                            # separate, dynamically TlsAlloc()'d slot
                            # instead -- see this comment block's own
                            # git-blame/commit history for exactly why it
                            # didn't work, empirically, not just in
                            # theory: TlsAlloc()'s index space is the
                            # Win32 "dynamic TLS" one (TEB.TlsSlots/
                            # TlsExpansionSlots), a *different* array from
                            # the one compiled `__declspec(thread)`/
                            # `__thread` access actually reads
                            # (TEB.ThreadLocalStoragePointer, offset 0x58
                            # on x64) -- confirmed by building and running
                            # the first version of this change, which
                            # produced wrong values without crashing).
                            #
                            # There is no public API to allocate a second
                            # *real* ThreadLocalStoragePointer-array slot,
                            # so this reuses the *one* real slot the OS
                            # loader assigned to whichever TLS-bearing
                            # entity became the authority first (the host
                            # itself, if it already had its own TLS
                            # directory, or else the very first TLS-
                            # bearing dependency, adopted above) -- every
                            # module's compiled TLS access ends up reading
                            # the exact same per-thread block, at
                            # *different, non-overlapping* offsets within
                            # one combined raw-data range that keeps
                            # growing by one more piece (this dependency's
                            # own) each time a new TLS-bearing dependency
                            # shows up:
                            #
                            # 1. If this is the very first TLS-bearing
                            #    dependency and the host already has its
                            #    own TLS directory, establish the host as
                            #    the authority, seeding `tls_pieces`/
                            #    `tls_cb_vas`/`tls_zero_fill_total` from
                            #    its own (unmodified, read straight out of
                            #    the original `pe` parse -- the host's own
                            #    raw TLS bytes are never themselves
                            #    patched by anything in this module) raw
                            #    bytes/callbacks/zero-fill.
                            # 1b. Otherwise, if a TLS-bearing dependency
                            #    was already cheaply adopted above (no
                            #    byte-level merge yet) and *this* is the
                            #    second one to show up, retroactively
                            #    convert that adoption into a real merge
                            #    target -- seeding the same three
                            #    accumulators from the first dependency's
                            #    own already-computed values (kept around
                            #    exactly for this).  Either way, after this
                            #    step `tls_pieces`/`tls_cb_vas`/
                            #    `tls_zero_fill_total` hold everything
                            #    merged into the authority so far, and
                            #    `tls_authority` names where its struct's
                            #    fields currently need writing.
                            # 2. Copy every piece merged so far
                            #    (unchanged content, same relative order)
                            #    immediately followed by *this*
                            #    dependency's own raw TLS bytes into a
                            #    fresh combined range appended onto the
                            #    end of `blob` -- the *native* loader then
                            #    keeps copying this correctly into a fresh
                            #    per-thread block on every thread's
                            #    creation, for every piece, with zero
                            #    custom runtime code needed for that part.
                            # 3. Patch the authority's own TLS directory
                            #    struct (Start/EndAddressOfRawData,
                            #    SizeOfZeroFill -- in `output` if the
                            #    authority is the host, or in the
                            #    authority dependency's own `blob` if it's
                            #    a dependency's adopted directory; see
                            #    `_write_authority_field`) to point at
                            #    this new combined range instead of its
                            #    previous (now-superseded) one.
                            #    AddressOfIndex is never touched -- that
                            #    real, loader-assigned slot number is
                            #    exactly what every merge keeps reusing.
                            # 4. Every piece already merged in before this
                            #    one keeps its own previously-patched
                            #    compiled TLS-access offset(s) correct
                            #    unchanged, since it's still preceded by
                            #    the exact same bytes it always was --
                            #    only new bytes are ever appended *after*
                            #    it. This dependency's own compiled
                            #    offset(s), by contrast, were computed
                            #    relative to *its own* original
                            #    StartAddressOfRawData, which is not
                            #    offset 0 of the combined range -- so its
                            #    access(es) need shifting by however many
                            #    bytes already precede it
                            #    (`_patch_dep_tls_access_offsets`, below --
                            #    see its own docstring for exactly which
                            #    compiled byte pattern it finds and edits,
                            #    and the honest limits of that pattern
                            #    match).
                            # 5. Only this dependency's own `_tls_index`
                            #    variable needs a *runtime* fixup left: a
                            #    tiny generated function, hooked onto the
                            #    init-call stub this module already builds
                            #    whenever any embedded dependency has its
                            #    own entry point (`dep_entry_calls`/
                            #    `build_windows_stub`, Task 7), copies the
                            #    authority's own (by-then loader-assigned)
                            #    `_tls_index` *value* into this
                            #    dependency's own `_tls_index` variable --
                            #    a plain data write, needing no further
                            #    per-thread work, since the slot *number*
                            #    is a process-wide constant once assigned.
                            if tls_authority is None:
                                host_struct = pe.DIRECTORY_ENTRY_TLS.struct
                                host_start_rva = host_struct.StartAddressOfRawData - image_base
                                host_raw_size = (
                                    host_struct.EndAddressOfRawData - host_struct.StartAddressOfRawData
                                )
                                host_raw_bytes = (
                                    pe.get_data(host_start_rva, host_raw_size) if host_raw_size else b""
                                )
                                host_cb_vas: List[int] = []
                                host_cb_va = host_struct.AddressOfCallBacks
                                if host_cb_va:
                                    hidx = 0
                                    while True:
                                        hentry = struct.unpack(
                                            "<Q",
                                            pe.get_data(
                                                host_cb_va - image_base + hidx * ptr_size, ptr_size
                                            ),
                                        )[0]
                                        if hentry == 0:
                                            break
                                        host_cb_vas.append(hentry)
                                        hidx += 1

                                tls_authority = {
                                    "is_host": True,
                                    "name": self.input_path.name,
                                    "index_va": host_struct.AddressOfIndex,
                                    "struct_abs_off": {
                                        "start": host_struct.get_field_absolute_offset(
                                            "StartAddressOfRawData"
                                        ),
                                        "end": host_struct.get_field_absolute_offset(
                                            "EndAddressOfRawData"
                                        ),
                                        "callbacks": host_struct.get_field_absolute_offset(
                                            "AddressOfCallBacks"
                                        ),
                                        "zero_fill": host_struct.get_field_absolute_offset(
                                            "SizeOfZeroFill"
                                        ),
                                    },
                                }
                                tls_pieces = [host_raw_bytes]
                                tls_cb_vas = list(host_cb_vas)
                                tls_zero_fill_total = host_struct.SizeOfZeroFill
                            elif tls_authority.get("adopted_cheap"):
                                tls_pieces = [tls_authority["own_raw_bytes"]]
                                tls_cb_vas = list(tls_authority["own_cb_vas"])
                                tls_zero_fill_total = tls_authority["own_zero_fill"]
                                tls_authority["adopted_cheap"] = False

                            def _write_authority_field(field: str, value: int, size: int) -> None:
                                packed = value.to_bytes(size, "little")
                                if tls_authority["is_host"]:
                                    off = tls_authority["struct_abs_off"][field]
                                    output[off:off + size] = packed
                                else:
                                    dblob = tls_authority["dep_blob"]
                                    off = tls_authority["struct_rel_off"] + _TLS64_FIELD_OFFSET[field]
                                    dblob[off:off + size] = packed

                            shift = sum(len(p) for p in tls_pieces)
                            patched, anchors_found = _patch_dep_tls_access_offsets(
                                blob, dep_index_blob_rva, shift
                            )
                            if patched == 0:
                                raise ValueError(
                                    f"cannot embed dependency '{node.name}': merging "
                                    f"its own Thread Local Storage (TLS) directory "
                                    f"into a host (or another already-merged "
                                    f"dependency) that already has one needs to "
                                    f"locate and shift its own compiled TLS-variable "
                                    f"access offset(s), but none of its {anchors_found} "
                                    f"found `_tls_index` load site(s) matched a "
                                    f"recognized compiled pattern -- refusing to "
                                    f"proceed rather than silently leave its TLS "
                                    f"access reading the wrong location"
                                )
                            # Deliberately *not* `patched < anchors_found`: see
                            # `_patch_dep_tls_access_offsets`'s own docstring --
                            # this scanner trades recall for precision on
                            # purpose (each pattern only accepts a candidate it
                            # has real, local corroboration for, specifically
                            # to rule out the false-positive-corruption bugs
                            # found via real 010 Editor testing against
                            # SHLWAPI.dll/SHELL32.dll), so a real dependency
                            # can legitimately have *some* access sites this
                            # narrow a scanner doesn't recognize yet without
                            # that meaning the whole merge is unsupported --
                            # see "the host-already-has-TLS merge's byte-
                            # pattern scanner... is narrower than its own
                            # docstring implies" in limitations.md.

                            tls_pieces.append(dep_raw_bytes)
                            merged_raw_off = len(blob)
                            for piece in tls_pieces:
                                blob += piece
                            merged_start_va = image_base + X + merged_raw_off
                            merged_end_va = merged_start_va + sum(len(p) for p in tls_pieces)
                            tls_zero_fill_total += final_zero_fill

                            _write_authority_field("start", merged_start_va, 8)
                            _write_authority_field("end", merged_end_va, 8)
                            _write_authority_field("zero_fill", tls_zero_fill_total, 4)

                            tls_cb_vas.extend(dep_cb_vas)
                            if tls_cb_vas:
                                # Append a fresh combined callback array
                                # (every piece's own callback VAs, in
                                # merge order) onto `blob`, and repoint
                                # AddressOfCallBacks at it; left completely
                                # alone if there are still no callbacks at
                                # all merged in from anywhere.
                                while len(blob) % ptr_size:
                                    blob += b"\x00"
                                cb_array_off = len(blob)
                                for cb_va in tls_cb_vas:
                                    blob += struct.pack("<Q", cb_va)
                                blob += struct.pack("<Q", 0)  # null terminator
                                for i in range(len(tls_cb_vas)):
                                    new_reloc_entries.append(
                                        (X + cb_array_off + i * ptr_size, IMAGE_REL_BASED_DIR64)
                                    )
                                _write_authority_field("callbacks", image_base + X + cb_array_off, 8)

                            # The one remaining runtime step: a tiny
                            # generated function copying the authority's
                            # own (real, loader-assigned) `_tls_index`
                            # value into this dependency's own
                            # `_tls_index` variable, hooked onto the
                            # init-call stub (see the long comment above).
                            fixup_off = len(blob)
                            fixup_code, fixup_abs_offsets = build_windows_tls_index_fixup(
                                host_tlsindex_va=tls_authority["index_va"],
                                dep_tlsindex_va=final_index_va,
                            )
                            blob += fixup_code
                            for off in fixup_abs_offsets:
                                new_reloc_entries.append((X + fixup_off + off, IMAGE_REL_BASED_DIR64))
                            fixup_va = image_base + X + fixup_off
                            dep_entry_calls.append((f"__tls_fixup_{node.name}__", 0, fixup_va))

                    # This dependency's own *raw* export table, by both name
                    # and ordinal: either an already-absolute VA (a normal,
                    # non-forwarded export -- cheap to compute right now,
                    # `image_base + X + sym.address`, no cross-dependency
                    # information needed) or, for a *forwarded* export (its
                    # real implementation lives in another DLL entirely --
                    # or even back in this same DLL, under a different name:
                    # a real, observed pattern, e.g. RPCRT4.dll's ANSI entry
                    # points forwarding to its own wide-string ones; pefile
                    # marks any forward via `sym.forwarder`, and `sym.address`
                    # is -- misleadingly -- just the RVA of the forwarder
                    # string itself for these, never a callable address), a
                    # pending ("fwd", target_dll_lower, target_func, raw_str)
                    # marker -- deliberately *not* resolved to a VA here.
                    #
                    # Resolving a forward needs the target DLL's own raw
                    # table, which, for a forward to *another* dependency,
                    # might not exist yet at this point in embed order (a
                    # forward is a real, observed source of genuine
                    # dependency cycles against plain PE imports -- e.g. a
                    # real WS2_32.dll forwards some exports to MSWSOCK.dll,
                    # while MSWSOCK.dll's own import table imports
                    # WS2_32.dll back, a cycle no single embed order can
                    # satisfy). So forward resolution (`_resolve_export`,
                    # below `global_raw_exports_by_dll`) and the host-IAT
                    # patches that may need it are both deferred to a
                    # finalize pass run after every dependency in `order`
                    # has been placed (has an `X` and a raw table) --
                    # `pending_host_iat_patches`, below.
                    raw_exports: Dict[object, object] = {}
                    if hasattr(dep, "DIRECTORY_ENTRY_EXPORT"):
                        for sym in dep.DIRECTORY_ENTRY_EXPORT.symbols:
                            name = sym.name.decode("ascii") if sym.name else None
                            if sym.forwarder:
                                forwarder = sym.forwarder.decode("ascii")
                                fwd_dll, _, fwd_func = forwarder.rpartition(".")
                                fwd_dll_lower = fwd_dll.lower()
                                if not fwd_dll_lower.endswith(".dll"):
                                    fwd_dll_lower += ".dll"
                                # A forward target can name the target's
                                # export either by name (the common case,
                                # already handled correctly below) or by
                                # ORDINAL, per the PE/COFF spec's own
                                # "#N" notation (a real, observed shape --
                                # e.g. SHLWAPI.dll forwards export #619 to
                                # "SHCORE.#192"). `raw_exports` below is
                                # keyed by the target's real `sym.ordinal`
                                # (an int) or `sym.name` (a str with no
                                # '#') -- the raw string "#192" would never
                                # match either, silently failing to
                                # resolve a forward that's otherwise
                                # perfectly resolvable. Convert it to the
                                # real int key here instead.
                                if fwd_func.startswith("#"):
                                    fwd_func = int(fwd_func[1:])
                                entry = ("fwd", fwd_dll_lower, fwd_func, forwarder)
                            else:
                                entry = image_base + X + sym.address
                            raw_exports[sym.ordinal] = entry
                            if name:
                                raw_exports[name] = entry
                            # `sym.name_offset` (unlike `sym.address`) is a
                            # *file* offset, not an RVA -- pefile's own
                            # "_offset"-suffixed ExportData fields
                            # (`name_offset`/`address_offset`/`ordinal_
                            # offset`) are all file offsets, set via
                            # `get_offset_from_rva(...)` internally; only
                            # the plain, unsuffixed `.address` is an RVA.
                            # Confirmed the hard way: using it directly as
                            # an RVA here pointed into inter-section
                            # padding (zero bytes) rather than the real
                            # name string, which a real GetProcAddress
                            # hook call then silently (no crash, just a
                            # byte-for-byte string-compare that can never
                            # match anything) failed to resolve.
                            name_va = (
                                image_base + X + dep.get_rva_from_offset(sym.name_offset)
                                if sym.name else None
                            )
                            pending_hook_export_syms.setdefault(node.name.lower(), []).append(
                                (sym.ordinal, name_va, entry)
                            )
                    global_raw_exports_by_dll[node.name.lower()] = raw_exports

                    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                        for host_entry in pe.DIRECTORY_ENTRY_IMPORT:
                            if host_entry.dll.decode("ascii") != node.name:
                                continue
                            for imp in host_entry.imports:
                                if imp.import_by_ordinal:
                                    key = imp.ordinal
                                    if key not in raw_exports:
                                        raise ValueError(
                                            f"dependency '{node.name}' does not "
                                            f"export ordinal {key}, required "
                                            f"by the host's import table"
                                        )
                                else:
                                    if imp.name is None:
                                        raise ValueError(
                                            f"cannot embed '{node.name}': import "
                                            f"entry has neither a name nor an ordinal"
                                        )
                                    key = imp.name.decode("ascii")
                                    if key not in raw_exports:
                                        raise ValueError(
                                            f"dependency '{node.name}' does not export "
                                            f"'{key}', required by the host's import table"
                                        )
                                # `imp.thunk_rva` is the *lookup* (ILT/
                                # OriginalFirstThunk) slot pefile derived the
                                # name from, which is a different array from
                                # the *address* (IAT/FirstThunk) slot that
                                # compiled call sites actually read through
                                # (`imp.address` is that slot's VA) -- it's
                                # the IAT slot we must overwrite.
                                iat_slot_rva = imp.address - image_base
                                pending_host_iat_patches.append((iat_slot_rva, node.name.lower(), key))
                            removed_dll_names_lower.add(node.name.lower())

                    if hasattr(dep, "DIRECTORY_ENTRY_IMPORT"):
                        ordinal_flag = (1 << 63) if is64 else (1 << 31)
                        for entry in dep.DIRECTORY_ENTRY_IMPORT:
                            entry_dll_lower = entry.dll.decode("ascii").lower()
                            # B1: if this dependency's own import target is
                            # itself one of the dependencies being embedded
                            # in this same embed() run, merging this
                            # descriptor into the combined dynamic import
                            # directory as-is (the `else` branch below)
                            # would leave the final image *both* embedding
                            # the target's code *and* still dynamically
                            # importing a second, disk-resident copy of it
                            # at runtime -- the duplicate-live-copy case
                            # (or `0xC0000135` if no disk copy exists) the
                            # design spec's transitive-exclusion anti-goal
                            # forbids. Instead, patch this dependency's own
                            # IAT slots directly to the target's resolved
                            # address (deferred to the finalize pass below,
                            # mirroring `pending_host_iat_patches`, since
                            # the target may not have its own placement/
                            # export table yet) and drop the live
                            # descriptor entirely.
                            target_is_embedded = entry_dll_lower in embedded_names_lower

                            thunk_rvas = []
                            if entry.struct.OriginalFirstThunk:
                                thunk_rvas.append(entry.struct.OriginalFirstThunk)
                            if entry.struct.FirstThunk and entry.struct.FirstThunk != entry.struct.OriginalFirstThunk:
                                thunk_rvas.append(entry.struct.FirstThunk)
                            for thunk_rva in thunk_rvas:
                                idx = 0
                                while True:
                                    off = thunk_rva + idx * ptr_size
                                    if off + ptr_size > blob_size:
                                        break
                                    raw = int.from_bytes(blob[off:off + ptr_size], "little")
                                    if raw == 0:
                                        break
                                    if not (raw & ordinal_flag):
                                        new_val = raw + X
                                        blob[off:off + ptr_size] = new_val.to_bytes(ptr_size, "little")
                                    idx += 1

                            if target_is_embedded:
                                for imp in entry.imports:
                                    if imp.import_by_ordinal:
                                        key = imp.ordinal
                                    else:
                                        if imp.name is None:
                                            raise ValueError(
                                                f"cannot embed '{node.name}': its own "
                                                f"import of '{entry_dll_lower}' has an "
                                                f"entry with neither a name nor an "
                                                f"ordinal"
                                            )
                                        key = imp.name.decode("ascii")
                                    # `imp.address` is the VA pefile computed
                                    # for the FirstThunk (IAT) slot itself --
                                    # the same slot this dependency's own
                                    # compiled call sites read through --
                                    # using dep's *own* (unrelocated)
                                    # ImageBase, so subtracting that back
                                    # out gives the slot's offset within
                                    # `blob` (unaffected by X, which isn't
                                    # known to have a final patch target
                                    # yet -- see `pending_dep_iat_patches`).
                                    slot_offset_in_blob = imp.address - dep_image_base
                                    pending_dep_iat_patches.append(
                                        (node.name.lower(), slot_offset_in_blob, entry_dll_lower, key)
                                    )
                            else:
                                merged_descriptors.append({
                                    "name_rva": X + entry.struct.Name,
                                    "orig_first_thunk_rva": (
                                        X + entry.struct.OriginalFirstThunk if entry.struct.OriginalFirstThunk else 0
                                    ),
                                    "first_thunk_rva": X + entry.struct.FirstThunk,
                                })
                                # Runtime hook support (see
                                # `kernel32_hook_slot_vas` above): this
                                # dependency's own remaining KERNEL32
                                # import survives as a live descriptor
                                # (the branch just above), so its own IAT
                                # slot for LoadLibraryA/LoadLibraryW/
                                # GetProcAddress -- if it imports any of
                                # them -- is a real call site the hook-
                                # install step below must also overwrite,
                                # not just the host's own. `imp.address`
                                # is this slot's VA using dep's own
                                # (unrelocated) ImageBase, same as
                                # `slot_offset_in_blob` above.
                                if entry_dll_lower == "kernel32.dll":
                                    for imp in entry.imports:
                                        if imp.import_by_ordinal or imp.name is None:
                                            continue
                                        api_name = imp.name.decode("ascii").lower()
                                        if api_name in kernel32_hook_slot_vas:
                                            kernel32_hook_slot_vas[api_name].append(
                                                image_base + X + (imp.address - dep_image_base)
                                            )

                    # Delay-loaded imports (IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
                    # the linker's `/DELAYLOAD` feature).
                    #
                    # A first fix attempt (since reverted -- see
                    # limitations.md) folded every delay-import module into
                    # the same merged/combined *ordinary* import mechanism
                    # used for a dependency's own remaining external
                    # imports, reasoning that the modern delay-import
                    # descriptor shape (`pINT`/`pIAT`) mirrors an ordinary
                    # one (`OriginalFirstThunk`/`FirstThunk`) closely enough
                    # to reuse that machinery. That stopped the original
                    # null-pointer-call crash (see below), but introduced a
                    # different, equally real regression: it turns every
                    # genuinely *lazy* delay-load into an *eager*, process-
                    # init-time one, resolved by `LdrpInitializeProcess`
                    # before any application code -- even the host's own
                    # entry point -- ever runs. Confirmed via a real full
                    # 010 Editor embed (57 transitive dependencies once
                    # ADVAPI32/SHELL32/COMDLG32 are added) plus `gflags /i
                    # <exe> +sls` (Show Loader Snaps): the build no longer
                    # crashed, but hung forever behind a
                    # `STATUS_DLL_INIT_FAILED` hard-error dialog, with the
                    # loader snap log pinpointing the exact cause --
                    #   LdrpPreprocessDllName - ERROR: ... for DLL
                    #   ext-ms-win-security-chambers-l1-1-0.dll failed with
                    #   status 0xc0000481 (STATUS_API_SET_NOT_PRESENT)
                    #   LdrpInitializeProcess - ERROR: Walking the import
                    #   tables of the executable and its static imports
                    #   failed with status 0xc0000481
                    # -- i.e. `SECHOST.dll` (itself one of the 57 embedded
                    # dependencies here, pulled in as an export-forward
                    # target of ADVAPI32.dll, nothing to do with delay
                    # imports at all) has its own perfectly ordinary,
                    # genuine `/DELAYLOAD` import of that API set --
                    # independently confirmed to have no real host at all on
                    # this machine (`LoadLibraryW` on it fails with
                    # `ERROR_MODULE_NOT_FOUND`/126, outside this project
                    # entirely). That's fine -- *expected*, even -- for a
                    # real delay import: it's resolved only on an actual
                    # first call, which evidently never happens during 010
                    # Editor's own normal startup, so the original,
                    # unmodified binary never cares that this particular
                    # API set doesn't exist on this machine. Forced into the
                    # *ordinary* import table instead, its absence became a
                    # mandatory, unrecoverable process-startup failure.
                    #
                    # So delay imports must never be folded into
                    # `merged_descriptors`. The natural next idea --
                    # restore the pre-77ccd2e behavior and leave every
                    # delay-import descriptor *completely untouched* -- was
                    # tried next here and *also* empirically falsified by a
                    # real crash, reproduced against the real 010 Editor
                    # embed and root-caused live under `cdb`:
                    #   LdrResolveDelayLoadedAPI - ERROR:
                    #   LdrResolveDelayLoadedAPI:Unable to locate DLL based
                    #   at 0x00000001425B0000. Status = 0xc0000135
                    #   Access violation - code c0000005 (first chance)
                    #   00000000`00000000 ??              ???
                    # -- this is the *original* bug 77ccd2e set out to fix
                    # in the first place (RIP becoming exactly 0), and it
                    # turns out to be unavoidable for *any* embedded
                    # dependency with its own delay imports, regardless of
                    # the delay-import's target: the compiler's own
                    # generated thunk calls `LdrResolveDelayLoadedAPI` with
                    # `ParentModuleBase` computed as `&__ImageBase` (an
                    # ordinary RIP-relative reference, which after
                    # embedding correctly resolves to this dependency's own
                    # placement *within* the host image -- the same
                    # property that lets its entry point, export table, and
                    # TLS directory all keep working untouched) -- but
                    # `LdrResolveDelayLoadedAPI` needs that address to be a
                    # *real, separately loaded module's* base, registered
                    # in the process's own loaded-module list, which it
                    # isn't once embedded, so the lookup fails and the
                    # thunk's own handling of that failure dereferences a
                    # null/garbage result. This has nothing to do with
                    # whether the delay-import's *target* is a real,
                    # always-loadable external DLL or itself embedded --
                    # it's purely about the *owning* dependency's own
                    # module identity being gone.
                    #
                    # So the compiler's own delay-load thunk can never be
                    # allowed to run for *any* delay import belonging to an
                    # embedded dependency. Two cases, split by what the
                    # *target* is (mirroring the ordinary-import B1 split
                    # above, but both sides now need active handling,
                    # unlike B1 where the "not embedded" side is a no-op):
                    #
                    # 1. Target IS embedded this run: there's no live DLL
                    #    by that name left to delay-load at all, so route
                    #    each function through `pending_dep_delay_iat_
                    #    patches` -- resolved directly to the embedded
                    #    target's own final address in the finalize pass
                    #    below, bypassing the delay-load thunk entirely (no
                    #    thunk code ever runs, since the IAT slot already
                    #    holds the real address by the time anything could
                    #    call through it). See that list's own declaration
                    #    above for the real, observed case (SHLWAPI.dll's
                    #    delay import of SHELL32.dll's ordinal 102) that
                    #    makes its soft-fail-on-resolve-failure fallback
                    #    necessary.
                    #
                    # 2. Target NOT embedded this run (the common case:
                    #    checked via the real DLL name, not merely a
                    #    theoretical concern -- a scan of this same real
                    #    010 Editor closure found >100 case-1 hits once
                    #    ADVAPI32/SHELL32/COMDLG32/SHLWAPI/SHCORE/NETAPI32/
                    #    etc. are all embedded, so case 2 -- everything
                    #    else -- is the overwhelming majority): the target
                    #    DLL is still perfectly real and loadable, so route
                    #    each function through `pending_dep_delay_lazy_
                    #    thunks` instead, resolved by its own finalize pass
                    #    (after the merged import directory below adds two
                    #    fresh KERNEL32.dll IAT slots for `LoadLibraryA`/
                    #    `GetProcAddress`) into a tiny generated per-
                    #    function replacement thunk -- see `build_windows_
                    #    delay_import_lazy_thunk`'s own docstring for
                    #    exactly what it does and why. Each such function's
                    #    IAT slot is patched (in the same finalize pass) to
                    #    point at that generated thunk instead of the
                    #    compiler's own (which never runs), so genuine
                    #    laziness is preserved -- nothing executes until
                    #    the host's own code actually calls through that
                    #    slot for the first time -- while what runs *then*
                    #    is safe.
                    if hasattr(dep, "DIRECTORY_ENTRY_DELAY_IMPORT"):
                        for delay_mod in dep.DIRECTORY_ENTRY_DELAY_IMPORT:
                            if not delay_mod.struct.pINT or not delay_mod.struct.pIAT:
                                continue
                            delay_dll_lower = delay_mod.dll.decode("ascii").lower()
                            target_is_embedded = delay_dll_lower in embedded_names_lower
                            if not target_is_embedded and not is64:
                                raise ValueError(
                                    f"cannot embed '{node.name}': its own delay "
                                    f"import of '{delay_dll_lower}' (a real, "
                                    f"external DLL, not itself embedded this run) "
                                    f"needs a generated lazy-resolution thunk, "
                                    f"which this project only implements for x64 "
                                    f"so far -- see docs/limitations.md"
                                )
                            dll_name_va = image_base + X + delay_mod.struct.szName
                            for imp in delay_mod.imports:
                                if imp.import_by_ordinal:
                                    key = imp.ordinal
                                else:
                                    if imp.name is None:
                                        raise ValueError(
                                            f"cannot embed '{node.name}': its own "
                                            f"delay-import of '{delay_dll_lower}' has "
                                            f"an entry with neither a name nor an "
                                            f"ordinal"
                                        )
                                    key = imp.name.decode("ascii")
                                slot_offset_in_blob = imp.address - dep_image_base
                                if target_is_embedded:
                                    pending_dep_delay_iat_patches.append(
                                        (node.name.lower(), slot_offset_in_blob, delay_dll_lower, key)
                                    )
                                else:
                                    if imp.import_by_ordinal:
                                        func_key_va_or_ordinal = imp.ordinal
                                        func_key_is_ordinal = True
                                    else:
                                        func_key_va_or_ordinal = image_base + X + imp.name_offset
                                        func_key_is_ordinal = False
                                    pending_dep_delay_lazy_thunks.append((
                                        node.name.lower(), slot_offset_in_blob, dll_name_va,
                                        func_key_va_or_ordinal, func_key_is_ordinal,
                                    ))

                    entry_rva = dep.OPTIONAL_HEADER.AddressOfEntryPoint
                    if entry_rva:
                        dep_entry_calls.append((node.name, image_base + X, image_base + X + entry_rva))

                    # Keep `blob` itself (not a `bytes()` snapshot) in
                    # `new_sections` -- it's still a mutable bytearray, and
                    # `pending_dep_iat_patches`'s finalize pass (after this
                    # loop, before the actual file write-out below) patches
                    # this same dependency's own IAT slots in place via
                    # `dep_blobs_by_name_lower`, which must observe those
                    # writes.
                    new_sections.append((
                        f".sdep{len(new_sections)}".encode("ascii"), blob, X, _SCN_CODE_RWX, len(blob),
                    ))
                    dep_blobs_by_name_lower[node.name.lower()] = blob
                    dep_X_by_name_lower[node.name.lower()] = X
                    # `len(blob)` rather than `blob_size` -- the TLS
                    # phase-2 splice above (when it fires) appends extra
                    # bytes past the original (already section-aligned)
                    # `blob_size`, so `blob` itself may now be longer.
                    occupied_ranges.append((X, X + len(blob), node.name))
                    # For the reloc-bearing path X == next_rva always, so
                    # this is equivalent to the old unconditional
                    # `next_rva = X + blob_size`. For a no-reloc dependency,
                    # X can be far from (and even behind) the append
                    # cursor's previous value; never move the cursor
                    # backwards, so later appended structures (merged
                    # imports, the init stub, the combined reloc table)
                    # keep landing past every reservation made so far.
                    # `_align_up` re-rounds to a section boundary in case
                    # the TLS phase-2 splice above grew `blob` past that.
                    next_rva = max(next_rva, _align_up(X + len(blob), section_alignment))
                finally:
                    dep.close()

            # -- finalize deferred host IAT patches --------------------------
            # Every dependency in `order` now has an `X` placement and a raw
            # export table recorded in `global_raw_exports_by_dll` -- resolve
            # each pending host import (including any forward chain, however
            # it's oriented relative to embed order; see
            # `pending_host_iat_patches`'s declaration above for why that
            # couldn't be done inline in the main loop) and apply it now.
            def _resolve_raw_export(dll_lower: str, key, _depth: int = 0) -> int:
                if _depth > 16:
                    raise ValueError(
                        f"forward chain resolving '{key}' in '{dll_lower}' is "
                        f"too deep (possible forwarder cycle)"
                    )
                table = global_raw_exports_by_dll.get(dll_lower)
                if table is None or key not in table:
                    raise ValueError(
                        f"cannot resolve export '{key}' of '{dll_lower}': it "
                        f"isn't an already-embedded dependency (forward "
                        f"targets must themselves be embedded -- is it "
                        f"excluded, or not resolvable?)"
                    )
                entry = table[key]
                if isinstance(entry, tuple):
                    _, fwd_dll_lower, fwd_func, forwarder = entry
                    try:
                        return _resolve_raw_export(fwd_dll_lower, fwd_func, _depth + 1)
                    except ValueError:
                        raise ValueError(
                            f"'{dll_lower}' exports '{key}' as a forward to "
                            f"'{forwarder}', but '{fwd_dll_lower}' isn't an "
                            f"already-embedded dependency (forward targets "
                            f"must themselves be embedded -- is it excluded, "
                            f"or not resolvable?)"
                        )
                return entry

            for iat_slot_rva, dll_lower, key in pending_host_iat_patches:
                target_va = _resolve_raw_export(dll_lower, key)
                slot_offset = pe.get_offset_from_rva(iat_slot_rva)
                output[slot_offset:slot_offset + ptr_size] = target_va.to_bytes(ptr_size, "little")
                new_reloc_entries.append(
                    (iat_slot_rva, IMAGE_REL_BASED_DIR64 if is64 else IMAGE_REL_BASED_HIGHLOW)
                )

            # -- finalize deferred dependency-to-dependency IAT patches (B1) --
            # Mirrors the host-IAT finalize pass immediately above: every
            # dependency in `order` now has an `X` placement and raw export
            # table, so every other dependency's own import of an embedded
            # dependency (`pending_dep_iat_patches`, recorded in the main
            # loop above) can now be resolved and patched directly into
            # that *importing* dependency's own blob -- `dep_blobs_by_name_
            # lower` still holds the same mutable bytearray referenced from
            # `new_sections`, so this write is visible when that section's
            # bytes are actually laid out into `output` below.
            for dep_name_lower, slot_offset_in_blob, dll_lower, key in pending_dep_iat_patches:
                target_va = _resolve_raw_export(dll_lower, key)
                dep_blob = dep_blobs_by_name_lower[dep_name_lower]
                dep_blob[slot_offset_in_blob:slot_offset_in_blob + ptr_size] = target_va.to_bytes(
                    ptr_size, "little"
                )
                dep_X = dep_X_by_name_lower[dep_name_lower]
                new_reloc_entries.append(
                    (dep_X + slot_offset_in_blob, IMAGE_REL_BASED_DIR64 if is64 else IMAGE_REL_BASED_HIGHLOW)
                )

            # -- finalize deferred dependency-to-dependency DELAY-IAT -------
            # -- patches -----------------------------------------------------
            # Same mechanism as the B1 finalize pass immediately above, for
            # a delay-import whose target is itself one of this run's
            # embedded dependencies (`pending_dep_delay_iat_patches`,
            # recorded in the main loop above) -- except a resolution
            # failure here is NOT fatal: unlike an ordinary import (whose
            # target's live descriptor was already unconditionally removed,
            # leaving no safe fallback), a delay import's target DLL is
            # still a real, loadable file on disk even once it's also been
            # embedded, so leaving this one IAT slot's original compiled
            # bytes completely untouched -- the same "no special handling"
            # treatment every delay import whose target ISN'T embedded
            # already gets, above -- is always a safe fallback: in the
            # worst case, that one specific function falls back to a real,
            # genuinely lazy delay-load of a second, disk-resident copy of
            # the target DLL if the host's own code ever actually calls it
            # (the duplicate-live-copy case B1 otherwise guards against),
            # rather than this embed() run failing outright over a function
            # that may never even be called in practice. A real, observed
            # case this matters for: SHLWAPI.dll genuinely delay-imports
            # SHELL32.dll's ordinal 102 (`SHCoCreateInstance`), which
            # SHELL32 itself can only re-export as a forward to
            # `api-ms-win-shell-shellcom-l1-1-0.dll` -- a virtual API-set
            # DLL with no real host at all on this machine (confirmed:
            # `LoadLibraryW` on it fails with `ERROR_MODULE_NOT_FOUND`),
            # hence never embeddable -- a separate, pre-existing, out-of-
            # scope limitation around forward resolution (see
            # limitations.md), not something this delay-import fix should
            # turn into a hard failure merely because SHELL32.dll happens
            # to also be embedded in this same run.
            for dep_name_lower, slot_offset_in_blob, dll_lower, key in pending_dep_delay_iat_patches:
                try:
                    target_va = _resolve_raw_export(dll_lower, key)
                except ValueError:
                    continue
                dep_blob = dep_blobs_by_name_lower[dep_name_lower]
                dep_blob[slot_offset_in_blob:slot_offset_in_blob + ptr_size] = target_va.to_bytes(
                    ptr_size, "little"
                )
                dep_X = dep_X_by_name_lower[dep_name_lower]
                new_reloc_entries.append(
                    (dep_X + slot_offset_in_blob, IMAGE_REL_BASED_DIR64 if is64 else IMAGE_REL_BASED_HIGHLOW)
                )

            # -- synthetic KERNEL32.dll LoadLibraryA/GetProcAddress import --
            # Needed only if at least one delay import landed in
            # `pending_dep_delay_lazy_thunks` above -- every such generated
            # thunk calls through these two fresh IAT slots (see
            # `build_windows_delay_import_lazy_thunk`'s own docstring) to
            # do its own real, runtime LoadLibraryA+GetProcAddress
            # resolution, entirely independent of whatever KERNEL32
            # imports the host or any dependency already happens to have
            # (which may or may not already include these two specific
            # names -- never assumed either way). KERNEL32.dll itself is
            # never embeddable/excludable by this project's own design, so
            # a plain, ordinary (eager) import of it is always safe --
            # nothing optional or API-set-shaped about it, unlike the
            # delay-import targets this whole fix is about.
            #
            # A second, independent `IMAGE_IMPORT_DESCRIPTOR` for a DLL
            # name the image already imports elsewhere (if it does) is
            # unremarkable and standard -- the PE format allows any number
            # of descriptors per DLL, each resolved independently by the
            # real loader -- so this never needs to look for or reuse an
            # existing KERNEL32 entry.
            if pending_dep_delay_lazy_thunks:
                _k32_name = b"KERNEL32.DLL\x00"
                _ll_name = b"LoadLibraryA\x00"
                _gpa_name = b"GetProcAddress\x00"
                k32_blob = bytearray()
                k32_blob += _k32_name
                ll_ibn_off = len(k32_blob)
                k32_blob += struct.pack("<H", 0) + _ll_name  # IMAGE_IMPORT_BY_NAME: Hint, Name
                while len(k32_blob) % 2:
                    k32_blob += b"\x00"
                gpa_ibn_off = len(k32_blob)
                k32_blob += struct.pack("<H", 0) + _gpa_name
                while len(k32_blob) % ptr_size:
                    k32_blob += b"\x00"
                int_off = len(k32_blob)
                k32_blob += b"\x00" * (ptr_size * 3)
                iat_off = len(k32_blob)
                k32_blob += b"\x00" * (ptr_size * 3)

                k32_rva = next_rva
                for base_off in (int_off, iat_off):
                    k32_blob[base_off:base_off + ptr_size] = (k32_rva + ll_ibn_off).to_bytes(ptr_size, "little")
                    k32_blob[base_off + ptr_size:base_off + 2 * ptr_size] = (
                        (k32_rva + gpa_ibn_off).to_bytes(ptr_size, "little")
                    )
                    # third qword/dword of each array is already the null
                    # terminator from the zero-fill above.

                # `_SCN_CODE_RWX`, not `_SCN_DATA_R` -- this blob's IAT
                # array (unlike `.sidata2`'s own descriptor-only bytes
                # just below, never itself written to at runtime) is
                # exactly what the real loader's own import-snapping
                # overwrites in place with each resolved function's
                # absolute address, same as it does for any ordinary
                # import's `FirstThunk` array (which is why every other
                # dependency's own such array -- living inside that
                # dependency's `blob`, appended via `.sdepN` below -- is
                # also placed RWX, not read-only). Confirmed the hard way:
                # a read-only placement here reproduced a real
                # `STATUS_ACCESS_VIOLATION` inside `ntdll!LdrpSnapModule`
                # itself (a write fault on this exact IAT slot) against
                # `tests/windows/test_pe_real_binaries.py::
                # test_second_real_binary_curated_subset` (the only
                # existing test whose embedded dependency, WS2_32.dll,
                # happens to have delay imports of its own, so it's the
                # only one that ever exercises this synthetic import at
                # all).
                new_sections.append((
                    b".sdlzimp", bytes(k32_blob), k32_rva, _SCN_CODE_RWX, len(k32_blob),
                ))
                next_rva = _align_up(k32_rva + len(k32_blob), section_alignment)

                merged_descriptors.append({
                    "name_rva": k32_rva,
                    "orig_first_thunk_rva": k32_rva + int_off,
                    "first_thunk_rva": k32_rva + iat_off,
                })
                loadlibrarya_iat_slot_va = image_base + k32_rva + iat_off
                getprocaddress_iat_slot_va = image_base + k32_rva + iat_off + ptr_size
            else:
                loadlibrarya_iat_slot_va = None
                getprocaddress_iat_slot_va = None

            # -- runtime LoadLibraryW/LoadLibraryA/GetProcAddress hook: ----
            # -- locate every real KERNEL32 IAT slot for the three, and ---
            # -- add a synthetic import for whichever has none at all -----
            # (step 1 of this module's own top-of-file docstring's "Hook
            # mechanism" section). `kernel32_hook_slot_vas` already holds
            # every slot the main per-dependency loop above found among
            # each dependency's own *remaining* (non-embedded-target)
            # KERNEL32 imports; this adds the host's own (read directly
            # from `pe.DIRECTORY_ENTRY_IMPORT` -- KERNEL32.dll is never
            # one of the embedded/removed dependencies, so this still
            # accurately reflects the host's real, surviving import table
            # even this late). x64 only (matches this whole hook
            # mechanism's own scope), and only attempted at all when at
            # least one *real* (non-synthetic, `hinst != 0` -- excludes
            # the `__tls_fixup_*__` entries, which share this same
            # `dep_entry_calls` list but aren't real embedded modules)
            # dependency exists to ever hook a name against.
            hookable_deps_exist = is64 and any(hinst for _, hinst, _ in dep_entry_calls)
            if hookable_deps_exist and hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for host_entry in pe.DIRECTORY_ENTRY_IMPORT:
                    if host_entry.dll.decode("ascii").lower() != "kernel32.dll":
                        continue
                    for imp in host_entry.imports:
                        if imp.import_by_ordinal or imp.name is None:
                            continue
                        api_name = imp.name.decode("ascii").lower()
                        if api_name in kernel32_hook_slot_vas:
                            kernel32_hook_slot_vas[api_name].append(imp.address)

            if hookable_deps_exist:
                missing_apis = [api for api, slots in kernel32_hook_slot_vas.items() if not slots]
                if missing_apis:
                    # Same synthetic-import mechanism as the delay-import
                    # lazy thunk's own KERNEL32 import just above
                    # (deliberately NOT reused/shared with it -- a second,
                    # independent IMAGE_IMPORT_DESCRIPTOR for a DLL the
                    # image already imports elsewhere, including via that
                    # other synthetic entry, is unremarkable and standard;
                    # see that section's own comment), generalized from
                    # its fixed two names to however many of the three
                    # hook APIs genuinely have zero real call sites
                    # anywhere in the already-merged import graph.
                    _hook_api_export_name = {
                        "loadlibrarya": b"LoadLibraryA\x00",
                        "loadlibraryw": b"LoadLibraryW\x00",
                        "getprocaddress": b"GetProcAddress\x00",
                        "virtualprotect": b"VirtualProtect\x00",
                    }
                    syn_blob = bytearray()
                    syn_blob += b"KERNEL32.DLL\x00"
                    ibn_offs = []
                    for api in missing_apis:
                        ibn_offs.append(len(syn_blob))
                        syn_blob += struct.pack("<H", 0) + _hook_api_export_name[api]
                        while len(syn_blob) % 2:
                            syn_blob += b"\x00"
                    while len(syn_blob) % ptr_size:
                        syn_blob += b"\x00"
                    n_missing = len(missing_apis)
                    int_off = len(syn_blob)
                    syn_blob += b"\x00" * (ptr_size * (n_missing + 1))
                    iat_off = len(syn_blob)
                    syn_blob += b"\x00" * (ptr_size * (n_missing + 1))

                    syn_rva = next_rva
                    for i in range(n_missing):
                        name_rva = syn_rva + ibn_offs[i]
                        for base_off in (int_off, iat_off):
                            off = base_off + i * ptr_size
                            syn_blob[off:off + ptr_size] = name_rva.to_bytes(ptr_size, "little")

                    new_sections.append((
                        b".shkimp", bytes(syn_blob), syn_rva, _SCN_CODE_RWX, len(syn_blob),
                    ))
                    next_rva = _align_up(syn_rva + len(syn_blob), section_alignment)

                    merged_descriptors.append({
                        "name_rva": syn_rva,
                        "orig_first_thunk_rva": syn_rva + int_off,
                        "first_thunk_rva": syn_rva + iat_off,
                    })
                    for i, api in enumerate(missing_apis):
                        kernel32_hook_slot_vas[api].append(image_base + syn_rva + iat_off + i * ptr_size)

            # -- merged/combined import directory -------------------------
            if removed_dll_names_lower or merged_descriptors:
                combined: List[Dict[str, int]] = []
                if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                    for host_entry in pe.DIRECTORY_ENTRY_IMPORT:
                        if host_entry.dll.decode("ascii").lower() in removed_dll_names_lower:
                            continue
                        combined.append({
                            "name_rva": host_entry.struct.Name,
                            "orig_first_thunk_rva": host_entry.struct.OriginalFirstThunk,
                            "first_thunk_rva": host_entry.struct.FirstThunk,
                        })
                combined.extend(merged_descriptors)

                import_bytes = bytearray()
                for d in combined:
                    import_bytes += struct.pack(
                        "<IIIII", d["orig_first_thunk_rva"], 0, 0, d["name_rva"], d["first_thunk_rva"]
                    )
                import_bytes += struct.pack("<IIIII", 0, 0, 0, 0, 0)  # null terminator

                import_rva = next_rva
                new_sections.append((
                    b".sidata2", bytes(import_bytes), import_rva, _SCN_DATA_R, len(import_bytes),
                ))
                next_rva = _align_up(import_rva + len(import_bytes), section_alignment)
            else:
                import_rva = None
                import_bytes = b""

            # -- finalize deferred delay-import lazy-resolution thunks -----
            # `loadlibrarya_iat_slot_va`/`getprocaddress_iat_slot_va` are
            # only known now that the synthetic KERNEL32 import above has
            # been placed, so this necessarily runs after it (and after
            # the merged import directory, though it doesn't itself need
            # anything from there). Build every pending thunk's own code
            # first (into one growing buffer, each noting its own offset
            # within it), *then* place that buffer as a single new
            # section and only then patch every calling IAT slot -- a
            # thunk's own code never needs to know its own eventual
            # address (nothing in it is self-referential), only each
            # *calling* IAT slot does, so there's no ordering hazard in
            # splitting it this way, and it avoids a second full pass
            # purely to compute placement.
            if pending_dep_delay_lazy_thunks:
                thunks_blob = bytearray()
                thunk_patches: List[Tuple[str, int, int, List[int]]] = []
                for (dep_name_lower, slot_offset_in_blob, dll_name_va,
                     func_key_va_or_ordinal, func_key_is_ordinal) in pending_dep_delay_lazy_thunks:
                    dep_X = dep_X_by_name_lower[dep_name_lower]
                    self_iat_slot_va = image_base + dep_X + slot_offset_in_blob
                    code, reloc_offsets = build_windows_delay_import_lazy_thunk(
                        dll_name_va=dll_name_va,
                        func_key_va_or_ordinal=func_key_va_or_ordinal,
                        func_key_is_ordinal=func_key_is_ordinal,
                        loadlibrarya_iat_slot_va=loadlibrarya_iat_slot_va,
                        getprocaddress_iat_slot_va=getprocaddress_iat_slot_va,
                        self_iat_slot_va=self_iat_slot_va,
                    )
                    thunk_off = len(thunks_blob)
                    thunks_blob += code
                    thunk_patches.append((dep_name_lower, slot_offset_in_blob, thunk_off, reloc_offsets))

                thunks_rva = next_rva
                new_sections.append((
                    b".sdlzthk", bytes(thunks_blob), thunks_rva, _SCN_CODE_RWX, len(thunks_blob),
                ))
                next_rva = _align_up(thunks_rva + len(thunks_blob), section_alignment)

                reloc_type = IMAGE_REL_BASED_DIR64 if is64 else IMAGE_REL_BASED_HIGHLOW
                for dep_name_lower, slot_offset_in_blob, thunk_off, reloc_offsets in thunk_patches:
                    thunk_va = image_base + thunks_rva + thunk_off
                    dep_blob = dep_blobs_by_name_lower[dep_name_lower]
                    dep_blob[slot_offset_in_blob:slot_offset_in_blob + ptr_size] = thunk_va.to_bytes(
                        ptr_size, "little"
                    )
                    dep_X = dep_X_by_name_lower[dep_name_lower]
                    new_reloc_entries.append((dep_X + slot_offset_in_blob, reloc_type))
                    for off in reloc_offsets:
                        new_reloc_entries.append((thunks_rva + thunk_off + off, reloc_type))

            # -- generated init-call stub (build_windows_stub, Task 7) -----
            if dep_entry_calls:
                reloc_type = IMAGE_REL_BASED_DIR64 if is64 else IMAGE_REL_BASED_HIGHLOW
                init_order_names = [name for name, _, _ in dep_entry_calls]
                dep_entry_vas = {name: (hinst, entry) for name, hinst, entry in dep_entry_calls}

                # -- runtime LoadLibraryW/LoadLibraryA/GetProcAddress -----
                # -- hook: data tables + trampolines + install code -------
                # (steps 2-4 of this module's own docstring's "Hook
                # mechanism" section; step 1 -- `kernel32_hook_slot_vas` --
                # was already handled above). `hooked_names` excludes the
                # synthetic `__tls_fixup_*__` entries sharing this same
                # `dep_entry_calls` list (`hinst == 0` for those; every
                # real embedded dependency's own `hinst_va` is never 0).
                hooked_names = {name for name in init_order_names if dep_entry_vas[name][0]}
                if is64 and hooked_names:
                    hookdata_rva = next_rva
                    hook_blob = bytearray()
                    # Offsets (within `hook_blob`) of every absolute-VA
                    # 8-byte field written as *data* below -- each needs
                    # its own base-relocation entry, same as every other
                    # hardcoded absolute address this project emits (see
                    # this module's own docstring). Code-immediate offsets
                    # (the trampolines'/install code's own sentinel
                    # splices) are collected separately, from each
                    # builder's own returned offset list.
                    hook_reloc_offsets: List[int] = []

                    def _hook_va(offset: int) -> int:
                        return image_base + hookdata_rva + offset

                    def _put_va(value: int) -> None:
                        hook_reloc_offsets.append(len(hook_blob))
                        hook_blob.extend(value.to_bytes(8, "little"))

                    def _put_plain_u64(value: int) -> None:
                        hook_blob.extend((value & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little"))

                    # Per hooked dependency: its own wide/ANSI name string
                    # (for the LoadLibraryW/A match tables) and its own
                    # GetProcAddress by-name/by-ordinal sub-tables, built
                    # from `pending_hook_export_syms` -- resolving any
                    # still-unresolved forward (`("fwd", ...)`) entry via
                    # `_resolve_raw_export` (defined above, in the finalize
                    # pass that already needs the exact same resolution),
                    # and simply leaving an export out of this module's own
                    # table if that fails (see pe_stub.py's own docstring's
                    # scope-limits section on why that's a safe, honest
                    # fallback here -- `NULL`, matching a real "not
                    # found", rather than a hard embed() failure).
                    loadlib_entries: List[Tuple[int, int, int]] = []  # (wide_off, ansi_off, hinst)
                    module_table_entries: List[Tuple[int, int, int]] = []  # (hinst, name_tbl_off, ord_tbl_off)
                    for name in init_order_names:
                        hinst, _entry_va = dep_entry_vas[name]
                        if not hinst:
                            continue
                        name_lower = name.lower()

                        wide_off = len(hook_blob)
                        hook_blob.extend(name.encode("utf-16-le") + b"\x00\x00")
                        ansi_off = len(hook_blob)
                        hook_blob.extend(name.encode("ascii") + b"\x00")
                        loadlib_entries.append((wide_off, ansi_off, hinst))

                        name_rows: List[Tuple[int, int]] = []
                        ord_rows: List[Tuple[int, int]] = []
                        for ordinal, name_va, raw_entry in pending_hook_export_syms.get(name_lower, []):
                            if isinstance(raw_entry, tuple):
                                try:
                                    resolved_va = _resolve_raw_export(name_lower, ordinal)
                                except ValueError:
                                    continue
                            else:
                                resolved_va = raw_entry
                            ord_rows.append((ordinal, resolved_va))
                            if name_va is not None:
                                name_rows.append((name_va, resolved_va))

                        while len(hook_blob) % 8:
                            hook_blob.append(0)
                        name_table_off = len(hook_blob)
                        for nva, rva_ in name_rows:
                            _put_va(nva)
                            _put_va(rva_)
                        _put_plain_u64(0)
                        _put_plain_u64(0)

                        ord_table_off = len(hook_blob)
                        for ordv, rva_ in ord_rows:
                            _put_plain_u64(ordv)  # a small integer, not a VA -- never relocated
                            _put_va(rva_)
                        _put_plain_u64(0xFFFFFFFFFFFFFFFF)
                        _put_plain_u64(0)

                        module_table_entries.append((hinst, name_table_off, ord_table_off))

                    while len(hook_blob) % 8:
                        hook_blob.append(0)
                    wide_table_off = len(hook_blob)
                    for wide_off, _ansi_off, hinst in loadlib_entries:
                        _put_va(_hook_va(wide_off))
                        _put_va(hinst)
                    _put_plain_u64(0)
                    _put_plain_u64(0)

                    ansi_table_off = len(hook_blob)
                    for _wide_off, ansi_off, hinst in loadlib_entries:
                        _put_va(_hook_va(ansi_off))
                        _put_va(hinst)
                    _put_plain_u64(0)
                    _put_plain_u64(0)

                    module_table_off = len(hook_blob)
                    for hinst, name_off, ord_off in module_table_entries:
                        _put_va(hinst)
                        _put_va(_hook_va(name_off))
                        _put_va(_hook_va(ord_off))
                    _put_plain_u64(0)
                    _put_plain_u64(0)
                    _put_plain_u64(0)

                    saved_loadlibw_off = len(hook_blob)
                    _put_plain_u64(0)
                    saved_loadliba_off = len(hook_blob)
                    _put_plain_u64(0)
                    saved_getproc_off = len(hook_blob)
                    _put_plain_u64(0)
                    # Transient scratch cell `build_windows_hook_install`
                    # reuses across every one of its own VirtualProtect
                    # calls (see that function's own docstring) -- never
                    # read by anything else, so one shared cell suffices.
                    scratch_dword_off = len(hook_blob)
                    _put_plain_u64(0)

                    loadlibw_code, loadlibw_relocs = build_windows_loadlibrary_trampoline(
                        is_wide=True,
                        match_table_va=_hook_va(wide_table_off),
                        saved_original_va=_hook_va(saved_loadlibw_off),
                    )
                    loadlibw_off = len(hook_blob)
                    hook_blob.extend(loadlibw_code)
                    hook_reloc_offsets.extend(loadlibw_off + off for off in loadlibw_relocs)

                    loadliba_code, loadliba_relocs = build_windows_loadlibrary_trampoline(
                        is_wide=False,
                        match_table_va=_hook_va(ansi_table_off),
                        saved_original_va=_hook_va(saved_loadliba_off),
                    )
                    loadliba_off = len(hook_blob)
                    hook_blob.extend(loadliba_code)
                    hook_reloc_offsets.extend(loadliba_off + off for off in loadliba_relocs)

                    getproc_code, getproc_relocs = build_windows_getprocaddress_trampoline(
                        module_table_va=_hook_va(module_table_off),
                        saved_original_va=_hook_va(saved_getproc_off),
                    )
                    getproc_off = len(hook_blob)
                    hook_blob.extend(getproc_code)
                    hook_reloc_offsets.extend(getproc_off + off for off in getproc_relocs)

                    install_code, install_relocs = build_windows_hook_install(
                        [
                            (
                                _hook_va(saved_loadlibw_off),
                                kernel32_hook_slot_vas["loadlibraryw"],
                                _hook_va(loadlibw_off),
                            ),
                            (
                                _hook_va(saved_loadliba_off),
                                kernel32_hook_slot_vas["loadlibrarya"],
                                _hook_va(loadliba_off),
                            ),
                            (
                                _hook_va(saved_getproc_off),
                                kernel32_hook_slot_vas["getprocaddress"],
                                _hook_va(getproc_off),
                            ),
                        ],
                        virtualprotect_iat_slot_va=kernel32_hook_slot_vas["virtualprotect"][0],
                        scratch_dword_va=_hook_va(scratch_dword_off),
                    )
                    install_off = len(hook_blob)
                    hook_blob.extend(install_code)
                    hook_reloc_offsets.extend(install_off + off for off in install_relocs)

                    new_sections.append((
                        b".shkdat", bytes(hook_blob), hookdata_rva, _SCN_CODE_RWX, len(hook_blob),
                    ))
                    next_rva = _align_up(hookdata_rva + len(hook_blob), section_alignment)
                    for off in hook_reloc_offsets:
                        new_reloc_entries.append((hookdata_rva + off, reloc_type))

                    # Prepend (not append) -- the design's own requirement
                    # that hook installation runs *before* any embedded
                    # module's own initializer, exactly like
                    # `build_windows_stub`'s docstring explains for this
                    # same synthetic-entry trick (`__tls_fixup_*__` is the
                    # pre-existing precedent; this is just the first entry
                    # that specifically needs to run before *every other*
                    # one, not merely alongside its own dependency).
                    dep_entry_calls = [("__hook_install__", 0, _hook_va(install_off))] + dep_entry_calls
                    init_order_names = [name for name, _, _ in dep_entry_calls]
                    dep_entry_vas = {name: (hinst, entry) for name, hinst, entry in dep_entry_calls}

                stub_rva = next_rva
                # B6-PE: when the host (the file embed() is embedding
                # *into*, not a dependency) is itself a DLL, this stub
                # becomes its real DllEntryPoint/DllMain -- called by the
                # OS on every thread attach/detach and process detach, not
                # just once -- so build_windows_stub must guard the
                # per-dependency init-call block to DLL_PROCESS_ATTACH
                # only (see its own docstring on `host_is_dll`).
                host_is_dll = bool(pe.FILE_HEADER.Characteristics & _IMAGE_FILE_DLL)
                stub_bytes, abs_va_offsets = build_windows_stub(
                    init_order_names,
                    # `build_windows_stub` itself never reads this (see
                    # its own docstring) -- the real LoadLibraryW/
                    # LoadLibraryA/GetProcAddress interception mechanism
                    # was already built and spliced into `init_order_names`/
                    # `dep_entry_vas` as the `__hook_install__` entry above,
                    # when applicable (x64 host, at least one hooked name).
                    set(init_order_names),
                    is64=is64,
                    dep_entry_vas=dep_entry_vas,
                    original_entry_va=original_entry_va,
                    host_is_dll=host_is_dll,
                )
                for off in abs_va_offsets:
                    new_reloc_entries.append((stub_rva + off, reloc_type))

                new_sections.append((
                    b".sstub", stub_bytes, stub_rva, _SCN_CODE_RWX, len(stub_bytes),
                ))
                next_rva = _align_up(stub_rva + len(stub_bytes), section_alignment)
            else:
                stub_rva = None

            # -- combined exception (.pdata) directory -----------------------
            if dep_pdata_entries:
                host_excdir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[_IMAGE_DIRECTORY_ENTRY_EXCEPTION]
                host_entries = []
                if host_excdir.Size:
                    raw = pe.get_data(host_excdir.VirtualAddress, host_excdir.Size)
                    for i in range(host_excdir.Size // 12):
                        host_entries.append(struct.unpack_from("<III", raw, i * 12))

                # The x64 ABI requires RtlLookupFunctionEntry's table to be
                # sorted ascending by start RVA (it binary-searches it) --
                # combine the host's own (untouched, already-correct)
                # entries with every dependency's (already shifted to
                # host-relative RVAs above) and re-sort the whole thing,
                # rather than just appending.
                combined_pdata = sorted(host_entries + dep_pdata_entries, key=lambda t: t[0])
                exc_bytes = b"".join(struct.pack("<III", *t) for t in combined_pdata)
                exc_rva = next_rva
                new_sections.append((
                    b".sxcpt2", exc_bytes, exc_rva, _SCN_DATA_R, len(exc_bytes),
                ))
                next_rva = _align_up(exc_rva + len(exc_bytes), section_alignment)
            else:
                exc_rva = None
                exc_bytes = b""

            # -- combined relocation table ----------------------------------
            if new_reloc_entries:
                baserelocdir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[_IMAGE_DIRECTORY_ENTRY_BASERELOC]
                original_reloc_bytes = b""
                if baserelocdir.Size:
                    original_reloc_bytes = pe.get_data(baserelocdir.VirtualAddress, baserelocdir.Size)

                by_page: Dict[int, List[tuple]] = {}
                for rva, rtype in new_reloc_entries:
                    page = rva & ~0xFFF
                    by_page.setdefault(page, []).append((rva - page, rtype))

                new_blocks = bytearray()
                for page in sorted(by_page):
                    items = by_page[page]
                    entries_bytes = bytearray()
                    for off, rtype in items:
                        entries_bytes += struct.pack("<H", (rtype << 12) | (off & 0xFFF))
                    if len(items) % 2 == 1:
                        entries_bytes += struct.pack("<H", 0)  # pad, IMAGE_REL_BASED_ABSOLUTE filler
                    size_of_block = 8 + len(entries_bytes)
                    new_blocks += struct.pack("<II", page, size_of_block) + bytes(entries_bytes)

                combined_reloc_bytes = bytes(original_reloc_bytes) + bytes(new_blocks)
                reloc_rva = next_rva
                new_sections.append((
                    b".sreloc2", combined_reloc_bytes, reloc_rva, _SCN_DATA_R, len(combined_reloc_bytes),
                ))
                next_rva = _align_up(reloc_rva + len(combined_reloc_bytes), section_alignment)
            else:
                reloc_rva = None
                combined_reloc_bytes = b""

            # -- lay the new sections out in the file & write headers ------
            #
            # The section-header table has a fixed home: it always starts
            # right after the Optional Header (`section_table_offset`) and
            # has no RVA/pointer of its own the loader follows -- unlike
            # ELF's program-header table (relocatable via e_phoff), it
            # can't be moved somewhere else in the file. Its only
            # available capacity is whatever gap the original linker left
            # before the first section's own raw file data
            # (`first_raw_data_offset`). A real-world (especially
            # commercial, tightly-linked) host can leave only a few dozen
            # bytes there -- nowhere near this run's `len(new_sections) *
            # 40` requirement.
            #
            # When that happens, grow the gap itself: push every section's
            # `PointerToRawData` (and `SizeOfHeaders`, which bounds the
            # same headers region) forward by enough `FileAlignment`-
            # aligned bytes to close the shortfall, and physically widen
            # `output` by inserting that many padding bytes right before
            # the first section's current raw data. This only changes
            # FILE offsets, never RVAs/VAs -- every directory this module
            # reads/writes by RVA (imports, relocations, exceptions, TLS,
            # entry point, ...) is untouched by construction. The one
            # exception checked here is the debug directory, whose own
            # entries each carry a raw file-offset pointer
            # (`PointerToRawData`, alongside the RVA-based
            # `AddressOfRawData` this module doesn't otherwise touch)
            # that's now stale and must shift by the same delta.
            needed_header_bytes = len(new_sections) * 40
            available_slack = first_raw_data_offset - (
                section_table_offset + existing_section_count * 40
            )
            if needed_header_bytes > available_slack:
                shortfall = needed_header_bytes - available_slack
                delta = _align_up(shortfall, file_alignment)

                output[first_raw_data_offset:first_raw_data_offset] = b"\x00" * delta

                for sec in pe.sections:
                    if sec.PointerToRawData:
                        ptr_off = sec.get_field_absolute_offset("PointerToRawData")
                        output[ptr_off:ptr_off + 4] = struct.pack(
                            "<I", sec.PointerToRawData + delta
                        )

                if getattr(pe, "DIRECTORY_ENTRY_DEBUG", None):
                    for dbg in pe.DIRECTORY_ENTRY_DEBUG:
                        if dbg.struct.PointerToRawData:
                            # The IMAGE_DEBUG_DIRECTORY array itself lives
                            # inside a section's raw data (e.g. `.rdata`),
                            # not in the headers region before
                            # `first_raw_data_offset` -- unlike
                            # `sec`/`SizeOfHeaders` above, whose own fields
                            # live in the *headers*, before the insert
                            # point, and so need no adjustment. This
                            # struct's own absolute file offset, read from
                            # the original (pre-insert) `pe` parse, was
                            # just pushed forward by `delta` along with
                            # every other byte at/after
                            # `first_raw_data_offset` by the insert above
                            # -- so the offset being written to must be
                            # shifted by the same `delta`, exactly like the
                            # *value* already being written there.
                            # Omitting this (B8-PE) silently corrupted
                            # whatever real data now sits at the stale,
                            # pre-shift offset instead -- confirmed via a
                            # real CPython 3.13 python.exe + python313.dll
                            # embed (enough dependencies to overflow the
                            # section-header slack), which clobbered a
                            # Control Flow Guard support global sitting
                            # `delta` bytes earlier in `.rdata`, segfaulting
                            # on first use.
                            dbg_off = dbg.struct.get_field_absolute_offset("PointerToRawData") + delta
                            output[dbg_off:dbg_off + 4] = struct.pack(
                                "<I", dbg.struct.PointerToRawData + delta
                            )

                szh_off = pe.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfHeaders")
                output[szh_off:szh_off + 4] = struct.pack(
                    "<I", pe.OPTIONAL_HEADER.SizeOfHeaders + delta
                )

                first_raw_data_offset += delta
                available_slack += delta

            for i, (name, data, rva, characteristics, virtual_size) in enumerate(new_sections):
                size_of_raw_data = _align_up(len(data), file_alignment) if data else 0
                if data:
                    file_offset = _align_up(len(output), file_alignment)
                    output.extend(b"\x00" * (file_offset - len(output)))
                    output.extend(data)
                    output.extend(b"\x00" * (size_of_raw_data - len(data)))
                else:
                    # No raw file backing at all (a ".bss"-style filler
                    # section) -- PointerToRawData is conventionally 0 for
                    # these, and nothing needs to be appended to the file.
                    file_offset = 0

                header_offset = section_table_offset + (existing_section_count + i) * 40
                header = _pack_section_header(name, virtual_size, rva, size_of_raw_data, file_offset, characteristics)
                output[header_offset:header_offset + 40] = header

            new_section_count = existing_section_count + len(new_sections)
            noff = pe.FILE_HEADER.get_field_absolute_offset("NumberOfSections")
            output[noff:noff + 2] = struct.pack("<H", new_section_count)

            if reserved_base_ranges:
                # At least one embedded dependency has no relocation data
                # of its own, which means its internal absolute-address
                # references are only correct *as written* when this image
                # loads at exactly its declared ImageBase (that's the
                # entire point of reserving its address range there) --
                # relocating the final image elsewhere (ASLR) would shift
                # those unlisted absolute references without any
                # relocation-table entry to fix them back up. Disable
                # dynamic-base/high-entropy-VA so the loader only ever maps
                # this image at its preferred base (or fails outright,
                # rather than silently corrupting it).
                dllcoff = pe.OPTIONAL_HEADER.get_field_absolute_offset("DllCharacteristics")
                cur_dllc = struct.unpack_from("<H", output, dllcoff)[0]
                IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
                IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
                cur_dllc &= ~(IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
                output[dllcoff:dllcoff + 2] = struct.pack("<H", cur_dllc)

            new_size_of_image = next_rva
            szoff = pe.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfImage")
            output[szoff:szoff + 4] = struct.pack("<I", new_size_of_image)

            if stub_rva is not None:
                epoff = pe.OPTIONAL_HEADER.get_field_absolute_offset("AddressOfEntryPoint")
                output[epoff:epoff + 4] = struct.pack("<I", stub_rva)

            if import_rva is not None:
                impdir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[_IMAGE_DIRECTORY_ENTRY_IMPORT]
                va_off = impdir.get_field_absolute_offset("VirtualAddress")
                sz_off = impdir.get_field_absolute_offset("Size")
                output[va_off:va_off + 4] = struct.pack("<I", import_rva)
                output[sz_off:sz_off + 4] = struct.pack("<I", len(import_bytes))

            if reloc_rva is not None:
                relocdir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[_IMAGE_DIRECTORY_ENTRY_BASERELOC]
                va_off = relocdir.get_field_absolute_offset("VirtualAddress")
                sz_off = relocdir.get_field_absolute_offset("Size")
                output[va_off:va_off + 4] = struct.pack("<I", reloc_rva)
                output[sz_off:sz_off + 4] = struct.pack("<I", len(combined_reloc_bytes))

            if exc_rva is not None:
                excdir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[_IMAGE_DIRECTORY_ENTRY_EXCEPTION]
                va_off = excdir.get_field_absolute_offset("VirtualAddress")
                sz_off = excdir.get_field_absolute_offset("Size")
                output[va_off:va_off + 4] = struct.pack("<I", exc_rva)
                output[sz_off:sz_off + 4] = struct.pack("<I", len(exc_bytes))

            if adopted_tls_directory is not None:
                tls_rva, tls_size = adopted_tls_directory
                tlsdir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[_IMAGE_DIRECTORY_ENTRY_TLS]
                va_off = tlsdir.get_field_absolute_offset("VirtualAddress")
                sz_off = tlsdir.get_field_absolute_offset("Size")
                output[va_off:va_off + 4] = struct.pack("<I", tls_rva)
                output[sz_off:sz_off + 4] = struct.pack("<I", tls_size)

            # Authenticode (IMAGE_DIRECTORY_ENTRY_SECURITY) is left dangling
            # otherwise: embed() always mutates the host's bytes once there
            # is anything to embed (we're well past the early `if not
            # order: return` above), which invalidates any existing
            # Authenticode signature -- but the signature *directory entry*
            # itself isn't touched by anything above, so it would still
            # point at a (now-stale) WIN_CERTIFICATE blob, making the
            # output look signed-but-tampered rather than plainly unsigned.
            # A stale-but-present signature is more misleading than no
            # signature at all, so strip the directory entry outright.
            secdir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[_IMAGE_DIRECTORY_ENTRY_SECURITY]
            if secdir.Size:
                va_off = secdir.get_field_absolute_offset("VirtualAddress")
                sz_off = secdir.get_field_absolute_offset("Size")
                output[va_off:va_off + 4] = struct.pack("<I", 0)
                output[sz_off:sz_off + 4] = struct.pack("<I", 0)

            self.output_path.write_bytes(bytes(output))
        finally:
            pe.close()
