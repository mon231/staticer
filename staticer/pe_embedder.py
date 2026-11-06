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
entry point before handing off to the host's original one; see
``embed()``'s docstring for exactly what's simplified in the stub (it does
not yet implement the design's LoadLibraryW/GetProcAddress-interception
hook).
"""

import os
import struct
from pathlib import Path
from typing import Dict, List, Optional, Set

import pefile

from .common.depgraph import build_dependency_graph, embed_order
from .stubs.windows.pe_stub import build_windows_stub, build_windows_tls_index_fixup

IMAGE_REL_BASED_ABSOLUTE = 0
IMAGE_REL_BASED_HIGHLOW = 3
IMAGE_REL_BASED_DIR64 = 10

_IMAGE_DIRECTORY_ENTRY_IMPORT = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]
_IMAGE_DIRECTORY_ENTRY_BASERELOC = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]
_IMAGE_DIRECTORY_ENTRY_EXCEPTION = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]
_IMAGE_DIRECTORY_ENTRY_TLS = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"]
_IMAGE_DIRECTORY_ENTRY_SECURITY = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
_IMAGE_FILE_DLL = 0x2000  # FILE_HEADER.Characteristics bit: this image is a DLL

# x64 UNWIND_INFO flags (IMAGE_DIRECTORY_ENTRY_EXCEPTION's RUNTIME_FUNCTION
# entries point at one of these per function) -- see _adjust_unwind_info.
_UNW_FLAG_EHANDLER = 0x1
_UNW_FLAG_UHANDLER = 0x2
_UNW_FLAG_CHAININFO = 0x4

_SCN_CODE_RWX = 0x60000020 | 0x80000000  # CNT_CODE|MEM_EXECUTE|MEM_READ|MEM_WRITE
_SCN_DATA_R = 0x40000040  # CNT_INITIALIZED_DATA|MEM_READ
_SCN_UNINIT_RW = 0xC0000080  # CNT_UNINITIALIZED_DATA|MEM_READ|MEM_WRITE (".bss"-style)


def list_pe_imports(path: Path) -> List[str]:
    """Names of the DLLs a PE file imports, read from its IMPORT_DESCRIPTOR
    directory (empty list if it has none)."""
    pe = pefile.PE(str(path))
    try:
        pe.parse_data_directories(directories=[_IMAGE_DIRECTORY_ENTRY_IMPORT])
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return []
        return [entry.dll.decode("ascii") for entry in pe.DIRECTORY_ENTRY_IMPORT]
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

    and, unoptimized, the same `mov r32, imm32` instead appears *before*
    the `_tls_index` load rather than after it -- so this searches a
    bounded window on both sides of it (`anchor_begin`/
    `tls_index_load_end`), not just forward like the mingw-w64 pattern
    above.

    `mov r32, imm32` alone is far too generic a byte shape to trust
    without corroboration (it's an extremely common instruction for
    entirely unrelated reasons), so this only looks for it inside a
    window that also contains a `mov r64, gs:[0x58]`
    (`_TEB_TLS_POINTER_GS_TAIL`) access -- the one instruction every
    compiled `__declspec(thread)`/`__thread` access has in common
    regardless of compiler. Returns whether a match was found and
    patched.

    Known limitation, same honestly-documented spirit as the rest of
    this module: if `_tls_index` itself were loaded into an extended
    register (r8d-r15d, needing its own REX prefix before the `8B`
    opcode the caller matches), this function would never even be
    reached -- the caller's own anchor match doesn't look for that REX
    prefix. Not observed in practice (every real-world and locally
    compiled case seen loads it into eax/ecx/edx), so left as a gap
    rather than guessed at.
    """
    win_begin = max(0, anchor_begin - 32)
    win_end = min(limit, tls_index_load_end + 32, len(blob))
    if blob.find(_TEB_TLS_POINTER_GS_TAIL, win_begin, win_end) < 0:
        return False
    j = win_begin
    while j <= win_end - 5:
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
            if imm_off + 4 <= len(blob):
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


def _patch_dep_tls_access_offsets(blob: bytearray, dep_index_rva: int, shift: int) -> int:
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
    pattern added to that list. Returns how many call sites were found
    and patched (0 means the caller should treat the merge as
    unsupported for this dependency rather than silently leave a wrong
    offset in place).
    """
    count = 0
    n = len(blob)
    i = 0
    while i + 6 <= n:
        if blob[i] == 0x8B and (blob[i + 1] & 0xC7) == 0x05:
            disp = int.from_bytes(blob[i + 2:i + 6], "little", signed=True)
            if i + 6 + disp == dep_index_rva:
                j = i + 6
                for try_pattern in _KNOWN_DEP_TLS_ACCESS_PATTERNS:
                    if try_pattern(blob, i, j, n, shift):
                        count += 1
                        break
                i = j
                continue
        i += 1
    return count


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

        Simplification for this task (explicitly deferred, see
        ``staticer/stubs/windows/pe_stub.py``'s module docstring): step 7's
        stub does not implement the design doc's LoadLibraryW/
        GetProcAddress interception goal -- ``hooked_names`` is threaded
        through as an empty mechanism for interface compatibility, not
        acted on.
        """
        search_dirs = self._search_dirs()
        graph = build_dependency_graph(
            self.input_path, list_pe_imports, resolve_pe, search_dirs, self.lib_dir,
            _CaseInsensitiveNameSet(self.exclude),
        )
        order = embed_order(graph)

        if not order:
            self.output_path.write_bytes(self.input_path.read_bytes())
            return

        pe = pefile.PE(str(self.input_path))
        try:
            pe.parse_data_directories()

            host_machine = pe.FILE_HEADER.Machine
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
            # Every embedded dependency's own blob (bytearray, mutable even
            # once referenced from `new_sections`) and host RVA placement,
            # keyed by lowercased name -- so the finalize pass above can
            # patch a dependency's own IAT slot in place and compute the
            # right host-relative RVA for the accompanying relocation entry.
            dep_blobs_by_name_lower: Dict[str, bytearray] = {}
            dep_X_by_name_lower: Dict[str, int] = {}
            # (host_rva, size, dep_name) of the one dependency TLS directory
            # adopted as the host's own, once that dependency's placement X
            # is known -- see the TLS-directory handling comment in the
            # main loop below and its use at the end of embed() to patch
            # DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_TLS]. Stays None unless
            # some dependency in `order` actually carries a TLS directory.
            merged_tls: Optional[tuple] = None
            # Set instead of `merged_tls` when the HOST *also* already has
            # its own non-empty TLS directory (phase 2 / Task 5 -- see the
            # guard/assignment below). Holds the name of the one
            # dependency that brought its own TLS directory in (merged in
            # place, inline, once its own placement X is known), purely so
            # a *second* TLS-bearing dependency in the same run can be
            # named in the "more than one" guard's error message.
            tls_phase2: Optional[str] = None

            for node in order:
                dep = pefile.PE(str(node.path))
                try:
                    if dep.FILE_HEADER.Machine != host_machine:
                        raise ValueError(
                            f"architecture mismatch embedding '{node.name}': host "
                            f"'{self.input_path}' is {hex(host_machine)}, dependency "
                            f"'{node.path}' is {hex(dep.FILE_HEADER.Machine)}"
                        )

                    dep.parse_data_directories()

                    # TLS-directory handling (Task 2 phase 1 + Task 5 phase
                    # 2 of the design spec's PE merge mechanism): a
                    # dependency carrying its own non-empty
                    # IMAGE_DIRECTORY_ENTRY_TLS (any __declspec(thread)/
                    # thread_local variable) can now be merged in either of
                    # two ways: *adopted* as the host's own TLS directory
                    # when the host had none of its own (phase 1, below,
                    # unchanged), or -- when the host *also* already has
                    # its own non-empty TLS directory -- merged into one
                    # combined raw-data range sharing the host's own
                    # (real, loader-assigned) index slot (phase 2, see the
                    # inline block below, right where `tls_phase2` gets
                    # set, and `_patch_dep_tls_access_offsets`'s and
                    # `build_windows_tls_index_fixup`'s own docstrings, for
                    # the full mechanism and why it's needed: Windows' real
                    # PE loader only natively processes *one* TLS directory
                    # per image).
                    #
                    # Still not supported, for either path: more than one
                    # *dependency* bringing its own TLS directory into the
                    # same embed() run (there's still only one of these
                    # mechanisms set up per run) -- fail loudly rather than
                    # silently pick one and discard/alias the other (per
                    # the design spec's anti-goal: silent corruption is the
                    # one outcome worse than a loud failure). Phase 2 is
                    # also 64-bit-only so far (the synthesized callback is
                    # x64 machine code).
                    dep_tlsdir = dep.OPTIONAL_HEADER.DATA_DIRECTORY[_IMAGE_DIRECTORY_ENTRY_TLS]
                    if dep_tlsdir.Size:
                        if merged_tls is not None or tls_phase2 is not None:
                            already = merged_tls[2] if merged_tls is not None else tls_phase2
                            raise ValueError(
                                f"cannot embed dependency '{node.name}': it has its "
                                f"own Thread Local Storage (TLS) directory, but "
                                f"another dependency ('{already}') already had "
                                f"its TLS directory merged into the host's -- merging "
                                f"TLS directories from more than one dependency into "
                                f"a single host is not yet supported (phase 2 / "
                                f"Task 5)"
                            )
                        if host_has_tls and not is64:
                            raise ValueError(
                                f"cannot embed dependency '{node.name}': both the "
                                f"host and this dependency carry their own Thread "
                                f"Local Storage (TLS) directory, and the host is "
                                f"32-bit -- merging two real TLS directories into "
                                f"one is only implemented for 64-bit hosts so far "
                                f"(phase 2 / Task 5)"
                            )

                    dep_image_base = dep.OPTIONAL_HEADER.ImageBase
                    blob_size = _align_up(dep.OPTIONAL_HEADER.SizeOfImage, section_alignment)
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

                    # Adopt this dependency's TLS directory as the host's
                    # own (see the guard above): the struct's own fields
                    # (StartAddressOfRawData/EndAddressOfRawData/
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
                    # needs patching here -- only the new
                    # DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_TLS] entry
                    # itself (an ordinary RVA+Size pair, like every other
                    # data directory, not a VA) needs to point at it, which
                    # is applied once, after the loop, alongside the other
                    # directory patches.
                    #
                    # Phase 2 (host already has its own TLS directory too):
                    # the struct's contents are equally untouched/correct
                    # in `blob` by this point (same reasoning as above), so
                    # everything the post-loop "TLS phase 2" block needs --
                    # the dependency's own raw-data template VA/size,
                    # zero-fill size, `_tls_index` variable's VA, and its
                    # own (already host-relative, already-correct) callback
                    # VA list -- can be read directly out of `blob` right
                    # now, while `dep`/`blob`/`X` are all still in scope.
                    if dep_tlsdir.Size:
                        if host_has_tls:
                            tls_off = dep_tlsdir.VirtualAddress
                            final_start, final_end, final_index_va, final_cb_va = struct.unpack_from(
                                "<4Q", blob, tls_off
                            )
                            final_zero_fill = struct.unpack_from("<I", blob, tls_off + 32)[0]
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
                            # loader already assigned the host for its own
                            # native TLS directory -- both the host's own
                            # compiled TLS access and this dependency's own
                            # end up reading the exact same per-thread
                            # block, at *different, non-overlapping*
                            # offsets within one combined raw-data range:
                            #
                            # 1. Copy the host's own raw TLS bytes
                            #    (unchanged content, same relative layout)
                            #    immediately followed by this dependency's
                            #    own raw TLS bytes into a new, combined
                            #    range appended onto the end of `blob` --
                            #    the *native* loader then keeps copying
                            #    this correctly into a fresh per-thread
                            #    block on every thread's creation, for
                            #    both halves, with zero custom runtime
                            #    code needed for *that* part (this is
                            #    exactly how the host's own half already
                            #    worked, unaffected).
                            # 2. Patch the host's own TLS directory struct
                            #    (Start/EndAddressOfRawData, SizeOfZeroFill
                            #    -- directly in `output`, below) to point
                            #    at this new combined range instead of its
                            #    original (now-superseded) one.
                            #    AddressOfIndex stays the host's own
                            #    unchanged variable -- that real, loader-
                            #    assigned slot number is exactly what gets
                            #    reused.
                            # 3. The host's own compiled offset into its
                            #    per-thread block (a link-time constant
                            #    relative to its own *original*
                            #    StartAddressOfRawData, which is left at
                            #    the same relative position -- offset 0 of
                            #    the new range -- by placing the host's
                            #    copy first) needs no changes at all.
                            # 4. This dependency's own compiled offset(s),
                            #    by contrast, were computed relative to
                            #    *its own* original StartAddressOfRawData,
                            #    which is no longer offset 0 of the
                            #    combined range (the host's own raw data
                            #    now comes first) -- so every compiled
                            #    access to its own TLS variable(s) needs
                            #    its embedded offset shifted by
                            #    `len(host's own raw bytes)` to land on the
                            #    right spot in the new, combined layout
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
                            #    `build_windows_stub`, Task 7, which runs
                            #    unconditionally once at real process
                            #    start -- or, for a DLL host, once at its
                            #    own real DLL_PROCESS_ATTACH, already
                            #    guarded by `host_is_dll`), copies the
                            #    host's own (by-then loader-assigned)
                            #    `_tls_index` *value* into this
                            #    dependency's own `_tls_index` variable --
                            #    a plain data write, needing no further
                            #    per-thread work, since the slot *number*
                            #    is a process-wide constant once assigned
                            #    (only the per-thread *block pointer*
                            #    varies, and that's the native loader's
                            #    job, unaffected by any of this).
                            host_struct = pe.DIRECTORY_ENTRY_TLS.struct
                            host_start_rva = host_struct.StartAddressOfRawData - image_base
                            host_raw_size = host_struct.EndAddressOfRawData - host_struct.StartAddressOfRawData
                            host_zero_fill = host_struct.SizeOfZeroFill
                            host_index_va = host_struct.AddressOfIndex
                            host_raw_bytes = pe.get_data(host_start_rva, host_raw_size) if host_raw_size else b""

                            dep_index_blob_rva = (final_index_va - image_base) - X
                            raw_size = final_end - final_start
                            dep_raw_off_in_blob = (final_start - image_base) - X
                            dep_raw_bytes = bytes(blob[dep_raw_off_in_blob:dep_raw_off_in_blob + raw_size])

                            patched = _patch_dep_tls_access_offsets(
                                blob, dep_index_blob_rva, host_raw_size
                            )
                            if patched == 0:
                                raise ValueError(
                                    f"cannot embed dependency '{node.name}': merging "
                                    f"its own Thread Local Storage (TLS) directory "
                                    f"into a host that already has its own needs to "
                                    f"locate and shift its own compiled TLS-variable "
                                    f"access offset(s), but none were found matching "
                                    f"the expected compiled pattern -- refusing to "
                                    f"proceed rather than silently leave its TLS "
                                    f"access reading the wrong location"
                                )

                            merged_raw_off = len(blob)
                            blob += host_raw_bytes
                            blob += dep_raw_bytes
                            merged_start_va = image_base + X + merged_raw_off
                            merged_end_va = merged_start_va + len(host_raw_bytes) + len(dep_raw_bytes)
                            merged_zero_fill = host_zero_fill + final_zero_fill

                            start_off = host_struct.get_field_absolute_offset("StartAddressOfRawData")
                            end_off = host_struct.get_field_absolute_offset("EndAddressOfRawData")
                            zf_off = host_struct.get_field_absolute_offset("SizeOfZeroFill")
                            output[start_off:start_off + 8] = struct.pack("<Q", merged_start_va)
                            output[end_off:end_off + 8] = struct.pack("<Q", merged_end_va)
                            output[zf_off:zf_off + 4] = struct.pack("<I", merged_zero_fill)

                            if dep_cb_vas:
                                # The host had none of its own (confirmed
                                # above, `host_cb_va` truthiness) or did --
                                # either way, append this dependency's own
                                # (already host-relative, already-correct)
                                # callback VAs after whatever the host's
                                # own array already held, onto a fresh
                                # combined array (also appended onto
                                # `blob`), and repoint AddressOfCallBacks
                                # at it; left completely alone otherwise.
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

                                while len(blob) % ptr_size:
                                    blob += b"\x00"
                                cb_array_off = len(blob)
                                cb_entries = host_cb_vas + dep_cb_vas
                                for cb_va in cb_entries:
                                    blob += struct.pack("<Q", cb_va)
                                blob += struct.pack("<Q", 0)  # null terminator
                                for i in range(len(cb_entries)):
                                    new_reloc_entries.append(
                                        (X + cb_array_off + i * ptr_size, IMAGE_REL_BASED_DIR64)
                                    )

                                cb_field_off = host_struct.get_field_absolute_offset("AddressOfCallBacks")
                                output[cb_field_off:cb_field_off + ptr_size] = struct.pack(
                                    "<Q", image_base + X + cb_array_off
                                )

                            # The one remaining runtime step: a tiny
                            # generated function copying the host's own
                            # (real, loader-assigned) `_tls_index` value
                            # into this dependency's own `_tls_index`
                            # variable, hooked onto the init-call stub
                            # (see the long comment above).
                            fixup_off = len(blob)
                            fixup_code, fixup_abs_offsets = build_windows_tls_index_fixup(
                                host_tlsindex_va=host_index_va,
                                dep_tlsindex_va=final_index_va,
                            )
                            blob += fixup_code
                            for off in fixup_abs_offsets:
                                new_reloc_entries.append((X + fixup_off + off, IMAGE_REL_BASED_DIR64))
                            fixup_va = image_base + X + fixup_off
                            dep_entry_calls.append((f"__tls_fixup_{node.name}__", 0, fixup_va))

                            tls_phase2 = node.name
                        else:
                            merged_tls = (X + dep_tlsdir.VirtualAddress, dep_tlsdir.Size, node.name)

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
                                entry = ("fwd", fwd_dll_lower, fwd_func, forwarder)
                            else:
                                entry = image_base + X + sym.address
                            raw_exports[sym.ordinal] = entry
                            if name:
                                raw_exports[name] = entry
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

            # -- generated init-call stub (build_windows_stub, Task 7) -----
            if dep_entry_calls:
                reloc_type = IMAGE_REL_BASED_DIR64 if is64 else IMAGE_REL_BASED_HIGHLOW
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
                    # The design's LoadLibraryW/GetProcAddress-interception
                    # goal is for every *embedded* dependency's own name to
                    # resolve to its embedded address if something still
                    # dynamically loads it by name at runtime -- not yet
                    # acted on; see pe_stub.py's module docstring.
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
            if len(new_sections) * 40 > first_raw_data_offset - (
                section_table_offset + existing_section_count * 40
            ):
                raise ValueError(
                    "not enough slack in the host's section header table to add "
                    f"{len(new_sections)} new section(s)"
                )

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

            if merged_tls is not None:
                tls_rva, tls_size, _ = merged_tls
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
