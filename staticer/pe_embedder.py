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
from .stubs.windows.pe_stub import build_windows_stub

IMAGE_REL_BASED_ABSOLUTE = 0
IMAGE_REL_BASED_HIGHLOW = 3
IMAGE_REL_BASED_DIR64 = 10

_IMAGE_DIRECTORY_ENTRY_IMPORT = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]
_IMAGE_DIRECTORY_ENTRY_BASERELOC = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]
_IMAGE_DIRECTORY_ENTRY_EXCEPTION = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]

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


def resolve_pe(name: str, search_dirs: List[Path]) -> Optional[Path]:
    """Scan search_dirs in order for a file literally named `name`."""
    for directory in search_dirs:
        candidate = directory / name
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


def _adjust_unwind_info(blob: bytearray, unwind_rva: int, shift: int, _depth: int = 0) -> None:
    """Patch the RVA-relative fields *inside* an x64 UNWIND_INFO structure
    (and any chained UNWIND_INFO it references) by `shift`, in place
    within `blob`, at the structure's *original* (pre-shift) offset.

    Only two kinds of fields inside UNWIND_INFO are themselves RVAs (and
    so need the same "+shift" treatment as the RUNTIME_FUNCTION entries
    that point at them -- see _collect_and_patch_dep_unwind): a trailing
    exception-handler RVA (present when UNW_FLAG_EHANDLER/UHANDLER is set
    -- this is what the OS actually calls to run a C++ personality
    routine/__except filter when an exception unwinds through the
    function) and a chained RUNTIME_FUNCTION record (when
    UNW_FLAG_CHAININFO is set, itself recursed into). Everything else --
    the unwind-code array, and any language-specific exception data
    following the handler RVA (e.g. GCC's LSDA/call-site table, which
    encodes landing-pad offsets relative to the function itself, and type
    pointers via a self-relative/pcrel encoding) -- is already correct
    after a flat block move, needing no adjustment.
    """
    if unwind_rva == 0 or unwind_rva + 4 > len(blob) or _depth > 32:
        return
    version_flags = blob[unwind_rva]
    flags = (version_flags >> 3) & 0x1F
    count_of_codes = blob[unwind_rva + 2]
    codes_size = ((count_of_codes + 1) & ~1) * 2
    extra_off = unwind_rva + 4 + codes_size

    if flags & _UNW_FLAG_CHAININFO:
        if extra_off + 12 > len(blob):
            return
        cbegin, cend, cunwind = struct.unpack_from("<III", blob, extra_off)
        _adjust_unwind_info(blob, cunwind, shift, _depth + 1)
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
    """
    excdir = dep.OPTIONAL_HEADER.DATA_DIRECTORY[_IMAGE_DIRECTORY_ENTRY_EXCEPTION]
    if not excdir.Size:
        return []
    entries = []
    base = excdir.VirtualAddress
    for i in range(excdir.Size // 12):
        off = base + i * 12
        if off + 12 > len(blob):
            break
        begin, end, unwind = struct.unpack_from("<III", blob, off)
        if begin == 0 and end == 0 and unwind == 0:
            continue
        _adjust_unwind_info(blob, unwind, shift)
        new_begin, new_end = begin + shift, end + shift
        new_unwind = (unwind + shift) if unwind else 0
        struct.pack_into("<III", blob, off, new_begin, new_end, new_unwind)
        entries.append((new_begin, new_end, new_unwind))
    return entries


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
            self.input_path, list_pe_imports, resolve_pe, search_dirs, self.lib_dir, self.exclude
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
                    dep_image_base = dep.OPTIONAL_HEADER.ImageBase
                    blob_size = _align_up(dep.OPTIONAL_HEADER.SizeOfImage, section_alignment)
                    blob = bytearray(blob_size)
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

                    new_sections.append((
                        f".sdep{len(new_sections)}".encode("ascii"), bytes(blob), X, _SCN_CODE_RWX, len(blob),
                    ))
                    occupied_ranges.append((X, X + blob_size, node.name))
                    # For the reloc-bearing path X == next_rva always, so
                    # this is equivalent to the old unconditional
                    # `next_rva = X + blob_size`. For a no-reloc dependency,
                    # X can be far from (and even behind) the append
                    # cursor's previous value; never move the cursor
                    # backwards, so later appended structures (merged
                    # imports, the init stub, the combined reloc table)
                    # keep landing past every reservation made so far.
                    next_rva = max(next_rva, X + blob_size)
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

            self.output_path.write_bytes(bytes(output))
        finally:
            pe.close()
