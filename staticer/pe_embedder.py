"""PE (Windows) dependency embedding.

Implements both the reloc-bearing ("PIC") case -- a dependency DLL that
carries a base relocation table is appended into the host EXE/DLL as new
section(s), its own relocations are applied against the new addresses --
and the no-relocation-data ("fixed-base"/non-PIC) case -- the dependency is
instead placed at the fixed address its own preferred ImageBase demands,
reserved against the host's own image and every other such dependency.
Either way, the host's references to it are patched to the embedded
addresses and its import-table entry is removed. Unwind-metadata
preservation and the real generated entrypoint stub are later tasks; see
``embed()`` docstring for exactly what's simplified here.
"""

import os
import struct
from pathlib import Path
from typing import Dict, List, Optional, Set

import pefile

from .common.depgraph import build_dependency_graph, embed_order

IMAGE_REL_BASED_ABSOLUTE = 0
IMAGE_REL_BASED_HIGHLOW = 3
IMAGE_REL_BASED_DIR64 = 10

_IMAGE_DIRECTORY_ENTRY_IMPORT = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]
_IMAGE_DIRECTORY_ENTRY_BASERELOC = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]

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


# Each stub builder below returns (bytes, [relative offsets of embedded
# absolute-VA immediates]). Those immediates are hardcoded addresses the
# final image must keep correct if it's ever loaded somewhere other than
# its preferred base (e.g. ASLR, which is on by default for these fixtures)
# -- so every one of those offsets must become a new base relocation entry
# in the host, exactly like any other hardcoded absolute address reference.


def _x64_call_dllmain(hinst_va: int, entry_va: int):
    # Preserve the real entrypoint's incoming arg registers around our own
    # call, then call dep_entry(hinstDLL=hinst_va, DLL_PROCESS_ATTACH=1, NULL).
    prefix = (
        b"\x51"  # push rcx
        b"\x52"  # push rdx
        b"\x41\x50"  # push r8
        b"\x41\x51"  # push r9
        b"\x48\x83\xEC\x28"  # sub rsp, 0x28
    )
    mov_rcx_op = b"\x48\xB9"  # mov rcx, imm64
    hinst_off = len(prefix) + len(mov_rcx_op)
    mid = (
        b"\xBA\x01\x00\x00\x00"  # mov edx, 1
        b"\x45\x31\xC0"  # xor r8d, r8d
    )
    mov_rax_op = b"\x48\xB8"  # mov rax, imm64
    entry_off = hinst_off + 8 + len(mid) + len(mov_rax_op)
    tail = (
        b"\xFF\xD0"  # call rax
        b"\x48\x83\xC4\x28"  # add rsp, 0x28
        b"\x41\x59"  # pop r9
        b"\x41\x58"  # pop r8
        b"\x5A"  # pop rdx
        b"\x59"  # pop rcx
    )
    data = (
        prefix + mov_rcx_op + hinst_va.to_bytes(8, "little") + mid
        + mov_rax_op + entry_va.to_bytes(8, "little") + tail
    )
    return data, [hinst_off, entry_off]


def _x64_tail_jmp(target_va: int):
    mov_rax_op = b"\x48\xB8"
    data = mov_rax_op + target_va.to_bytes(8, "little") + b"\xFF\xE0"
    return data, [len(mov_rax_op)]


def _x86_call_dllmain(hinst_va: int, entry_va: int):
    # __stdcall DllMain(hinstDLL, fdwReason, lpvReserved) - callee pops its
    # own 3 args, so the stack is already balanced after `call`.
    prefix = (
        b"\x6A\x00"  # push 0            ; lpvReserved
        b"\x6A\x01"  # push 1            ; DLL_PROCESS_ATTACH
    )
    push_op = b"\x68"  # push imm32
    hinst_off = len(prefix) + len(push_op)
    mov_eax_op = b"\xB8"  # mov eax, imm32
    entry_off = hinst_off + 4 + len(mov_eax_op)
    tail = b"\xFF\xD0"  # call eax
    data = (
        prefix + push_op + hinst_va.to_bytes(4, "little")
        + mov_eax_op + entry_va.to_bytes(4, "little") + tail
    )
    return data, [hinst_off, entry_off]


def _x86_tail_jmp(target_va: int):
    mov_eax_op = b"\xB8"
    data = mov_eax_op + target_va.to_bytes(4, "little") + b"\xFF\xE0"
    return data, [len(mov_eax_op)]


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
          6. Append a tiny call to the dependency's own entry point
             (DllMain-style init) into a generated stub that runs before the
             host's original entrypoint.

        For a dependency that carries no relocation data at all (a fixed-
        base/non-PIC build), step 1's placement differs: instead of
        appending it at the next free RVA, it's placed at the one RVA that
        makes ``host ImageBase + RVA`` exactly equal to that dependency's
        own preferred ``ImageBase`` -- so none of its hardcoded absolute
        addresses need step 2's relocation-application at all. That address
        range is checked first against the host's own image (and anything
        already placed there) and against every other dependency reserved
        the same way, raising ``ValueError`` on any overlap. Steps 3-6
        proceed identically either way.

        Simplification for this task (explicitly deferred, see Task 7):
        step 6's stub is a flat, unconditional call sequence -- one call per
        embedded node, in dependencies-first order, then a tail-jump to the
        original entry point. It does not implement the real generated
        entrypoint/hook stub (LoadLibrary/GetProcAddress interception,
        richer init-order semantics); Task 7 replaces it.
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
            dep_entry_calls: List[tuple] = []  # (hinst_va, entry_va), in embed order
            removed_dll_names_lower: Set[str] = set()
            merged_descriptors: List[Dict[str, int]] = []
            # (start_rva, end_rva, name) of the host's own image and every
            # dependency (reloc-bearing or not) placed so far, host-relative
            # -- used to attribute a base-address conflict to whichever of
            # those a no-reloc dependency's reserved range collides with.
            occupied_ranges: List[tuple] = [(0, next_rva, self.input_path.name)]
            reserved_base_ranges: List[tuple] = []

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

                    exports_by_name = {}
                    if hasattr(dep, "DIRECTORY_ENTRY_EXPORT"):
                        for sym in dep.DIRECTORY_ENTRY_EXPORT.symbols:
                            if sym.name:
                                exports_by_name[sym.name.decode("ascii")] = sym.address

                    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                        for host_entry in pe.DIRECTORY_ENTRY_IMPORT:
                            if host_entry.dll.decode("ascii") != node.name:
                                continue
                            for imp in host_entry.imports:
                                if imp.import_by_ordinal or imp.name is None:
                                    raise ValueError(
                                        f"cannot embed '{node.name}': ordinal-only "
                                        f"imports aren't supported"
                                    )
                                fname = imp.name.decode("ascii")
                                if fname not in exports_by_name:
                                    raise ValueError(
                                        f"dependency '{node.name}' does not export "
                                        f"'{fname}', required by the host's import table"
                                    )
                                target_va = image_base + X + exports_by_name[fname]
                                # `imp.thunk_rva` is the *lookup* (ILT/
                                # OriginalFirstThunk) slot pefile derived the
                                # name from, which is a different array from
                                # the *address* (IAT/FirstThunk) slot that
                                # compiled call sites actually read through
                                # (`imp.address` is that slot's VA) -- it's
                                # the IAT slot we must overwrite.
                                iat_slot_rva = imp.address - image_base
                                slot_offset = pe.get_offset_from_rva(iat_slot_rva)
                                output[slot_offset:slot_offset + ptr_size] = target_va.to_bytes(
                                    ptr_size, "little"
                                )
                                new_reloc_entries.append(
                                    (iat_slot_rva, IMAGE_REL_BASED_DIR64 if is64 else IMAGE_REL_BASED_HIGHLOW)
                                )
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
                        dep_entry_calls.append((image_base + X, image_base + X + entry_rva))

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

            # -- generated init-call stub (placeholder; Task 7 replaces) --
            if dep_entry_calls:
                call_fn = _x64_call_dllmain if is64 else _x86_call_dllmain
                tail_jmp_fn = _x64_tail_jmp if is64 else _x86_tail_jmp
                reloc_type = IMAGE_REL_BASED_DIR64 if is64 else IMAGE_REL_BASED_HIGHLOW

                stub_rva = next_rva
                stub_bytes = bytearray()
                for hinst, entry in dep_entry_calls:
                    block, offs = call_fn(hinst, entry)
                    for off in offs:
                        new_reloc_entries.append((stub_rva + len(stub_bytes) + off, reloc_type))
                    stub_bytes += block
                tail_block, tail_offs = tail_jmp_fn(original_entry_va)
                for off in tail_offs:
                    new_reloc_entries.append((stub_rva + len(stub_bytes) + off, reloc_type))
                stub_bytes += tail_block

                new_sections.append((
                    b".sstub", bytes(stub_bytes), stub_rva, _SCN_CODE_RWX, len(stub_bytes),
                ))
                next_rva = _align_up(stub_rva + len(stub_bytes), section_alignment)
            else:
                stub_rva = None

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

            self.output_path.write_bytes(bytes(output))
        finally:
            pe.close()
