"""ELF (Linux) dependency embedding.

Implements the reloc-bearing ("PIC path") case: a dependency .so is
appended into the host ELF executable as a new PT_LOAD segment, its own
relocations are applied against the new addresses, the host's references
to it (GOT/PLT slots) are patched to the embedded addresses, and its
DT_NEEDED entry is neutralized. Non-PIC/no-relocation-data handling,
unwind-metadata preservation, and the real generated entrypoint stub are
later tasks; see ``ElfEmbedder.embed()``'s docstring for exactly what's
simplified here.

``pyelftools`` is read-only, so every byte this module *writes* is built
by hand from the fixed, standardized ELF32/ELF64 struct layouts (ELF
headers, program headers, dynamic-tag entries, and REL/RELA relocation
entries are all fixed-size, unlike PE's variable-length optional header).
pyelftools is used only for the read side: walking the PT_DYNAMIC segment
to get DT_NEEDED/relocation tables/dynamic symbols without needing (and
without disturbing) section headers at all.
"""

import io
import struct
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from elftools.elf.elffile import ELFFile

from .common.depgraph import build_dependency_graph, embed_order

# -- ELF constants pyelftools doesn't expose as plain ints for our needs --
# (it hands back Enum-mapped strings for e.g. p_type/d_tag, which is fine
# for reading but useless for re-packing bytes we write ourselves).

PT_LOAD = 1
PF_X, PF_W, PF_R = 1, 2, 4

DT_NEEDED = 1
DT_DEBUG = 21  # harmless/ignored by every runtime linker; see _remove_needed

# Relocation type numbers below happen to share the same values on
# EM_386 and EM_X86_64 for every type this module handles.
R_NONE = 0
R_ABS_PLUS_ADDEND = 1  # R_X86_64_64 / R_386_32: value = S (+A for RELA)
R_GLOB_DAT = 6
R_JUMP_SLOT = 7
R_RELATIVE = 8

_SUPPORTED_MACHINES = ("EM_X86_64", "EM_386")

_PAGE = 0x1000


def list_elf_imports(path: Path) -> List[str]:
    """Names from the DT_NEEDED entries of an ELF file's dynamic section,
    read via its PT_DYNAMIC segment (so this works even without section
    headers); empty list if it has none."""
    with open(path, "rb") as f:
        elf = ELFFile(f)
        dyn = _dynamic_segment(elf)
        if dyn is None:
            return []
        return [tag.needed for tag in dyn.iter_tags("DT_NEEDED")]


def resolve_elf(name: str, search_dirs: List[Path]) -> Optional[Path]:
    """Scan search_dirs in order for a file literally named `name`."""
    for directory in search_dirs:
        candidate = directory / name
        if candidate.is_file():
            return candidate
    return None


def _dynamic_segment(elf: ELFFile):
    return next(elf.iter_segments(type="PT_DYNAMIC"), None)


def _align_up(value: int, alignment: int) -> int:
    if alignment <= 1:
        return value
    return (value + alignment - 1) // alignment * alignment


# -- raw Phdr packing (pyelftools doesn't write; layouts are fixed by ABI) --

def _pack_phdr(is64: bool, p_type: int, p_flags: int, p_offset: int, p_vaddr: int,
               p_paddr: int, p_filesz: int, p_memsz: int, p_align: int) -> bytes:
    if is64:
        return struct.pack("<IIQQQQQQ", p_type, p_flags, p_offset, p_vaddr,
                            p_paddr, p_filesz, p_memsz, p_align)
    # Elf32_Phdr has a different field order: p_flags comes *after*
    # p_filesz/p_memsz, unlike Elf64_Phdr where it's right after p_type.
    return struct.pack("<IIIIIIII", p_type, p_offset, p_vaddr, p_paddr,
                        p_filesz, p_memsz, p_flags, p_align)


# ELF header field (offset, size) for the handful of fields embed() needs
# to patch, per the fixed Elf32_Ehdr/Elf64_Ehdr layout (both start with the
# same 16-byte e_ident).
_EHDR_FIELDS_64 = {"e_entry": (24, 8), "e_phoff": (32, 8), "e_phnum": (56, 2)}
_EHDR_FIELDS_32 = {"e_entry": (24, 4), "e_phoff": (28, 4), "e_phnum": (44, 2)}


def _set_ehdr_field(raw: bytearray, is64: bool, field: str, value: int) -> None:
    off, size = (_EHDR_FIELDS_64 if is64 else _EHDR_FIELDS_32)[field]
    raw[off:off + size] = (value & ((1 << (size * 8)) - 1)).to_bytes(size, "little")


def _remove_needed(dyn, raw: bytearray, ptr_size: int, needed_name: str) -> bool:
    """Convert the DT_NEEDED entry for `needed_name` into a DT_DEBUG entry,
    in place. DT_DEBUG is ignored by every real-world runtime linker, and
    (crucially) this doesn't shrink/grow the dynamic array or disturb its
    DT_NULL terminator's position -- unlike turning it into DT_NULL
    directly, which would truncate the whole table at that point for any
    tag scanner that stops at the first DT_NULL (every real one does)."""
    dyn_entry_size = 2 * ptr_size
    for n in range(dyn.num_tags()):
        tag = dyn.get_tag(n)
        if tag.entry.d_tag == "DT_NEEDED" and tag.needed == needed_name:
            entry_off = dyn["p_offset"] + n * dyn_entry_size
            fmt = "<Q" if ptr_size == 8 else "<I"
            struct.pack_into(fmt, raw, entry_off, DT_DEBUG)
            return True
    return False


def _find_dyn_tag_file_offset(dyn, ptr_size: int, tag_name: str) -> Optional[int]:
    dyn_entry_size = 2 * ptr_size
    for n in range(dyn.num_tags()):
        if dyn.get_tag(n).entry.d_tag == tag_name:
            return dyn["p_offset"] + n * dyn_entry_size
    return None


def _set_dyn_tag_value(dyn, raw: bytearray, ptr_size: int, tag_name: str, value: int) -> None:
    entry_off = _find_dyn_tag_file_offset(dyn, ptr_size, tag_name)
    if entry_off is None:
        raise ValueError(f"expected dynamic tag {tag_name!r} not found")
    fmt = "<Q" if ptr_size == 8 else "<I"
    struct.pack_into(fmt, raw, entry_off + ptr_size, value)


def _read_int(buf, offset: int, size: int) -> int:
    return int.from_bytes(buf[offset:offset + size], "little")


def _write_int(buf: bytearray, offset: int, size: int, value: int) -> None:
    buf[offset:offset + size] = (value & ((1 << (size * 8)) - 1)).to_bytes(size, "little")


def _pack_relative_entries(entries: List[Tuple[int, int]], is64: bool, is_rela: bool) -> bytes:
    """Pack (vaddr, value) pairs as new R_*_RELATIVE REL/RELA entries
    (symbol index 0, so r_info reduces to just the type)."""
    out = bytearray()
    for vaddr, value in entries:
        if is64:
            if is_rela:
                out += struct.pack("<QQq", vaddr, R_RELATIVE, value)
            else:
                out += struct.pack("<QQ", vaddr, R_RELATIVE)
        else:
            if is_rela:
                out += struct.pack("<IIi", vaddr, R_RELATIVE, value)
            else:
                out += struct.pack("<II", vaddr, R_RELATIVE)
    return bytes(out)


# -- generated entrypoint stub (placeholder; a later task replaces this) --
#
# Mirrors pe_embedder's _x64_call_dllmain/_x64_tail_jmp: each builder
# returns (bytes, [relative offsets of embedded absolute-VA immediates]),
# since those immediates are hardcoded addresses that must become new
# R_*_RELATIVE entries in the host (see embed()) to stay correct if the
# final image is loaded at a different base (ASLR).
#
# Unlike PE's DllMain(..., DLL_PROCESS_ATTACH, ...) convention, an ELF
# shared object's load-time initialization hooks are its DT_INIT/
# DT_INIT_ARRAY function pointers, normally called by the dynamic linker's
# _dl_init when the object is loaded. Removing the dependency from the
# host's DT_NEEDED list means ld.so will never call them for us, so the
# stub calls them directly, with no arguments -- compiler-generated
# init_array entries (global constructors) are effectively always
# argument-less in practice, which is the same kind of simplification
# PE's docstring documents for DllMain's reason-code argument.
#
# Each call/ret pair is self-balancing on the stack (the callee's own
# `ret` restores %rsp exactly), so -- unlike PE, which explicitly saves
# and restores incoming arg registers around its call -- no register or
# stack bookkeeping is needed between calls: nothing here ever leaves
# %rsp anywhere other than where it started, which `_start` further down
# the tail-jump chain needs completely undisturbed to find argc/argv.

def _x64_call(func_va: int):
    data = b"\x48\xB8" + func_va.to_bytes(8, "little") + b"\xFF\xD0"  # movabs rax, imm64; call rax
    return data, [2]


def _x64_tail_jmp(target_va: int):
    data = b"\x48\xB8" + target_va.to_bytes(8, "little") + b"\xFF\xE0"  # movabs rax, imm64; jmp rax
    return data, [2]


def _x86_call(func_va: int):
    data = b"\xB8" + func_va.to_bytes(4, "little") + b"\xFF\xD0"  # mov eax, imm32; call eax
    return data, [1]


def _x86_tail_jmp(target_va: int):
    data = b"\xB8" + target_va.to_bytes(4, "little") + b"\xFF\xE0"  # mov eax, imm32; jmp eax
    return data, [1]


class ElfEmbedder:
    def __init__(self, input_path: Path, output_path: Path, exclude: Set[str], lib_dir: Optional[Path]):
        self.input_path = Path(input_path)
        self.output_path = Path(output_path)
        self.exclude = exclude
        self.lib_dir = lib_dir

    def _search_dirs(self) -> List[Path]:
        if self.lib_dir is not None:
            return [self.lib_dir]
        return [
            self.input_path.parent,
            Path("/lib"), Path("/usr/lib"), Path("/lib64"), Path("/usr/lib64"),
        ]

    def embed(self) -> None:
        """Embed every embeddable dependency (per Task 1's dependency
        graph) into the host, reloc-bearing (PIC) path only.

        Mechanism, per dependency (in dependencies-first order):
          1. Copy its mapped image (every PT_LOAD segment, laid out at its
             own vaddr-relative offset) into a new blob at a freshly chosen
             vaddr `X`.
          2. Apply the dependency's own .rela.dyn/.rel.dyn relocations
             against that new placement (delta = X - dep_base, where
             dep_base is the lowest vaddr among the dependency's own
             PT_LOAD segments -- the ELF analogue of PE's ImageBase, except
             ELF vaddrs are already absolute-in-their-own-space, with no
             separate base field to add back in).
          3. For each of the host's relocations against this dependency's
             exported symbols (GOT/PLT slots -- R_*_JUMP_SLOT/R_*_GLOB_DAT
             entries, whichever the compiler used), resolve the matching
             export and patch the slot in place with the resolved absolute
             address, exactly as eager (`-z now`) binding would; record
             that slot (and every relocation applied in step 2) as a *new*
             host R_*_RELATIVE entry, so the whole thing stays correct if
             the final image is itself relocated at load time (ASLR).
             Neutralize (zero out -- R_*_NONE) the original relocation
             entry in place, so ld.so never tries to re-resolve a symbol
             that no longer has a provider.
          4. Convert the dependency's DT_NEEDED entry to a harmless
             DT_DEBUG entry in place (see _remove_needed).
          5. Collect the dependency's own DT_INIT/DT_INIT_ARRAY function
             pointers (already relocated to their new addresses by step 2,
             since init_array slots are themselves R_*_RELATIVE targets),
             to be called from a generated init stub.

        Simplifications for this task (explicitly deferred -- see Task 8):
          - The dependency's *own* further external requirements aren't
            supported: if it has any PLT/JMPREL relocations at all, or any
            RELA/REL entry referencing a symbol that's undefined within
            itself, embedding fails loudly rather than silently leaving an
            unresolvable reference in the output. Unlike PE's import-table
            merge (step 5 in pe_embedder's docstring), nothing here merges
            a dependency's remaining imports into the host's own dynamic
            section -- the brief for this task doesn't ask for it, and the
            fixtures this task is scoped to (single-function .so's with no
            further library needs) never exercise it.
          - Unlike pe_embedder, there's deliberately no "dependency has no
            relocation data -> fail loudly" guard here: in PE, a DLL with
            no base-relocation directory at all reliably means a fixed-
            base/non-PIC build. In ELF, a *simple* PIC .so with no absolute
            self-pointers (e.g. this task's own `lib.c` fixture) just as
            reliably produces an *empty* .rela.dyn -- that's the normal,
            fully-position-independent case, not a warning sign. The ELF-
            specific non-PIC signal (DT_TEXTREL / relocations into an
            executable segment) is Task 6's concern, not this one's.
          - step 3's new-relocation-entries go into a brand new, bigger
            REL(A) table at a new location (growing the existing one in
            place isn't generally safe -- same reasoning as pe_embedder's
            import-directory rebuild); the original entries are preserved
            byte-for-byte as that new table's prefix.
          - The whole new PT_LOAD segment (dependency blobs + stub +
            combined relocation table + the relocated program header
            table itself) is marked RWX, mirroring pe_embedder's blanket
            `_SCN_CODE_RWX` section characteristics -- a real W^X split is
            out of scope for this placeholder.
          - Step 5's stub (see the module-level comment above the x64/x86
            builders) is a flat, unconditional call sequence, one call per
            init_array/DT_INIT entry across all embedded nodes, then a
            tail-jump to the host's original entry point. It's built (and
            e_entry is only repointed to it) when at least one such call
            exists; otherwise the host's entry point is left untouched.
        """
        search_dirs = self._search_dirs()
        graph = build_dependency_graph(
            self.input_path, list_elf_imports, resolve_elf, search_dirs, self.lib_dir, self.exclude
        )
        order = embed_order(graph)

        if not order:
            self.output_path.write_bytes(self.input_path.read_bytes())
            return

        raw = bytearray(self.input_path.read_bytes())
        # A read-only snapshot of the *original* bytes: every vaddr/offset
        # we look up via `elf` below stays valid against `raw` for the rest
        # of this method, since we only ever append to `raw` or edit
        # existing bytes in place -- never move or delete anything.
        elf = ELFFile(io.BytesIO(bytes(raw)))

        host_machine = elf["e_machine"]
        if host_machine not in _SUPPORTED_MACHINES:
            raise ValueError(
                f"unsupported host architecture {host_machine!r}; only "
                f"{_SUPPORTED_MACHINES} are supported"
            )
        is64 = elf.elfclass == 64
        ptr_size = 8 if is64 else 4

        host_dyn = _dynamic_segment(elf)
        if host_dyn is None:
            raise ValueError(f"'{self.input_path}' has no PT_DYNAMIC segment to embed into")

        host_load_segments = list(elf.iter_segments(type="PT_LOAD"))
        if not host_load_segments:
            raise ValueError(f"'{self.input_path}' has no PT_LOAD segments")

        host_reloc_tables = host_dyn.get_relocation_tables()
        dyn_table_key = "RELA" if "RELA" in host_reloc_tables else ("REL" if "REL" in host_reloc_tables else None)
        if dyn_table_key is None:
            raise ValueError(
                f"'{self.input_path}' has no DT_RELA/DT_REL table to extend; embedding "
                "into a host with no dynamic-relocation table isn't supported"
            )
        dyn_tag_name = "DT_RELA" if dyn_table_key == "RELA" else "DT_REL"
        dyn_sz_tag_name = "DT_RELASZ" if dyn_table_key == "RELA" else "DT_RELSZ"
        dyn_table = host_reloc_tables[dyn_table_key]
        dyn_is_rela = dyn_table.is_RELA()

        def vaddr_to_offset(vaddr: int, size: int) -> int:
            off = next(elf.address_offsets(vaddr, size), None)
            if off is None:
                raise ValueError(
                    f"address {hex(vaddr)} isn't covered by any PT_LOAD segment of '{self.input_path}'"
                )
            return off

        new_sections: List[Tuple[int, bytes]] = []  # (vaddr, data), contiguous in placement order
        new_reloc_entries: List[Tuple[int, int]] = []  # (host vaddr, value) -> new R_*_RELATIVE entries
        dep_init_calls: List[int] = []  # absolute (host-space) VAs to call from the stub
        combined_exports: Dict[str, Tuple[int, int]] = {}  # export name -> (X, offset-within-dep)

        max_end = max(seg["p_vaddr"] + seg["p_memsz"] for seg in host_load_segments)
        next_vaddr = _align_up(max_end, _PAGE)

        # -- per-dependency: copy, relocate, and remove its DT_NEEDED -----
        for node in order:
            with open(node.path, "rb") as depf:
                dep = ELFFile(depf)
                if dep["e_machine"] != host_machine:
                    raise ValueError(
                        f"architecture mismatch embedding '{node.name}': host "
                        f"'{self.input_path}' is {host_machine}, dependency "
                        f"'{node.path}' is {dep['e_machine']}"
                    )

                dep_load_segments = list(dep.iter_segments(type="PT_LOAD"))
                if not dep_load_segments:
                    raise ValueError(f"dependency '{node.name}' has no PT_LOAD segments")
                dep_base = min(seg["p_vaddr"] for seg in dep_load_segments)
                blob_size = _align_up(
                    max(seg["p_vaddr"] + seg["p_memsz"] for seg in dep_load_segments) - dep_base, _PAGE
                )
                blob = bytearray(blob_size)
                for seg in dep_load_segments:
                    data = seg.data()
                    start = seg["p_vaddr"] - dep_base
                    blob[start:start + len(data)] = data

                X = next_vaddr
                delta = X - dep_base

                dep_dyn = _dynamic_segment(dep)
                if dep_dyn is None:
                    raise ValueError(f"dependency '{node.name}' has no PT_DYNAMIC segment")

                dep_reloc_tables = dep_dyn.get_relocation_tables()
                if "JMPREL" in dep_reloc_tables and dep_reloc_tables["JMPREL"].num_relocations() > 0:
                    raise ValueError(
                        f"dependency '{node.name}' itself calls external functions through "
                        "its own PLT; embedding dependencies with further external "
                        "requirements isn't supported yet"
                    )

                for key in ("RELA", "REL"):
                    table = dep_reloc_tables.get(key)
                    if table is None:
                        continue
                    is_rela = table.is_RELA()
                    for reloc in table.iter_relocations():
                        rtype = reloc["r_info_type"]
                        if rtype == R_NONE:
                            continue
                        target_vaddr = reloc["r_offset"]
                        blob_offset = target_vaddr - dep_base
                        if blob_offset < 0 or blob_offset + ptr_size > blob_size:
                            raise ValueError(
                                f"relocation target {hex(target_vaddr)} in dependency "
                                f"'{node.name}' falls outside its own PT_LOAD segments"
                            )
                        if rtype == R_RELATIVE:
                            base_value = (
                                reloc["r_addend"] if is_rela else _read_int(blob, blob_offset, ptr_size)
                            )
                            new_val = base_value + delta
                        else:
                            sym = dep_dyn.get_symbol(reloc["r_info_sym"])
                            if sym["st_shndx"] == "SHN_UNDEF":
                                raise ValueError(
                                    f"dependency '{node.name}' has an unresolved external "
                                    f"symbol reference ('{sym.name}'); embedding dependencies "
                                    "with further external requirements isn't supported yet"
                                )
                            if rtype != R_ABS_PLUS_ADDEND:
                                raise ValueError(
                                    f"unsupported relocation type {rtype} in dependency '{node.name}'"
                                )
                            addend = reloc["r_addend"] if is_rela else 0
                            new_val = X + (sym["st_value"] - dep_base) + addend
                        _write_int(blob, blob_offset, ptr_size, new_val)
                        new_reloc_entries.append((X + blob_offset, new_val & ((1 << (ptr_size * 8)) - 1)))

                for i in range(dep_dyn.num_symbols()):
                    sym = dep_dyn.get_symbol(i)
                    if (
                        sym.name
                        and sym["st_shndx"] != "SHN_UNDEF"
                        and sym["st_info"]["type"] in ("STT_FUNC", "STT_OBJECT")
                        and sym["st_info"]["bind"] in ("STB_GLOBAL", "STB_WEAK")
                    ):
                        combined_exports[sym.name] = (X, sym["st_value"] - dep_base)

                init_tag = next(dep_dyn.iter_tags("DT_INIT"), None)
                if init_tag is not None:
                    dep_init_calls.append(X + (init_tag.entry.d_val - dep_base))
                init_array_ptr, _ = dep_dyn.get_table_offset("DT_INIT_ARRAY")
                if init_array_ptr is not None:
                    sz_tag = next(dep_dyn.iter_tags("DT_INIT_ARRAYSZ"), None)
                    count = (sz_tag.entry.d_val // ptr_size) if sz_tag is not None else 0
                    base_off = init_array_ptr - dep_base
                    for i in range(count):
                        dep_init_calls.append(_read_int(blob, base_off + i * ptr_size, ptr_size))

                if not _remove_needed(host_dyn, raw, ptr_size, node.name):
                    raise ValueError(f"expected DT_NEEDED entry for '{node.name}' not found in host")

                new_sections.append((X, bytes(blob)))
                next_vaddr = _align_up(X + blob_size, _PAGE)

        # -- patch the host's GOT/PLT references to embedded exports -----
        patch_specs = [(dyn_table_key, dyn_tag_name)]
        if "JMPREL" in host_reloc_tables:
            patch_specs.append(("JMPREL", "DT_JMPREL"))

        for key, tag_name in patch_specs:
            table = host_reloc_tables[key]
            is_rela = table.is_RELA()
            # File offset of the *table itself* (what the DT_* tag's value
            # points at) -- not to be confused with the DT_* tag entry's
            # own location inside .dynamic (that's what
            # _find_dyn_tag_file_offset is for, used elsewhere to edit a
            # tag's d_val in place).
            _, table_file_offset = host_dyn.get_table_offset(tag_name)
            entry_size = table.entry_size
            for idx, reloc in enumerate(table.iter_relocations()):
                if reloc["r_info_type"] not in (R_JUMP_SLOT, R_GLOB_DAT, R_ABS_PLUS_ADDEND):
                    continue
                sym = host_dyn.get_symbol(reloc["r_info_sym"])
                if sym["st_shndx"] != "SHN_UNDEF" or not sym.name or sym.name not in combined_exports:
                    continue
                X, offset_in_dep = combined_exports[sym.name]
                addend = reloc["r_addend"] if is_rela else 0
                resolved = (X + offset_in_dep + addend) & ((1 << (ptr_size * 8)) - 1)
                target_off = vaddr_to_offset(reloc["r_offset"], ptr_size)
                _write_int(raw, target_off, ptr_size, resolved)
                new_reloc_entries.append((reloc["r_offset"], resolved))

                entry_off = table_file_offset + idx * entry_size
                raw[entry_off:entry_off + entry_size] = b"\x00" * entry_size

        # -- generated init-call stub (placeholder; a later task replaces) -
        stub_vaddr = None
        if dep_init_calls:
            call_fn = _x64_call if is64 else _x86_call
            tail_fn = _x64_tail_jmp if is64 else _x86_tail_jmp

            stub_vaddr = next_vaddr
            stub_bytes = bytearray()
            for func_va in dep_init_calls:
                block, offs = call_fn(func_va)
                for off in offs:
                    new_reloc_entries.append((stub_vaddr + len(stub_bytes) + off, func_va))
                stub_bytes += block
            tail_block, tail_offs = tail_fn(elf["e_entry"])
            for off in tail_offs:
                new_reloc_entries.append((stub_vaddr + len(stub_bytes) + off, elf["e_entry"]))
            stub_bytes += tail_block

            new_sections.append((stub_vaddr, bytes(stub_bytes)))
            next_vaddr = _align_up(stub_vaddr + len(stub_bytes), _PAGE)

        # -- combined relocation table -------------------------------------
        if new_reloc_entries:
            _, orig_table_offset = host_dyn.get_table_offset(dyn_tag_name)
            orig_size_tag = next(host_dyn.iter_tags(dyn_sz_tag_name), None)
            orig_table_size = orig_size_tag.entry.d_val if orig_size_tag is not None else 0
            orig_table_bytes = bytes(raw[orig_table_offset:orig_table_offset + orig_table_size])

            new_entries_bytes = _pack_relative_entries(new_reloc_entries, is64, dyn_is_rela)
            combined_bytes = orig_table_bytes + new_entries_bytes

            reloc_table_vaddr = next_vaddr
            new_sections.append((reloc_table_vaddr, combined_bytes))
            next_vaddr = _align_up(reloc_table_vaddr + len(combined_bytes), _PAGE)

            _set_dyn_tag_value(host_dyn, raw, ptr_size, dyn_tag_name, reloc_table_vaddr)
            _set_dyn_tag_value(host_dyn, raw, ptr_size, dyn_sz_tag_name, len(combined_bytes))

        # -- lay everything out at the end of the file, in one new RWX
        #    PT_LOAD segment that also covers the relocated program
        #    header table itself (so AT_PHDR stays inside mapped memory) --
        data_start_vaddr = new_sections[0][0]
        data_start_offset = _align_up(len(raw), _PAGE)
        raw.extend(b"\x00" * (data_start_offset - len(raw)))

        cursor_vaddr = data_start_vaddr
        for vaddr, data in new_sections:
            pad = vaddr - cursor_vaddr
            if pad < 0:
                raise ValueError("internal error: overlapping generated ELF segments")
            raw.extend(b"\x00" * pad)
            raw.extend(data)
            cursor_vaddr = vaddr + len(data)

        old_phdr_off = elf["e_phoff"]
        old_phdr_count = elf["e_phnum"]
        old_phdr_entsize = elf["e_phentsize"]
        old_phdrs_bytes = bytes(raw[old_phdr_off:old_phdr_off + old_phdr_count * old_phdr_entsize])

        new_phdr_table_offset = _align_up(len(raw), ptr_size)
        raw.extend(b"\x00" * (new_phdr_table_offset - len(raw)))
        new_phdr_table_size = (old_phdr_count + 1) * old_phdr_entsize

        new_segment_filesz = (new_phdr_table_offset + new_phdr_table_size) - data_start_offset
        new_segment = _pack_phdr(
            is64, PT_LOAD, PF_R | PF_W | PF_X, data_start_offset, data_start_vaddr,
            data_start_vaddr, new_segment_filesz, new_segment_filesz, _PAGE,
        )
        raw.extend(old_phdrs_bytes)
        raw.extend(new_segment)

        _set_ehdr_field(raw, is64, "e_phoff", new_phdr_table_offset)
        _set_ehdr_field(raw, is64, "e_phnum", old_phdr_count + 1)
        if stub_vaddr is not None:
            _set_ehdr_field(raw, is64, "e_entry", stub_vaddr)

        self.output_path.write_bytes(bytes(raw))
