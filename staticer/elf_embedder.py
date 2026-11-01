"""ELF (Linux) dependency embedding.

Implements the reloc-bearing ("PIC path") case: a dependency .so is
appended as an in-place extension of the host ELF executable's own
highest-vaddr PT_LOAD segment (deliberately *not* a new PT_LOAD segment of
its own -- see ``ElfEmbedder.embed()``'s docstring for why that breaks
AT_PHDR), its own relocations are applied against the new addresses, the
host's references to it (GOT/PLT slots) are patched to the embedded
addresses, and its DT_NEEDED entry is neutralized. Non-PIC/no-relocation-
data handling, unwind-metadata preservation, and the real generated
entrypoint stub are later tasks; see ``ElfEmbedder.embed()``'s docstring
for exactly what's simplified here.

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
    (symbol index 0, so r_info reduces to just the type).

    `value` is packed as an *unsigned* bit pattern (struct format 'Q'/'I',
    not 'q'/'i'): the ELF ABI only cares about the addend's raw bits, and
    `value` is already masked into unsigned range by every caller (see
    `new_reloc_entries.append(...)` call sites) -- a signed format would
    raise OverflowError for any legitimate 32-bit address >= 2**31 (common
    for e.g. mmap-assigned bases), even though the bit pattern itself is
    perfectly valid."""
    out = bytearray()
    for vaddr, value in entries:
        if is64:
            if is_rela:
                out += struct.pack("<QQQ", vaddr, R_RELATIVE, value & 0xFFFFFFFFFFFFFFFF)
            else:
                out += struct.pack("<QQ", vaddr, R_RELATIVE)
        else:
            if is_rela:
                out += struct.pack("<III", vaddr, R_RELATIVE, value & 0xFFFFFFFF)
            else:
                out += struct.pack("<II", vaddr, R_RELATIVE)
    return bytes(out)


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

        Deliberately NOT done: calling the dependency's own DT_INIT/
        DT_INIT_ARRAY entries (the ELF analogue of PE's DllMain(...,
        DLL_PROCESS_ATTACH, ...) call, which pe_embedder's docstring lists
        as its own step 6). An earlier version of this method did exactly
        that -- collect those function pointers (already relocated to
        their new addresses, since init_array slots are themselves
        R_*_RELATIVE targets) and call them from a generated stub
        installed as the new e_entry, mirroring pe_embedder's approach.
        Verified by actually building and running the embedded output on
        real Linux (not just reasoning about it): on x86 (EM_386), this
        reliably segfaults. crtstuff's own init_array entries
        (`frame_dummy`/`register_tm_clones`, injected into *every* GCC-
        built shared object regardless of user code -- the same
        toolchain-boilerplate pattern as the weak GLOB_DAT symbols
        documented below) are compiled as 32-bit PIC code, which computes
        its own GOT-relative addressing via a `call __x86.get_pc_thunk.bx`
        / `add ebx, <offset>` sequence at entry; calling them "cold" from
        a plain `mov eax, imm32; call eax` (no attempt to establish
        whatever calling-convention precondition that sequence depends
        on) corrupts something, with a concrete observed crash signature
        of `SIGSEGV, error 6 (write, not-present), si_addr=1` a few
        instructions into glibc's own post-relocation startup path. x86-64
        (EM_X86_64) uses RIP-relative addressing instead and happened not
        to crash in testing, but calling crtstuff-internal functions
        directly is risky enough on its own merits (undocumented
        preconditions, no argc/argv/envp despite glibc's own _dl_init
        passing them by convention -- see glibc's elf/dl-init.c) that
        shipping it on the strength of "didn't crash on one machine" would
        just be trading a *known* bug for an *unknown* one. The task
        brief's own instructions for this method don't actually list an
        entrypoint stub as a required step (unlike Task 3's PE brief,
        which explicitly does) -- so, given it's proven actively unsafe as
        a naive port of PE's approach, it's left for Task 8 to design
        properly (which will need to either establish the x86-32 PIC
        calling convention precondition correctly, or find a safer hook
        point than "call directly from a synthetic entrypoint stub").
        e_entry is therefore never touched by this method.

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
          - The host's extended PT_LOAD segment (dependency blobs +
            combined relocation table, all appended as a single in-place
            extension of it -- see below) has RWX ORed into its existing
            flags, mirroring pe_embedder's blanket `_SCN_CODE_RWX` section
            characteristics -- a real W^X split is out of scope for this
            placeholder.
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
        combined_exports: Dict[str, Tuple[int, int]] = {}  # export name -> (X, offset-within-dep)

        # Every newly-built blob/reloc-table is appended as an
        # *extension* of the host's own highest-vaddr PT_LOAD segment,
        # rather than as a new PT_LOAD segment of its own -- see the large
        # comment further down, right before this same `ext`/`ext_idx` pair
        # is used to actually grow it, for why a brand new segment (with a
        # freshly chosen vaddr/offset pair, generally skewed differently
        # from the host's first PT_LOAD segment) breaks AT_PHDR.
        all_host_segments = [elf.get_segment(i) for i in range(elf.num_segments())]
        host_load_indices = [i for i, s in enumerate(all_host_segments) if s["p_type"] == "PT_LOAD"]
        ext_idx = max(host_load_indices, key=lambda i: all_host_segments[i]["p_vaddr"] + all_host_segments[i]["p_memsz"])
        ext = all_host_segments[ext_idx]
        max_file_end = max(s["p_offset"] + s["p_filesz"] for s in all_host_segments)
        if ext["p_offset"] + ext["p_filesz"] != max_file_end:
            raise ValueError(
                f"'{self.input_path}': its highest-vaddr PT_LOAD segment isn't also "
                "the last one in the file; extending it in place isn't supported"
            )
        ext_align = ext["p_align"] if ext["p_align"] >= _PAGE else _PAGE
        # The skew this segment's new (extended) content must keep -- any
        # vaddr V within it is at file offset V - ext_skew, and vice versa.
        ext_skew = ext["p_vaddr"] - ext["p_offset"]
        next_vaddr = _align_up(ext["p_vaddr"] + ext["p_memsz"], ext_align)

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
                                if sym["st_info"]["bind"] == "STB_WEAK":
                                    # Every GCC-built shared object links in
                                    # crtstuff's weak references to
                                    # __cxa_finalize/__gmon_start__/the
                                    # _ITM_*TMCloneTable hooks via
                                    # R_*_GLOB_DAT, regardless of what the
                                    # user's own code does -- this isn't a
                                    # dependency-specific "further external
                                    # requirement", it's unconditional
                                    # toolchain boilerplate. A weak
                                    # undefined symbol left unresolved is
                                    # normal ELF semantics: ld.so itself
                                    # just resolves it to NULL when nothing
                                    # provides it (callers are required to
                                    # null-check before using it), so
                                    # explicitly zero the slot and move on
                                    # -- exactly what ld.so would have done.
                                    _write_int(blob, blob_offset, ptr_size, 0)
                                    continue
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

                # Deliberately not collecting/calling this dependency's own
                # DT_INIT/DT_INIT_ARRAY entries -- see embed()'s docstring
                # for why (verified-unsafe on x86).

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

        # -- lay everything out as an in-place extension of the host's own
        #    `ext` PT_LOAD segment (see where ext/ext_idx/ext_skew/ext_align
        #    were derived, above the per-dependency loop) --
        #
        # The straightforward-looking alternative -- append everything at
        # the end of the file in a brand new PT_LOAD segment of its own --
        # is wrong: the Linux kernel computes AT_PHDR as
        # `load_bias + e_phoff`, where `load_bias` is derived once, from
        # matching the *first* PT_LOAD segment's own p_vaddr/p_offset skew
        # against where the kernel actually mapped it -- it does not
        # re-derive a skew per segment, and it never re-translates e_phoff
        # through address_offsets()-style segment lookup. That formula is
        # only correct for a given e_phoff when the segment that e_phoff
        # physically falls inside shares the *first* segment's skew. A
        # brand new segment, placed at a freshly chosen vaddr/offset pair
        # with no particular reason to share that skew, breaks this the
        # moment e_phoff is moved into it: AT_PHDR then lands on
        # `original_skew + new_e_phoff`, a bogus address still inside the
        # *original* image's range, not the new segment at all. glibc's
        # `_dl_aux_init`/`__libc_start_main` walk that (garbage) phdr array
        # looking for PT_TLS/PT_GNU_RELRO/PT_GNU_STACK for the main
        # executable -- silently skipping TLS/RELRO/stack-flag setup, or
        # segfaulting outright if the bogus address isn't even mapped.
        #
        # Extending an *existing* segment in place sidesteps this
        # completely: e_phoff/e_phnum (and every other segment's entry)
        # stay byte-for-byte untouched, so AT_PHDR's computation doesn't
        # change at all. Growing `ext`'s p_filesz/p_memsz all the way from
        # its own original p_offset up to the new end of file is always
        # safe content-wise (anything in that span that isn't one of our
        # new blobs is either `ext`'s own original content or inert
        # trailing bytes -- e.g. a stale section header table -- that
        # nothing else maps), *as long as* `ext` is confirmed above to
        # also be the last segment's content in the file, so growing its
        # filesz can't stomp on some other segment's bytes.
        data_start_vaddr = new_sections[0][0]
        data_start_offset = data_start_vaddr - ext_skew
        if data_start_offset < len(raw):
            raise ValueError("internal error: new ELF content would overlap existing file content")
        raw.extend(b"\x00" * (data_start_offset - len(raw)))

        cursor_vaddr = data_start_vaddr
        for vaddr, data in new_sections:
            pad = vaddr - cursor_vaddr
            if pad < 0:
                raise ValueError("internal error: overlapping generated ELF segments")
            raw.extend(b"\x00" * pad)
            raw.extend(data)
            cursor_vaddr = vaddr + len(data)

        new_filesz = len(raw) - ext["p_offset"]
        extended_entry = _pack_phdr(
            is64, PT_LOAD, ext["p_flags"] | PF_R | PF_W | PF_X, ext["p_offset"], ext["p_vaddr"],
            ext["p_paddr"], new_filesz, new_filesz, ext["p_align"],
        )
        entry_off = elf["e_phoff"] + ext_idx * elf["e_phentsize"]
        raw[entry_off:entry_off + len(extended_entry)] = extended_entry

        # e_entry is deliberately never touched -- see embed()'s docstring.

        self.output_path.write_bytes(bytes(raw))
