"""ELF (Linux) dependency embedding.

Implements the reloc-bearing ("PIC path") case -- a dependency .so is
appended as an in-place extension of the host ELF executable's own
highest-vaddr PT_LOAD segment (deliberately *not* a new PT_LOAD segment of
its own -- see ``ElfEmbedder.embed()``'s docstring for why that breaks
AT_PHDR), its own relocations are applied against the new addresses, the
host's references to it (GOT/PLT slots) are patched to the embedded
addresses, and its DT_NEEDED entry is neutralized -- and the fixed-base
("non-PIC path") case, where a dependency's own ELF header says it can
only ever be loaded at one specific address and gets its own, separate
PT_LOAD segment reserved at exactly that address instead (see the base-
address-reservation comment inside ``embed()``, by ``fixed_base_segments``,
for the full mechanism and its one real limitation). Unwind-metadata
preservation and the real generated entrypoint stub are later tasks; see
``ElfEmbedder.embed()``'s docstring for exactly what's simplified here.

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
PT_PHDR = 6
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
          - Unlike pe_embedder, this doesn't treat "the dependency has no
            relocation data at all" as the fixed-base/non-PIC signal: in
            PE, a DLL with no base-relocation directory at all reliably
            means a fixed-base build. In ELF, a *simple* PIC .so with no
            absolute self-pointers (e.g. this task's own `lib.c` fixture)
            just as reliably produces an *empty* .rela.dyn -- that's the
            normal, fully-position-independent case, not a warning sign.
            The actual fixed-base signal this method keys off instead is
            the dependency's own `e_type` (see the base-address-reservation
            comment further down, by `fixed_base_segments`, for the full
            mechanism and its one real limitation).
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

        # -- base-address reservation for fixed-base (non-PIC) dependencies --
        # A dependency whose own ELF header says ET_EXEC (not ET_DYN) was
        # built assuming it will *always* load at exactly its own PT_LOAD
        # segments' own p_vaddr -- unlike a PIC .so (ET_DYN), which is
        # designed to tolerate loading at any delta and records every
        # absolute self-pointer that needs fixing up for that delta in its
        # own .rela.dyn/.rel.dyn, a fixed-base dependency's code may contain
        # absolute address references baked directly into its instructions
        # with *no* corresponding relocation entry at all (real-world
        # example, confirmed against this project's own toolchain: an
        # internal-data access compiled with `-fno-pic` for a plain ET_EXEC
        # target produces a bare `mov 0x<absolute addr>, %eax`-style
        # instruction with zero relocation tracking, whereas the *same*
        # access compiled into a `-shared` object -- PIC or not -- always
        # gets at least an R_*_RELATIVE entry, because any `.so` must
        # support loading away from its preferred base, and the linker
        # arranges for that regardless of the `-f{,no-}pic` codegen flag).
        # This is the ELF analogue of why a PE DLL with no base-relocation
        # directory can only be loaded at exactly its declared ImageBase:
        # there's no delta the loader could apply to such a dependency's
        # untracked absolute references and have them stay correct, so the
        # only place such a dependency can go is its own already-fixed
        # address.
        #
        # So, for these nodes, `X` below is forced to the dependency's own
        # `dep_base` (delta = X - dep_base = 0, a no-op for whatever
        # relocations it *does* still have) rather than freshly allocated
        # from `next_vaddr`, and that fixed range has to be reserved up
        # front against both the host's own existing PT_LOAD ranges and
        # every other such dependency's own reservation -- mirroring
        # pe_embedder's same-named mechanism for a reloc-table-less DLL.
        # Because that fixed address generally has nothing to do with where
        # the host's own content ends, it can't just extend `ext` like
        # everything else in this method does (see `fixed_base_segments`'s
        # use, further down, for the brand-new-PT_LOAD-segment mechanism
        # that needs instead, and why growing the program header array to
        # add it is still AT_PHDR-safe).
        #
        # Soundness note (also true of pe_embedder's mechanism, and not
        # solved here -- doesn't seem to be solvable at all without a way
        # to enumerate a dependency's *untracked* absolute references,
        # which by construction there's no record of): this only stays
        # correct if the final combined image itself never gets relocated
        # as a whole at load time (e.g. ASLR). If the host is non-PIE
        # (ET_EXEC itself -- the realistic pairing for a genuinely
        # fixed-base dependency, and what this task's own tests use), the
        # kernel always maps every PT_LOAD segment at exactly its file
        # p_vaddr and this is completely sound; if the host is PIE, the
        # whole image (including whatever's reserved here) moves together
        # under ASLR and a fixed-base dependency's untracked references
        # silently go stale by the same amount the rest of the image moved.
        fixed_base_segments: List[Tuple[int, bytes]] = []  # (X, blob) -- each gets its own new PT_LOAD entry
        reserved_ranges: List[Tuple[int, int, str]] = [
            (seg["p_vaddr"], seg["p_vaddr"] + seg["p_memsz"], f"the host image ('{self.input_path}')")
            for seg in host_load_segments
        ]

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
        # New content must start at a vaddr that (a) doesn't collide with
        # `ext`'s own existing memsz, and (b) whose corresponding file
        # offset (vaddr - ext_skew) is past the *actual* end of the file
        # -- which, for any ordinary unstripped binary, extends further
        # than `ext`'s own rounded-up memsz: .comment/.symtab/.strtab/
        # .shstrtab/the section header table are normal trailing content
        # that no PT_* segment covers at all (the check above only
        # confirms `ext` is the last *segment-covered* content, which
        # isn't the same as the last *byte in the file*). Taking the max
        # of both lower bounds before rounding -- rather than assuming
        # `ext`'s own page-rounding slack always happens to cover
        # whatever trailing content exists -- means this never
        # spuriously rejects a completely normal binary just because its
        # one page of rounding slack happens to be smaller than its
        # trailing symbol-table/debug-info content.
        min_vaddr_for_memsz = ext["p_vaddr"] + ext["p_memsz"]
        min_vaddr_for_eof = len(raw) + ext_skew
        next_vaddr = _align_up(max(min_vaddr_for_memsz, min_vaddr_for_eof), ext_align)

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

                is_fixed_base = dep["e_type"] == "ET_EXEC"
                if is_fixed_base:
                    X = dep_base
                    lo, hi = X, X + blob_size
                    for r_lo, r_hi, label in reserved_ranges:
                        if lo < r_hi and r_lo < hi:
                            raise ValueError(
                                f"base address conflict at {hex(max(lo, r_lo))} between "
                                f"dependency '{node.name}' (fixed base {hex(X)}) and {label}"
                            )
                    reserved_ranges.append((lo, hi, f"dependency '{node.name}' (fixed base {hex(X)})"))
                else:
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

                if is_fixed_base:
                    fixed_base_segments.append((X, bytes(blob)))
                else:
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

        # -- reserve room for a grown program header array, if any fixed-
        #    base dependency needs its own new PT_LOAD entry (see the large
        #    comment above, by `fixed_base_segments`, for why those can't
        #    just extend `ext` like everything above this point does) --
        #    placed as one more piece of `ext`'s own extension, same as the
        #    relocation table just above, so it shares the extension's skew
        #    and keeps AT_PHDR's computation (which assumes e_phoff always
        #    falls inside a segment sharing the *first* PT_LOAD segment's
        #    skew -- see the comment further down, by `data_start_vaddr`)
        #    correct even though e_phoff is about to move. Its *content*
        #    can't be filled in yet -- it needs to record `ext`'s own
        #    final, grown p_filesz/p_memsz, which isn't known until after
        #    this whole extension (including this array's own reserved
        #    bytes) is actually laid out below -- so a same-sized
        #    zero-filled placeholder goes here for now and gets overwritten
        #    in place, once that size is known, right before this method
        #    returns.
        if fixed_base_segments:
            old_phnum = elf.num_segments()
            new_phnum = old_phnum + len(fixed_base_segments)
            phdr_array_size = new_phnum * elf["e_phentsize"]
            phdr_array_vaddr = next_vaddr
            new_sections.append((phdr_array_vaddr, b"\x00" * phdr_array_size))
            next_vaddr = _align_up(phdr_array_vaddr + phdr_array_size, _PAGE)

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

        if not fixed_base_segments:
            entry_off = elf["e_phoff"] + ext_idx * elf["e_phentsize"]
            raw[entry_off:entry_off + len(extended_entry)] = extended_entry
        else:
            # Grow the program header array itself: copy the *original*
            # array byte-for-byte (still untouched, at its original
            # location -- only `ext`'s own entry within the copy gets
            # updated), append one brand-new PT_LOAD entry per fixed-base
            # dependency, and write the result into the placeholder
            # reserved for it above (inside `ext`'s own just-finished
            # extension, so it shares the first PT_LOAD segment's skew --
            # see the comment by that placeholder for why that's what
            # keeps AT_PHDR correct here). The *original* array's bytes are
            # simply abandoned in place (dead, harmless bytes nothing reads
            # anymore once e_phoff is repointed) -- the same
            # leave-it-dead-in-place pattern _remove_needed already uses
            # for a neutralized DT_NEEDED entry.
            entsize = elf["e_phentsize"]
            old_phnum = elf.num_segments()
            old_array_bytes = bytes(raw[elf["e_phoff"]: elf["e_phoff"] + old_phnum * entsize])
            new_array = bytearray(old_array_bytes)
            new_array[ext_idx * entsize:(ext_idx + 1) * entsize] = extended_entry

            placeholder_file_offset = phdr_array_vaddr - ext_skew

            # The PT_PHDR entry (if any -- not every ELF file has one, but
            # every ordinary executable does) is the *other* place the
            # array's own location/size is recorded, independently of
            # e_phoff/e_phnum, and it's just as important to keep correct:
            # glibc's ld.so derives the main executable's load bias not
            # from e_phoff but from `AT_PHDR - PT_PHDR.p_vaddr` (AT_PHDR
            # being where the kernel *actually* put the array, which is
            # correct automatically -- see the e_phoff/e_phnum comment
            # below). Leaving PT_PHDR's own copy of the array's old
            # location in place would make that subtraction produce a
            # bogus nonzero "load bias" out of what should be a
            # non-relocated (ET_EXEC) image, corrupting every other
            # address ld.so derives from it -- confirmed by actually
            # running the result on real Linux (WSL): it crashes inside
            # ld.so itself, before any user code runs, with this entry
            # stale, and runs correctly once it's updated here too.
            phdr_idx = next((i for i, s in enumerate(all_host_segments) if s["p_type"] == "PT_PHDR"), None)
            if phdr_idx is not None:
                phdr_seg = all_host_segments[phdr_idx]
                updated_phdr_entry = _pack_phdr(
                    is64, PT_PHDR, phdr_seg["p_flags"], placeholder_file_offset, phdr_array_vaddr,
                    phdr_array_vaddr, phdr_array_size, phdr_array_size, phdr_seg["p_align"],
                )
                new_array[phdr_idx * entsize:(phdr_idx + 1) * entsize] = updated_phdr_entry

            # Each fixed-base dependency's own blob is appended past the
            # very end of the file as it now stands (which already
            # includes `ext`'s whole extension, placeholder and all) --
            # unlike everything in `new_sections`, it doesn't need to be
            # contiguous with `ext` at all (it gets its own PT_LOAD entry,
            # with its own independent p_offset/p_vaddr pair), only
            # page-aligned consistently with its own fixed vaddr, which an
            # at-most-one-page padding gap is always enough to arrange
            # (the ELF ABI only requires p_vaddr and p_offset to agree
            # modulo p_align, not to be numerically equal).
            for X, blob in fixed_base_segments:
                offset = len(raw) + ((X - len(raw)) % _PAGE)
                raw.extend(b"\x00" * (offset - len(raw)))
                raw.extend(blob)
                new_array += _pack_phdr(is64, PT_LOAD, PF_R | PF_W | PF_X, offset, X, X, len(blob), len(blob), _PAGE)

            if len(new_array) != phdr_array_size:
                raise ValueError("internal error: grown ELF program header array size mismatch")
            raw[placeholder_file_offset:placeholder_file_offset + len(new_array)] = new_array

            # e_phoff/e_phnum are fixed-size fields at a fixed byte offset
            # in every ELF32/ELF64 header alike (this module writes every
            # byte it touches from the ABI's own fixed, hand-verified
            # struct layouts rather than through pyelftools, which is
            # read-only -- see this module's own top-of-file docstring);
            # e_phoff is ptr-sized (4 bytes for ELF32, 8 for ELF64) and
            # immediately follows e_ident/e_type/e_machine/e_version/
            # e_entry, while e_phnum is a fixed 2-byte field three
            # ptr-sized fields (e_phoff/e_shoff) plus one 4-byte field
            # (e_flags) and two 2-byte fields (e_ehsize/e_phentsize)
            # further along.
            e_phoff_off = 16 + 2 + 2 + 4 + ptr_size
            e_phnum_off = e_phoff_off + ptr_size * 2 + 4 + 2 + 2
            _write_int(raw, e_phoff_off, ptr_size, placeholder_file_offset)
            _write_int(raw, e_phnum_off, 2, old_phnum + len(fixed_base_segments))

        # e_entry is deliberately never touched -- see embed()'s docstring.

        self.output_path.write_bytes(bytes(raw))
