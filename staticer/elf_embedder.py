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
import shutil
import struct
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from elftools.elf.elffile import ELFFile

from .common.depgraph import build_dependency_graph, embed_order
from .stubs.linux.elf_stub import build_linux_init_array_stub, build_linux_stub

# -- ELF constants pyelftools doesn't expose as plain ints for our needs --
# (it hands back Enum-mapped strings for e.g. p_type/d_tag, which is fine
# for reading but useless for re-packing bytes we write ourselves).

PT_LOAD = 1
PT_DYNAMIC = 2
PT_PHDR = 6
PT_TLS = 7
PT_GNU_EH_FRAME = 0x6474E550
PF_X, PF_W, PF_R = 1, 2, 4

DT_NULL = 0
DT_NEEDED = 1

DT_DEBUG = 21  # harmless/ignored by every runtime linker; see _remove_needed

# Relocation type numbers below happen to share the same values on
# EM_386 and EM_X86_64 for every type this module handles.
R_NONE = 0
R_ABS_PLUS_ADDEND = 1  # R_X86_64_64 / R_386_32: value = S (+A for RELA)
R_COPY = 5  # R_X86_64_COPY / R_386_COPY: copy `st_size` bytes from the definition
R_GLOB_DAT = 6
R_JUMP_SLOT = 7
R_RELATIVE = 8

# TLS GOT-slot-data-patch relocation type numbers -- UNLIKE every type
# above, these do NOT share the same numeric value between EM_X86_64 and
# EM_386 (e.g. R_386_TLS_DTPMOD32 is type 35, not 16), so they're only
# ever recognized when host_machine == "EM_X86_64" -- see where they're
# used, further down, for why a 32-bit TLS-bearing dependency just falls
# through to the ordinary "unsupported relocation type" error instead
# of being misinterpreted. Per Task 1's findings
# (.superpowers/findings/2026-11-04-frida-gadget-tls-shape.md), only
# R_X86_64_DTPMOD64 is ever actually seen in practice (frida-gadget: 14
# occurrences, 0 DTPOFF64/TPOFF64) -- DTPOFF64/TPOFF64 are handled too,
# for whatever other TLS-bearing dependency might emit them, but
# R_X86_64_TLSGD/TLSLD (the call-site General/Local-Dynamic relaxation
# types, 19/20) are explicitly OUT of this task's scope (phase 2/Task 6).
R_X86_64_DTPMOD64 = 16
R_X86_64_DTPOFF64 = 17
R_X86_64_TPOFF64 = 18

# The call-site General/Local-Dynamic relaxation relocation types
# (Task 6). Investigated, not guessed: these exist ONLY as a directive
# from the compiler to the STATIC LINKER inside an unlinked relocatable
# object file (.o) -- confirmed with `readelf -r` against a `gcc -c`
# .o built from a source file carrying
# `__attribute__((tls_model("global-dynamic")))`, which genuinely does
# emit R_X86_64_TLSGD there. But every linker tried against the *linked*
# .so built from that same .o (GNU ld/bfd, lld; gold wasn't installed to
# test but there is no reason to expect it differs -- the ELF TLS ABI
# itself, not a particular linker's heuristic, requires this) always
# consumes/resolves the TLSGD/TLSLD relocation at link time and replaces
# it with an ordinary DTPMOD64/DTPOFF64 GOT-slot pair (what Task 3 above
# already handles) -- even for the one case that should structurally
# defeat link-time resolution: a `.so` whose `extern __thread` variable
# is defined in a wholly different, unlinked shared object (so its
# module id genuinely cannot be known until load time) still comes out
# as DTPMOD64/DTPOFF64 against the undefined symbol, never TLSGD/TLSLD.
# So R_X86_64_TLSGD/TLSLD (and the i386 equivalents, R_386_TLS_GD/
# R_386_TLS_LDM, including their _PUSH/_CALL/_POP sequence variants)
# cannot appear in any ELF file `embed()` actually ever opens -- every
# dependency it processes is already a linked `.so`, never a raw `.o` --
# regardless of source code shape, compiler flags, or GCC version.
# Checked for explicitly anyway, right before the generic "unsupported
# relocation type" fallback, so that IF this analysis is ever wrong -- a future
# toolchain, a hand-crafted/malicious input, or a target this project
# doesn't support yet -- the error names the specific relocation type
# and explains why GD/LD relaxation isn't implemented, instead of the
# much less specific generic message.
R_X86_64_TLSGD = 19
R_X86_64_TLSLD = 20
R_386_TLS_GD = 18
R_386_TLS_LDM = 19

_SUPPORTED_MACHINES = ("EM_X86_64", "EM_386")

_PAGE = 0x1000

# -- DWARF exception-handling pointer-encoding bits (DW_EH_PE_*), just the
# ones GCC's own default .eh_frame_hdr layout actually uses -- see
# _parse_eh_frame_hdr/_build_eh_frame_hdr.
_DW_EH_PE_UDATA4 = 0x03
_DW_EH_PE_SDATA4 = 0x0B
_DW_EH_PE_PCREL = 0x10
_DW_EH_PE_DATAREL = 0x30
_DW_EH_PE_OMIT = 0xFF

STB_GLOBAL = 1
STB_WEAK = 2
STT_FUNC = 2


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
    """Scan search_dirs in order for a file that `name` denotes.

    `name` comes straight from the ELF file being processed's own
    DT_NEEDED entries (an attacker-controlled dependency name, if the
    input binary is untrusted) -- it must never be allowed to escape the
    `search_dirs` entry it's being matched against via path-traversal
    components (``..``) or an absolute path (CWE-22), or `--lib-dir`'s
    whole purpose (scoping embedding to one chosen folder) is defeated.

    A DT_NEEDED entry is *usually* a bare filename (e.g. "libc.so.6"),
    but it legitimately isn't always one: a .so with no DT_SONAME of its
    own that was linked by passing its full path on the linker command
    line gets that literal path recorded as the NEEDED string by ld --
    this project's own test fixtures do exactly that (`build_exe` passes
    `str(lib)`, an absolute `tmp_path`-rooted path, with no
    `-Wl,-soname=...` ever set). An earlier version of this check
    rejected any such non-bare-filename name outright, which (correctly)
    blocked a genuine traversal/absolute escape attempt but also
    (incorrectly) blocked this entirely legitimate same-directory case,
    since ``directory / name`` only ever *joins* when `name` is relative
    -- for an absolute `name` it discards `directory` and evaluates to
    `name` itself, so the real containment check below is what has to
    carry the whole security property, not a cheap name-shape guard in
    front of it.

    So: no shape-based rejection up front. Every `name` -- bare,
    relative-with-components, or absolute -- is joined against each
    `directory` in turn (a no-op join for an absolute `name`, same as
    Path's own semantics) and the resulting candidate is accepted only
    if it both exists as a file and *resolves* (symlinks and all) to
    somewhere inside that same `directory`'s own resolved form. A
    genuine traversal (``../../etc/passwd``) or an absolute escape
    (``/etc/passwd``) still fails that resolved-containment check against
    every `search_dirs` entry, exactly as before -- only a `name` that
    truly denotes a file inside one of them, however it's spelled, is
    ever accepted. Either way a rejection behaves exactly like "not found
    in this directory" -- falling through to the next search_dirs entry,
    or returning None if none match -- never a hard error."""
    if not name:
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


def _dynamic_segment(elf: ELFFile):
    return next(elf.iter_segments(type="PT_DYNAMIC"), None)


def _real_symtab_count(dyn, reloc_tables: dict) -> int:
    """The true number of entries in `dyn`'s own DT_SYMTAB, more reliable
    than pyelftools' own ``DynamicSegment.num_symbols()`` for a host that
    exports no symbols at all (the common case for an ordinary
    executable, which usually only *imports*).

    ``num_symbols()`` derives its count from the DT_GNU_HASH table (or
    DT_HASH), which only indexes *exported/defined* symbols -- GNU_HASH's
    own lookup degrades, for a host with nothing hashed at all, to
    returning its own `symoffset` bias value as if that were the total
    symbol count (see pyelftools' ``GNUHashTable.get_number_of_symbols``:
    ``if max_idx < self.params['symoffset']: return self.params['symoffset']``),
    silently undercounting every purely-undefined symbol past that bias.
    Confirmed empirically against a real `-fno-plt`/`-no-pie` host on
    real WSL Linux: with `__cxa_finalize`/`_ITM_registerTMCloneTable`/
    `_ITM_deregisterTMCloneTable` at dynsym indices 1-3 (all undefined,
    all referenced by real relocations), `num_symbols()` reported 1 --
    appending new symbol-table growth past that wrong, too-small index
    silently overwrote/discarded those three real, already-occupied
    entries, corrupting what their own pre-existing relocations' symbol
    indices resolved to and segfaulting at process startup.

    Falls back to one past the highest symbol index any of the host's
    OWN existing relocations (main table + JMPREL, if present) already
    reference, whenever that's larger than what `num_symbols()` reports
    -- every such index is, by construction, a real, already-occupied
    dynsym slot that must not be overwritten."""
    count = dyn.num_symbols()
    for table in reloc_tables.values():
        for reloc in table.iter_relocations():
            count = max(count, reloc["r_info_sym"] + 1)
    return count


_EI_CLASS_OFFSET = 4  # fixed byte offset in e_ident, identical for ELF32/ELF64
_ELFCLASS64 = 2


def _peek_elfclass64(path: Path) -> bool:
    """Whether `path` is a 64-bit ELF file (ELFCLASS64), read directly
    from the single e_ident[EI_CLASS] byte rather than a full ELF parse
    -- used only to pick a same-bitness-first multiarch search-dir order
    (see `ElfEmbedder._search_dirs`); any malformed/unreadable input
    here is caught properly, with a real diagnostic, by the full parse
    `embed()` already does right after, so this deliberately doesn't
    duplicate that error handling -- a bool default of False (32-bit)
    on a read failure just means the search order picked here doesn't
    matter, since `embed()` is about to fail loudly on the same file
    for an unrelated, more informative reason moments later."""
    try:
        with open(path, "rb") as f:
            f.seek(_EI_CLASS_OFFSET)
            return f.read(1) == bytes([_ELFCLASS64])
    except OSError:
        return False


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


_VERNEED_ENTRY_SIZE = 16  # Elf32_Verneed/Elf64_Verneed share one layout (see _VERNEED_FMT)
_VERNEED_FMT = "<HHIII"  # vn_version, vn_cnt, vn_file, vn_aux, vn_next (all fixed-width, class-independent)


def _remove_verneed_entry(dyn, raw: bytearray, ptr_size: int, vaddr_to_offset, needed_name: str) -> None:
    """Remove `needed_name`'s own top-level DT_VERNEED (symbol-versioning
    "needed version" list) entry, if the host has one, splicing the
    linked list around it in place -- the version-requirement analogue of
    _remove_needed, needed for the same reason but discovered only
    against real system binaries (none of this project's own small
    fixtures use GNU symbol versioning, so nothing exercised this path
    before Task 10b): ld.so's _dl_check_map_versions walks the WHOLE
    top-level Verneed list unconditionally at load time and asserts a
    loaded module exists for *every* entry's own vn_file SONAME --
    unconditionally, regardless of whether any relocation still actually
    references a version from it. Leaving a stale entry for an embedded
    (DT_NEEDED-neutralized) dependency in place makes that assertion fail
    at process startup ("Inconsistency detected by ld.so: dl-version.c:
    ...: _dl_check_map_versions: Assertion `needed != NULL' failed"),
    confirmed against a real `bash`/`libtinfo.so.6` embed on real Linux
    (WSL) before this fix -- it ran `embed()` successfully and loaded via
    a plain run but crashed immediately in the dynamic linker itself,
    before any user code ran.

    The corresponding Vernaux (per-version) entries hanging off the
    removed node are simply left as dead bytes in place, unchanged -- the
    same leave-it-dead-in-place pattern _remove_needed already uses for a
    neutralized DT_NEEDED entry -- since nothing reaches them anymore
    once their own Verneed node is spliced out of the list; a Verneed
    entry's own vn_file (the only thing this function reads from each
    entry) must always name one of the host's own *direct* DT_NEEDED
    entries per the ELF ABI (a version can only ever be required from a
    library the host itself directly depends on), so this is only ever
    called for a direct import -- see this method's one call site."""
    verneed_tag = next(dyn.iter_tags("DT_VERNEED"), None)
    verneednum_tag = next(dyn.iter_tags("DT_VERNEEDNUM"), None)
    strtab_tag = next(dyn.iter_tags("DT_STRTAB"), None)
    if verneed_tag is None or verneednum_tag is None or strtab_tag is None:
        return
    count = verneednum_tag.entry.d_val
    if count == 0:
        return
    strtab_vaddr = strtab_tag.entry.d_val

    def _cstr_at(vaddr: int) -> str:
        off = vaddr_to_offset(vaddr, 1)
        end = raw.index(b"\x00", off)
        return raw[off:end].decode("ascii")

    # Walk the chain, recording each entry's own (vaddr, file offset,
    # resolved vn_file name) -- vn_next entries are threaded by byte
    # offset *from each entry's own vaddr*, not a flat array, so this
    # can't just iterate `count` fixed-size slots directly.
    entries = []
    cur_vaddr = verneed_tag.entry.d_val
    for _ in range(count):
        off = vaddr_to_offset(cur_vaddr, _VERNEED_ENTRY_SIZE)
        _, _, vn_file, _, vn_next = struct.unpack_from(_VERNEED_FMT, raw, off)
        name = _cstr_at(strtab_vaddr + vn_file)
        entries.append({"vaddr": cur_vaddr, "offset": off, "name": name})
        if vn_next == 0:
            break
        cur_vaddr += vn_next

    kept = [e for e in entries if e["name"] != needed_name]
    if len(kept) == len(entries):
        return  # this host has no Verneed entry for `needed_name` at all

    # Re-thread vn_next across only the kept entries (last one's becomes
    # 0, the "no more entries" terminator) and update DT_VERNEEDNUM/the
    # head DT_VERNEED tag's own d_val in place -- same append-nothing,
    # edit-existing-fields-in-place pattern as _remove_needed/
    # _set_dyn_tag_value, since nothing here needs new file content, just
    # different field values at already-existing offsets.
    for i, e in enumerate(kept):
        new_next = 0 if i == len(kept) - 1 else kept[i + 1]["vaddr"] - e["vaddr"]
        struct.pack_into("<I", raw, e["offset"] + 12, new_next & 0xFFFFFFFF)
    if kept:
        _set_dyn_tag_value(dyn, raw, ptr_size, "DT_VERNEED", kept[0]["vaddr"])
    _set_dyn_tag_value(dyn, raw, ptr_size, "DT_VERNEEDNUM", len(kept))


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


def _pack_glob_dat_entries(entries: List[Tuple[int, int]], is64: bool, is_rela: bool) -> bytes:
    """Pack (slot_vaddr, sym_index) pairs as new R_*_GLOB_DAT REL/RELA
    entries -- used to forward an embedded dependency's remaining
    external symbol references (functions/data it calls via its own,
    now-dead PT_DYNAMIC that no embedded dependency provides -- e.g.
    `malloc`, `__cxa_throw`) into the host's own dynamic section, so
    ld.so resolves them normally, by name, at load time -- exactly as it
    would if the host had referenced them directly -- rather than the
    value being something *this module* computes (unlike
    _pack_relative_entries' RELATIVE entries, which always encode an
    address this module already resolved itself; a GLOB_DAT entry here
    instead carries a *symbol index* for ld.so's own lookup to resolve,
    since the real address -- e.g. malloc's -- isn't known until load
    time and isn't ours to compute). Addend is always 0: the whole
    resolved value replaces the slot's content outright, there's nothing
    to add it to."""
    out = bytearray()
    for vaddr, sym_idx in entries:
        if is64:
            r_info = (sym_idx << 32) | R_GLOB_DAT
            if is_rela:
                out += struct.pack("<QQq", vaddr, r_info, 0)
            else:
                out += struct.pack("<QQ", vaddr, r_info)
        else:
            r_info = (sym_idx << 8) | R_GLOB_DAT
            if is_rela:
                out += struct.pack("<IIi", vaddr, r_info, 0)
            else:
                out += struct.pack("<II", vaddr, r_info)
    return bytes(out)


def _pack_undef_sym(is64: bool, name_off: int, weak: bool = False) -> bytes:
    """A new Elf32_Sym/Elf64_Sym entry for a symbol this module itself
    never defines (SHN_UNDEF, st_value/st_size 0) -- used only so ld.so's
    relocation processing has a name to look up for a forwarded external
    reference (see _pack_glob_dat_entries); STT_FUNC matches what a real
    external function import's own symbol table entry would normally
    carry (ld.so's lookup doesn't actually care about the type for OUR
    copy of it -- only the *name* and the fact that it's undefined here
    -- but matching convention costs nothing).

    `weak` preserves the ORIGINAL reference's own binding (STB_WEAK vs
    STB_GLOBAL) rather than always hardcoding STB_GLOBAL -- this is what
    makes a forwarded weak-undefined reference behave like real ld.so
    semantics instead of this module's own: ld.so's symbol lookup
    tolerates an unresolved STB_WEAK reference (silently leaves it at 0)
    but raises a fatal "undefined symbol" error for an unresolved
    STB_GLOBAL one, exactly matching what a dependency's own weak
    reference (e.g. crtstuff's __cxa_finalize/__gmon_start__-style
    optional hooks) would have done had it never been embedded at all."""
    st_info = ((STB_WEAK if weak else STB_GLOBAL) << 4) | STT_FUNC
    if is64:
        # st_name, st_info, st_other, st_shndx, st_value, st_size
        return struct.pack("<IBBHQQ", name_off, st_info, 0, 0, 0, 0)
    # Elf32_Sym has a different field order: st_value/st_size come right
    # after st_name, with st_info/st_other/st_shndx packed at the end.
    return struct.pack("<IIIBBH", name_off, 0, 0, st_info, 0, 0)


def _decode_eh_pe_sdata4(encoding: int, raw: int, field_vaddr: int, hdr_vaddr: int) -> int:
    """Decode one DW_EH_PE-encoded 4-byte field from .eh_frame_hdr, as
    used by every encoding GCC's own default layout actually emits for
    this structure's fields: `sdata4`/`udata4` format (this module
    doesn't need to tell those apart -- both are 4 bytes, and the
    unsigned-vs-signed distinction only matters for a value that could
    legitimately be negative *before* adding a base, which none of
    these are once decoded) combined with either a `pcrel` base
    (relative to this field's own vaddr) or a `datarel` base (relative
    to the start of .eh_frame_hdr itself). Raises for anything else --
    failing loudly rather than silently misinterpreting unwind data
    matches this module's existing architecture-mismatch/unsupported-
    relocation-type precedent elsewhere."""
    width_bits = encoding & 0x0F
    if width_bits not in (_DW_EH_PE_UDATA4, _DW_EH_PE_SDATA4):
        raise ValueError(f"unsupported .eh_frame_hdr value encoding {hex(encoding)}")
    base_bits = encoding & 0x70
    if base_bits == _DW_EH_PE_PCREL:
        return field_vaddr + raw
    if base_bits == _DW_EH_PE_DATAREL:
        return hdr_vaddr + raw
    raise ValueError(f"unsupported .eh_frame_hdr base encoding {hex(encoding)}")


def _parse_eh_frame_hdr(hdr_bytes: bytes, hdr_vaddr: int) -> List[Tuple[int, int]]:
    """-> [(initial_loc, fde_addr), ...] -- absolute vaddrs, decoded from
    a .eh_frame_hdr's binary-search table per whatever DW_EH_PE_*
    encodings its own 4-byte encoding header declares (see
    _decode_eh_pe_sdata4), not any one hardcoded scheme. This is the
    *only* thing ever read from a dependency's .eh_frame/.eh_frame_hdr --
    the FDE/CIE bytes themselves never need touching at all (see
    ElfEmbedder.embed()'s docstring for why: every PC-relative offset a
    FDE encodes -- to its own function, to its CIE, to its LSDA -- stays
    numerically correct under a uniform shift, and a dependency's whole
    mapped image, .eh_frame included, is always relocated as one single
    uniform shift by this module)."""
    version, eh_frame_ptr_enc, fde_count_enc, table_enc = hdr_bytes[0:4]
    if version != 1:
        raise ValueError(f"unsupported .eh_frame_hdr version {version}")
    pos = 4
    if eh_frame_ptr_enc != _DW_EH_PE_OMIT:
        pos += 4  # eh_frame_ptr itself is never needed by this module
    if fde_count_enc == _DW_EH_PE_OMIT:
        return []
    if (fde_count_enc & 0x0F) != _DW_EH_PE_UDATA4:
        raise ValueError(f"unsupported .eh_frame_hdr fde_count encoding {hex(fde_count_enc)}")
    fde_count = struct.unpack_from("<I", hdr_bytes, pos)[0]
    pos += 4
    entries = []
    for i in range(fde_count):
        off = pos + i * 8
        iloc_raw, fde_raw = struct.unpack_from("<ii", hdr_bytes, off)
        initial_loc = _decode_eh_pe_sdata4(table_enc, iloc_raw, hdr_vaddr + off, hdr_vaddr)
        fde_addr = _decode_eh_pe_sdata4(table_enc, fde_raw, hdr_vaddr + off + 4, hdr_vaddr)
        entries.append((initial_loc, fde_addr))
    return entries


def _build_eh_frame_hdr(hdr_vaddr: int, eh_frame_vaddr: int, entries: List[Tuple[int, int]]) -> bytes:
    """Inverse of _parse_eh_frame_hdr, always emitting GCC's own default
    encoding scheme (`pcrel`/`sdata4` for the eh_frame_ptr field,
    `udata4` for fde_count, `datarel`/`sdata4` for the table -- the same
    scheme _parse_eh_frame_hdr already knows how to read, so a hdr this
    function builds is always itself re-parseable) regardless of what
    encoding scheme the *input* entries were originally read with.
    `entries` must already be sorted ascending by initial_loc -- the ABI
    requires this for the binary search the table exists to support to
    actually work."""
    eh_frame_ptr_field_vaddr = hdr_vaddr + 4
    out = bytearray([1, 0x1B, 0x03, 0x3B])
    out += struct.pack("<i", eh_frame_vaddr - eh_frame_ptr_field_vaddr)
    out += struct.pack("<I", len(entries))
    for initial_loc, fde_addr in entries:
        out += struct.pack("<ii", initial_loc - hdr_vaddr, fde_addr - hdr_vaddr)
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
        dirs = [
            self.input_path.parent,
            Path("/lib"), Path("/usr/lib"), Path("/lib64"), Path("/usr/lib64"),
        ]
        # Debian/Ubuntu-style "multiarch" layout: real shared objects live
        # in an architecture-qualified subdirectory (e.g. the real
        # libc.so.6 at /usr/lib/x86_64-linux-gnu/libc.so.6), never directly
        # under /usr/lib itself -- discovered against real system binaries
        # (Task 10b): without this, lib_dir=None (every resolvable import
        # is a candidate, per this method's own docstring) silently
        # resolved *zero* real dependencies on any such system, even
        # libc.so.6, making the whole lib_dir=None/"full closure" path
        # dead code there. /lib is a symlink to /usr/lib on these systems,
        # so checking both costs nothing and also covers non-symlinked
        # layouts (e.g. a system where only one of the two is qualified).
        #
        # Deliberately only the two *exact* triplets this module's own
        # `_SUPPORTED_MACHINES` ever allows (EM_X86_64/EM_386) -- NOT a
        # wildcard glob over every "*-linux-gnu*" directory present. An
        # earlier version of this fix used such a glob and broke for
        # real on a host that also had a foreign-architecture multiarch
        # directory installed (e.g. aarch64-linux-gnu, from an unrelated
        # cross-compilation/container toolchain already on the system):
        # resolve_elf's own plain by-name file search has no architecture
        # awareness at all, so a same-named file (e.g. "libc.so.6") in
        # the *wrong*-architecture directory could get resolved first
        # purely by directory sort order, pulling in a whole
        # foreign-architecture dependency subtree that then failed this
        # method's own (correct) architecture-mismatch check several
        # steps later -- confirmed for real against a real multi-
        # toolchain WSL box while building this fix. Hardcoding exactly
        # the two supported triplets sidesteps that regardless of
        # whatever *other* architectures' multiarch directories happen
        # to also be installed.
        #
        # Moderate final-review finding: an earlier version of this
        # method always listed "x86_64-linux-gnu" before
        # "i386-linux-gnu" unconditionally, regardless of the HOST's own
        # bitness -- resolve_elf's by-name search (see its own docstring)
        # has no architecture awareness either, so for a genuinely
        # 32-bit host/full-closure embed, a same-named file (e.g.
        # "libc.so.6") sitting in the wrong-architecture (64-bit)
        # multiarch directory would get resolved FIRST, pulled into the
        # dependency graph, and only THEN rejected by this method's own
        # (correct) architecture-mismatch check -- making 32-bit
        # lib_dir=None/"full closure" embedding unusable in practice
        # whenever both multiarch directories happen to carry a
        # same-named file (the ordinary case on any real multiarch-
        # enabled distro). Peeking at the host's own ELFCLASS (a single
        # byte, e_ident[EI_CLASS] at a fixed offset -- no need for a full
        # ELF parse just to pick a search order) and listing the
        # matching-bitness triplet first fixes this: a 32-bit host now
        # finds its own real i386-linux-gnu libc.so.6 before the
        # wrong-architecture x86_64-linux-gnu one could ever shadow it.
        host_is64 = _peek_elfclass64(self.input_path)
        triplets = ("x86_64-linux-gnu", "i386-linux-gnu") if host_is64 else ("i386-linux-gnu", "x86_64-linux-gnu")
        for triplet in triplets:
            for base in (Path("/usr/lib"), Path("/lib")):
                candidate = base / triplet
                if candidate.is_dir():
                    dirs.append(candidate)
        return dirs

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
        # Names the *host* itself directly lists in its own DT_NEEDED --
        # as opposed to a node that's only reachable *transitively*
        # (needed by some other embedded dependency, not by the host).
        # Only a direct name has anything to neutralize in the host's own
        # dynamic section at all; see its one use, further down, for why
        # treating every node in `order` as if it had one is wrong.
        host_direct_import_names = set(list_elf_imports(self.input_path))

        if not order:
            self.output_path.write_bytes(self.input_path.read_bytes())
            shutil.copymode(self.input_path, self.output_path)
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
        ptr_mask = (1 << (ptr_size * 8)) - 1

        def _host_dyn_tag_val(tag_name: str) -> Optional[int]:
            tag = next(host_dyn.iter_tags(tag_name), None)
            return tag.entry.d_val if tag is not None else None

        # Needed only if some embedded dependency turns out to have a
        # remaining external symbol reference to forward (see
        # `external_symbol_index`, below) -- read unconditionally here
        # since they're cheap dynamic-tag lookups, not real work.
        host_symtab_count = _real_symtab_count(host_dyn, host_reloc_tables)
        host_symtab_vaddr = _host_dyn_tag_val("DT_SYMTAB")
        host_strtab_vaddr = _host_dyn_tag_val("DT_STRTAB")
        host_strsz = _host_dyn_tag_val("DT_STRSZ")
        host_versym_vaddr = _host_dyn_tag_val("DT_VERSYM")

        def vaddr_to_offset(vaddr: int, size: int) -> int:
            off = next(elf.address_offsets(vaddr, size), None)
            if off is None:
                raise ValueError(
                    f"address {hex(vaddr)} isn't covered by any PT_LOAD segment of '{self.input_path}'"
                )
            return off

        new_sections: List[Tuple[int, bytes]] = []  # (vaddr, data), contiguous in placement order
        new_reloc_entries: List[Tuple[int, int]] = []  # (host vaddr, value) -> new R_*_RELATIVE entries
        combined_exports: Dict[str, Tuple[int, int, int]] = {}  # export name -> (X, offset-within-dep, st_size)
        # Each embedded dependency's own blob bytes, keyed by its own `X`
        # (the same key `combined_exports` values' first element uses) --
        # needed only for a host R_*_COPY relocation's data (see the
        # R_COPY handling in the patch_specs loop, further down): at that
        # point `raw` doesn't contain any embedded dependency's bytes yet
        # (everything in `new_sections`/`fixed_base_segments` is only
        # actually appended into `raw` by the "lay everything out" block,
        # well after this), so a COPY relocation's source bytes have to
        # come from here instead.
        dep_blob_by_base: Dict[int, bytes] = {}
        # (host vaddr, bytes-to-write) pairs for R_*_COPY relocations (see
        # the R_COPY handling in the patch_specs loop) -- writing has to
        # be deferred until after the "lay everything out" block, further
        # down: a COPY relocation's target is frequently inside the
        # host's own *BSS* (confirmed for real against bash/libtinfo.so.6
        # on real Linux, WSL -- its `UP` symbol lands there), which has no
        # file bytes at all yet at the point the patch_specs loop runs
        # (the host's own `ext` PT_LOAD segment's filesz only grows to
        # cover its full memsz -- backfilling that BSS gap with explicit
        # zero bytes -- once "lay everything out" actually extends `raw`;
        # see `ext_skew`'s own declaration, and this list's one other use
        # further down, for exactly where/why).
        deferred_copy_writes: List[Tuple[int, bytes]] = []
        # A symbol an embedded dependency itself still references
        # externally (through its own, now-dead PT_DYNAMIC/PLT) that no
        # embedded dependency's own exports satisfy -- e.g. `malloc`,
        # `__cxa_throw` (C++ exceptions always need at least the former,
        # even in the simplest possible throw/catch: __cxa_allocate_
        # exception calls it internally -- there's no way to support
        # unwind-metadata preservation's own flagship scenario, an
        # exception crossing the embedding boundary, without this).
        # Forwarded into the host's own dynamic section (new DT_SYMTAB/
        # DT_STRTAB/DT_VERSYM entries, further down, past the per-
        # dependency loop) as a brand new, genuinely-external,
        # R_*_GLOB_DAT-resolved import -- exactly as if the *host* had
        # referenced it directly -- rather than something this module
        # tries to resolve itself (unlike `combined_exports`, there's no
        # static address to resolve here at all: the real provider, e.g.
        # libc, is loaded and relocated by ld.so at a load-time-chosen
        # address this module can't know). Keyed by name; value is this
        # symbol's index in the *grown* host .dynsym (assigned in
        # insertion order, starting right after the host's existing
        # entries -- see where it's grown, further down).
        external_symbol_index: Dict[str, int] = {}
        # Whether every occurrence seen so far of a given forwarded
        # name was itself a *weak* undefined reference (STB_WEAK) --
        # if ANY occurrence is a strong (STB_GLOBAL) reference, the
        # forwarded symbol must behave like a strong one (ld.so must
        # raise if nothing resolves it), so this is ANDed across every
        # occurrence rather than just keyed off the first one seen. See
        # _pack_undef_sym's own docstring for why this distinction is
        # preserved at all, instead of hard-zeroing every weak-undefined
        # reference the way an earlier version of this method did.
        external_symbol_is_weak: Dict[str, bool] = {}
        new_glob_dat_entries: List[Tuple[int, int]] = []  # (slot vaddr, symbol index) -> new R_*_GLOB_DAT entries
        # (initial_loc, fde_addr) pairs, absolute vaddrs already shifted
        # by each dependency's own delta -- collected so the host's own
        # .eh_frame_hdr binary-search table can be grown to cover them
        # too (see the merge block past the per-dependency loop, and
        # ElfEmbedder.embed()'s docstring, for why nothing here ever
        # needs to touch the FDE/CIE bytes themselves).
        collected_eh_entries: List[Tuple[int, int]] = []
        # Resolved absolute VAs of every embedded dependency's own
        # DT_INIT_ARRAY entries (its .init_array constructors -- already
        # relocated to their final addresses by the time they're read,
        # since .init_array slots are themselves normal R_*_RELATIVE
        # targets processed like any other), flattened in
        # dependencies-first order, for the generated stub to call.

        init_array_calls: List[int] = []

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
        # Set at most once, by whichever embedded dependency turns out to
        # carry its own PT_TLS segment (X, dep_base, that segment, the
        # dependency's own name) -- None if no dependency has one, or if
        # the host already has its own (see `host_has_tls` above; that
        # case raises instead of reaching this). A *second* TLS-bearing
        # dependency also raises (merging more than one into a single
        # combined block needs a real layout/offset-renumbering scheme
        # phase 1 doesn't implement -- see the per-dependency loop).
        # Needs its own new PT_PHDR entry exactly like `fixed_base_
        # segments` does (see the "reserve room for a grown program
        # header array" block, further down) -- but unlike those, its
        # *data* is never a separately-placed blob: the dependency's own
        # TLS bytes are already physically part of its ordinary blob,
        # appended into `new_sections` (i.e. into `ext`'s own extension)
        # exactly like the rest of that same dependency, so only a new
        # *descriptor* pointing into that already-placed data is needed.
        new_tls_entry: Optional[Tuple[int, int, object, str]] = None
        reserved_ranges: List[Tuple[int, int, str]] = [
            (seg["p_vaddr"], seg["p_vaddr"] + seg["p_memsz"], f"the host image ('{self.input_path}')")
            for seg in host_load_segments
        ]

        # Every newly-built blob/reloc-table is appended as an
        # *extension* of the host's own highest-vaddr PT_LOAD segment,
        # rather than as a new PT_LOAD segment of its own -- see the large
        # comment further down, right before this same `ext`/`ext_idx` pair
        # is used to actually grow it, for why a brand new segment (with a
        # freshly chosen vaddr/offset pair, with no particular reason to
        # share whatever segment-specific skew AT_PHDR's derivation
        # actually keys off) risks landing AT_PHDR on a bogus address.
        all_host_segments = [elf.get_segment(i) for i in range(elf.num_segments())]
        # Whether the HOST itself already carries its own PT_TLS segment
        # -- if so, a TLS-bearing dependency's own PT_TLS can't be
        # adopted as described below (there'd be two real TLS blocks to
        # merge into one, needing a real combined-layout/offset-
        # renumbering scheme this phase-1 merge doesn't implement -- see
        # where this is checked, further down, and
        # test_host_with_own_tls_directory_fails_loudly's PE sibling for
        # the same phase-1/phase-2 scope split). This is independent of
        # `ext`/`ext_idx` below (a TLS-less host's lack of PT_TLS has
        # nothing to do with which PT_LOAD segment is last in the file).
        host_has_tls = any(s["p_type"] == "PT_TLS" for s in all_host_segments)
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

        # The host's own PT_DYNAMIC entry -- needed only if some embedded
        # dependency turns out to have its own further, non-embedded
        # DT_NEEDED import to forward into the host's own dynamic section
        # (see the B2-fix block past the per-dependency loop, by
        # `extra_needed_names`). Always exists (host_dyn above is None-
        # checked already), found the same way as `ext_idx`/`phdr_idx`.
        host_dynamic_idx = next(
            i for i, s in enumerate(all_host_segments) if s["p_type"] == "PT_DYNAMIC"
        )

        # The host's own PT_GNU_EH_FRAME entry (if any), found the same
        # way as `ext_idx`/`phdr_idx` -- needed only if some embedded
        # dependency turns out to have unwind info to merge (see the
        # merge block past the per-dependency loop).
        host_gnu_eh_frame_idx = next(
            (i for i, s in enumerate(all_host_segments) if s["p_type"] == "PT_GNU_EH_FRAME"), None
        )

        # Every symbol name the HOST's own dynamic relocation table already
        # has an R_*_COPY entry for, mapped to that entry's own target
        # vaddr -- pre-scanned up front, before any dependency is
        # processed, because of what an R_*_COPY relocation actually
        # *means* per the ELF ABI: once ld.so processes it, the copied-to
        # address in the *executable* becomes THE one true storage for
        # that global, and every other module's own access to it --
        # including the *defining* shared object's own internal GOT-
        # indirect accesses to its own global, exactly the same
        # same-module-but-interposable pattern this method's own
        # `_resolve_dep_reference` docstring already discusses for a
        # plain exported mutable data symbol -- has to be redirected
        # there too, not left pointing at the shared object's own
        # original (now dead) storage. Confirmed for real (a `bash`/
        # `libtinfo.so.6` embed on real Linux, WSL, crashing deep inside
        # bash's own `parse_and_execute` with a garbage pointer) before
        # this fix: libtinfo's own internal reference to its "UP" global
        # (copy-relocated into bash itself, since old-style termcap
        # globals like UP/PC/BC are always accessed this way) was being
        # resolved to libtinfo's own embedded-blob-local copy instead,
        # silently diverging from the value anything else (bash itself,
        # or libtinfo's own tgetent()-equivalent setup code) reads/writes
        # through the host's copy -- needed *before* the per-dependency
        # loop below so a dependency's own self-reference to such a
        # symbol (processed inline, during that very loop) already
        # redirects correctly, not just cross-dependency references
        # resolved via `combined_exports`.
        host_copy_targets: Dict[str, int] = {}
        for copy_reloc in host_reloc_tables[dyn_table_key].iter_relocations():
            if copy_reloc["r_info_type"] != R_COPY:
                continue
            copy_sym = host_dyn.get_symbol(copy_reloc["r_info_sym"])
            if copy_sym.name:
                host_copy_targets[copy_sym.name] = copy_reloc["r_offset"]

        def _resolve_dep_reference(sym, blob: bytearray, blob_offset: int, X: int, dep_base: int,
                                    node_name: str, addend: int) -> None:
            """Resolve a dependency's own reference to `sym` (anything
            that isn't a plain load-bias-only R_*_RELATIVE entry, which
            callers handle inline themselves without needing this) and
            record whatever new *host*-level relocation entry keeps it
            correct, exactly mirroring how the embedded dependency's own
            relocation would have been processed had it still been
            independently loaded:
              - a self-reference, or a reference to an *earlier*
                dependency's own export (dependencies-first order means
                those are already in `combined_exports` by the time a
                later dependency is processed) -- resolve directly, same
                as step 3's host GOT/PLT patch further down (a new
                R_*_RELATIVE entry).
              - a *named*, still-unresolved reference (weak or strong)
                -- forward it into the host's own dynamic section (see
                `external_symbol_index`'s own declaration for why; a new
                R_*_GLOB_DAT entry, not RELATIVE, since the real address
                is only known at load time, via ld.so's own by-name
                lookup, not something this module resolves itself),
                preserving its original STB_WEAK/STB_GLOBAL binding (see
                `_pack_undef_sym`) so ld.so's own real weak-symbol
                semantics apply -- a weak reference that's genuinely
                unresolved anywhere else, at the real process's load
                time, stays silently 0 exactly as it would have if this
                dependency had never been embedded, while a strong one
                still raises a fatal "undefined symbol" error.
              - an *unnamed* weak reference -- can't be forwarded (no
                name to look up by), so it's zeroed directly, exactly as
                ld.so itself would resolve a weak reference with nothing
                defining it.
              - an unnamed STRONG reference -- fails loudly; nothing
                can resolve it and there's no name to even try."""
            if sym.name and sym.name in host_copy_targets:
                # Takes priority over everything else below, including a
                # same-dependency self-reference to its own defined
                # symbol (the `new_val = X + ...` fallback at the bottom)
                # -- see `host_copy_targets`'s own declaration for why.
                new_val = (host_copy_targets[sym.name] + addend) & ptr_mask
                _write_int(blob, blob_offset, ptr_size, new_val)
                new_reloc_entries.append((X + blob_offset, new_val))
                return
            if sym.name and sym.name in combined_exports:
                exp_X, exp_off, _ = combined_exports[sym.name]
                new_val = (exp_X + exp_off + addend) & ptr_mask
                _write_int(blob, blob_offset, ptr_size, new_val)
                new_reloc_entries.append((X + blob_offset, new_val))
                return
            if sym["st_shndx"] == "SHN_UNDEF":
                is_weak = sym["st_info"]["bind"] == "STB_WEAK"
                if not sym.name:
                    if is_weak:
                        _write_int(blob, blob_offset, ptr_size, 0)
                        return
                    raise ValueError(
                        f"dependency '{node_name}' has an unresolved, unnamed external "
                        "symbol reference; can't forward it to the host"
                    )
                if sym.name not in external_symbol_index:
                    external_symbol_index[sym.name] = host_symtab_count + len(external_symbol_index)
                    external_symbol_is_weak[sym.name] = is_weak
                else:
                    external_symbol_is_weak[sym.name] = external_symbol_is_weak[sym.name] and is_weak
                _write_int(blob, blob_offset, ptr_size, 0)
                new_glob_dat_entries.append((X + blob_offset, external_symbol_index[sym.name]))
                return
            new_val = (X + (sym["st_value"] - dep_base) + addend) & ptr_mask
            _write_int(blob, blob_offset, ptr_size, new_val)
            new_reloc_entries.append((X + blob_offset, new_val))

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
                # Minor final-review finding: p_memsz is an attacker-
                # controlled field (it's read directly from a dependency
                # file this module doesn't otherwise trust) with no
                # inherent upper bound of its own -- a crafted/malformed
                # dependency could declare a multi-exabyte p_memsz,
                # turning `bytearray(blob_size)` just below into an
                # unbounded-allocation DoS before any other validation
                # ever runs. Real shared objects never need anywhere
                # close to this; failing loudly on an obviously-absurd
                # size (comfortably above any legitimate real-world .so,
                # by many orders of magnitude) costs nothing for a
                # genuine dependency and avoids attempting the
                # allocation at all for an adversarial one.
                _MAX_SANE_BLOB_SIZE = 1 << 34  # 16 GiB
                if blob_size > _MAX_SANE_BLOB_SIZE:
                    raise ValueError(
                        f"dependency '{node.name}' declares an implausibly large mapped "
                        f"size ({blob_size} bytes); refusing to allocate it"
                    )
                blob = bytearray(blob_size)
                for seg in dep_load_segments:
                    data = seg.data()
                    start = seg["p_vaddr"] - dep_base
                    blob[start:start + len(data)] = data

                is_fixed_base = dep["e_type"] == "ET_EXEC"
                if is_fixed_base and elf["e_type"] == "ET_DYN":
                    # Moderate final-review finding: a fixed-base
                    # dependency's own untracked absolute references
                    # (see the big comment above, by `fixed_base_segments`,
                    # for exactly what those are and why) only stay
                    # correct if the final combined image's load address
                    # never shifts as a whole -- true for a non-PIE
                    # (ET_EXEC) host (the kernel always maps every PT_LOAD
                    # segment at exactly its declared p_vaddr), but NOT for
                    # an ET_DYN host (a PIE executable, or this method's
                    # own B6-ELF .so-input case): under ASLR, the whole
                    # image -- including the fixed-base dependency's own
                    # untracked references -- moves together by the same
                    # load bias, silently going stale by exactly that
                    # amount. Unlike PE (pe_embedder.py can clear
                    # DYNAMIC_BASE/HIGH_ENTROPY_VA on its own output to
                    # neutralize this for a fixed-base DLL dependency),
                    # ELF has no per-image "disable ASLR" flag this module
                    # can set on its own output -- PIE-ness is baked into
                    # e_type/the kernel's own ASLR policy, not a flag this
                    # module could flip afterward. Rather than silently
                    # producing an output that corrupts itself the moment
                    # ASLR picks a non-zero load address (the exact
                    # silent-corruption case the design spec's anti-goal
                    # forbids), fail loudly here instead.
                    raise ValueError(
                        f"dependency '{node.name}' is a fixed-base (non-PIC) ELF object, but "
                        f"'{self.input_path}' is a PIE/ET_DYN image; a fixed-base dependency's "
                        "own untracked absolute references would silently go stale under ASLR "
                        "once the combined image's load address shifts -- embedding a fixed-base "
                        "dependency is only supported into a non-PIE (ET_EXEC) host"
                    )
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

                # This dependency's own PT_TLS segment, if it has one --
                # see `new_tls_entry`'s own declaration for what adopting
                # it as the (TLS-less) host's own PT_TLS actually
                # involves, and the DTPMOD64/DTPOFF64/TPOFF64 relocation
                # handling just below for why detecting it here, before
                # that loop runs, matters even though its phdr entry
                # itself is only built much further down.
                dep_tls_seg = next(dep.iter_segments(type="PT_TLS"), None)
                if dep_tls_seg is not None:
                    if host_has_tls:
                        raise ValueError(
                            f"dependency '{node.name}' has its own TLS directory (PT_TLS "
                            f"segment), but '{self.input_path}' already has one of its own; "
                            "merging two real TLS directories into one isn't supported yet"
                        )
                    if new_tls_entry is not None:
                        raise ValueError(
                            f"both '{new_tls_entry[3]}' and '{node.name}' carry their own "
                            "PT_TLS segment; merging more than one TLS-bearing dependency "
                            "into a single combined block isn't supported yet (phase 1 scope)"
                        )
                    if is_fixed_base:
                        raise ValueError(
                            f"dependency '{node.name}' is a fixed-base (non-PIC) ELF object "
                            "with its own TLS directory; unsupported"
                        )
                    new_tls_entry = (X, dep_base, dep_tls_seg, node.name)

                dep_reloc_tables = dep_dyn.get_relocation_tables()

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
                            new_val = (base_value + delta) & ptr_mask
                            _write_int(blob, blob_offset, ptr_size, new_val)
                            new_reloc_entries.append((X + blob_offset, new_val))
                            continue
                        if host_machine == "EM_X86_64" and rtype in (
                            R_X86_64_DTPMOD64, R_X86_64_DTPOFF64, R_X86_64_TPOFF64,
                        ):
                            # GOT-slot-data-patch TLS relocations (see
                            # Task 1's findings, this module's module-
                            # level docstring note above
                            # R_X86_64_DTPMOD64's own declaration, and
                            # `new_tls_entry`'s declaration) -- reached
                            # only once `dep_tls_seg is not None` already
                            # passed every check above (host_has_tls/
                            # multiple-TLS-dependency/fixed-base), so a
                            # dependency that reaches here always has a
                            # PT_TLS segment of its own, now becoming the
                            # host's own sole PT_TLS.
                            #
                            # Unlike every relocation type handled above,
                            # none of these three ever need a new runtime
                            # (R_*_RELATIVE-style) relocation entry of
                            # their own: both the merged module's id and
                            # any variable's static offset within the
                            # combined TLS block are fixed, load-bias-
                            # independent constants once the dependency
                            # is no longer an independently-loaded module
                            # -- they're simply written directly into the
                            # blob, once, here.
                            if rtype == R_X86_64_DTPMOD64:
                                # The real .so (independently loaded) had
                                # this filled in at load time by ld.so
                                # with whatever module id *that* load
                                # happened to assign it (frida-gadget's
                                # own 14 occurrences are all against
                                # symbol index 0 -- a "my own module"
                                # self-relocation, confirmed via `readelf
                                # -r` against the real downloaded .so).
                                # Once merged, this dependency's TLS data
                                # becomes part of the HOST's own static,
                                # initial TLS block (no separate module/
                                # dlopen-time registration exists anymore
                                # -- exactly glibc's own main-executable
                                # case): glibc's dynamic linker always
                                # assigns TLS module id 1 to the main
                                # executable's own PT_TLS (it's the first
                                # link map `_dl_next_tls_modid` is ever
                                # called for, in `_dl_start`/`dl_main`'s
                                # own object-processing order, before any
                                # DT_NEEDED dependency) -- the id this
                                # merge creates a brand-new PT_TLS for IS
                                # that executable's own, so 1 is the
                                # correct constant here, not a guess.
                                # Verified for real: the synthetic
                                # `lib_tls_simple.so`/`main_tls_simple`
                                # fixture pair (test_elf_tls.py) and the
                                # real, genuine frida-gadget .so both run
                                # to their expected results on actual
                                # Linux (WSL) once this is wired in -- a
                                # wrong module id would either crash
                                # inside __tls_get_addr's own dtv lookup
                                # or silently read back the wrong thread's
                                # slot, neither of which happens.
                                #
                                # Same external-symbol guard as the
                                # DTPOFF64/TPOFF64 branch below: a
                                # DTPMOD64 relocation against an
                                # SHN_UNDEF (external, not-embedded) TLS
                                # symbol belongs to some OTHER module, not
                                # this merge's module-id-1 host -- without
                                # this check, it would silently get
                                # assigned module id 1 anyway instead of
                                # failing loudly.
                                sym_idx = reloc["r_info_sym"]
                                if sym_idx != 0:
                                    tls_sym = dep_dyn.get_symbol(sym_idx)
                                    if tls_sym["st_shndx"] == "SHN_UNDEF":
                                        raise ValueError(
                                            f"dependency '{node.name}' has a TLS relocation "
                                            f"referencing an external (not embedded) TLS "
                                            f"symbol '{tls_sym.name}'; unsupported"
                                        )
                                new_val = 1
                            else:
                                sym_idx = reloc["r_info_sym"]
                                if sym_idx != 0:
                                    tls_sym = dep_dyn.get_symbol(sym_idx)
                                    if tls_sym["st_shndx"] == "SHN_UNDEF":
                                        raise ValueError(
                                            f"dependency '{node.name}' has a TLS relocation "
                                            f"referencing an external (not embedded) TLS "
                                            f"symbol '{tls_sym.name}'; unsupported"
                                        )
                                    # An STT_TLS symbol's st_value is
                                    # already its offset within its own
                                    # module's TLS block, per the ELF TLS
                                    # ABI -- unaffected by `delta`/`X`,
                                    # since adopting this PT_TLS as the
                                    # host's own moves the whole block's
                                    # base address, not its own internal
                                    # layout.
                                    tls_offset = tls_sym["st_value"]
                                else:
                                    tls_offset = 0
                                addend = reloc["r_addend"] if is_rela else 0
                                if rtype == R_X86_64_DTPOFF64:
                                    new_val = (tls_offset + addend) & ptr_mask
                                else:  # R_X86_64_TPOFF64
                                    # Initial-Exec model: a direct, fixed
                                    # %fs-relative offset (ELF TLS ABI
                                    # variant II: a *negative* offset from
                                    # the thread pointer, computed from
                                    # the combined static TLS block's own
                                    # total size) -- genuinely needs that
                                    # real static-TLS-layout computation,
                                    # which this phase-1 merge doesn't
                                    # implement (Task 1's findings: zero
                                    # occurrences in frida-gadget, and the
                                    # synthetic fixture built for this
                                    # task doesn't produce any either --
                                    # see test_elf_tls.py). Failing loudly
                                    # here is strictly better than writing
                                    # a plausible-looking but wrong offset.
                                    raise ValueError(
                                        f"dependency '{node.name}' has an R_X86_64_TPOFF64 "
                                        "TLS relocation; this phase-1 merge doesn't support "
                                        "the Initial-Exec TLS model yet"
                                    )
                            _write_int(blob, blob_offset, ptr_size, new_val)
                            continue
                        is_tlsgd_or_tlsld = (
                            (host_machine == "EM_X86_64" and rtype in (R_X86_64_TLSGD, R_X86_64_TLSLD))
                            or (host_machine == "EM_386" and rtype in (R_386_TLS_GD, R_386_TLS_LDM))
                        )
                        if is_tlsgd_or_tlsld:
                            # See R_X86_64_TLSGD's own declaration above
                            # (Task 6) for the investigation backing this:
                            # a linked .so can never actually carry this
                            # relocation type (the static linker always
                            # consumes/resolves it, replacing it with an
                            # ordinary DTPMOD64/DTPOFF64 GOT-slot pair,
                            # handled above) -- reaching this line means
                            # either a hand-crafted/malicious input, or an
                            # assumption here turning out wrong for some
                            # future toolchain. Named explicitly rather
                            # than falling into the generic "unsupported
                            # relocation type" message below: General/
                            # Local-Dynamic TLS call-site relaxation
                            # (rewriting the `lea ...@tlsgd; call
                            # __tls_get_addr` sequence into a direct
                            # thread-pointer-relative access) is not
                            # implemented.
                            gd_ld_names = (
                                "R_X86_64_TLSGD/TLSLD"
                                if host_machine == "EM_X86_64"
                                else "R_386_TLS_GD/TLS_LDM"
                            )
                            raise ValueError(
                                f"dependency '{node.name}' has an {gd_ld_names} "
                                f"(type {rtype}) call-site General/Local-Dynamic TLS "
                                "relocation; GD/LD instruction-sequence relaxation is not "
                                "implemented (see docs/limitations.md)"
                            )
                        if rtype not in (R_ABS_PLUS_ADDEND, R_GLOB_DAT):
                            raise ValueError(
                                f"unsupported relocation type {rtype} in dependency '{node.name}'"
                            )
                        sym = dep_dyn.get_symbol(reloc["r_info_sym"])
                        addend = reloc["r_addend"] if is_rela else 0
                        # See _resolve_dep_reference's own docstring for
                        # the self/earlier-dependency-export vs. weak vs.
                        # genuinely-external cases it handles -- R_*_GLOB_DAT
                        # here (rather than the more usual
                        # R_*_ABS_PLUS_ADDEND) for a symbol *defined* within
                        # this same dependency means it's one of its own
                        # exports (default/global visibility): GCC can't
                        # assume a reference to a global-bound, exported
                        # mutable data symbol is necessarily *its own*
                        # definition (another loaded object could preempt/
                        # interpose it), so even a same-module reference
                        # goes through the GOT, resolved via symbol lookup
                        # rather than a plain load-bias-only fixup. Confirmed
                        # by a real crash (ValueError, not a silent
                        # miscompute) building this task's own
                        # `lib_ctor_b.c` fixture, whose non-`static`
                        # `b_ctor_ran` global triggers exactly this -- with
                        # no actual interposition happening here (this
                        # dependency's own copy is the only one ever
                        # loaded), resolving it to its own address is
                        # correct either way.
                        _resolve_dep_reference(sym, blob, blob_offset, X, dep_base, node.name, addend)

                # A dependency's own PLT entries (DT_JMPREL) are always
                # R_*_JUMP_SLOT, always against an undefined (external)
                # symbol by construction -- *unless* it's a symbol some
                # earlier-processed (dependencies-first order) embedded
                # dependency itself exports, which _resolve_dep_reference
                # also handles. An earlier version of this method rejected
                # a dependency with *any* JMPREL entries outright ("further
                # external requirements aren't supported yet"); unwind-
                # metadata preservation's own flagship scenario -- a C++
                # exception crossing the embedding boundary -- makes that
                # genuinely unworkable to keep: even the simplest possible
                # `throw` calls `__cxa_throw`, which calls `malloc`
                # internally, through the dependency's own PLT. Verified by
                # actually forwarding a synthetic external import this way
                # and running the result on real Linux (WSL) before wiring
                # this in, for both 32- and 64-bit -- including the
                # .gnu.version/DT_VERSYM-array-growth part, which silent
                # static reasoning alone couldn't settle (ld.so's relocation
                # processing indexes it by the *same* symbol-table index as
                # the new symbol, so leaving it ungrown risks an out-of-
                # bounds read deciding a bogus required symbol version).
                jmprel = dep_reloc_tables.get("JMPREL")
                if jmprel is not None:
                    is_rela = jmprel.is_RELA()
                    for reloc in jmprel.iter_relocations():
                        rtype = reloc["r_info_type"]
                        if rtype == R_NONE:
                            continue
                        if rtype not in (R_JUMP_SLOT, R_ABS_PLUS_ADDEND, R_GLOB_DAT):
                            raise ValueError(
                                f"unsupported PLT relocation type {rtype} in dependency '{node.name}'"
                            )
                        target_vaddr = reloc["r_offset"]
                        blob_offset = target_vaddr - dep_base
                        if blob_offset < 0 or blob_offset + ptr_size > blob_size:
                            raise ValueError(
                                f"PLT relocation target {hex(target_vaddr)} in dependency "
                                f"'{node.name}' falls outside its own PT_LOAD segments"
                            )
                        sym = dep_dyn.get_symbol(reloc["r_info_sym"])
                        addend = reloc["r_addend"] if is_rela else 0
                        _resolve_dep_reference(sym, blob, blob_offset, X, dep_base, node.name, addend)

                for i in range(dep_dyn.num_symbols()):
                    sym = dep_dyn.get_symbol(i)
                    if (
                        sym.name
                        and sym["st_shndx"] != "SHN_UNDEF"
                        and sym["st_info"]["type"] in ("STT_FUNC", "STT_OBJECT")
                        and sym["st_info"]["bind"] in ("STB_GLOBAL", "STB_WEAK")
                    ):
                        combined_exports[sym.name] = (X, sym["st_value"] - dep_base, sym["st_size"])

                # This dependency's own .init_array constructors -- already
                # relocated to their final absolute addresses in `blob` by
                # the RELA/REL loop above, since each slot is itself a
                # normal R_*_RELATIVE target -- for the generated stub
                # (build_linux_stub) to call. Deliberately *not* collecting/
                # calling DT_INIT (legacy `_init`, a single crtstuff-
                # provided entry point, separate from DT_INIT_ARRAY): on a
                # modern GCC/glibc toolchain it's boilerplate with an empty
                # body for a plain `-shared` build (DT_INIT_ARRAY -- what
                # `__attribute__((constructor))` actually populates, and
                # what this task's own fixtures exercise -- carries every
                # real constructor instead), and Task 4's own docstring
                # already found calling *other* crtstuff-provided init
                # machinery directly, cold, to be unsafe on x86 -- no
                # reason to take on that same risk for a part no fixture
                # here needs.
                dep_init_array_vaddr = next(
                    (t.entry.d_val for t in dep_dyn.iter_tags("DT_INIT_ARRAY")), None
                )
                dep_init_array_sz = next(
                    (t.entry.d_val for t in dep_dyn.iter_tags("DT_INIT_ARRAYSZ")), None
                )
                if dep_init_array_vaddr is not None and dep_init_array_sz:
                    for i in range(dep_init_array_sz // ptr_size):
                        off = (dep_init_array_vaddr - dep_base) + i * ptr_size
                        init_array_calls.append(_read_int(blob, off, ptr_size))

                # This dependency's own unwind info, if it has any -- see
                # _parse_eh_frame_hdr's docstring for why only these two
                # numbers per FDE (never the FDE/CIE bytes themselves) ever
                # need reading, and the merge block past this loop for how
                # they get folded into the host's own .eh_frame_hdr.
                dep_eh_hdr_seg = next(dep.iter_segments(type="PT_GNU_EH_FRAME"), None)
                if dep_eh_hdr_seg is not None:
                    hdr_vaddr = dep_eh_hdr_seg["p_vaddr"]
                    hdr_off_in_blob = hdr_vaddr - dep_base
                    hdr_bytes = bytes(blob[hdr_off_in_blob: hdr_off_in_blob + dep_eh_hdr_seg["p_filesz"]])
                    for initial_loc, fde_addr in _parse_eh_frame_hdr(hdr_bytes, hdr_vaddr):
                        collected_eh_entries.append((initial_loc + delta, fde_addr + delta))

                # Only a node the *host* directly lists in its own
                # DT_NEEDED has anything to neutralize there at all -- a
                # transitive-only node (needed by some other embedded
                # dependency, e.g. this task's own lib_ctor_a->lib_ctor_b
                # fixture) has no entry of its own in the host's dynamic
                # section to begin with; its DT_NEEDED edge lives inside
                # *that other dependency's* own (already-copied-into-
                # `blob`, now-inert) PT_DYNAMIC segment instead, which
                # nothing ever reads again once that dependency is no
                # longer independently loaded as a module -- so there's
                # nothing to do here for it, and treating its absence as
                # an error (as an earlier version of this method did)
                # was itself the bug: it assumed every embedded node is
                # always a *direct* host import, which a real transitive
                # chain disproves.
                if node.name in host_direct_import_names:
                    if not _remove_needed(host_dyn, raw, ptr_size, node.name):
                        raise ValueError(f"expected DT_NEEDED entry for '{node.name}' not found in host")
                    _remove_verneed_entry(host_dyn, raw, ptr_size, vaddr_to_offset, node.name)

                dep_blob_by_base[X] = bytes(blob)
                if is_fixed_base:
                    fixed_base_segments.append((X, bytes(blob)))
                else:
                    new_sections.append((X, bytes(blob)))
                    next_vaddr = _align_up(X + blob_size, _PAGE)

        # -- B2 fix: every embedded dependency's OWN DT_NEEDED entries that
        #    aren't themselves embedded need to become new entries in the
        #    HOST's own DT_NEEDED, or ld.so never loads them at all --
        #    even though `_resolve_dep_reference` already forwards the
        #    dependency's remaining symbol references into the host's
        #    dynamic section as plain by-name GLOB_DAT lookups (see its
        #    own docstring), that only works if the library that actually
        #    *defines* those symbols is also loaded. An embedded
        #    dependency's own DT_NEEDED entry has no further use once it's
        #    no longer independently loaded as a module (see the
        #    `_remove_needed`-call comment just above) for an *embedded*
        #    target -- but when that target was never resolved into the
        #    graph at all (excluded, or simply outside `lib_dir`/
        #    unresolvable), it's a real, still-needed runtime dependency
        #    that this method must now take over advertising, since the
        #    dependency that used to advertise it is gone. Order names are
        #    deduplicated and kept in a deterministic (dependency, then
        #    that dependency's own DT_NEEDED) order, skipping anything
        #    that's itself embedded or that the host already has its own,
        #    still-active DT_NEEDED entry for (no embedded node overlaps
        #    this set, since those get neutralized above).
        order_names = {node.name for node in order}
        host_still_needed_names = host_direct_import_names - order_names
        extra_needed_names: List[str] = []
        _seen_extra_needed: Set[str] = set()
        for node in order:
            for needed in list_elf_imports(node.path):
                if (
                    needed in order_names
                    or needed in host_still_needed_names
                    or needed in _seen_extra_needed
                ):
                    continue
                _seen_extra_needed.add(needed)
                extra_needed_names.append(needed)

        # -- forward embedded dependencies' remaining external symbol
        #    references into the host's own dynamic section (see
        #    `external_symbol_index`'s own declaration for the full "why")
        #    -- grow .dynsym/.dynstr (and .gnu.version/DT_VERSYM, if the
        #    host has one, kept in lockstep since ld.so's relocation
        #    processing indexes it by the very same symbol-table index) as
        #    brand new, bigger combined tables, same append-past-the-end-
        #    and-repoint-the-DT_*-tag pattern already used for the combined
        #    relocation table just below (and PE's own import-directory
        #    rebuild) -- growing any of these three in place isn't
        #    generally safe either, for the same reason. `extra_needed_names`'
        #    own strings (see the B2-fix block just above) are folded into
        #    this same .dynstr growth, since both need "append new strings
        #    past the end of a brand-new, bigger .dynstr" -- even if
        #    `external_symbol_index` itself is empty, needing room for a
        #    new DT_NEEDED's own name string is reason enough to grow
        #    .dynstr (but NOT .dynsym/.gnu.version, which a plain
        #    DT_NEEDED name has no entry in at all).
        needed_name_offsets: Dict[str, int] = {}
        dynstr_vaddr = host_strtab_vaddr
        if external_symbol_index or extra_needed_names:
            if host_strtab_vaddr is None or host_strsz is None:
                raise ValueError(
                    f"'{self.input_path}' is missing DT_STRTAB/DT_STRSZ; can't forward an "
                    "embedded dependency's external symbol/DT_NEEDED references into it"
                )
            old_dynstr_off = vaddr_to_offset(host_strtab_vaddr, host_strsz)
            old_dynstr_bytes = bytes(raw[old_dynstr_off: old_dynstr_off + host_strsz])
            new_dynstr_bytes = bytearray(old_dynstr_bytes)

            if external_symbol_index:
                if host_symtab_vaddr is None:
                    raise ValueError(
                        f"'{self.input_path}' is missing DT_SYMTAB; can't forward an "
                        "embedded dependency's external symbol references into it"
                    )
                sym_entry_size = 24 if is64 else 16
                old_dynsym_off = vaddr_to_offset(host_symtab_vaddr, host_symtab_count * sym_entry_size)
                old_dynsym_bytes = bytes(
                    raw[old_dynsym_off: old_dynsym_off + host_symtab_count * sym_entry_size]
                )
                new_dynsym_bytes = bytearray(old_dynsym_bytes)
                for name in external_symbol_index:  # dict preserves insertion order == assigned index order
                    name_off = len(new_dynstr_bytes)
                    new_dynstr_bytes += name.encode("ascii") + b"\x00"
                    new_dynsym_bytes += _pack_undef_sym(
                        is64, name_off, weak=external_symbol_is_weak.get(name, False)
                    )

                dynsym_vaddr = next_vaddr
                new_sections.append((dynsym_vaddr, bytes(new_dynsym_bytes)))
                next_vaddr = _align_up(dynsym_vaddr + len(new_dynsym_bytes), ptr_size)

            for name in extra_needed_names:
                needed_name_offsets[name] = len(new_dynstr_bytes)
                new_dynstr_bytes += name.encode("ascii") + b"\x00"

            dynstr_vaddr = next_vaddr
            new_sections.append((dynstr_vaddr, bytes(new_dynstr_bytes)))
            next_vaddr = _align_up(dynstr_vaddr + len(new_dynstr_bytes), _PAGE)

            if external_symbol_index:
                _set_dyn_tag_value(host_dyn, raw, ptr_size, "DT_SYMTAB", dynsym_vaddr)
            _set_dyn_tag_value(host_dyn, raw, ptr_size, "DT_STRTAB", dynstr_vaddr)
            _set_dyn_tag_value(host_dyn, raw, ptr_size, "DT_STRSZ", len(new_dynstr_bytes))

            if external_symbol_index and host_versym_vaddr is not None:
                old_versym_off = vaddr_to_offset(host_versym_vaddr, host_symtab_count * 2)
                old_versym_bytes = bytes(raw[old_versym_off: old_versym_off + host_symtab_count * 2])
                # 0 (VER_NDX_LOCAL) per new entry: "no version requirement"
                # for this (our own, newly forwarded) reference -- an
                # ordinary unversioned lookup, verified end-to-end against
                # a real `malloc` import on real Linux (WSL, both 32- and
                # 64-bit) before wiring this in; see this method's docstring.
                # Only grown when `external_symbol_index` itself is
                # non-empty -- a plain new DT_NEEDED (see
                # `extra_needed_names`) adds no new .dynsym entry at all,
                # so .gnu.version (indexed 1:1 by .dynsym entry) needs no
                # corresponding growth for it.
                new_versym_bytes = old_versym_bytes + b"\x00\x00" * len(external_symbol_index)
                versym_vaddr = next_vaddr
                new_sections.append((versym_vaddr, new_versym_bytes))
                next_vaddr = _align_up(versym_vaddr + len(new_versym_bytes), _PAGE)
                _set_dyn_tag_value(host_dyn, raw, ptr_size, "DT_VERSYM", versym_vaddr)

        # -- patch the host's GOT/PLT references to embedded exports -----
        #
        # B5: whether the HOST itself was built with eager (`-z now`/
        # BIND_NOW) binding matters only for how a *PLT* (DT_JMPREL)
        # relocation entry gets neutralized below -- see the JMPREL-
        # specific branch, further down, for why. Checked via either of
        # the two real-world ways a linker records it (DF_BIND_NOW in
        # DT_FLAGS, or the more modern DF_1_NOW in DT_FLAGS_1 -- confirmed
        # against real `readelf -d` output on this project's own toolchain,
        # which emits the latter); the legacy, presence-only DT_BIND_NOW
        # tag is deliberately not checked too -- no modern linker emits it
        # (GNU ld hasn't since the mid-2000s), and a host that genuinely
        # used only that legacy mechanism would, worst case, just take the
        # (already-correct-today) eager-binding code path below instead of
        # the lazy one, not silently corrupt anything.
        DF_BIND_NOW = 0x8
        DF_1_NOW = 0x1
        host_bind_now = bool((_host_dyn_tag_val("DT_FLAGS") or 0) & DF_BIND_NOW) or bool(
            (_host_dyn_tag_val("DT_FLAGS_1") or 0) & DF_1_NOW
        )

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
                rtype = reloc["r_info_type"]
                if rtype == R_COPY:
                    # A direct-data-symbol import (e.g. ncurses/termcap's
                    # legacy `extern char *UP;`-style globals, confirmed
                    # against a real `bash`/`libtinfo.so.6` embed on real
                    # Linux (WSL) -- none of this project's own fixtures
                    # exercise a copy relocation at all): the *value*
                    # (`st_size` raw bytes, copied verbatim from the
                    # definition) has to be written into the host's own
                    # reserved space at `r_offset` right now, since ld.so
                    # itself would normally do this copy at load time by
                    # looking up the defining module by name -- which no
                    # longer exists once that dependency is embedded,
                    # otherwise reproducing exactly the undefined-symbol
                    # load failure this fix was written against.
                    sym = host_dyn.get_symbol(reloc["r_info_sym"])
                    if not sym.name or sym.name not in combined_exports:
                        continue
                    X, offset_in_dep, dep_size = combined_exports[sym.name]
                    size = sym["st_size"] or dep_size
                    src = dep_blob_by_base[X][offset_in_dep:offset_in_dep + size]
                    if len(src) != size:
                        raise ValueError(
                            f"COPY relocation for '{sym.name}' needs {size} bytes "
                            f"at offset {offset_in_dep} in its defining dependency, "
                            f"but only {len(src)} are available -- symbol size/offset "
                            f"mismatch, refusing a silent partial copy"
                        )
                    target_vaddr = reloc["r_offset"]
                    if not (ext["p_vaddr"] <= target_vaddr < ext["p_vaddr"] + ext["p_memsz"]):
                        raise ValueError(
                            f"R_*_COPY target {hex(target_vaddr)} in '{self.input_path}' falls "
                            "outside its own extendable PT_LOAD segment; not supported"
                        )
                    deferred_copy_writes.append((target_vaddr, bytes(src)))
                    # If the copied value is itself a pointer-sized field
                    # whose value lands inside this very same dependency's
                    # own embedded blob range, it's one of *our* addresses
                    # (e.g. a `char *` into the dependency's own relocated
                    # .rodata) and needs the same ASLR-safety new
                    # R_*_RELATIVE entry as every other such address this
                    # method introduces -- unlike a NULL or an address
                    # pointing somewhere else entirely (e.g. still-external
                    # data), which needs no fixup at all.
                    #
                    # Known architectural limitation (documented, not
                    # fixed -- see PLAN.md's "Known problems" entry for
                    # this): this only ever checks the copied value AS A
                    # WHOLE, and only when it's exactly one pointer wide.
                    # A larger COPY-relocated object (e.g. a struct with
                    # its OWN interior pointer field, not just scalar
                    # data) could have such a field pointing into the
                    # dependency's own blob too, needing the exact same
                    # fixup at that field's own offset -- but nothing
                    # here can tell, from `size`/`src`'s raw bytes alone,
                    # which sub-offsets of a >ptr_size object are even
                    # pointers at all. ELF's own COPY-relocation symbol
                    # info carries only `st_size` (a byte count), no
                    # type/layout metadata; doing this correctly in
                    # general needs DWARF type info this module doesn't
                    # use anywhere else. Every real COPY-relocated symbol
                    # this module has actually been tested against (this
                    # project's own fixtures, and bash/libtinfo.so.6's
                    # termcap globals in Task 10b) happens to be
                    # pointer-sized or smaller, so this gap is currently
                    # unexercised in practice.
                    if size == ptr_size:
                        copied_value = _read_int(src, 0, ptr_size)
                        if X <= copied_value < X + len(dep_blob_by_base[X]):
                            new_reloc_entries.append((reloc["r_offset"], copied_value))

                    entry_off = table_file_offset + idx * entry_size
                    raw[entry_off:entry_off + entry_size] = b"\x00" * entry_size
                    continue

                if rtype not in (R_JUMP_SLOT, R_GLOB_DAT, R_ABS_PLUS_ADDEND):
                    continue
                sym = host_dyn.get_symbol(reloc["r_info_sym"])
                if sym["st_shndx"] != "SHN_UNDEF" or not sym.name or sym.name not in combined_exports:
                    continue
                X, offset_in_dep, _ = combined_exports[sym.name]
                addend = reloc["r_addend"] if is_rela else 0
                resolved = (X + offset_in_dep + addend) & ((1 << (ptr_size * 8)) - 1)
                target_off = vaddr_to_offset(reloc["r_offset"], ptr_size)
                _write_int(raw, target_off, ptr_size, resolved)

                if key == "JMPREL" and rtype == R_JUMP_SLOT and not host_bind_now:
                    # B5 fix: a lazy-bound host (the ABI default -- most
                    # real-world ELF binaries, though this project's own
                    # toolchain happens to default to BIND_NOW) still has
                    # ld.so walk *every* DT_JMPREL entry at load time, via
                    # a completely separate code path from the one that
                    # processes the main DT_RELA/DT_REL table
                    # (`elf_machine_lazy_rel`, not the generic relocation
                    # dispatch `_remove_needed`'s own R_*_NONE-zeroing
                    # trick already relies on elsewhere) -- its only job
                    # for a R_*_JUMP_SLOT entry is to add the image's own
                    # load bias to whatever's *already* sitting in the GOT
                    # slot (deferring the real by-name symbol lookup to
                    # the PLT0 trampoline on first call, under genuine
                    # laziness) -- it does NOT consult the entry's own
                    # symbol index to do this. Confirmed empirically (real
                    # WSL Linux, both bitnesses): zeroing this entry to
                    # R_*_NONE -- correct for the eager/BIND_NOW path,
                    # where DT_JMPREL is instead processed through the
                    # *generic* dispatch, which does tolerate R_*_NONE --
                    # crashes a lazy-bound host at process startup with
                    # "unexpected PLT reloc type 0x00", since
                    # elf_machine_lazy_rel's own switch has no such
                    # tolerance. The fix: leave this entry's bytes
                    # completely untouched (still nominally R_*_JUMP_SLOT,
                    # against its original, now-dead symbol -- never read
                    # by elf_machine_lazy_rel for this type) and skip
                    # adding a new host R_*_RELATIVE entry for the GOT slot
                    # too, since `elf_machine_lazy_rel`'s own load-bias add
                    # already does exactly that job for this specific slot
                    # -- adding a second, independent bias-add via a new
                    # RELATIVE entry in the *main* table would double-apply
                    # the load bias on a PIE host (every fixture this
                    # module is tested against), corrupting the address.
                    continue

                new_reloc_entries.append((reloc["r_offset"], resolved))

                entry_off = table_file_offset + idx * entry_size
                raw[entry_off:entry_off + entry_size] = b"\x00" * entry_size

        # -- B6-ELF: is the INPUT itself a shared object, rather than an
        #    executable? -- ld.so never calls e_entry for anything but the
        #    process's own main executable; a .so loaded via dlopen (or as
        #    an ordinary DT_NEEDED dependency) has e_entry completely
        #    ignored, so installing the generated init-call stub as the
        #    new e_entry (as the EXE-input branch just below does) would
        #    silently never run it at all. ET_EXEC always means "the
        #    input is an ordinary non-PIE executable" -- no ambiguity. An
        #    ET_DYN input, though, is ambiguous by itself: a modern PIE
        #    executable is ALSO ET_DYN, indistinguishable from a plain
        #    shared library by e_type alone. The real-world disambiguator
        #    GNU ld actually emits is DF_1_PIE in DT_FLAGS_1 (confirmed
        #    against this project's own toolchain's `readelf -d` output on
        #    one of its own PIE fixtures: "Flags: NOW PIE") -- set only
        #    for an ET_DYN that's actually meant to be executed directly,
        #    never for an ordinary .so. Its absence on an ET_DYN input is
        #    this method's signal that the input is a genuine shared
        #    object, and the e_entry-based mechanism isn't applicable.
        DF_1_PIE = 0x08000000
        host_is_pie_exe = (elf["e_type"] == "ET_DYN") and bool((_host_dyn_tag_val("DT_FLAGS_1") or 0) & DF_1_PIE)
        host_is_so_input = (elf["e_type"] == "ET_DYN") and not host_is_pie_exe

        # -- generated entrypoint/init-array stub (calls each embedded
        #    dependency's own .init_array constructors, in dependencies-
        #    first order) -- see build_linux_stub's/
        #    build_linux_init_array_stub's own docstrings for exactly what
        #    each does and doesn't do (the dlopen/dlsym hook
        #    `hooked_names` implies isn't implemented yet, for the
        #    EXE-input stub). Only installed when there's actually
        #    something for it to do (`init_array_calls` non-empty) --
        #    e_entry/DT_INIT_ARRAY are otherwise left completely
        #    untouched, exactly as before this task, rather than
        #    installing a stub that would just immediately return/
        #    tail-jump with no other effect. Must run *before* the
        #    combined relocation table just below, since the stub's own
        #    embedded absolute-VA immediates need new R_*_RELATIVE entries
        #    of their own (for ASLR-safety -- see build_linux_stub's
        #    docstring), and that table is built once, from whatever's in
        #    `new_reloc_entries` at that point.
        entry_stub_vaddr = None  # only set in the EXE/PIE-exe branch below
        if init_array_calls and host_is_so_input:
            init_array_stub_vaddr = next_vaddr
            stub_bytes, stub_reloc_offsets = build_linux_init_array_stub(is64=is64, init_calls=init_array_calls)
            new_sections.append((init_array_stub_vaddr, stub_bytes))
            next_vaddr = _align_up(init_array_stub_vaddr + len(stub_bytes), _PAGE)
            for off in stub_reloc_offsets:
                new_reloc_entries.append((init_array_stub_vaddr + off, _read_int(stub_bytes, off, ptr_size)))

            # Inject it as a brand-new, prepended entry in the host's own
            # DT_INIT_ARRAY -- the dynamic linker's normal, built-in
            # mechanism for calling a shared object's own constructors
            # when it's loaded (unlike e_entry, which it never touches
            # for anything but the main executable). Prepended (runs
            # before the host's own pre-existing constructors) to match
            # this method's own "dependencies-first" ordering convention
            # elsewhere. Only the array's *content* needs to grow at a
            # new location (re-pointing the already-existing DT_INIT_ARRAY/
            # DT_INIT_ARRAYSZ tags' own d_val fields in place, same
            # pattern as DT_SYMTAB/DT_STRTAB/DT_RELA growth elsewhere in
            # this method) -- no new *tag* needs adding to the dynamic
            # array itself, unlike B2's DT_NEEDED fix, since every
            # GCC-built .so already carries crtstuff's own DT_INIT_ARRAY/
            # DT_INIT_ARRAYSZ tags (frame_dummy/register_tm_clones) even
            # with no user-written constructor at all. A .so genuinely
            # built with neither tag at all (e.g. assembled by hand, or
            # by a toolchain that omits crtstuff) is explicitly out of
            # scope -- failing loudly here rather than also implementing
            # "add two brand-new dynamic tags from scratch" for a case
            # this project's own fixtures (and, empirically, every real
            # GCC-built .so) never hits.
            host_init_array_vaddr = _host_dyn_tag_val("DT_INIT_ARRAY")
            host_init_array_sz = _host_dyn_tag_val("DT_INIT_ARRAYSZ")
            if host_init_array_vaddr is None or not host_init_array_sz:
                raise ValueError(
                    f"'{self.input_path}' is a shared object with no existing DT_INIT_ARRAY "
                    "of its own; injecting an embedded dependency's constructor call into "
                    "a .so input with no constructors of its own isn't supported"
                )
            old_ia_off = vaddr_to_offset(host_init_array_vaddr, host_init_array_sz)
            old_ia_bytes = bytes(raw[old_ia_off: old_ia_off + host_init_array_sz])
            ptr_fmt = "<Q" if is64 else "<I"
            new_ia_vaddr = next_vaddr
            new_ia_bytes = struct.pack(ptr_fmt, init_array_stub_vaddr) + old_ia_bytes
            new_sections.append((new_ia_vaddr, new_ia_bytes))
            next_vaddr = _align_up(new_ia_vaddr + len(new_ia_bytes), ptr_size)

            # Every slot in the new array -- our own new one AND each of
            # the host's own original entries, now copied to a new
            # location -- is itself a pointer value that needs the
            # image's own load bias applied at load time, exactly like
            # every other absolute-VA this method writes; the host's own
            # original entries already had their OWN R_*_RELATIVE entries
            # for their OLD location (left stale/dead in place, same
            # pattern as every other abandoned old location in this
            # method), which doesn't help them at their NEW one.
            new_reloc_entries.append((new_ia_vaddr, init_array_stub_vaddr))
            for i in range(host_init_array_sz // ptr_size):
                old_val = _read_int(old_ia_bytes, i * ptr_size, ptr_size)
                new_reloc_entries.append((new_ia_vaddr + ptr_size + i * ptr_size, old_val))

            _set_dyn_tag_value(host_dyn, raw, ptr_size, "DT_INIT_ARRAY", new_ia_vaddr)
            _set_dyn_tag_value(host_dyn, raw, ptr_size, "DT_INIT_ARRAYSZ", len(new_ia_bytes))
        elif init_array_calls:
            original_entry_va = elf["e_entry"]
            entry_stub_vaddr = next_vaddr
            stub_bytes, stub_reloc_offsets = build_linux_stub(
                [node.name for node in order],
                set(),
                is64=is64,
                init_calls=init_array_calls,
                original_entry=original_entry_va,
            )
            new_sections.append((entry_stub_vaddr, stub_bytes))
            next_vaddr = _align_up(entry_stub_vaddr + len(stub_bytes), _PAGE)
            for off in stub_reloc_offsets:
                new_reloc_entries.append((entry_stub_vaddr + off, _read_int(stub_bytes, off, ptr_size)))

        # -- combined relocation table -------------------------------------
        if new_reloc_entries or new_glob_dat_entries:
            _, orig_table_offset = host_dyn.get_table_offset(dyn_tag_name)
            orig_size_tag = next(host_dyn.iter_tags(dyn_sz_tag_name), None)
            orig_table_size = orig_size_tag.entry.d_val if orig_size_tag is not None else 0
            orig_table_bytes = bytes(raw[orig_table_offset:orig_table_offset + orig_table_size])

            new_entries_bytes = _pack_relative_entries(new_reloc_entries, is64, dyn_is_rela)
            new_glob_dat_bytes = _pack_glob_dat_entries(new_glob_dat_entries, is64, dyn_is_rela)
            combined_bytes = orig_table_bytes + new_entries_bytes + new_glob_dat_bytes

            reloc_table_vaddr = next_vaddr
            new_sections.append((reloc_table_vaddr, combined_bytes))
            next_vaddr = _align_up(reloc_table_vaddr + len(combined_bytes), _PAGE)

            _set_dyn_tag_value(host_dyn, raw, ptr_size, dyn_tag_name, reloc_table_vaddr)
            _set_dyn_tag_value(host_dyn, raw, ptr_size, dyn_sz_tag_name, len(combined_bytes))

        # -- B2 fix, continued: grow the host's own dynamic array itself
        #    with one new DT_NEEDED entry per name in `extra_needed_names`
        #    (see that variable's own declaration, earlier, for the full
        #    "why") --
        #
        # Must run *after* every other `_set_dyn_tag_value` call above
        # (the external-symbol-forwarding block's DT_SYMTAB/DT_STRTAB/
        # DT_STRSZ/DT_VERSYM, and this combined-relocation-table block's
        # own DT_RELA/DT_RELASZ): those all edit the dynamic array's
        # entries *in place*, at their ORIGINAL file location (via
        # `host_dyn`, parsed once against the original bytes) -- reading
        # that same, by-now-fully-updated array's current byte content
        # here and copying it into a brand new, bigger array (rather than
        # growing it in place, same reasoning as every other table this
        # method grows) preserves every one of those edits. Doing this
        # any earlier would mean a later `_set_dyn_tag_value` call writes
        # into the OLD array's now-abandoned bytes instead of the new one
        # ld.so will actually read via the updated PT_DYNAMIC program
        # header entry below.
        #
        # New entries are spliced in just before the array's own
        # terminating DT_NULL (which must stay last -- every real-world
        # loader stops scanning at the first one), rather than appended
        # past it, mirroring `_remove_needed`'s own "never disturb the
        # DT_NULL terminator's position" rule for the same reason.
        if extra_needed_names:
            dyn_entry_size = 2 * ptr_size
            old_dyn_count = host_dyn.num_tags()
            old_dyn_bytes = bytes(raw[host_dyn["p_offset"]: host_dyn["p_offset"] + old_dyn_count * dyn_entry_size])
            null_index = next(
                (n for n in range(old_dyn_count) if host_dyn.get_tag(n).entry.d_tag == "DT_NULL"), None
            )
            if null_index is None:
                raise ValueError(f"'{self.input_path}': its dynamic section has no DT_NULL terminator")

            # d_val for a DT_NEEDED entry is a plain .dynstr *offset* (not
            # an absolute vaddr), exactly like `needed_name_offsets` was
            # already recorded as.
            needed_fmt = "<QQ" if is64 else "<II"
            new_entries = bytearray()
            for name in extra_needed_names:
                new_entries += struct.pack(needed_fmt, DT_NEEDED, needed_name_offsets[name])

            head = old_dyn_bytes[: null_index * dyn_entry_size]
            tail = old_dyn_bytes[null_index * dyn_entry_size:]
            new_dyn_bytes = bytes(head) + bytes(new_entries) + bytes(tail)

            dynamic_vaddr = next_vaddr
            new_sections.append((dynamic_vaddr, new_dyn_bytes))
            next_vaddr = _align_up(dynamic_vaddr + len(new_dyn_bytes), _PAGE)

            host_dynamic_seg = all_host_segments[host_dynamic_idx]
            dynamic_phdr_update = _pack_phdr(
                is64, PT_DYNAMIC, host_dynamic_seg["p_flags"], dynamic_vaddr - ext_skew, dynamic_vaddr,
                dynamic_vaddr, len(new_dyn_bytes), len(new_dyn_bytes), host_dynamic_seg["p_align"],
            )
        else:
            dynamic_phdr_update = None

        # -- merge embedded dependencies' unwind info into the host's own
        #    .eh_frame_hdr binary-search table --
        #
        # Once a dependency is embedded, it no longer has a PT_GNU_EH_FRAME
        # segment -- or module -- of its own: dl_iterate_phdr (what
        # _Unwind_Find_FDE actually walks to find unwind info for a given
        # PC) only ever sees the *host's* program headers now, so an
        # unwind through a PC that's now inside embedded dependency code
        # only succeeds if the *host's* own .eh_frame_hdr table has an
        # entry covering it. The dependency's FDEs themselves need no
        # changes at all to stay valid (see _parse_eh_frame_hdr's
        # docstring) -- only the table of (initial_loc, fde_addr) pairs
        # that lets the unwinder *find* them needs to grow to list them,
        # each already shifted by its own dependency's `delta` (collected
        # into `collected_eh_entries` during the per-dependency loop
        # above). A brand new, bigger table is built here (same append-
        # and-repoint pattern as everything else in this method) rather
        # than growing the existing one in place, and the host's *existing*
        # PT_GNU_EH_FRAME program-header entry is overwritten in place to
        # point at it -- unlike the phdr-array-growth case further down,
        # this only ever *edits* an already-existing entry, never adds a
        # new one, so it's needed in both the fixed_base_segments and
        # non-fixed_base_segments branches below alike.
        eh_hdr_update: Optional[bytes] = None
        if collected_eh_entries:
            if host_gnu_eh_frame_idx is None:
                raise ValueError(
                    f"'{self.input_path}' has no PT_GNU_EH_FRAME segment to merge "
                    "an embedded dependency's unwind info into"
                )
            host_eh_hdr_seg = all_host_segments[host_gnu_eh_frame_idx]
            host_hdr_vaddr = host_eh_hdr_seg["p_vaddr"]
            host_hdr_size = host_eh_hdr_seg["p_filesz"]
            host_hdr_file_off = vaddr_to_offset(host_hdr_vaddr, host_hdr_size)
            host_hdr_bytes = bytes(raw[host_hdr_file_off: host_hdr_file_off + host_hdr_size])
            host_eh_entries = _parse_eh_frame_hdr(host_hdr_bytes, host_hdr_vaddr)
            # The host's own .eh_frame start never moves (nothing in this
            # method ever relocates the host's *own*, pre-existing
            # content) -- re-derive it from the host's own hdr rather than
            # hardcoding anything, and keep using it as the regenerated
            # hdr's own eh_frame_ptr field too (that field is otherwise
            # unused by the dl_iterate_phdr/hdr-table-based unwind path
            # this relies on; see _build_eh_frame_hdr).
            eh_frame_ptr_enc = host_hdr_bytes[1]
            if eh_frame_ptr_enc == _DW_EH_PE_OMIT:
                raise ValueError(
                    f"'{self.input_path}': its .eh_frame_hdr has no eh_frame_ptr field"
                )
            host_eh_frame_vaddr = _decode_eh_pe_sdata4(
                eh_frame_ptr_enc, struct.unpack_from("<i", host_hdr_bytes, 4)[0], host_hdr_vaddr + 4, host_hdr_vaddr
            )

            combined_entries = sorted(host_eh_entries + collected_eh_entries, key=lambda e: e[0])
            new_hdr_vaddr = next_vaddr
            new_hdr_bytes = _build_eh_frame_hdr(new_hdr_vaddr, host_eh_frame_vaddr, combined_entries)
            new_sections.append((new_hdr_vaddr, new_hdr_bytes))
            next_vaddr = _align_up(new_hdr_vaddr + len(new_hdr_bytes), _PAGE)

            eh_hdr_update = _pack_phdr(
                is64, PT_GNU_EH_FRAME, host_eh_hdr_seg["p_flags"], new_hdr_vaddr - ext_skew, new_hdr_vaddr,
                new_hdr_vaddr, len(new_hdr_bytes), len(new_hdr_bytes), host_eh_hdr_seg["p_align"],
            )

        # -- reserve room for a grown program header array, if any fixed-
        #    base dependency needs its own new PT_LOAD entry (see the large
        #    comment above, by `fixed_base_segments`, for why those can't
        #    just extend `ext` like everything above this point does) --
        #    placed as one more piece of `ext`'s own extension, same as the
        #    relocation table just above, so it shares the extension's skew
        #    and keeps AT_PHDR's computation correct even though e_phoff is
        #    about to move (empirically confirmed via LD_SHOW_AUXV=1
        #    against a real host while building this mechanism -- see the
        #    comment further down, by `data_start_vaddr`, for exactly what
        #    that showed and how it corrects this file's own older claim
        #    about how the kernel derives AT_PHDR). Its *content*
        #    can't be filled in yet -- it needs to record `ext`'s own
        #    final, grown p_filesz/p_memsz, which isn't known until after
        #    this whole extension (including this array's own reserved
        #    bytes) is actually laid out below -- so a same-sized
        #    zero-filled placeholder goes here for now and gets overwritten
        #    in place, once that size is known, right before this method
        #    returns.
        # A brand-new PT_TLS entry (see `new_tls_entry`'s own declaration)
        # needs exactly the same program-header-array growth as a
        # fixed-base dependency's own new PT_LOAD entry does -- one more
        # slot in the grown array, reserved the same way -- even though,
        # unlike `fixed_base_segments`, its own *data* never needs a
        # separately-placed blob (see further down, where the array
        # itself is actually built, for where that one difference shows
        # up).
        _extra_phdr_entries = len(fixed_base_segments) + (1 if new_tls_entry is not None else 0)
        if _extra_phdr_entries:
            old_phnum = elf.num_segments()
            new_phnum = old_phnum + _extra_phdr_entries
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
        # is risky: AT_PHDR's value is derived from e_phoff through a
        # translation that depends on *some* segment's own p_vaddr/
        # p_offset skew. An earlier version of this comment claimed that
        # skew always comes from the *first* PT_LOAD segment specifically,
        # with the kernel never re-deriving one per segment -- empirical
        # testing while building the fixed-base mechanism further up in
        # this method (LD_SHOW_AUXV=1 against a real host) contradicts
        # that: `ext` (the segment e_phoff gets moved into, there) does
        # *not* share the first PT_LOAD segment's skew for that host, yet
        # AT_PHDR still came out correct relative to *ext's own* skew. So
        # the precise mechanism this comment used to assert isn't right --
        # what's still true, and still the reason to prefer extending an
        # existing segment over adding a new one, is that *some*
        # segment-specific skew is involved, and there's no particular
        # reason a brand new segment, placed at a freshly chosen vaddr/
        # offset pair, would happen to share whatever skew that
        # translation actually keys off. Moving e_phoff into one without
        # knowing that risks AT_PHDR landing on a bogus address the moment
        # it happens. glibc's `_dl_aux_init`/`__libc_start_main` walk that
        # (potentially garbage) phdr array looking for PT_TLS/
        # PT_GNU_RELRO/PT_GNU_STACK for the main executable -- silently
        # skipping TLS/RELRO/stack-flag setup, or segfaulting outright if
        # the bogus address isn't even mapped.
        #
        # Extending an *existing* segment in place sidesteps this
        # completely: e_phoff/e_phnum (and every other segment's entry)
        # stay byte-for-byte untouched, so AT_PHDR's computation doesn't
        # change at all. Growing `ext`'s p_filesz/p_memsz all the way from
        # its own original p_offset up to the new end of file is always
        # safe *placement*-wise (nothing one of our new blobs writes can
        # collide with some other segment's bytes), *as long as* `ext` is
        # confirmed above to also be the last segment's content in the
        # file -- but it is NOT safe *content*-wise to leave whatever was
        # already sitting past `ext`'s own original filesz unchanged: an
        # earlier version of this comment claimed those bytes (e.g. a
        # stale section header table/.comment/.note content -- normal
        # for any unstripped-of-everything binary) were "inert... that
        # nothing else maps", which was true only in the *original* file,
        # where `ext`'s filesz genuinely stopped short of them. The
        # moment this method grows `ext`'s filesz to cover that same
        # span, the kernel DOES map it -- as real, non-zero file content,
        # not the zero-filled BSS the ABI promises for anything between
        # p_filesz and p_memsz. Confirmed for real (a `bash`/
        # `libtinfo.so.6` embed on real Linux, WSL) before this fix: a
        # handful of bash's own ordinary BSS globals happened to fall
        # inside that exact span (p_filesz..p_memsz, with real leftover
        # trailing bytes already occupying the first ~2KB of it on a
        # real, not-fully-stripped `/bin/bash`) and came up initialized
        # to that garbage instead of zero, crashing deep inside bash's
        # own `parse_and_execute` on first use. Zeroing that whole span
        # -- from `ext`'s own original filesz end through whatever the
        # file's actual length already is -- before growing filesz over
        # it restores the zero-BSS guarantee for it; losing those inert
        # bytes' own original content costs nothing, since nothing in
        # the original file's own PT_LOAD segments ever mapped them
        # either.
        ext_filesz_end_offset = ext["p_offset"] + ext["p_filesz"]
        if ext_filesz_end_offset < len(raw):
            raw[ext_filesz_end_offset:len(raw)] = b"\x00" * (len(raw) - ext_filesz_end_offset)

        data_start_vaddr = new_sections[0][0]
        data_start_offset = data_start_vaddr - ext_skew
        if data_start_offset < len(raw):
            raise ValueError("internal error: new ELF content would overlap existing file content")
        raw.extend(b"\x00" * (data_start_offset - len(raw)))

        # Now that `raw` covers `ext`'s whole original memsz as real file
        # bytes (the backfill just above) -- not just its original,
        # possibly-smaller filesz -- any deferred R_*_COPY write's target
        # (validated above to be within `ext`) is guaranteed in range;
        # see `deferred_copy_writes`'s own declaration for why this can't
        # happen any earlier.
        for copy_target_vaddr, copy_src in deferred_copy_writes:
            copy_target_off = copy_target_vaddr - ext_skew
            raw[copy_target_off:copy_target_off + len(copy_src)] = copy_src

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

        # `reserved_ranges` (seeded above, before the per-dependency loop)
        # only ever checked a fixed-base node's reservation against the
        # host's own *original* PT_LOAD ranges and other fixed-base
        # nodes' reservations -- never against `ext`, since fixed-base
        # nodes don't participate in `next_vaddr`'s progression and
        # `ext`'s own eventual grown extent (every ordinary dependency's
        # blob, the combined relocation table, the phdr-array placeholder
        # -- everything laid out just above) isn't known until right now,
        # well after every fixed-base node already passed its own check.
        # A fixed-base reservation that looked clear of the host at the
        # time could still end up virtually overlapping wherever `ext`
        # actually grew to by the time this method is done -- the same
        # silent-overlap anti-goal `reserved_ranges`'s own checks exist to
        # catch everywhere else, just caught late instead of never (same
        # class of gap as pe_embedder's alignment-gap-filler fix).
        if fixed_base_segments:
            ext_final_lo, ext_final_hi = ext["p_vaddr"], ext["p_vaddr"] + new_filesz
            for X, blob in fixed_base_segments:
                lo, hi = X, X + len(blob)
                if lo < ext_final_hi and ext_final_lo < hi:
                    raise ValueError(
                        f"base address conflict at {hex(max(lo, ext_final_lo))} between a "
                        f"fixed-base dependency (base {hex(X)}) and the host's own extended "
                        f"image (grown to {hex(ext_final_lo)}-{hex(ext_final_hi)})"
                    )

        if not _extra_phdr_entries:
            entry_off = elf["e_phoff"] + ext_idx * elf["e_phentsize"]
            raw[entry_off:entry_off + len(extended_entry)] = extended_entry
            if eh_hdr_update is not None:
                eh_entry_off = elf["e_phoff"] + host_gnu_eh_frame_idx * elf["e_phentsize"]
                raw[eh_entry_off:eh_entry_off + len(eh_hdr_update)] = eh_hdr_update
            if dynamic_phdr_update is not None:
                dyn_entry_off = elf["e_phoff"] + host_dynamic_idx * elf["e_phentsize"]
                raw[dyn_entry_off:dyn_entry_off + len(dynamic_phdr_update)] = dynamic_phdr_update
        else:
            # Grow the program header array itself: copy the *original*
            # array byte-for-byte (still untouched, at its original
            # location -- only `ext`'s own entry within the copy gets
            # updated), append one brand-new PT_LOAD entry per fixed-base
            # dependency, and write the result into the placeholder
            # reserved for it above (inside `ext`'s own just-finished
            # extension, so it shares whatever segment-specific skew
            # AT_PHDR's derivation actually keys off -- see the comment
            # by that placeholder for what that is and why it's what
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
            if eh_hdr_update is not None:
                new_array[host_gnu_eh_frame_idx * entsize:(host_gnu_eh_frame_idx + 1) * entsize] = eh_hdr_update
            if dynamic_phdr_update is not None:
                new_array[host_dynamic_idx * entsize:(host_dynamic_idx + 1) * entsize] = dynamic_phdr_update

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

            # The new PT_TLS entry (see `new_tls_entry`'s own
            # declaration): unlike `fixed_base_segments` just above, its
            # data is never appended here -- it's already physically
            # present, as part of its owning dependency's own ordinary
            # blob, somewhere inside `ext`'s own just-finished extension
            # (that dependency was never a fixed-base node -- see where
            # `new_tls_entry` is set, which raises instead for that case
            # -- so its blob went through the ordinary `new_sections`
            # path, not `fixed_base_segments`). Only a descriptor,
            # pointing at that already-placed data, is needed: its own
            # vaddr shifted by the same `tls_X - tls_dep_base` delta
            # every other part of that dependency's blob already got,
            # and a file offset keeping `ext_skew` (same skew as every
            # other entry inside `ext`'s extension, including this very
            # placeholder) so AT_PHDR's computation stays correct.
            if new_tls_entry is not None:
                tls_X, tls_dep_base, dep_tls_seg, _tls_dep_name = new_tls_entry
                tls_vaddr = tls_X + (dep_tls_seg["p_vaddr"] - tls_dep_base)
                tls_file_offset = tls_vaddr - ext_skew
                new_array += _pack_phdr(
                    is64, PT_TLS, dep_tls_seg["p_flags"], tls_file_offset, tls_vaddr, tls_vaddr,
                    dep_tls_seg["p_filesz"], dep_tls_seg["p_memsz"], dep_tls_seg["p_align"],
                )

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
            _write_int(raw, e_phnum_off, 2, old_phnum + _extra_phdr_entries)

        # e_entry is overwritten to point at the generated stub only when
        # one was actually built as an EXE/PIE-exe entrypoint stub
        # (`entry_stub_vaddr` set above, by the init_array_calls-gated
        # block's EXE/PIE-exe branch); otherwise -- including the B6-ELF
        # .so-input case, where the init-array stub was installed via
        # DT_INIT_ARRAY instead, never touching e_entry at all -- it's
        # left completely untouched. e_entry is a fixed, ptr-sized field
        # immediately following e_ident/e_type/e_machine/e_version in
        # every ELF32/ELF64 header alike.
        if entry_stub_vaddr is not None:
            e_entry_off = 16 + 2 + 2 + 4
            _write_int(raw, e_entry_off, ptr_size, entry_stub_vaddr)

        self.output_path.write_bytes(bytes(raw))
        # Moderate final-review finding: write_bytes() alone creates the
        # output file with the process's own default (umask-governed)
        # permissions, losing the input's executable bit -- every test in
        # this suite has had to work around this by calling
        # `out.chmod(0o755)` itself right after `embed()` returns,
        # strongly suggesting this was never actually handled here.
        # Preserve the input's own full permission bits (not just force
        # a fixed 0o755) so an input with unusual permissions (e.g. a
        # setuid/setgid bit, or a more restrictive executable-only mode)
        # round-trips the same way, matching the CLI's documented
        # "produces a working replacement for the original binary" goal.
        shutil.copymode(self.input_path, self.output_path)
