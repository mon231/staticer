import platform
import struct
import subprocess
from pathlib import Path
from typing import Optional

import pytest
from elftools.elf.elffile import ELFFile

from conftest import FIXTURES, build_exe, build_shared_lib

from staticer.elf_embedder import ElfEmbedder, R_RELATIVE

pytestmark = pytest.mark.skipif(platform.system() != "Linux", reason="ELF embedding is Linux-only")

# e_type lives at a fixed byte offset in the ELF header, identical for
# ELFCLASS32 and ELFCLASS64 (it comes right after the 16-byte e_ident).
_E_TYPE_OFFSET = 16
_ET_EXEC = 2
_ET_DYN = 3

# A fixed vaddr comfortably clear of every bitness/compiler combination
# this suite's hosts load at on a conventional x86 Linux toolchain (a
# 32-bit -no-pie exe starts around 0x08048000, a 64-bit one around
# 0x400000 -- both confirmed against this project's own WSL toolchain
# while building this fixture).
_FIXED_BASE = 0x20000000

_PAGE = 0x1000


def _align_up(value: int, alignment: int = _PAGE) -> int:
    return (value + alignment - 1) // alignment * alignment


def _force_fixed_base(so_path: Path, *, untrack_func: Optional[str] = None, base: int = _FIXED_BASE) -> None:
    """Makes `so_path` -- an ordinary PIC .so, already linked at a chosen
    preferred base via `-Wl,-Ttext-segment=<base>` so every address it
    carries (PT_LOAD p_vaddr, .dynsym st_value, .rela.dyn/.rel.dyn
    r_offset, every DT_* tag) is self-consistently computed by the real
    linker -- look like a genuinely fixed-base/non-PIC dependency to
    ElfEmbedder:

      1. Flips e_type from ET_DYN to ET_EXEC: the actual signal
         ElfEmbedder's fixed-base/base-address-reservation path keys off
         (not "zero relocations" -- see elf_embedder.py's `embed()`
         docstring, by `fixed_base_segments`, for why that signal is
         ambiguous in ELF: a *real* `-fno-pic -shared` build, confirmed
         against this project's own toolchain, still gets at least one
         R_*_RELATIVE entry for every absolute self-pointer, because any
         `.so` must support loading away from its own preferred base --
         only a genuine ET_EXEC skips that tracking entirely). There's no
         compiler/linker flag combination that reliably produces a
         genuinely fixed-base *shared object* to build this fixture from
         directly, so this flips the one field ElfEmbedder actually
         checks instead -- mirroring `conftest.py`'s own
         `_strip_pe_relocations` helper's spirit (synthesize the exact
         condition under test via direct binary surgery) but targeting
         ELF's real signal.

      2. If `untrack_func` is given, additionally neuters (zeroes out --
         the same R_*_NONE idiom elf_embedder.py itself uses to
         neutralize a relocation entry in place) every R_*_RELATIVE entry
         targeting somewhere inside that exported function's own byte
         range. This simulates the one real difference a genuinely
         fixed-base dependency has that this helper's e_type flip alone
         doesn't: an absolute address reference baked directly into an
         instruction with *no* relocation tracking it at all (confirmed
         against this project's own toolchain: a 32-bit `-fno-pic`
         build's internal data accesses compile to exactly this, with
         zero corresponding relocation entries, when linked as a plain
         ET_EXEC -- but still get an R_386_RELATIVE entry when linked as
         a `.so`, regardless of PIC-ness, for the reason above). Without
         this, there would be nothing for ElfEmbedder's fixed-base path
         to get right that its ordinary reloc-bearing path wouldn't
         already get right by accident -- a fully `.rela.dyn`/`.rel.dyn`-
         tracked `.so` is, underneath the lying e_type, still completely
         delta-relocatable the normal way. See
         `test_embed_non_pic_so_without_relocs`'s own docstring for why
         this only actually bites on 32-bit.
    """
    data = bytearray(so_path.read_bytes())
    e_type = struct.unpack_from("<H", data, _E_TYPE_OFFSET)[0]
    assert e_type == _ET_DYN, f"expected a PIC .so (ET_DYN) to start from; got e_type={e_type}"

    if untrack_func is not None:
        with open(so_path, "rb") as f:
            elf = ELFFile(f)
            dyn = next(elf.iter_segments(type="PT_DYNAMIC"))
            sym = None
            for i in range(dyn.num_symbols()):
                candidate = dyn.get_symbol(i)
                if candidate.name == untrack_func:
                    sym = candidate
                    break
            assert sym is not None, f"{untrack_func!r} not found in {so_path}'s dynamic symbol table"
            lo, hi = sym["st_value"], sym["st_value"] + sym["st_size"]

            tables = dyn.get_relocation_tables()
            table = tables.get("RELA") or tables.get("REL")
            entry_size = table.entry_size
            _, table_file_offset = dyn.get_table_offset("DT_RELA" if table.is_RELA() else "DT_REL")
            targets = [
                table_file_offset + i * entry_size
                for i, reloc in enumerate(table.iter_relocations())
                if reloc["r_info_type"] == R_RELATIVE and lo <= reloc["r_offset"] < hi
            ]
        for off in targets:
            data[off:off + entry_size] = b"\x00" * entry_size

    struct.pack_into("<H", data, _E_TYPE_OFFSET, _ET_EXEC)
    so_path.write_bytes(bytes(data))


def _build_rebased_so(
    tmp_path: Path, source: Path, name: str, *, bits: int, pic: bool = True, base: int = _FIXED_BASE,
) -> Path:
    """An ordinary .so, linked at preferred base `base` -- still ET_DYN
    (not yet `_force_fixed_base`-flipped): a host must link against
    *this*, before the dependency gets flipped to ET_EXEC, since a real
    linker refuses to use an ET_EXEC file as link input at all (confirmed
    against this project's own toolchain) -- DT_NEEDED only records the
    dependency's *name*, so flipping it in place after the host is
    already built doesn't disturb that link.

    `pic` (codegen, independent of e_type) matters only together with
    `_force_fixed_base`'s `untrack_func`: `-fPIC` codegen (the default
    here) addresses even an *internal* global through an indirect GOT
    slot -- itself a tracked, correctly delta-shiftable R_*_RELATIVE
    target elsewhere in the file, not inside the referencing function's
    own byte range at all -- so neutering only the entries *inside* that
    function's range leaves this GOT indirection intact and the access
    keeps working even at the wrong address. Reproducing the actual
    untracked-reference condition needs `-fno-pic` codegen instead (a
    real non-PIC/fixed-base dependency's own compilation mode), which
    compiles an internal global access as a bare absolute-address
    instruction with no indirection to go through.
    """
    return build_shared_lib(
        tmp_path, source, name, pic=pic, bits=bits,
        extra_flags=[f"-Wl,-Ttext-segment={hex(base)}"],
    )


@pytest.mark.parametrize("bits", [32, 64])
def test_embed_non_pic_so_without_relocs(tmp_path, c_compiler, bits):
    """The dependency is `lib_nopic_global.c` (not the suite's usual
    `lib.c`) because `lib.c`'s `lib_value` is a bare `return 42` with no
    address references at all -- embedding it via the *wrong* mechanism
    (the ordinary reloc-bearing path, which would place it at a freshly
    allocated address rather than its own declared fixed one) would still
    happen to produce a correct result, since there'd be nothing for a
    wrong placement to get wrong. `lib_nopic_global.c`'s internal-counter
    access gives `_force_fixed_base`'s `untrack_func` an actual untracked
    absolute reference to misplace if embed() picks the wrong address for
    it -- confirmed by running this exact scenario against this project's
    *pre-fix* `elf_embedder.py` on real Linux (WSL): it segfaults deep
    inside the dependency's own code, since the embedded blob lands
    wherever the ordinary path's address allocator happens to put it, not
    at the one address its untracked reference actually assumes.

    32-bit-only would arguably be enough (x86-64's RIP-relative addressing
    makes this *particular* bug unreachable there -- same
    PIC/architecture-addressing-mode asymmetry `elf_embedder.py`'s own
    docstring discusses for a different reason, around calling a
    dependency's crtstuff-injected init functions): on 64-bit,
    `_force_fixed_base`'s neutering step finds nothing to neuter (the
    counter access needs no relocation there in the first place), so that
    half of the test is a no-op. It's still parametrized over both, to
    exercise the rest of the mechanism (the new standalone PT_LOAD
    segment, the grown program header array, AT_PHDR) on both bitnesses
    the way every other test in this suite does.

    The host is deliberately built non-PIE (`pic=False`): a fixed-base
    dependency's untracked references are only correct if the *combined*
    image's own load address never shifts as a whole (see `embed()`'s
    own docstring, by `fixed_base_segments`, for the full reasoning) --
    which is only guaranteed for a non-PIE host (no ASLR at all for the
    main image), not a PIE one.

    `-fno-plt` on the host works around something unrelated this test
    happened to surface: embed()'s host GOT/PLT patch loop zeroing out a
    *PLT* (JMPREL) relocation entry in place makes glibc's ld.so abort
    with "unexpected PLT reloc type" for a non-PIE host -- reproduced
    with a completely ordinary, unmodified PIC dependency (nothing to do
    with this task's fixed-base logic at all; only the non-PIE host
    matters). `-fno-plt` routes the host's call through the regular GOT
    instead of the PLT, which embed() already zeroes out successfully
    elsewhere in this same suite, sidestepping it. Worth a look for
    whichever task next touches that patch loop; out of scope here.
    """
    # pic=False: -fno-pic codegen, needed for the counter access to
    # compile as an untracked absolute reference -- see
    # `_build_rebased_so`'s own docstring on its `pic` parameter.
    so = _build_rebased_so(tmp_path, FIXTURES / "lib_nopic_global.c", "lib.so", bits=bits, pic=False)
    # Link the host against the still-ET_DYN .so first (see
    # `_build_rebased_so`'s own docstring for why), *then* flip it.
    exe = build_exe(tmp_path, FIXTURES / "main.c", "main", [so], pic=False, bits=bits, extra_flags=["-fno-plt"])
    _force_fixed_base(so, untrack_func="lib_value")
    out = tmp_path / "static"

    ElfEmbedder(exe, out, exclude=set(), lib_dir=tmp_path).embed()
    out.chmod(0o755)

    result = subprocess.run([str(out)], capture_output=True)
    assert result.returncode == 42


def test_fixed_base_dependency_into_pie_host_fails_loudly(tmp_path, c_compiler):
    """Moderate final-review finding: unlike PE (which can clear
    DYNAMIC_BASE/HIGH_ENTROPY_VA on its own output to neutralize ASLR
    for a fixed-base DLL dependency), ELF has no per-image "disable
    ASLR" flag embed() could set on its own output -- PIE-ness is baked
    into e_type, not a flag this module can flip afterward. A fixed-base
    dependency's own untracked absolute references only stay correct if
    the combined image's load address never shifts as a whole, which
    ASLR (the default for any PIE/ET_DYN host) breaks. embed() must fail
    loudly here rather than silently producing an output that corrupts
    itself the moment ASLR picks a non-zero load address."""
    so = _build_rebased_so(tmp_path, FIXTURES / "lib.c", "lib.so", bits=64)
    exe = build_exe(tmp_path, FIXTURES / "main.c", "main", [so], pic=True, bits=64)
    _force_fixed_base(so)

    with pytest.raises(ValueError, match="PIE/ET_DYN"):
        ElfEmbedder(exe, tmp_path / "out", exclude=set(), lib_dir=tmp_path).embed()


def test_base_address_conflict_fails_loudly(tmp_path, c_compiler):
    # Two independent fixed-base dependencies, both left at the *same*
    # preferred base (`_build_fixed_base_so`'s default) -- guaranteed to
    # overlap regardless of their own (differing) sizes, since both
    # ranges start at the exact same address.
    liba = _build_rebased_so(tmp_path, FIXTURES / "lib.c", "liba.so", bits=64)
    libb = _build_rebased_so(tmp_path, FIXTURES / "lib_b.c", "libb.so", bits=64)
    exe = build_exe(tmp_path, FIXTURES / "main_two_libs.c", "main_two_libs", [liba, libb], pic=True, bits=64)
    _force_fixed_base(liba)
    _force_fixed_base(libb)

    with pytest.raises(ValueError):
        ElfEmbedder(exe, tmp_path / "out", set(), lib_dir=tmp_path).embed()


def test_base_address_conflict_inside_ext_growth_fails_loudly(tmp_path, c_compiler):
    """Regression test for a gap where a fixed-base dependency's
    reservation was only ever checked (in `embed()`'s per-dependency
    loop) against the host's *original* PT_LOAD ranges and other
    fixed-base dependencies' own reservations -- never against `ext`
    (the host's own extended PT_LOAD segment)'s eventual *grown* extent,
    which isn't known until after every ordinary dependency's blob, the
    combined relocation table, and the phdr-array placeholder are all
    laid out (fixed-base nodes don't participate in `next_vaddr`'s
    progression, so there was nothing tracking how far that growth
    reaches by the time a fixed-base node's own check ran). A reservation
    placed just past the host's *original* end passed that early check
    even though it ends up virtually inside `ext`'s own final range once
    a large enough ordinary dependency pushes `ext` that far -- exactly
    the silent-overlap anti-goal `reserved_ranges` exists to catch
    everywhere else, just missed for this specific case (the same class
    of gap as pe_embedder's own alignment-gap-filler fix for the PE
    side).

    `lib_big.c`'s 2MB `big_buffer` forces `ext` to grow by a couple of
    megabytes once embedded; the fixed-base dependency below is placed
    only one page past the host's own *original* vaddr range -- clear of
    the host at the time it's checked, but comfortably inside where
    `ext` actually grows to once the big dependency's blob (and the
    phdr-array placeholder the fixed-base dependency itself requires) are
    both appended.
    """
    big_so = build_shared_lib(tmp_path, FIXTURES / "lib_big.c", "lib_big.so", pic=True, bits=64)
    # Built at the module default base first, just to get *some* valid
    # ET_DYN .so for the host to link against -- see
    # `_build_rebased_so`'s own docstring for why the real base doesn't
    # matter until after the host exists (DT_NEEDED only records a name).
    small_so = _build_rebased_so(tmp_path, FIXTURES / "lib_b.c", "lib_b.so", bits=64)
    exe = build_exe(
        tmp_path, FIXTURES / "main_two_libs.c", "main_two_libs", [big_so, small_so], pic=True, bits=64
    )

    with open(exe, "rb") as f:
        host_end = max(seg["p_vaddr"] + seg["p_memsz"] for seg in ELFFile(f).iter_segments(type="PT_LOAD"))
    conflict_base = _align_up(host_end) + _PAGE

    # Rebuild the *same* lib_b.so, now at `conflict_base` -- overwriting
    # it in place doesn't disturb the host's already-built DT_NEEDED
    # entry for "lib_b.so" (just a name, resolved by `resolve_elf` at
    # embed() time, same as every other fixture in this file relies on).
    small_so = _build_rebased_so(tmp_path, FIXTURES / "lib_b.c", "lib_b.so", bits=64, base=conflict_base)
    _force_fixed_base(small_so)

    with pytest.raises(ValueError):
        ElfEmbedder(exe, tmp_path / "out", set(), lib_dir=tmp_path).embed()
