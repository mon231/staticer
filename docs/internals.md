# Internals: binary formats, patching, and rebuild mechanics

A consolidated technical reference for everything this project learned
about PE and ELF internals while building `staticer` — gathered from
real investigation (disassembly, `readelf`/`pefile` introspection,
strace, real toolchain experiments), not just reading the spec. If
you're extending `staticer`, debugging a new real-world binary it
chokes on, or just want to understand why the embedder code looks the
way it does, this page is for you.

## PE (Windows)

### Sections, RVAs, and relocations

A PE image is a set of sections, each with a `VirtualAddress` (RVA,
relative to the image's own `ImageBase`), a `VirtualSize`, and a
`SizeOfRawData`/`PointerToRawData` pair describing its on-disk
representation. Embedding a dependency means appending its own sections
as new sections in the host, at a new base address (either the host's
own next free RVA, or the dependency's declared preferred address if it
has no relocations — see
[Fixed-base / non-relocatable dependencies](features.md#fixed-base-non-relocatable-dependencies)
in Features).

The PE loader requires **zero-gap RVA coverage** between sections — if a
dependency's declared base is far from the host's existing sections, the
gap must be bridged with a real (even if zero-file-backed) filler
section, or the loader rejects the image. `staticer` discovered this the
hard way while implementing fixed-base embedding: a naive
"just place the dependency wherever it wants" approach produced an image
that `LoadLibraryExW` refused to load, with no useful error — only
visible by actually attempting to load the output, not from `pefile`'s
own round-trip (which doesn't validate RVA contiguity).

**Base relocations** (`.reloc`, `IMAGE_REL_BASED_DIR64`/`HIGHLOW` entries)
are how a PE image can be moved to a different base address: every
absolute-VA field a compiler/linker emits that isn't position-independent
gets a relocation entry, and the loader (or, in `staticer`'s case, the
embedder itself) patches each one by adding the new base's delta.
**This covers far more than code addresses** — it includes every field of
an `IMAGE_TLS_DIRECTORY64` struct (see below), every entry in a TLS
callback array, forwarded-export thunks, and more. `staticer` relies on
this directly: merging a TLS directory into a host turned out to need
almost no new relocation-handling code, because the dependency's own
linker had already emitted real base relocations for the TLS
directory's struct fields and every callback-array entry — confirmed by
cross-referencing each field's RVA against the dependency's own
`IMAGE_DIRECTORY_ENTRY_BASERELOC` entries, not assumed.

### Import directory: ILT vs IAT — a real bug found the hard way

A PE's Import Directory has **two parallel thunk arrays** for each
imported DLL: the **Import Lookup Table (ILT)**, which records what to
*resolve* (by name or ordinal), and the **Import Address Table (IAT)**,
which is where *compiled call sites* actually read the resolved address
from at runtime. `pefile`'s `imp.thunk_rva` refers to the ILT slot;
`imp.address` is the IAT slot. **These are different arrays** — patching
the wrong one compiles clean, round-trips through `pefile` clean, and
then crashes (or silently calls the wrong address) the moment the
embedded code actually runs. This was found only by disassembling the
compiled output and confirming call sites read through `FirstThunk`
(IAT), not `OriginalFirstThunk` (ILT) — a classic "looks correct in the
parser, wrong at the byte level" bug.

### Exception/unwind directory (`.pdata`/`.xdata`)

x64 PE binaries carry a `RUNTIME_FUNCTION` table (the exception
directory, `IMAGE_DIRECTORY_ENTRY_EXCEPTION`) mapping address ranges to
`UNWIND_INFO` structs, which the OS unwinder walks to run destructors and
`catch` handlers during exception propagation. Merging a dependency's
own exception directory into the host means: shift every
`RUNTIME_FUNCTION` entry's start/end RVA and its `UNWIND_INFO` RVA to the
relocated address, then merge the combined table **sorted by start
RVA** (required by `RtlLookupFunctionEntry`'s binary search — an
unsorted merged table silently breaks unwinding for entries after the
first out-of-order one).

**A real, still-open limit**: ordinary cross-boundary unwinding (an
exception thrown in the host, propagating through an embedded
dependency's frame that doesn't itself handle it) works correctly and is
tested. A module that both **throws and catches** a C++ exception
*entirely within itself*, once embedded, can still crash under MSVC
specifically — `__CxxFrameHandler4`'s compact unwind-state tables encode
further undocumented, version-specific, bit-packed data beyond the
documented `RUNTIME_FUNCTION`/`UNWIND_INFO` fields, and decoding/patching
only the documented trailing exception-handler RVA leaves that extra
data pointing at garbage. This was confirmed by direct byte inspection
(the decoded "RVA" pointed outside the module's own size entirely) and
is a genuine limit of the public unwind ABI, not an oversight — the
GCC/Itanium model (used by MinGW) doesn't have this problem, since its
LSDA format is simpler and self-relative.

### TLS directory (`IMAGE_TLS_DIRECTORY64`)

```
StartAddressOfRawData   VA   -- start of the module's TLS data template
EndAddressOfRawData     VA   -- end of the template
AddressOfIndex          VA   -- points at a DWORD; the LOADER writes the
                               assigned _tls_index here at load time
AddressOfCallBacks       VA   -- points at a null-terminated array of
                               PIMAGE_TLS_CALLBACK VAs, or 0
SizeOfZeroFill          DWORD
Characteristics         DWORD
```

Implicit thread-local storage (`__declspec(thread)`/`thread_local`)
works through this directory: the loader assigns each module **one**
`_tls_index` (a small integer), and compiled code reads thread-local
variables via `TEB.ThreadLocalStoragePointer[index] + offset` — this is
a genuinely **different mechanism** from the explicit Win32 API
(`TlsAlloc`/`TlsGetValue`/`TlsSetValue`), which manages a completely
separate `TEB.TlsSlots`/`TlsExpansionSlots` array. `staticer` discovered
this the hard way: an early design for merging two TLS directories tried
giving the embedded dependency a fresh slot via `TlsAlloc()` at process
start — it built, ran, and **produced wrong values without crashing**,
because the compiled `__declspec(thread)` access in the dependency's own
code was never reading the slot `TlsAlloc` had allocated. Confirmed by
disassembly, not guessed. The fix: there's only ever one real,
loader-assigned slot per process when everything is combined into one
image, so both the host's and a dependency's TLS data get combined into
one raw-data range (sharing the one real `_tls_index`), and the
dependency's own **compiled TLS-access byte offsets** get located via a
byte-pattern scanner and shifted to match. The pattern search exploits
that the `_tls_index` load is an exact `mov r32,[rip+disp32]` whose
target RVA equals the known index slot's address — effectively
zero-false-positive — but the immediately-following per-thread-block
access is found via a bounded forward scan for the first matching
instruction shape, which is sound for the verified compiler's exact
codegen and would need re-verification (not blind trust) for a different
compiler or optimization level.

A module's TLS data can also carry a non-null **callback array** — real
functions the loader calls on thread attach/detach for that module's TLS.
A naive implementation that only handles the callback-free case will
work on every toy fixture and then fail on real third-party binaries —
`frida-gadget` (used as this project's own flagship real-world test) has
exactly 3 real callbacks, confirmed by walking its actual
`AddressOfCallBacks` array.

### DllCharacteristics / ASLR

Embedding a fixed-base (non-relocatable) dependency means the whole
output image can no longer safely be relocated as a whole — the
dependency's own untracked absolute references are only valid at its
declared preferred address. `IMAGE_OPTIONAL_HEADER.DllCharacteristics`
must have `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` (`0x0040`) and
`IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA` (`0x0020`) cleared in this
case, or ASLR will relocate the whole image and silently corrupt the
fixed-base dependency's own internal references.

### DllMain calling convention and process-attach discrimination

`DllMain(HINSTANCE hinst, DWORD fdwReason, LPVOID reserved)` — the second
parameter distinguishes `DLL_PROCESS_ATTACH` (1), `DLL_THREAD_ATTACH`
(2), `DLL_THREAD_DETACH` (3), `DLL_PROCESS_DETACH` (0). On x64 fastcall
it's in `RDX`/`EDX`; on x86 `__stdcall` it's at `[esp+8]` (after the
return address and `hinstDLL`). A generated entrypoint stub that needs
to run an embedded dependency's init code **exactly once**, not on every
thread event, must check this value before running that code — getting
it wrong (running init on every attach/detach) is invisible in a
single-threaded test and only shows up with real multi-threaded
execution.

### A real, still-open gap: `FreeLibrary` before process exit

Because `DLL_PROCESS_DETACH` is deliberately never delivered to an
embedded dependency (it would require unwinding the same init-ordering
machinery in reverse, and real-world need for it is low), a dependency
built against a dynamically-linked CRT registers process-wide TLS/FLS
bookkeeping during its own (real, unmodified) CRT-startup code at
process-attach — bookkeeping nothing ever tears down. Calling
`FreeLibrary` on a `staticer`-produced DLL **before process exit**, then
letting the process exit normally, can crash: the CRT's own exit-time
cleanup later dereferences that now-freed registration. Confirmed
reproducible via a real multi-threaded test, isolated from a generic
double-free by a clean control run against the *unembedded* original.
Safe as long as the output DLL stays loaded for the life of the process
— the overwhelmingly common case — but a real risk for a plugin-host
style consumer that dynamically unloads things.

## ELF (Linux)

### Program headers, segments, and the AT_PHDR trap

An ELF file's `PT_LOAD` segments each declare a `p_vaddr`/`p_offset` pair
— the file maintains a **constant skew** (`p_vaddr - p_offset`) across
all of a normal linker's output, which the kernel relies on. Specifically:
`AT_PHDR` (the auxiliary vector entry telling `ld.so`/the CRT where the
program header table lives in memory) is computed as
`load_addr + e_phoff`, where `load_addr` is derived from whichever
segment's skew actually covers `e_phoff`'s own file offset — **not
universally "the first `PT_LOAD` segment,"** a wrong assumption that cost
this project three real fix rounds to fully correct. The first,
plausible-looking fix appended new content as a **brand-new** `PT_LOAD`
segment and relocated the program header table into it — this breaks
`AT_PHDR` the instant that new segment's skew differs from whatever
segment used to cover `e_phoff`, because the kernel's single-skew
shortcut then computes a garbage address, silently skipping (or
crashing on) `PT_TLS`/`PT_GNU_RELRO`/`PT_GNU_STACK` setup. The three
fixture tests in place at the time didn't exercise TLS or RELRO, so this
genuinely passed CI while being wrong — only caught by a reviewer
specifically hunting for "looks plausible, isn't correct" gaps.

**The fix, and the discipline every later ELF feature in this project
had to follow**: never add an independent new segment for ordinary
growth. Instead, **extend the host's own existing highest-vaddr
`PT_LOAD` segment in place** — new dependency blobs, the combined
relocation table, a grown program-header array (when a fixed-base
dependency needs its own new `PT_LOAD` entry), and a combined `PT_TLS`
segment all get folded into this one extension, preserving the
*original* skew throughout. When the program header array itself needs
to grow (adding a fixed-base dependency's own `PT_LOAD` entry, or a new
`PT_TLS` entry), the **`PT_PHDR` segment entry** — a second, independent
record of the program-header-array's own location/size — must also be
updated, or `ld.so` derives a bogus load bias from the stale copy and
crashes inside `ld.so` itself, before any user code runs.

A related, separately-discovered pitfall: placement of new content past
the extended segment's own `p_memsz` must account for the real,
**actual end of file** — not just the segment's own page-rounding slack.
GNU `ld` always leaves trailing, non-segment-covered content
(`.comment`/`.symtab`/`.strtab`/`.shstrtab`/the section header table) on
any unstripped binary, and a placement computed purely from
`align_up(p_memsz)` can land *before* that real trailing content,
silently (or, if guarded, spuriously) conflicting with it. The guard
that actually catches this: take `max(segment's own rounded memsz end,
real EOF translated through the segment's skew)` before the final
alignment, not just the first term.

### Dynamic section manipulation

The `.dynamic` section is a flat array of `Elf_Dyn` (tag, value) pairs,
terminated by `DT_NULL`. Two safe manipulation patterns this project
relies on:

- **Removing a `DT_NEEDED` entry** (when its dependency gets fully
  embedded): overwrite just the `d_tag` half of that one entry with
  `DT_DEBUG` (a real, legitimate, otherwise-unused tag) — this neutralizes
  it without shifting the array's layout or disturbing the `DT_NULL`
  terminator's position, which every other `_set_dyn_tag_value`-style
  edit depends on staying put.
- **Adding entries** (growing `DT_NEEDED` for a dependency's own further,
  non-embedded import, or extending the relocation table): build a new
  array (old bytes, new entries spliced in before the existing
  `DT_NULL`, old tail), write it as a new, independently-placed chunk via
  the segment-extension discipline above, and repoint `PT_DYNAMIC`'s own
  program-header entry at it — applied *after* every other in-place
  `_set_dyn_tag_value` edit, so those edits land on the live data, not a
  stale pre-growth snapshot.
- Symbol versioning (`DT_VERNEED`, a linked list of version-requirement
  records) needs the same "re-thread the list without disturbing
  siblings" care when removing one entry — a naive removal that doesn't
  correctly relink `vn_next` crashes `ld.so`'s own version-check assertion
  at load time, confirmed via a real SIGSEGV against an actual system
  library (`libtinfo.so.6`).

### Relocations: REL vs RELA, and real-world surprises

`R_X86_64_RELATIVE` (8) and `R_X86_64_GLOB_DAT` (6) are the ordinary
"patch this GOT/data slot to the relocated address" cases. Three
real-world complications this project hit, each only found by actually
embedding real system binaries:

- **`R_X86_64_JUMP_SLOT` (PLT entries) under lazy binding.** The naive
  fix (zero out a PLT-targeting relocation entry once resolved) only
  works under eager/`BIND_NOW` binding — most real binaries use **lazy**
  binding by default, where the PLT stub machinery still expects to read
  a live slot. The correct fix: write the resolved address directly into
  the GOT slot the PLT stub reads (matching how `_dl_fixup`'s own
  lazy-binding path behaves: it only adds the load bias to whatever's
  already sitting in a `JUMP_SLOT`'s GOT entry, resolved value already
  pre-filled), rather than neutering the relocation entry the way the
  simpler `GLOB_DAT` case allows.
- **`R_*_COPY` relocations.** A host executable's own copy of a shared
  library's mutable global data (e.g. `bash`'s termcap globals from
  `libtinfo.so.6`) needs a three-part fix when that library gets
  embedded: deferred write (after the host segment has actually grown to
  its final size), zeroing stale trailing file content before treating
  it as fresh BSS, and redirecting the dependency's own *internal*
  self-references to the host's copy of that storage rather than its
  own original location. A **real, acknowledged architectural limit**:
  ELF carries no type/layout metadata for a COPY-relocated symbol beyond
  a byte count, so a COPY-relocated object **larger than one pointer**
  that itself contains interior pointer fields gets no relocation
  entries for those interior pointers — there's no way to know which
  sub-offsets are pointers without DWARF info this module doesn't use
  anywhere else.
- **Weak vs. strong undefined symbols.** Every real GCC-built `.so`
  links in crtstuff's own weak-undefined GOT references
  (`__cxa_finalize`, `__gmon_start__`, ITM clone-table symbols) regardless
  of user code. Treating every undefined symbol as a hard error makes it
  impossible to embed *any* real-world `.so`. The correct behavior
  mirrors `ld.so`'s own "weak symbol, not found → resolves to NULL":
  forward a weak-undefined reference against a sibling embedded export
  when one exists, zero the slot only when genuinely undefined
  everywhere in the embedded set, and reserve hard failure for a
  **strong** undefined symbol.

### TLS on ELF: the ABI's own object-file-vs-linked-output split

The ELF TLS ABI defines several access models — **General Dynamic**
(`TLSGD`), **Local Dynamic** (`TLSLD`), **Initial Exec**, **Local Exec**
— each with its own relocation types. The General/Local-Dynamic models
produce a real `call __tls_get_addr`-style instruction sequence in
compiled code, backed by `R_X86_64_TLSGD`/`TLSLD` (types 19/20)
relocations against a GOT pair. **These relocation types are an
unlinked-object-file (`.o`) encoding only** — confirmed by real
experiment (GCC 15.2, both GNU `bfd` `ld` and `lld`, including explicitly
forcing `-ftls-model=global-dynamic` and the hardest case, an
`extern __thread` variable defined in a wholly separate, unlinked
module): the linker **always** resolves `TLSGD`/`TLSLD` into ordinary
`R_X86_64_DTPMOD64`/`DTPOFF64` GOT-slot relocations by the time it
produces a linked `.so`, regardless of source shape or compiler flags.
A tool that only ever opens already-linked `.so` files — exactly
`staticer`'s own input — can therefore never actually encounter a real
`TLSGD`/`TLSLD` relocation through any real code path; attempting to
implement byte-level call-site relaxation for it would be speculative
code with no way to test it against real input (confirmed, not
implemented — loud rejection instead, with a hand-crafted test since
there's no other way to construct the input at all).

What a real linked `.so`'s TLS access *does* need, confirmed against a
real third-party binary (`frida-gadget`, 14 real `DTPMOD64` relocations,
zero `TLSGD`/`TLSLD`):

- `R_X86_64_DTPMOD64` (16): the module id a thread-local variable belongs
  to. Once everything is merged into one output image, there's only ever
  one logical module — glibc's own documented convention assigns the
  main executable module id **1** (the first object `_dl_next_tls_modid`
  is ever called for), so every merged `DTPMOD64` slot gets id 1.
- `R_X86_64_DTPOFF64` (17) / `R_X86_64_TPOFF64` (18): the variable's
  static byte offset within the combined TLS block.
- The combined `PT_TLS` segment itself follows the same
  segment-extension discipline as everything else (see above) — never a
  parallel, independently-placed segment.

A genuinely still-open ELF gap: merging **two separate, already-present**
TLS directories (the host's own PLUS a dependency's) isn't implemented —
PE has this (see above), ELF currently still rejects it loudly. The PE
mechanism's "byte-pattern-scan the dependency's own compiled TLS-access
offsets" step doesn't have an ELF ABI equivalent worked out yet.

### Multiarch search directories

On Debian/Ubuntu-style systems, real shared objects live in an
architecture-qualified subdirectory (`/usr/lib/x86_64-linux-gnu/`), never
directly under `/usr/lib` itself. Without checking these directories, an
unrestricted (`--lib-dir` omitted) embed silently resolves **zero** real
system dependencies on such a system — even `libc.so.6`. The search list
must check exactly the two *supported* architecture triplets this module
actually targets (not a wildcard glob over every `*-linux-gnu*`
directory present, which pulls in unrelated foreign-architecture
directories from unrelated cross-toolchains that happen to be installed)
and must list the **host's own bitness's** triplet first, or a
wrong-architecture same-named file (most commonly `libc.so.6`) shadows
the correct one by directory sort order alone, making 32-bit
`lib_dir=None` embedding unusable in practice on any real multiarch
system.

## Cross-cutting lessons

- **Resolver path-traversal (CWE-22)**: a dependency name comes directly
  from the binary *being processed* — its own import table (PE) or
  `DT_NEEDED` strings (ELF) — so it's attacker-controlled input if the
  binary being processed is untrusted. A name with path-traversal
  components or an absolute path must never be allowed to resolve outside
  the intended search directory. The robust fix is NOT a bare string
  shape check alone (e.g. rejecting any absolute path outright) — some
  completely legitimate real-world inputs genuinely are absolute (a
  `.so` with no `DT_SONAME`, linked by its own full path, legitimately
  gets that literal path recorded as its `DT_NEEDED` string). The correct
  check is: join the name to the search directory, **resolve** the
  result, and verify it's still a descendant of that directory —
  `Path(directory) / name` is a documented no-op join when `name` is
  itself absolute, so this single check correctly handles both the
  legitimate-absolute-path case and the genuine-escape-attempt case.
- **"Looks correct" is not "is correct" for hand-written machine code.**
  A hand-assembled x86-64 stub's `mov r12,rsp`/`mov rsp,r12` save/restore
  pair looks symmetric but uses *opposite* REX bits (`B` for one
  direction, `R` for the other) — using the same byte for both silently
  encodes the wrong instruction in one direction. Found only by manual
  byte-level decoding, cross-checked against a real disassembler.
  Stack-alignment arithmetic for a generated stub needs the same rigor:
  an extra defensive-looking `sub rsp,8` "fixing" a misalignment can
  itself *introduce* a different misalignment if applied to a path that
  was already correctly aligned.
- **Test discriminating power is not free.** A regex match string chosen
  for a negative test (asserting a specific error fires) can
  coincidentally also match unrelated text embedded in every error on
  that code path — e.g. `pytest`'s own `tmp_path` fixture naming a
  directory after the test function itself, which can contain the same
  substring the test's `match=` pattern is checking for. A test like this
  passes even with the code under test's actual check disabled — the
  only way to catch it is to deliberately disable the production code
  and confirm the test then fails for the *right* reason, not just trust
  that a passing test proves anything.

## Where this knowledge lives in the codebase

- `staticer/pe_embedder.py` — PE section/import/relocation/exception/TLS
  merge logic, with inline comments at each hard-won fix pointing back at
  the specific failure mode that required it.
- `staticer/elf_embedder.py` — the ELF equivalent, including the
  `ext`/`ext_skew` segment-extension machinery and the `PT_PHDR`-update
  code the AT_PHDR history above is about.
- `staticer/stubs/windows/pe_stub.py` / `staticer/stubs/linux/elf_stub.py`
  — the generated entrypoint stubs, including the process-attach
  discrimination and stack-alignment logic.
- `tests/windows/`, `tests/linux/` — every lesson above has a
  corresponding regression test, usually named after the exact scenario
  that caught it.
