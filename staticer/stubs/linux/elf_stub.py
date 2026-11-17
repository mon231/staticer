"""Generated Linux (ELF) entrypoint stub.

Mirrors Task 7's pe_stub.py in *shape*: a small, hand-assembled x86/
x86-64 machine-code sequence that becomes the embedded binary's new
entrypoint, calls each embedded dependency's own initializers (here,
.init_array constructors -- the ELF analogue of Task 7's DllMain
process-attach calls) in dependencies-first order, then falls through to
the host's original entrypoint.

Deviation from the task brief's literal ``build_linux_stub(init_order,
hooked_names) -> bytes`` signature, and why: a flat function returning
only bytes has nowhere to report which of its *own* embedded absolute-VA
immediates (one per init call, plus the tail jump) need a new host
``R_*_RELATIVE`` entry for ASLR-safety -- silently omitting that would
make the generated stub wrong the instant the image loads anywhere other
than its preferred base, which is the default for a PIE host (every
fixture this task's own tests build). ``ElfEmbedder.embed()``'s own
``pe_embedder.py`` sibling already makes the identical deviation for the
identical reason, in its own internal stub-builder functions
(``_x64_call_dllmain``/``_x64_tail_jmp``/etc., each returning
``(bytes, [offsets])`` rather than plain ``bytes``) despite Task 7's own
brief describing ``build_windows_stub`` the same "-> bytes"-only way --
this function returns ``(bytes, [offsets])`` for the same reason.
``init_order`` (bare dependency names, carrying no address information
of its own) and ``hooked_names`` are still accepted so this function's
*public interface* matches the brief; the actual call targets
(``init_calls``) and the original entry's address are supplied
separately as resolved, absolute VAs -- see ``ElfEmbedder.embed()`` for
exactly how those are derived (each embedded dependency's own, already-
relocated DT_INIT_ARRAY entries, flattened in dependencies-first order;
``.init_array`` specifically, not the legacy single DT_INIT entry -- see
``embed()``'s own docstring for why).

Hook mechanism (implemented, x64 only): mirrors ``pe_stub.py``'s own
LoadLibraryW/LoadLibraryA/GetProcAddress hook in *shape* -- a generated
trampoline intercepts an explicit, application-level call asking for one
of this run's embedded dependencies by name and redirects it to the
already-embedded copy -- but ``dlopen``/``dlsym`` differ from Win32's
LoadLibrary/GetProcAddress in ways that rule out a direct transliteration:

* **Lazy PLT binding self-clobbers a naive GOT-slot patch.** A plain
  "read the GOT slot, save it, overwrite it with the trampoline" step
  (exactly what the PE hook does -- correct there because the PE loader
  always eagerly resolves every IAT slot before any code runs) is *wrong*
  here: under the ABI-default lazy-binding scheme, an unresolved
  ``dlopen``/``dlsym`` GOT slot initially holds the address of its own
  PLT entry's lazy-resolution trailer, not a real function pointer. The
  first *fallthrough* call after the hook is installed still works (the
  trailer's own resolution logic runs, and execution reaches the real
  function correctly), but as a side effect ``ld.so``'s resolver
  (``_dl_fixup``) permanently overwrites that same GOT slot with the real
  resolved address -- silently uninstalling the trampoline for every call
  after that first one. ``build_linux_hook_install`` avoids this with an
  upfront, harmless bootstrap call through *every* discovered slot before
  ever reading/overwriting any of them (``dlopen(NULL, RTLD_LAZY)`` --
  well-defined, returns a handle to the main program, no real loading;
  ``dlsym(RTLD_DEFAULT, <bogus probe name>)`` -- well-defined, returns
  ``NULL``): this forces real, final resolution to happen once, by us,
  before the hook is ever installed, so the GOT slot it then reads and
  overwrites is guaranteed to already hold the real address, and nothing
  ever triggers ``_dl_fixup`` again afterward. Done per-slot (not just
  once per API, unlike the PE hook's "read the first slot" shortcut),
  because -- unlike Windows's uniformly eagerly-resolved IAT -- each
  independent GOT slot importing the same symbol (the host's own, and/or
  any embedded dependency's own remaining import of it) has its *own*
  independent lazy-resolution state.
* **A pre-existing GOT slot can be RELRO-protected (read-only).** Modern
  toolchains (confirmed against this project's own: a plain ``gcc -fpie
  -pie`` build already defaults to full RELRO + ``BIND_NOW``) place
  ``.got.plt`` inside the ``PT_GNU_RELRO`` segment, which the loader
  ``mprotect``s to read-only as its very last startup step, before any
  ``.init_array`` entry (including this hook's own install code) ever
  runs. Writing to such a slot without first restoring write access
  faults with ``SIGSEGV`` -- the direct ELF analogue of the PE hook's own
  ``VirtualProtect`` dance around a read-only IAT slot, for the same
  underlying reason. ``build_linux_hook_install`` checks each discovered
  slot against the host's own ``PT_GNU_RELRO`` range (known statically at
  embed time, computed by the caller) and only wraps the ones that fall
  inside it in a real ``mprotect(PROT_READ|PROT_WRITE)`` / write /
  ``mprotect(PROT_READ)`` sequence -- through a synthetic external
  ``mprotect`` import the caller adds the same way it already forwards any
  other unresolved external reference (see ``ElfEmbedder.embed()``'s
  ``external_symbol_index`` mechanism). A slot outside that range (e.g.
  one newly created inside an embedded dependency's own appended data,
  which the host's pre-existing ``PT_GNU_RELRO`` segment was never
  extended to cover) is written directly, with no protection dance at
  all -- restoring an already-writable page to merely ``PROT_READ`` would
  wrongly downgrade every *other*, unrelated GOT slot sharing that same
  4 KiB page.
* **Symbol versioning**: real glibc exports ``dlopen``/``dlsym`` as
  versioned symbols (confirmed via ``readelf -s``/``nm -D`` against a real
  glibc 2.43 ``libc.so.6``: ``dlopen@GLIBC_2.2.5``/``dlopen@@GLIBC_2.34``,
  and the pre-2.34 name was in ``libdl.so.2`` instead -- glibc >= 2.34
  merged ``libdl`` into ``libc``). This needs no special handling at all:
  confirmed via ``pyelftools`` against a real compiled fixture that a
  ``.dynsym`` entry's own ``name`` field is always the bare, unversioned
  string (``"dlopen"``) -- the ``@``/``@@`` version suffix ``readelf``
  prints is synthesized for display by cross-referencing ``.gnu.version``/
  ``.gnu.version_r`` separately, never stored in the name string itself --
  so an ordinary by-name relocation walk (exactly what this project's
  other GOT/PLT handling already does) matches correctly regardless of
  which glibc version/library actually provides either symbol.
* **A recognized handle with no matching export returns NULL, not a real
  ``dlsym`` fallback** -- deliberately narrower than ``GetProcAddress``'s
  own documented "fall through to the real API" latitude might suggest,
  and for the same reason ``pe_stub.py``'s own GetProcAddress trampoline
  already stops short of that for its exact same case: a fake, non-
  loader-tracked handle is never safe to hand to the *real* API. For ELF
  specifically this is *worse* than merely calling the wrong function --
  real ``dlsym`` (glibc's ``_dl_sym``) does ``l = (struct link_map *)
  handle`` and dereferences fields on it with **no validation at all**
  when ``handle`` isn't ``RTLD_DEFAULT``/``RTLD_NEXT``; our fake handle
  (an embedded dependency's own base VA) *is* a validly mapped address,
  so this wouldn't even reliably crash -- it would read whatever
  unrelated bytes happen to sit at a fixed offset from that base (this
  dependency's own ELF header/code, not a ``link_map``) and chase them as
  pointers, risking a wild write or a silently wrong resolved address
  rather than a clean failure. Returning ``NULL`` is the same, deliberate
  trade their own docstring makes, for the same reason.
* ``RTLD_DEFAULT``/``RTLD_NEXT`` (dlsym's two pseudo-handles) need no
  special-casing at all: both are small, fixed non-address values (0 and
  ``(void*)-1``) that can never coincidentally equal one of this run's
  embedded dependencies' own real base VAs, so the ordinary table-miss
  path already falls them through to the real ``dlsym`` unconditionally.

The three builders below mirror ``pe_stub.py``'s own trio in role
(``build_linux_dlopen_trampoline`` ~ LoadLibrary, ``build_linux_dlsym_
trampoline`` ~ GetProcAddress, ``build_linux_hook_install`` ~ the IAT-slot
installer), using the SysV x86-64 calling convention throughout (``rdi``/
``rsi`` for the first two integer/pointer arguments, never Windows's
``rcx``/``rdx`` fastcall registers, and no shadow-space requirement around
a call -- SysV only needs 16-byte stack alignment immediately before
one). ``ElfEmbedder.embed()`` builds the match/module tables (from the
same per-dependency export data it already computes for its own GOT/PLT
patching) and splices the install code in as one more, synthetic,
zero-argument entry prepended to ``init_array_calls`` -- exactly the same
"runs before any embedded dependency's own real initializer" trick
``pe_embedder.py`` uses for its ``__hook_install__`` entry.

x64 only, matching every other machine-code-generating stub in this
module; a 32-bit (x86) host gets no hook at all.
"""

import itertools
from typing import List, Optional, Sequence, Set, Tuple

from staticer.stubs._keystone_utils import assemble as _assemble
from staticer.stubs._keystone_utils import assemble_with_immediate as _assemble_with_immediate
from staticer.stubs._keystone_utils import patch_va_sentinels as _patch_va_sentinels
from staticer.stubs._keystone_utils import patch_two_va_sentinels as _patch_two_va_sentinels

# -- assembling via Keystone instead of hand-encoded opcode bytes --
#
# This module used to spell out every instruction as raw hex literals
# (`b"\x48\xB8"` for "mov rax, imm64", etc.) with a comment naming the
# mnemonic next to each one. That's now inverted: the mnemonics below are
# real x86/x86-64 assembly text, assembled by Keystone
# (https://www.keystone-engine.org/) into the actual bytes. This is a
# deliberate, explicit exception to this project's otherwise-strict
# "pure Python, no compiled C extensions" rule (the same rule that
# excluded `lief` early in this project's history) -- `keystone-engine`
# ships a compiled assembler engine under its Python bindings. See
# `docs/architecture.md` for why this specific exception was made and
# why it doesn't compromise the "no C toolchain required to install or
# run this project" property that rule exists to protect.
#
# None of this module's instruction sequences are long enough to
# justify a separate `.asm` file -- they're inlined as short strings
# below -- but each one is still written as its own named helper so a
# future, longer stub could reasonably grow into one without disturbing
# this structure.
#
# The actual Keystone-engine caching, assembly, and sentinel locate/
# splice mechanics (`assemble`/`assemble_with_immediate` above) are not
# defined in this module -- they live in
# `staticer/stubs/_keystone_utils.py`, shared with the Windows (PE) stub
# builder (`staticer/stubs/windows/pe_stub.py`), which independently
# arrived at the same mechanism. Only the platform-specific assembly
# mnemonics/registers for the SysV calling convention, and this module's
# own sentinel constants, stay here.
#
# Sentinel immediates used only to *locate* an instruction's own
# immediate-operand bytes within Keystone's assembled output -- never
# actually written into a returned stub. Chosen to be maximally
# distinctive (no repeated byte, nothing resembling a plausible VA) so
# their own little-endian byte pattern cannot plausibly recur anywhere
# else in the same handful of instructions.
_SENTINEL_64 = 0x1122334455667788
_SENTINEL_32 = 0x11223344

# Cross-sentinel collision -- not applicable here: unlike pe_stub.py's
# `_x64_call_dllmain`/etc (which assemble a *single* sequence containing
# *two* independent VA sentinels, then must patch both against the same
# pristine buffer -- see `_keystone_utils.patch_two_va_sentinels`), every
# immediate this module emits (one per init call, plus the tail jump) is
# assembled, located, and spliced by its own, separate `_assemble_with_imm`
# call -- see `emit_call`/`emit_tail_jmp_via_cx` below -- before being
# concatenated onto the growing stub. Each buffer `_assemble_with_imm`
# touches holds exactly one sentinel at a time and is fully patched before
# the next one is ever assembled, so there is never a second, still-live
# sentinel left in a buffer for an already-applied splice to collide
# with. This was verified by inspection of every call site below (`emit_call`,
# `emit_tail_jmp_via_cx`, and `build_linux_init_array_stub`'s own
# `emit_call`), not assumed -- if a future change to this module ever
# assembles two sentinels into one shared buffer before patching either,
# it must switch that call site to `_keystone_utils.patch_two_va_sentinels`
# instead.


def _assemble_with_imm(is64: bool, asm_template: str, addr: int) -> Tuple[bytes, int]:
    """Thin wrapper choosing this module's own 64-/32-bit sentinel for
    `_keystone_utils.assemble_with_immediate` -- see the module-level
    comment above for why no cross-sentinel-collision handling is needed
    here."""
    ptr_size = 8 if is64 else 4
    sentinel = _SENTINEL_64 if is64 else _SENTINEL_32
    return _assemble_with_immediate(is64, asm_template, sentinel, ptr_size, addr)


def build_linux_init_array_stub(*, is64: bool, init_calls: List[int]) -> Tuple[bytes, List[int]]:
    """B6-ELF: the ``.so``-as-input counterpart of ``build_linux_stub``.

    ``ld.so``/the dynamic linker never invokes ``e_entry`` for anything
    other than the process's own main executable -- a shared object
    loaded via ``dlopen`` (or as an ordinary ``DT_NEEDED`` dependency) has
    its ``e_entry`` field completely ignored. Its *own* constructors run
    instead via the completely separate ``DT_INIT_ARRAY`` mechanism,
    called by ``_dl_init`` as ordinary functions (per glibc's own
    convention, with ``(argc, argv, envp)`` arguments -- irrelevant here,
    since this stub never uses them and every embedded dependency's own
    ``.init_array`` entries are themselves plain zero-argument functions).
    So, when the embedder's own input is a ``.so`` (not an executable),
    this stub is installed as a brand-new, *additional* entry in the
    host's own ``DT_INIT_ARRAY`` instead of as the new ``e_entry`` --
    see ``ElfEmbedder.embed()`` for exactly how that's wired in.

    Being called as an ordinary function (via a normal ``call``
    instruction from ``_dl_init``, not handed control directly as a
    process entrypoint) makes this much simpler than
    ``build_linux_stub``: no stack-realignment-then-restore dance is
    needed around the whole call sequence (the System V ABI already
    guarantees call-site alignment at the point ``_dl_init`` calls this
    stub, exactly the same guarantee any ordinary compiled function
    relies on), and there's no ``rtld_fini`` register to preserve either
    (that's an ``e_entry``-only concept -- this stub isn't the process
    entrypoint, so ld.so never hands it anything like that at all). All
    that's actually needed is the ordinary callee-saved-register
    discipline any hand-written function must observe: one callee-saved
    register (``r12``/``edi``) is pushed, used to remember the original,
    correctly call-site-aligned stack pointer, clobbered to force
    alignment for this stub's *own* outgoing calls (defensive -- a
    well-behaved caller already guarantees it, but this costs nothing and
    protects against any caller that doesn't), restored, and the saved
    register is popped back before an ordinary ``ret``.

    Returns ``(stub_bytes, reloc_offsets)`` exactly like
    ``build_linux_stub`` -- see its own docstring for why a new host
    ``R_*_RELATIVE`` entry is needed at each returned offset.
    """
    reloc_offsets: List[int] = []
    out = bytearray()

    # "mov rax/eax, {imm}; call rax/eax" -- {imm} is filled in per-call via
    # _assemble_with_imm, which also reports the immediate's byte offset.
    call_template = "mov rax, {imm}\ncall rax" if is64 else "mov eax, {imm}\ncall eax"

    def emit_call(addr: int) -> None:
        code, imm_offset = _assemble_with_imm(is64, call_template, addr)
        reloc_offsets.append(len(out) + imm_offset)
        out.extend(code)

    if is64:
        # push r12  (save caller's r12 -- callee-saved under SysV x86-64)
        # mov r12, rsp  (remember our own restore point)
        # and rsp, -16  (defensive call-site realignment)
        out.extend(_assemble(is64, "push r12\nmov r12, rsp\nand rsp, -16"))
    else:
        # push edi  (save caller's edi -- callee-saved under cdecl)
        # mov edi, esp  (remember our own restore point)
        # and esp, -16  (defensive call-site realignment)
        out.extend(_assemble(is64, "push edi\nmov edi, esp\nand esp, -16"))

    for addr in init_calls:
        emit_call(addr)

    if is64:
        # mov rsp, r12  (restore our own restore point)
        # pop r12  (restore caller's r12)
        # ret  (ordinary return to _dl_init)
        out.extend(_assemble(is64, "mov rsp, r12\npop r12\nret"))
    else:
        # mov esp, edi  (restore our own restore point)
        # pop edi  (restore caller's edi)
        # ret  (ordinary return to _dl_init)
        out.extend(_assemble(is64, "mov esp, edi\npop edi\nret"))

    return bytes(out), reloc_offsets


def build_linux_stub(
    init_order: List[str],
    hooked_names: Set[str],
    *,
    is64: bool,
    init_calls: List[int],
    original_entry: int,
) -> Tuple[bytes, List[int]]:
    """Build the stub's machine code.

    `init_order` is accepted only to mirror Task 7's public interface
    (and so a caller can sanity-check len(init_order) against the number
    of dependencies `init_calls` was derived from) -- it carries no
    address information of its own and this function doesn't otherwise
    use it. `init_calls` are the resolved, absolute VAs to call, already
    in dependencies-first order; `original_entry` is the absolute VA of
    the host's own original entrypoint to tail-jump to once every call
    is done.

    Returns `(stub_bytes, reloc_offsets)`: `reloc_offsets` are byte
    offsets *within* `stub_bytes` of each embedded absolute-VA immediate
    (one per init call, plus the final tail-jump target) -- the caller
    (ElfEmbedder.embed()) must record a new host R_*_RELATIVE entry at
    `stub_vaddr + offset` for each one, exactly as it already does for
    every other absolute address this module writes, so the stub keeps
    working if the final image is itself relocated at load time (ASLR).

    Each init call is a plain zero-argument call (`mov reg, imm; call
    reg`). Two pieces of ABI-mandated setup bracket the whole call
    sequence, both required because this stub runs as the *literal*
    process entrypoint (e_entry) rather than as an ordinarily-`call`ed
    function, and both found to matter only by actually running the
    result and hitting a real SIGSEGV, not by static reasoning alone:

    1. Stack realignment. The ABI requires %rsp/%esp to be a clean
       multiple of 16 immediately *before* a `call` instruction -- the
       kernel/ld.so already hand e_entry a 16-aligned %rsp/%esp (the
       System V ABI's *process-entry* guarantee), which happens to
       satisfy this directly, with no adjustment needed at all; this
       function went through two wrong states before landing there. The
       first emitted a bare `call` straight off that pointer with *no*
       realignment, which is actually fine on x86-64 (already 16-aligned)
       but wrong on i386 wherever the loader doesn't give that same
       guarantee -- see the fixture-driven regression test this was
       caught by for specifics. A later revision "fixed" that by adding
       an extra `and $-16`-then-`sub $8`/`sub $4`, which *overshoots*: it
       produces exactly the one-pointer-width misalignment it was meant
       to remove, on both architectures. Neither mistake has any symptom
       until something deep in the affected call's own call graph
       (observed for the rtld_fini bug below: well past the init calls
       themselves, inside glibc's own exit-handling, long after this
       stub has already tail-jumped away; for the alignment bug itself:
       directly, inside any constructor that executes an
       alignment-sensitive SSE/AVX instruction of its own, such as
       `tests/fixtures/ctor_sse_align.c`'s) executes an
       alignment-sensitive instruction against the mis-aligned stack and
       faults. The correct fix is the plain `and $-16, %rsp`/`and $-16,
       %esp` below, with nothing further -- saving the kernel-provided
       pointer in a callee-saved register first, and restoring the exact
       original value before the tail-jump, since original_entry (crt1's
       `_start`) needs that one unmodified, not just "some 16-aligned
       value" -- it reads argc/argv/envp directly off it.

    2. Preserving ld.so's own incoming "rtld_fini" pointer. On entry to
       a dynamically-linked ELF, ld.so hands e_entry a function pointer
       in a fixed register (%rdx on x86-64, %edx on i386 -- confirmed
       empirically, not from documentation alone: a raw register dump
       taken at this exact entry point on real i386 Linux showed a
       plausible ld.so-internal code address sitting in %edx, with %eax
       -- the more commonly assumed register -- holding nothing but a
       small, meaningless value) which `_start` forwards into
       `__libc_start_main`'s `rtld_fini` parameter, later registered (via
       `__cxa_atexit`) to run at process exit. Clobbering that register
       with this stub's own calls and never restoring it before the
       tail-jump means `_start` forwards garbage, `__libc_start_main`
       dutifully registers it, and the whole process SIGSEGVs at
       `exit()` -- calling through a demangled garbage pointer, well
       after every one of this stub's own init calls has already
       succeeded. Fixed the same way as the stack pointer: saved in a
       second callee-saved register, restored immediately before the
       tail-jump.

    All of the above were found and confirmed by actually building and
    running real fixtures on real Linux (WSL), never by static review
    alone -- including the stack-alignment *overcorrection* bug itself
    (see point 1), caught only once a regression fixture that actually
    executes an aligned SSE/AVX instruction in a called constructor
    existed; none of this task's other fixtures (timestamp-recording
    constructors, a plain C++ throw/catch) happen to touch alignment-
    sensitive instructions at all, so they could not have caught it.
    """
    del init_order  # see docstring: informational only, carries no addresses
    del hooked_names  # unused here by design -- see module docstring's "Hook mechanism"
    # section: the real dlopen/dlsym interception machinery is built by the caller
    # and spliced into `init_calls` as one more entry, same as pe_stub.py's
    # build_windows_stub never reading its own same-named parameter either.

    reloc_offsets: List[int] = []
    out = bytearray()
    ptr_size = 8 if is64 else 4

    # "mov rax/eax, {imm}; call rax/eax" -- {imm} is filled in per-call via
    # _assemble_with_imm, which also reports the immediate's byte offset.
    call_template = "mov rax, {imm}\ncall rax" if is64 else "mov eax, {imm}\ncall eax"

    def emit_call(addr: int) -> None:
        code, imm_offset = _assemble_with_imm(is64, call_template, addr)
        reloc_offsets.append(len(out) + imm_offset)
        out.extend(code)

    # "mov rcx/ecx, {imm}; jmp rcx/ecx" -- deliberately NOT the same
    # "mov eax/rax, imm; jmp eax/rax" shape emit_call uses -- eax/rax is
    # where this function's *own* restore of the ld.so-provided
    # rtld_fini register lands (see the big comment below), immediately
    # before this jump; clobbering it again right here to hold the jump
    # target would silently discard that restore one instruction before
    # it would have mattered. ecx/rcx is free (nothing else in this
    # stub's tail still needs it) and ABI-irrelevant for a jump (unlike
    # eax/rax, it's not where any incoming-register convention expects
    # anything).
    tail_jmp_template = "mov rcx, {imm}\njmp rcx" if is64 else "mov ecx, {imm}\njmp ecx"

    def emit_tail_jmp_via_cx(addr: int) -> None:
        code, imm_offset = _assemble_with_imm(is64, tail_jmp_template, addr)
        reloc_offsets.append(len(out) + imm_offset)
        out.extend(code)

    # -- stack realignment around the call sequence --
    #
    # The kernel hands control to e_entry with the ABI's *process-entry*
    # stack-alignment guarantee: %rsp/%esp is 16-byte aligned (System V
    # ABI, "Initial Stack and Register State" -- the same convention
    # crt1.o's own `_start` relies on, reading argc/argv/envp directly
    # off this exact, unmodified pointer). Luckily that happens to BE a
    # valid *call-site* alignment too -- the ABI requires %rsp/%esp to be
    # a clean multiple of 16 immediately *before* a `call` instruction
    # (so that, after the implicit return-address push, the callee's own
    # raw incoming %rsp/%esp sits at exactly 16n-8/16n-4, the fixed,
    # known-odd-by-convention baseline every compiler's own prologue
    # assumes when it goes on to establish 16-byte-aligned *local* slots
    # for its own SSE/AVX spills -- this is also exactly what glibc's own
    # `_start` does: a bare `and $-16, %rsp` immediately before `call
    # __libc_start_main`, nothing more). Both this stub and its own first
    # version got this backwards at different times: emitting a bare
    # `call` straight off the kernel-provided, already-16-aligned entry
    # pointer, with NO realignment at all, hands every callee a stack
    # mis-aligned by one pointer width -- and a *later* version of this
    # function overcorrected, adding an extra `sub $8`/`sub $4` after the
    # `and`, re-introducing the exact same one-pointer-width
    # misalignment it was meant to fix (worse, on x86-64 specifically,
    # since the kernel-provided entry %rsp was *already* a valid pre-call
    # value there with no adjustment needed at all -- that `sub` was a
    # straight regression, not just an incomplete fix). Neither mistake
    # has any symptom until something deep in the affected call's own
    # call graph (observed: well past frame_dummy/a real user
    # constructor, inside glibc's own exit-handling machinery) finally
    # executes an alignment-sensitive SSE/AVX instruction against the
    # mis-aligned stack and faults -- each reproduced as a real SIGSEGV,
    # on real Linux (WSL), for both 32- and 64-bit; the version below is
    # the one actually confirmed correct by running
    # `tests/fixtures/ctor_sse_align.c`'s `movaps`-using constructor
    # (see `tests/linux/test_elf_unwind.py`).
    #
    # Save the untouched, kernel-provided pointer in a callee-saved
    # register (unused by anything else in this stub, and ABI-guaranteed
    # to survive across every call below unclobbered), force %rsp/%esp
    # down to a fresh, correctly call-site-aligned value for the actual
    # calls, then restore the saved pointer *exactly* before the final
    # tail-jump -- original_entry (crt1's `_start`) needs that one
    # untouched, not just "some 16-aligned value", since it reads
    # argc/argv/envp directly off of it.
    # -- preserve the dynamic linker's own incoming "rtld_fini" pointer --
    #
    # On process entry to a dynamically-linked ELF, the dynamic linker
    # (ld.so) hands control to e_entry with a function pointer in a
    # fixed, ABI-defined register -- %rdx on x86-64, %edx on i386 (NOT
    # %eax -- confirmed empirically: a raw register dump taken at this
    # exact entry point, on real Linux/WSL i386, showed a plausible
    # ld.so-internal code address sitting in %edx, with %eax holding
    # nothing but a small, meaningless value) -- which crt1.o's own
    # `_start` reads and forwards into
    # `__libc_start_main`'s own `rtld_fini` parameter, which registers it
    # (via `__cxa_atexit`) to run at process exit (it's what actually
    # runs each loaded shared object's own finalization and unmaps it).
    # An earlier version of this function clobbered that register with
    # its own call sequence and never restored it before tail-jumping to
    # original_entry (the real `_start`) -- `_start` then forwarded
    # whatever garbage was left in it, `__libc_start_main` dutifully
    # registered *that* as the exit-time callback, and the whole process
    # SIGSEGV'd at `exit()`, well after this stub's own, otherwise
    # perfectly successful, init-array calls -- reproduced as a real
    # crash, on real Linux (WSL), for both 32- and 64-bit, before this
    # fix; confirmed fixed by it. Save it in the same callee-saved
    # register as the stack-pointer save below (nothing else in this
    # stub's own call sequence touches either), and restore it -- before
    # restoring %rsp/%esp itself, and before the final jump touches
    # %eax/%rax again for its own purposes (see emit_tail_jmp_via_cx) --
    # immediately ahead of the tail-jump to original_entry.
    if is64:
        # mov r15, rsp  (save; r15 is callee-saved)
        # mov rbx, rdx  (save rtld_fini; rbx is callee-saved)
        # and rsp, -16  (-> rsp == 0 (mod 16), correct pre-call)
        out.extend(_assemble(is64, "mov r15, rsp\nmov rbx, rdx\nand rsp, -16"))
    else:
        # mov edi, esp  (save; edi is callee-saved under cdecl)
        # mov esi, edx  (save rtld_fini; esi is callee-saved)
        # and esp, -16  (-> esp == 0 (mod 16), correct pre-call)
        out.extend(_assemble(is64, "mov edi, esp\nmov esi, edx\nand esp, -16"))

    for addr in init_calls:
        emit_call(addr)

    if is64:
        # mov rdx, rbx  (restore rtld_fini)
        # mov rsp, r15  (restore stack pointer)
        out.extend(_assemble(is64, "mov rdx, rbx\nmov rsp, r15"))
    else:
        # mov edx, esi  (restore rtld_fini)
        # mov esp, edi  (restore stack pointer)
        out.extend(_assemble(is64, "mov edx, esi\nmov esp, edi"))

    emit_tail_jmp_via_cx(original_entry)

    assert all(off + ptr_size <= len(out) for off in reloc_offsets)  # sanity: every immediate fits
    return bytes(out), reloc_offsets


# -- dlopen/dlsym runtime hook (x64 only) -----------------------------------
# See this module's own docstring's "Hook mechanism" section for the full
# design derivation and the caller-side (ElfEmbedder.embed()) integration
# this assumes.

_HOOK_SENTINEL_TABLE = 0x1122334455667788
_HOOK_SENTINEL_SAVED = 0x8877665544332211

# Base for the install builder's own, a-priori-unknown number of
# independent absolute-VA sentinels (one per discovered GOT slot, per
# bootstrap-force/read/overwrite step -- see build_linux_hook_install) --
# same "generate as many as needed" approach as pe_stub.py's own
# `_make_hook_install_sentinels`, just using an unbounded counter instead
# of a precomputed budget, since nothing here needs to preallocate an
# array of them up front. Chosen in a distinct, easily recognizable range
# from this module's other sentinels purely for readability when
# debugging a failed splice, not a correctness requirement.
_HOOK_INSTALL_SENTINEL_BASE = 0x9999000000000000

_MPROTECT_PAGE = 0x1000


def build_linux_dlopen_trampoline(*, match_table_va: int, saved_original_va: int) -> Tuple[bytes, List[int]]:
    """x64 machine code for a drop-in ``dlopen`` replacement, installed over
    every discovered real GOT slot for it by ``build_linux_hook_install``.

    ``match_table_va`` points at a caller-built array of 16-byte entries --
    ``(name_string_va: u64, fake_handle_va: u64)``, ASCII, NUL-terminated by
    one all-zero sentinel entry (``name_string_va == 0``) -- one per
    embedded dependency, keyed by the exact name the host's own dynamic
    section originally knew it by (the same string a real ``dlopen`` call
    for it would have to use). The match is byte-for-byte, case-
    *sensitive* (unlike the PE hook's case-insensitive DLL-name fold --
    Linux filenames are case-sensitive); on a match, the table entry's own
    ``fake_handle_va`` (that dependency's own base VA within the merged
    image -- mirroring the PE hook's own "HMODULE is the module's base
    address" convention) is returned directly in ``rax``, without ever
    calling the real ``dlopen``.

    ``rdi`` (the incoming ``filename``) is explicitly NULL-checked before
    any table lookup -- unlike Win32's ``lpLibFileName``, a real ``dlopen``
    call legitimately passes ``NULL`` (meaning "the main program itself"),
    and dereferencing it unconditionally the way the PE hook's own
    ``lpLibFileName`` handling does would crash on that case.

    No match at all (including every ordinary ``dlopen`` call, by far the
    common case, and every ``NULL`` one) tail-jumps to the real, saved
    original at ``saved_original_va`` with ``rdi``/``esi`` (the incoming
    ``filename``/``flags``) completely undisturbed.
    """
    asm = (
        f"mov r11, {_HOOK_SENTINEL_TABLE}\n"
        "test rdi, rdi\n"
        "jz no_match\n"
        "try_entry:\n"
        "mov rax, [r11]\n"
        "test rax, rax\n"
        "jz no_match\n"
        "mov r10, rdi\n"
        "char_loop:\n"
        "movzx r8d, byte ptr [r10]\n"
        "movzx r9d, byte ptr [rax]\n"
        "cmp r8d, r9d\n"
        "jne next_entry\n"
        "test r8d, r8d\n"
        "jz matched\n"
        "inc r10\n"
        "inc rax\n"
        "jmp char_loop\n"
        "next_entry:\n"
        "add r11, 16\n"
        "jmp try_entry\n"
        "matched:\n"
        "mov rax, [r11+8]\n"
        "ret\n"
        "no_match:\n"
        f"mov rax, {_HOOK_SENTINEL_SAVED}\n"
        "mov rax, [rax]\n"
        "jmp rax"
    )
    data = _assemble(True, asm)
    data, table_off, saved_off = _patch_two_va_sentinels(
        data, _HOOK_SENTINEL_TABLE, match_table_va, _HOOK_SENTINEL_SAVED, saved_original_va, 8
    )
    return data, [table_off, saved_off]


def build_linux_dlsym_trampoline(*, module_table_va: int, saved_original_va: int) -> Tuple[bytes, List[int]]:
    """x64 machine code for a drop-in ``dlsym`` replacement, installed over
    every discovered real GOT slot for it by ``build_linux_hook_install``.

    ``module_table_va`` points at a caller-built array of 16-byte entries --
    ``(fake_handle_va: u64, by_name_table_va: u64)``, sentinel-terminated
    on ``fake_handle_va == 0`` -- one per embedded dependency. ``rdi`` (the
    incoming ``handle``) is matched against each entry's own
    ``fake_handle_va``; ``RTLD_DEFAULT``/``RTLD_NEXT`` (0 and all-ones) and
    any genuine real handle can never coincidentally match one of these
    (real base VAs), so they fall through to the real, saved original at
    ``saved_original_va`` exactly like every other miss, with ``rdi``/
    ``rsi`` (``handle``/``symbol``) undisturbed.

    A match commits to resolving against that module's own by-name table
    (``by_name_table_va``, 16-byte ``(name_string_va: u64, resolved_va:
    u64)`` pairs, sentinel-terminated on ``name_string_va == 0``) -- an
    exact, case-sensitive byte-for-byte compare against ``rsi`` (real ELF
    symbol lookup is case-sensitive), same walk shape as the PE hook's own
    export-name scan. If found, the resolved VA is returned directly in
    ``rax``. If the module matched but the symbol doesn't appear in its
    own table, this returns ``NULL`` (``rax = 0``) rather than falling
    through to the real ``dlsym`` -- see this module's own docstring for
    exactly why a fake handle is never safe to hand to the real API here.
    """
    asm = (
        f"mov r11, {_HOOK_SENTINEL_TABLE}\n"
        "find_module:\n"
        "mov rax, [r11]\n"
        "test rax, rax\n"
        "jz no_match\n"
        "cmp rax, rdi\n"
        "je module_found\n"
        "add r11, 16\n"
        "jmp find_module\n"
        "module_found:\n"
        "mov r9, [r11+8]\n"
        "name_scan:\n"
        "mov rax, [r9]\n"
        "test rax, rax\n"
        "jz ret_null\n"
        "mov r8, rax\n"
        "mov rcx, rsi\n"
        "name_cmp_loop:\n"
        "movzx eax, byte ptr [r8]\n"
        "movzx r10d, byte ptr [rcx]\n"
        "cmp eax, r10d\n"
        "jne name_next\n"
        "test eax, eax\n"
        "jz name_matched\n"
        "inc r8\n"
        "inc rcx\n"
        "jmp name_cmp_loop\n"
        "name_next:\n"
        "add r9, 16\n"
        "jmp name_scan\n"
        "name_matched:\n"
        "mov rax, [r9+8]\n"
        "ret\n"
        "ret_null:\n"
        "xor eax, eax\n"
        "ret\n"
        "no_match:\n"
        f"mov rax, {_HOOK_SENTINEL_SAVED}\n"
        "mov rax, [rax]\n"
        "jmp rax"
    )
    data = _assemble(True, asm)
    data, table_off, saved_off = _patch_two_va_sentinels(
        data, _HOOK_SENTINEL_TABLE, module_table_va, _HOOK_SENTINEL_SAVED, saved_original_va, 8
    )
    return data, [table_off, saved_off]


def build_linux_hook_install(
    entries: Sequence[Tuple[str, int, Sequence[int], int]],
    *,
    dlsym_probe_va: int,
    mprotect_slot_va: Optional[int] = None,
    relro_range: Optional[Tuple[int, int]] = None,
) -> Tuple[bytes, List[int]]:
    """x64 machine code that installs the dlopen/dlsym hook: for each
    ``(api_kind, saved_cell_va, slot_vas, trampoline_va)`` in ``entries``
    (``api_kind`` is ``"dlopen"`` or ``"dlsym"``; an entry with an empty
    ``slot_vas`` -- nothing to hook for that API in this image -- is
    skipped entirely), per discovered real GOT slot:

    1. An upfront, harmless bootstrap call through the slot's *current*
       value, forcing real resolution to happen now, by us, before this
       slot is ever read or overwritten -- see this module's own
       docstring's "Hook mechanism" section for exactly why this step
       exists (it's the ELF-specific fix for a problem Windows's IAT-based
       hook never has). Done for every slot independently, not just the
       first.
    2. Only then: the first slot's now-guaranteed-resolved value is read
       and stored into ``saved_cell_va`` (one per API, read once -- every
       slot for the same symbol holds the identical real address once
       actually resolved, same simplification ``pe_stub.py``'s own
       install builder uses).
    3. Every slot is overwritten with ``trampoline_va``. A slot falling
       inside ``relro_range`` (the host's own ``PT_GNU_RELRO`` segment
       bounds, ``(lo, hi)``, computed by the caller -- ``None`` if the
       host has none) is wrapped in a real
       ``mprotect(page, 0x1000, PROT_READ|PROT_WRITE)`` / write /
       ``mprotect(page, 0x1000, PROT_READ)`` sequence through
       ``mprotect_slot_va`` (a GOT slot for ``mprotect`` itself, added by
       the caller the same way any other unresolved external reference
       already gets forwarded -- required whenever any slot falls inside
       ``relro_range``, otherwise unused). A slot outside that range is
       written directly.

    ``dlsym_probe_va`` is the absolute VA of a short, NUL-terminated ASCII
    string naming a symbol that doesn't exist -- used as every dlsym
    bootstrap call's harmless probe (``dlsym(RTLD_DEFAULT, <probe>)``,
    well-defined, returns ``NULL``).

    Runs with no live incoming arguments to preserve (spliced into the
    generated init-array call sequence as one more, synthetic, zero-
    argument entry -- see this module's own docstring), but still needs
    its own SysV-ABI-correct call-site realignment for its *own* nested
    calls (unlike a normal callee, nothing guarantees this function's own
    incoming ``rsp`` leaves room for that) -- the same ``push r12``/
    ``and rsp, -16``/...-/``mov rsp, r12``/``pop r12`` bracket
    ``build_linux_init_array_stub`` already uses for the identical reason
    (running as an ordinarily-``call``ed function, not a process entry
    point), reused here rather than invented a second time.
    """
    if not any(slot_vas for _, _, slot_vas, _ in entries):
        return b"", []

    relro_lo, relro_hi = relro_range if relro_range is not None else (None, None)

    pairs: List[Tuple[int, int]] = []
    sentinels = (_HOOK_INSTALL_SENTINEL_BASE + i for i in itertools.count())

    def sentinel_for(real_va: int) -> int:
        s = next(sentinels)
        pairs.append((s, real_va))
        return s

    lines: List[str] = ["push r12", "mov r12, rsp", "and rsp, -16"]

    for api_kind, saved_cell_va, slot_vas, trampoline_va in entries:
        if not slot_vas:
            continue

        # Step 1: bootstrap-force every slot, independently.
        for slot_va in slot_vas:
            lines.append(f"mov r11, {sentinel_for(slot_va)}")
            lines.append("mov rax, [r11]")
            if api_kind == "dlopen":
                lines.append("xor edi, edi")  # filename = NULL
                lines.append("mov esi, 1")  # flags = RTLD_LAZY
            else:
                lines.append("xor edi, edi")  # handle = RTLD_DEFAULT
                lines.append(f"mov rsi, {sentinel_for(dlsym_probe_va)}")  # symbol = bogus probe name
            lines.append("call rax")

        # Step 2: read the first slot's now-resolved value into saved_cell_va.
        lines.append(f"mov r11, {sentinel_for(slot_vas[0])}")
        lines.append("mov rax, [r11]")
        lines.append(f"mov r10, {sentinel_for(saved_cell_va)}")
        lines.append("mov [r10], rax")

        # Step 3: overwrite every slot with the trampoline's address.
        for slot_va in slot_vas:
            needs_relro = relro_lo is not None and relro_lo <= slot_va < relro_hi
            if needs_relro:
                page_va = slot_va & ~(_MPROTECT_PAGE - 1)
                lines.append(f"mov rdi, {sentinel_for(page_va)}")
                lines.append(f"mov esi, {_MPROTECT_PAGE}")
                lines.append("mov edx, 3")  # PROT_READ | PROT_WRITE
                lines.append(f"mov rax, {sentinel_for(mprotect_slot_va)}")
                lines.append("call qword ptr [rax]")

            lines.append(f"mov r11, {sentinel_for(slot_va)}")
            lines.append(f"mov rax, {sentinel_for(trampoline_va)}")
            lines.append("mov [r11], rax")

            if needs_relro:
                lines.append(f"mov rdi, {sentinel_for(page_va)}")
                lines.append(f"mov esi, {_MPROTECT_PAGE}")
                lines.append("mov edx, 1")  # PROT_READ (restore -- matches PT_GNU_RELRO's own p_flags)
                lines.append(f"mov rax, {sentinel_for(mprotect_slot_va)}")
                lines.append("call qword ptr [rax]")

    lines += ["mov rsp, r12", "pop r12", "ret"]

    data = _assemble(True, "\n".join(lines))
    data, offsets = _patch_va_sentinels(data, pairs, 8)
    return data, offsets
