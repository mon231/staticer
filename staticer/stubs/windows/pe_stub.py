"""Windows (PE) generated entrypoint stub.

``build_windows_stub`` produces the machine code
``PortableExecutableEmbedder.embed()`` installs as the final image's new
entrypoint: in order, a ``DllMain`` process-attach-style call into each
embedded dependency named in ``init_order`` (dependencies before
dependents, matching the topological order ``embed_order`` -- Task 1 --
already produces), then a tail-jump to the host's own original
entrypoint.

Interface note: the task brief sketches this as
``build_windows_stub(init_order: List[str], hooked_names: Set[str]) ->
bytes``. Those two parameters are preserved exactly, but the function
cannot actually be *just* those two -- the whole point is to emit machine
code containing each named dependency's own (hinstDLL, entry-point)
addresses and the host's original entrypoint address, none of which are
derivable from names alone, and which differ for x86 vs. x64 encodings.
So this adds the addresses (``dep_entry_vas``) and bitness (``is64``) as
additional keyword-only parameters, and returns ``(bytes, offsets)``
rather than bare ``bytes`` -- ``offsets`` lists every byte offset within
the returned blob holding a hardcoded absolute-VA immediate, which the
caller must also record as a new base-relocation entry (mirroring every
other hardcoded absolute address this project already emits -- see
``pe_embedder.py``'s own module docstring on why) if the final image
might ever load somewhere other than its preferred base.

Hook mechanism (implemented, x64 only): ``hooked_names`` is accepted for
interface compatibility with the design brief's exact signature, but the
actual LoadLibraryW/LoadLibraryA/GetProcAddress interception machinery it
describes is *not* built from that parameter directly inside
``build_windows_stub`` -- it's built by the caller (``pe_embedder.py``,
which already has every address this needs: each hooked dependency's own
``hinst_va`` from ``dep_entry_vas``, and its own raw export table from
``global_raw_exports_by_dll``) and spliced in as one more synthetic,
no-op-DllMain-signature entry prepended to ``init_order`` -- exactly the
same trick already used for the per-dependency TLS-index fixup
(``__tls_fixup_<name>__``, built by ``build_windows_tls_index_fixup`` and
appended to the caller's own ``dep_entry_calls`` list). Prepending it
(rather than appending) is what satisfies the design's "runs *before* any
embedded module's own initializer" requirement: every call in
``init_order`` after it, including every real dependency's own entry
point, only runs once hook installation has already completed.

The three builders below this module exports for that mechanism:

* ``build_windows_loadlibrary_trampoline`` -- one instance built per
  (is_wide) combination, i.e. once for LoadLibraryW and once for
  LoadLibraryA. Walks a caller-supplied, NUL-sentinel-terminated match
  table of (name-string VA, base VA) pairs, case-folding both the
  requested name and each table entry one code unit (wchar_t or char) at
  a time -- DLL names are ASCII-only in practice, so a simple
  ``'A'-'Z'`` fold suffices and needs no locale/Unicode-casing machinery
  -- and returns the matching base VA directly (what a real LoadLibrary
  would have returned as the module's ``HINSTANCE``) without ever calling
  the real API. No match -- including the common case, every name this
  process ever asks for that *isn't* one of this run's embedded
  dependencies -- falls through to the real, saved original via an
  unconditional tail-jump, so ordinary LoadLibrary calls are completely
  unaffected.
* ``build_windows_getprocaddress_trampoline`` -- walks a module table of
  (base VA, by-name sub-table VA, by-ordinal sub-table VA) triples to
  find the one matching the incoming ``HMODULE``; GetProcAddress's own
  by-name/by-ordinal convention (`lpProcName`'s high 48 bits all zero
  means it's really a 16-bit ordinal via `MAKEINTRESOURCE`, not a string
  pointer) picks the by-name sub-table (an exact, case-*sensitive*
  byte-for-byte string match -- real export-name lookup is
  case-sensitive, unlike a DLL filename) or the by-ordinal one (a plain
  integer compare) accordingly. If the `HMODULE` doesn't match any
  hooked dependency's own base VA at all, falls through to the real,
  saved original, same as the LoadLibrary trampolines; if it *does*
  match a hooked module but the requested name/ordinal isn't present in
  that module's own table, returns ``NULL`` directly (matching a real
  GetProcAddress's own "not found" behavior for a real module) rather
  than calling through to the real API with a fake, non-loader-tracked
  `HMODULE` it would never recognize.
* ``build_windows_hook_install`` -- straight-line code (no branches) that,
  for each hooked API, reads the *first* of its caller-supplied IAT slot
  VAs (every slot for the same real API ends up holding the identical
  loader-resolved address once the real loader has snapped it, regardless
  of which importer's own IAT array that particular slot physically lives
  in, so one read suffices), stores it into a small saved-original data
  cell the matching trampoline reads back from, then overwrites *every*
  supplied slot (there can be more than one -- the host's own IAT, and/or
  any number of already-merged dependencies' own remaining IAT arrays,
  since each embedded dependency keeps its own distinct FirstThunk array
  physically inside its own relocated blob rather than sharing one) with
  that API's trampoline address. Each individual slot write is wrapped in
  a real `VirtualProtect`/write/`VirtualProtect`-restore pair -- confirmed
  via a real, reproduced crash that a pre-existing IAT slot can live in a
  read-only page (a common, legitimate compiler layout; only the loader's
  own privileged one-time import-snapping can write there otherwise) --
  so this does make real calls (needing the standard `sub rsp,
  0x28`/`add rsp, 0x28` shadow-space prologue/epilogue around them) and
  treats every argument-passing register as clobbered across each one,
  reloading every value fresh from its own sentinel immediately after.
  Still never leaves `rcx`/`rdx`/`r8`/`r9` holding anything this function
  *itself* needs to persist across its own `ret` -- the per-dependency
  init-call sequences immediately following it (and, for a DLL host, the
  real `DllMain` it eventually tail-jumps to) rely on those holding the
  stub's own original incoming arguments untouched, which this never
  touches in the first place (its own "no live incoming arguments"
  calling convention -- see its own docstring).

Known, deliberate scope limits (see ``docs/limitations.md`` for the fuller
write-up):

* x64 only, matching every other recently-added stub in this module (the
  TLS-index fixup, the delay-import lazy thunk). 32-bit PE support has its
  own, separately documented, pre-existing gaps.
* Only `LoadLibraryW`/`LoadLibraryA`/`GetProcAddress` themselves are
  hooked -- not `LoadLibraryExW` or any loader-internal resolution path
  (e.g. `ntdll!LdrLoadDll`) a module's own *statically compiled* import
  table goes through when the OS loader itself resolves it while mapping
  that module (as opposed to an explicit, application-level
  LoadLibrary/GetProcAddress call, which this hook does intercept). A
  module that is itself loaded dynamically by name (e.g. a plugin loaded
  via an explicit `LoadLibraryW` call this hook *does* see) but which in
  turn statically imports one of this run's embedded dependencies by
  name is NOT redirected to the embedded copy by this mechanism alone --
  the OS loader's own internal import-table walk for that plugin never
  calls through any IAT slot this hook can see or overwrite. Confirmed
  against a real-world repro (010 Editor's Qt platform plugin,
  `qwindows.dll`, itself loaded dynamically via `QPluginLoader`-
  >`LoadLibraryW`, statically importing `Qt6Core.dll`/`Qt6Gui.dll`) --
  see ``docs/limitations.md`` for the full account of what this hook does
  and doesn't fix for that case.
* A hooked GetProcAddress's by-name/by-ordinal lookup against a matched
  module only covers exports this project could resolve at embed time --
  a forwarded export whose target DLL isn't itself embedded this run is
  silently left out of that module's own runtime table (returning
  ``NULL``, the same as a real "not found"), exactly mirroring this
  project's existing delay-import forward-resolution fallback elsewhere.

Assembly mechanism: every byte sequence below is assembled from real
x86/x64 assembly *source text* by the Keystone assembler engine
(``keystone-engine``, a deliberate, documented exception to this
project's otherwise-pure-Python/no-native-toolchain rule -- see
``docs/architecture.md``'s "Why no linker is involved" section), not
hand-encoded as hex-literal bytes. None of these stubs is long enough to
warrant a separate ``.asm`` source file -- each is built from an inline
string -- but the ``_assemble``/sentinel-splice helpers below are
structured so a future, longer stub could reasonably load its source from
a ``.asm`` file instead without changing the calling convention.

Each builder below needs to emit code containing an address value
(``hinst_va``, ``entry_va``, ``target_va``, ``host_tlsindex_va``,
``dep_tlsindex_va``) that is only known at call time, *and* report the
exact byte offset of that immediate within the assembled output (for
ASLR base-relocation registration -- see above). Keystone needs a
concrete immediate to assemble against, so each builder assembles the
instruction text with a distinctive placeholder ("sentinel") constant
substituted in (``_X64_SENTINEL_A``/``_B`` or ``_X86_SENTINEL_A``/``_B``:
chosen as alternating-nibble patterns vanishingly unlikely to recur
elsewhere in these few-instruction sequences), locates the sentinel's own
little-endian byte pattern in the assembled output (asserting it occurs
*exactly once*, so a coincidental collision fails loudly instead of
silently mis-patching), and splices in the real value at that offset.
This -- rather than assembling directly against the real value and
searching for *its* byte pattern -- is deliberately the more robust of
the two options the embedding task considered: real VAs are caller
-controlled and not guaranteed to have a byte pattern absent elsewhere in
the same short sequence, whereas the sentinels are chosen once, verified
once (see ``tests/windows/test_pe_stub_keystone.py``), and never vary.

The locate/splice mechanics themselves (``assemble``, ``patch_immediate``,
``patch_va_sentinel``, ``patch_two_va_sentinels``) are not defined in this
module -- they live in ``staticer/stubs/_keystone_utils.py``, shared with
the Linux (ELF) stub builder (``staticer/stubs/linux/elf_stub.py``), which
independently arrived at the same mechanism. Only the platform-specific
parts -- which assembly mnemonics/registers a given calling convention
needs, and which sentinel constants this module happens to use -- stay
here.
"""

import itertools
from typing import Dict, List, Sequence, Set, Tuple

from staticer.stubs._keystone_utils import (
    assemble as _assemble,
    patch_immediate as _patch_immediate,
    patch_two_va_sentinels as _patch_two_va_sentinels,
    patch_va_sentinel as _patch_va_sentinel,
    patch_va_sentinels as _patch_va_sentinels,
)

# Each helper below returns (bytes, [byte offsets of embedded absolute-VA
# immediates within that block]) -- moved essentially unchanged from
# Task 3/5's inline versions in pe_embedder.py (now superseded by this
# module). Those immediates are hardcoded addresses the final image must
# keep correct if it's ever loaded somewhere other than its preferred base
# (e.g. ASLR, on by default for these fixtures) -- see this module's own
# docstring on why the caller must turn each one into a new base
# relocation entry.

# Sentinel placeholders substituted into assembly source text in place of
# a not-yet-known runtime VA, then located (by their own distinctive
# little-endian byte pattern) and overwritten with the real value after
# assembly -- see the module docstring's "Assembly mechanism" section.
# "_A"/"_B" are used when a single instruction sequence embeds two
# independent absolute addresses, so each can be located unambiguously.
# The actual locate/splice/two-sentinel-collision mechanics live in
# ``staticer/stubs/_keystone_utils.py``, shared with the Linux (ELF) stub
# builder -- see that module's docstring for why.
_X64_SENTINEL_A = 0x1122334455667788
_X64_SENTINEL_B = 0x8877665544332211
_X86_SENTINEL_A = 0x11223344
_X86_SENTINEL_B = 0x44332211


def _x64_call_dllmain(hinst_va: int, entry_va: int) -> Tuple[bytes, List[int]]:
    # Preserve the real entrypoint's incoming arg registers around our own
    # call, then call dep_entry(hinstDLL=hinst_va, DLL_PROCESS_ATTACH=1, NULL).
    #
    # The push/pop pairs bracketing the call are what fixed the original
    # REX-byte save/restore asymmetry bug: `r8`/`r9` need the REX.B bit
    # (`push r8`/`push r9` encode as `41 50`/`41 51`, their `pop`
    # counterparts as `41 58`/`41 59`) while `rcx`/`rdx` don't -- getting
    # any of those four REX bytes wrong, or popping in a different order
    # than pushed, corrupts the real entrypoint's own incoming registers.
    # Assembling real `push`/`pop` mnemonics for all four registers (rather
    # than hand-picking hex bytes) makes Keystone responsible for emitting
    # the correct REX prefixes, removing that whole class of mistake.
    asm = (
        "push rcx\n"
        "push rdx\n"
        "push r8\n"
        "push r9\n"
        "sub rsp, 0x28\n"
        f"mov rcx, {_X64_SENTINEL_A}\n"
        "mov edx, 1\n"
        "xor r8d, r8d\n"
        f"mov rax, {_X64_SENTINEL_B}\n"
        "call rax\n"
        "add rsp, 0x28\n"
        "pop r9\n"
        "pop r8\n"
        "pop rdx\n"
        "pop rcx"
    )
    data = _assemble(True, asm)
    data, hinst_off, entry_off = _patch_two_va_sentinels(
        data, _X64_SENTINEL_A, hinst_va, _X64_SENTINEL_B, entry_va, 8
    )
    return data, [hinst_off, entry_off]


def _x64_tail_jmp(target_va: int) -> Tuple[bytes, List[int]]:
    asm = f"mov rax, {_X64_SENTINEL_A}\njmp rax"
    data = _assemble(True, asm)
    data, off = _patch_va_sentinel(data, _X64_SENTINEL_A, 8, target_va)
    return data, [off]


def _x86_call_dllmain(hinst_va: int, entry_va: int) -> Tuple[bytes, List[int]]:
    # __stdcall DllMain(hinstDLL, fdwReason, lpvReserved) - callee pops its
    # own 3 args, so the stack is already balanced after `call`.
    asm = (
        "push 0\n"  # lpvReserved
        "push 1\n"  # DLL_PROCESS_ATTACH
        f"push {_X86_SENTINEL_A}\n"  # hinstDLL
        f"mov eax, {_X86_SENTINEL_B}\n"
        "call eax"
    )
    data = _assemble(False, asm)
    data, hinst_off, entry_off = _patch_two_va_sentinels(
        data, _X86_SENTINEL_A, hinst_va, _X86_SENTINEL_B, entry_va, 4
    )
    return data, [hinst_off, entry_off]


def _x86_tail_jmp(target_va: int) -> Tuple[bytes, List[int]]:
    asm = f"mov eax, {_X86_SENTINEL_A}\njmp eax"
    data = _assemble(False, asm)
    data, off = _patch_va_sentinel(data, _X86_SENTINEL_A, 4, target_va)
    return data, [off]


_DLL_PROCESS_ATTACH = 1


def _patch_guard_jump(data: bytes, forced_target: int, skip_len: int) -> bytes:
    """Shared machinery for the two process-attach guards below: both
    assemble a `jne <forced_target>` against a target address far enough
    away that Keystone cannot use the short (rel8) jump encoding, forcing
    the deterministic `0F 85 <rel32>` ("jne near") form regardless of the
    real `skip_len`'s magnitude -- exactly as the original hand-encoded
    bytes always used the near form unconditionally. The rel32 Keystone
    actually computed for `forced_target` is then located by its own
    (deterministic, since `data`'s length is now known) little-endian
    pattern and overwritten with the real `skip_len`, the same
    sentinel-splice technique used for the absolute-VA immediates above,
    just applied to a relative-displacement immediate instead.
    """
    computed_disp = forced_target - len(data)
    sentinel_bytes = computed_disp.to_bytes(4, "little", signed=True)
    replacement_bytes = skip_len.to_bytes(4, "little", signed=True)
    patched, _off = _patch_immediate(data, sentinel_bytes, replacement_bytes)
    return patched


# A target address this far away can never be reached by a one-byte
# (rel8) displacement from these few-byte guard sequences, so Keystone is
# forced into the near (rel32) `jne` encoding every time.
_GUARD_FORCED_TARGET = 0x7FFFFFFF


def _x64_process_attach_guard(skip_len: int) -> bytes:
    # cmp edx, 1 ; jne +skip_len -- this stub's entrypoint *is* the host's
    # real DllEntryPoint/DllMain when the host being embedded into is
    # itself a DLL (see build_windows_stub's `host_is_dll`), so it's called
    # by the OS loader not just once at process-attach but also on every
    # thread attach/detach and on process-detach, each time with a
    # different `fdwReason` (the Windows x64 calling convention's 2nd
    # integer argument, in EDX) -- B6-PE: without this guard, every
    # embedded dependency's own process-attach-style init would spuriously
    # re-run on every one of those too. `skip_len` is the length of the
    # per-dependency init-call block immediately following this guard (the
    # `jne` lands exactly at the tail-jump to `original_entry_va`, which
    # must always run regardless of `fdwReason` so the host's own real
    # DllMain still sees every notification it's supposed to).
    asm = f"cmp edx, 1\njne {_GUARD_FORCED_TARGET}"
    data = _assemble(True, asm)
    return _patch_guard_jump(data, _GUARD_FORCED_TARGET, skip_len)


def _x86_process_attach_guard(skip_len: int) -> bytes:
    # cmp dword [esp+8], 1 ; jne +skip_len -- same guard as the x64
    # version above, but fdwReason is __stdcall's 2nd stack argument here
    # ([esp+0]=return address, [esp+4]=hinstDLL, [esp+8]=fdwReason) rather
    # than a register, since this stub's entrypoint hasn't pushed anything
    # of its own yet at this point.
    asm = f"cmp dword ptr [esp+8], 1\njne {_GUARD_FORCED_TARGET}"
    data = _assemble(False, asm)
    return _patch_guard_jump(data, _GUARD_FORCED_TARGET, skip_len)


def build_windows_tls_index_fixup(*, host_tlsindex_va: int, dep_tlsindex_va: int) -> Tuple[bytes, List[int]]:
    """x64 machine code for the one remaining runtime step in task 5 /
    phase 2's TLS merge (host already has its own TLS directory too):
    copy the host's own, by-then loader-assigned, `_tls_index` *value*
    into the embedded dependency's own `_tls_index` variable.

    Why this is the only runtime code phase 2 still needs (see
    pe_embedder.py's own phase-2 comment, right where this is called,
    for the full derivation): once the host's own TLS directory has been
    extended to cover a combined raw-data range holding both the host's
    own and the dependency's own raw TLS bytes (at correctly
    non-overlapping offsets -- a pure data change, needing no runtime
    code at all, since the native per-thread copy the OS loader already
    does for the host's own directory keeps doing the right thing for
    both halves automatically), both modules' compiled TLS access end up
    reading the exact same per-thread block through the exact same real,
    loader-assigned `ThreadLocalStoragePointer` slot -- *if* both their
    own `_tls_index` variables hold that same slot *number*. Only the
    host's own ever gets written by the real loader (there's only one
    real TLS directory left); this one-time copy is what makes the
    dependency's own agree with it. The slot number is a process-wide
    constant once assigned (unlike the per-thread block *pointer*, which
    varies per thread and needs no attention here at all), so copying it
    once, this early, is sufficient -- no per-thread re-invocation
    needed.

    Takes no `(DllHandle, Reason, Reserved)` parameters at all (unlike a
    real TLS callback) -- the caller hooks it onto the init-call stub
    this module already generates for any embedded dependency with its
    own entry point (`dep_entry_calls`/`build_windows_stub`), which calls
    everything in `dep_entry_calls` with that same 3-argument call
    convention regardless, so it's simplest to just ignore all three
    here rather than ask the caller to use a different call shape for
    one single entry.

    Register usage: `rax` holds each `_tls_index` variable's own address
    in turn (never a thread-local block pointer -- that distinction
    matters, see docstring above), and `ecx` carries the 4-byte slot
    *value* being copied between them. Both are scratch here (this code
    runs with no live incoming arguments it needs to preserve, unlike
    `_x64_call_dllmain` above), so no save/restore is needed around them.
    """
    asm = (
        f"mov rax, {_X64_SENTINEL_A}\n"  # rax = &host._tls_index
        "mov ecx, dword ptr [rax]\n"  # ecx = host._tls_index (the real slot number)
        f"mov rax, {_X64_SENTINEL_B}\n"  # rax = &dep._tls_index
        "mov dword ptr [rax], ecx\n"  # dep._tls_index = ecx
        "ret"
    )
    data = _assemble(True, asm)
    data, host_off, dep_off = _patch_two_va_sentinels(
        data, _X64_SENTINEL_A, host_tlsindex_va, _X64_SENTINEL_B, dep_tlsindex_va, 8
    )
    return data, [host_off, dep_off]


# Distinct from `_X64_SENTINEL_A`/`_B` above purely for readability (each
# function's own sentinels only ever appear in buffers *that function*
# assembles, so there's no actual collision risk in sharing them --
# `patch_va_sentinels`, like `patch_two_va_sentinels`, locates every
# sentinel against the original, unmodified buffer before splicing any of
# them in).
_X64_DELAY_SENTINEL_DLLNAME = 0x1111111111111111
_X64_DELAY_SENTINEL_FUNCKEY = 0x2222222222222222
_X64_DELAY_SENTINEL_LOADLIBRARYA_SLOT = 0x3333333333333333
_X64_DELAY_SENTINEL_GETPROCADDRESS_SLOT = 0x4444444444444444
_X64_DELAY_SENTINEL_SELF_IAT_SLOT = 0x5555555555555555


def build_windows_delay_import_lazy_thunk(
    *,
    dll_name_va: int,
    func_key_va_or_ordinal: int,
    func_key_is_ordinal: bool,
    loadlibrarya_iat_slot_va: int,
    getprocaddress_iat_slot_va: int,
    self_iat_slot_va: int,
) -> Tuple[bytes, List[int]]:
    """x64 machine code for a single delay-imported function whose real
    target DLL is *not* itself embedded this run (see pe_embedder.py's
    long comment on the two-case split for why only this case -- "target
    not embedded" -- needs a generated stub at all, and why the stub
    exists in the first place rather than leaving the compiler's own
    delay-load descriptor untouched).

    Confirmed via a real crash, reproduced against a real 010 Editor
    embed and root-caused with `cdb`: once this dependency's own code is
    physically embedded inside the host's single image (rather than
    separately `LoadLibrary`'d as its own OS-registered module), the
    *compiler's own* generated delay-load thunk's call into
    `ntdll!LdrResolveDelayLoadedAPI` -- passing `&__ImageBase` as
    `ParentModuleBase`, which after embedding correctly computes (via
    ordinary RIP-relative addressing) to this dependency's own placement
    *within* the host image, not a real, separately loaded module's base
    -- fails with `LdrResolveDelayLoadedAPI:Unable to locate DLL based at
    <address>. Status = 0xc0000135`, and the thunk's own handling of that
    failure dereferences a null/garbage result, crashing with RIP
    becoming exactly 0 (`First chance exceptions`... `Access violation -
    code c0000005`, confirmed live under `cdb`). This happens regardless
    of whether the delay-import's *target* DLL is itself embedded or a
    real, always-loadable external one -- the broken half is
    `ParentModuleBase`, which is wrong either way once the *descriptor's
    own module* has been embedded, not anything about the target.

    So the real compiler-generated thunk for this function must never
    run at all, for any embedded dependency with delay imports --
    regardless of target. This builds a drop-in replacement: a tiny,
    self-contained thunk that performs the *exact same* work a real
    `__delayLoadHelper2` would (resolve, once, via plain `LoadLibraryA`
    + `GetProcAddress` -- real Win32 APIs that handle API-set redirection
    correctly on their own, unlike this project's own static,
    build-time-only resolution -- then self-patch the IAT slot with the
    resolved address so every later call skips straight to it, exactly
    matching a real delay-load's own steady-state-bound behavior), using
    only ordinary Win32 calls through two freshly-added KERNEL32.dll IAT
    slots (`loadlibrarya_iat_slot_va`/`getprocaddress_iat_slot_va` --
    KERNEL32.dll is never embeddable/excludable by this project's own
    design, so these always resolve at real process load, same as any
    other ordinary import) -- never touching `LdrResolveDelayLoadedAPI`
    or anything else loader-internal.

    `self_iat_slot_va`'s caller installs *this stub's own address* into
    that same IAT slot beforehand (mirroring B1/B1-delay's direct-address
    patch elsewhere in `pe_embedder.py`) -- nothing here runs until the
    host's own compiled code actually calls through that slot for the
    first time, preserving genuine delay-load laziness; this only
    replaces *what* runs on that first call, not *when*.

    `func_key_va_or_ordinal` is either the absolute VA of the function
    name's existing ASCII string (already present, unmodified, in the
    owning dependency's own embedded blob -- the compiler's own
    `IMAGE_IMPORT_BY_NAME.Name`) for a by-name import, or the raw ordinal
    integer value itself (not a pointer -- `GetProcAddress`'s own
    `MAKEINTRESOURCE`-style convention for an ordinal-style
    `lpProcName`) for a by-ordinal one; either way it's loaded into
    `rdx` as an opaque 8-byte value, but `func_key_is_ordinal` tells the
    caller (via this function's returned offset list) whether that
    particular immediate is a real address needing its own base-
    relocation entry (by-name) or a small integer that must never be
    treated as one (by-ordinal -- adding an ASLR delta to an ordinal
    number would silently corrupt it into a bogus one).

    Register save/restore: unlike `_x64_call_dllmain` above (whose own
    callee, `DllMain`, has a fixed, integer-only signature), a delay-
    imported function's real signature is unknown here, so this must
    preserve every x64 argument-passing register it might disturb --
    `rcx`/`rdx`/`r8`/`r9` *and* `xmm0`-`xmm3` (the first four integer and
    floating-point argument slots respectively; MSVC's own real
    `__tailMerge*` thunks preserve exactly this same set, for the same
    reason) -- around its own two calls, then restores all eight before
    tail-jumping to the resolved address with the original incoming
    register state otherwise completely undisturbed and the stack
    exactly as the caller left it (no new frame left behind), so the
    resolved function's own eventual `ret` lands directly back at the
    real caller.

    Failure path (either Win32 call returns NULL): `ud2` -- a real delay
    import's *default* (unhooked) failure behavior is itself fatal (MSVC
    raises a structured exception), and this case should be exceedingly
    rare in practice (it only means a real system DLL this project never
    touched at all somehow isn't loadable on this machine, a condition
    the original, unmodified binary would be equally unable to recover
    from) -- `ud2` is a clean, deterministic, immediately-debuggable
    trap, deliberately safer than letting execution continue into
    whatever garbage a silent NULL `jmp` would land on.
    """
    asm = (
        "push rcx\n"
        "push rdx\n"
        "push r8\n"
        "push r9\n"
        "sub rsp, 0x78\n"
        "movups [rsp+0x20], xmm0\n"
        "movups [rsp+0x30], xmm1\n"
        "movups [rsp+0x40], xmm2\n"
        "movups [rsp+0x50], xmm3\n"
        f"mov rcx, {_X64_DELAY_SENTINEL_DLLNAME}\n"
        f"mov rax, {_X64_DELAY_SENTINEL_LOADLIBRARYA_SLOT}\n"
        "call qword ptr [rax]\n"
        "test rax, rax\n"
        "jz fail\n"
        "mov rcx, rax\n"
        f"mov rdx, {_X64_DELAY_SENTINEL_FUNCKEY}\n"
        f"mov rax, {_X64_DELAY_SENTINEL_GETPROCADDRESS_SLOT}\n"
        "call qword ptr [rax]\n"
        "test rax, rax\n"
        "jz fail\n"
        f"mov rcx, {_X64_DELAY_SENTINEL_SELF_IAT_SLOT}\n"
        "mov [rcx], rax\n"
        "movups xmm0, [rsp+0x20]\n"
        "movups xmm1, [rsp+0x30]\n"
        "movups xmm2, [rsp+0x40]\n"
        "movups xmm3, [rsp+0x50]\n"
        "add rsp, 0x78\n"
        "pop r9\n"
        "pop r8\n"
        "pop rdx\n"
        "pop rcx\n"
        "jmp rax\n"
        "fail:\n"
        "ud2"
    )
    data = _assemble(True, asm)
    data, offsets = _patch_va_sentinels(
        data,
        [
            (_X64_DELAY_SENTINEL_DLLNAME, dll_name_va),
            (_X64_DELAY_SENTINEL_FUNCKEY, func_key_va_or_ordinal),
            (_X64_DELAY_SENTINEL_LOADLIBRARYA_SLOT, loadlibrarya_iat_slot_va),
            (_X64_DELAY_SENTINEL_GETPROCADDRESS_SLOT, getprocaddress_iat_slot_va),
            (_X64_DELAY_SENTINEL_SELF_IAT_SLOT, self_iat_slot_va),
        ],
        8,
    )
    dllname_off, funckey_off, loadlib_off, getproc_off, self_off = offsets
    reloc_offsets = [dllname_off, loadlib_off, getproc_off, self_off]
    if not func_key_is_ordinal:
        reloc_offsets.append(funckey_off)
    return data, reloc_offsets


# -- LoadLibraryW/LoadLibraryA/GetProcAddress runtime hook ------------------
# See this module's own docstring's "Hook mechanism" section for the full
# design derivation and the caller-side (`pe_embedder.py`) integration this
# assumes. Everything below is x64 only.

# Reused (like `_X64_SENTINEL_A`/`_B` above) across every builder in this
# section -- each is only ever located against a buffer *that builder*
# itself assembled, so there's no real collision risk in sharing them.
_X64_HOOK_SENTINEL_TABLE = _X64_SENTINEL_A
_X64_HOOK_SENTINEL_SAVED = _X64_SENTINEL_B

# `build_windows_hook_install` below can embed an a-priori unknown number
# of independent absolute-VA sentinels in one buffer (one IAT slot address
# per *importer* of a hooked API, which varies run to run), so it can't
# reuse a small fixed set of named constants the way every other builder
# in this module does -- it generates as many as it needs from this base,
# via `_make_hook_install_sentinels` below. Chosen in a distinct, easily
# recognizable range (`0x9999...`) from every other sentinel in this
# module purely for readability when debugging a failed splice -- not a
# correctness requirement (`patch_va_sentinels` would just as happily
# reuse any other unused range).
_X64_HOOK_INSTALL_SENTINEL_BASE = 0x9999000000000000


def _make_hook_install_sentinels(n: int) -> List[int]:
    return [_X64_HOOK_INSTALL_SENTINEL_BASE + i for i in range(n)]


def build_windows_loadlibrary_trampoline(
    *, is_wide: bool, match_table_va: int, saved_original_va: int
) -> Tuple[bytes, List[int]]:
    """x64 machine code for a drop-in LoadLibraryW (`is_wide=True`) or
    LoadLibraryA (`is_wide=False`) replacement, installed over every
    discovered real IAT slot for that API by `build_windows_hook_install`.

    `match_table_va` points at a caller-built array of 16-byte entries --
    `(name_string_va: u64, base_va: u64)`, wide (UTF-16LE) or ANSI to
    match `is_wide` -- terminated by one all-zero sentinel entry
    (`name_string_va == 0`). On a match, returns that entry's own
    `base_va` directly (the embedded dependency's own `hinst_va`) without
    ever calling the real API; the match is case-*insensitive* (Windows
    DLL names are) via a one-code-unit-at-a-time `'A'-'Z'` fold applied to
    *both* the incoming name and the table entry as they're compared --
    deliberately not pre-folded into the table at build time, since that
    would just move the same fold logic from "every comparison" to "every
    table entry, once" without saving anything (the incoming name still
    needs folding either way, and still has to be compared one code unit
    at a time regardless of whether the other operand was pre-folded).

    On no match (including every ordinary, non-hooked LoadLibrary call --
    the overwhelmingly common case in practice), tail-jumps to the real,
    saved original at `saved_original_va` with the incoming argument
    register (`rcx` -- x64's one-pointer-argument fastcall convention for
    both LoadLibraryW/A) completely undisturbed, so the real call behaves
    exactly as if this trampoline were never installed.

    Register usage: `rcx` (the incoming name pointer) is read but never
    written, so it's valid for the real API's own use the entire time
    this runs, including the final tail-jump. `rax`, `r8`, `r9`, `r10`,
    `r11` are scratch -- all volatile under x64 fastcall, so none needs
    saving. No stack frame is used at all.
    """
    load_insn = "word ptr" if is_wide else "byte ptr"
    step = 2 if is_wide else 1
    asm = (
        f"mov r11, {_X64_HOOK_SENTINEL_TABLE}\n"
        "try_entry:\n"
        "mov rax, [r11]\n"
        "test rax, rax\n"
        "jz no_match\n"
        "mov r10, rcx\n"
        "char_loop:\n"
        f"movzx r8d, {load_insn} [r10]\n"
        f"movzx r9d, {load_insn} [rax]\n"
        "cmp r8d, 0x41\n"
        "jl fold1_done\n"
        "cmp r8d, 0x5A\n"
        "jg fold1_done\n"
        "add r8d, 0x20\n"
        "fold1_done:\n"
        "cmp r9d, 0x41\n"
        "jl fold2_done\n"
        "cmp r9d, 0x5A\n"
        "jg fold2_done\n"
        "add r9d, 0x20\n"
        "fold2_done:\n"
        "cmp r8d, r9d\n"
        "jne next_entry\n"
        "test r8d, r8d\n"
        "jz matched\n"
        f"add r10, {step}\n"
        f"add rax, {step}\n"
        "jmp char_loop\n"
        "next_entry:\n"
        "add r11, 16\n"
        "jmp try_entry\n"
        "matched:\n"
        "mov rax, [r11+8]\n"
        "ret\n"
        "no_match:\n"
        f"mov rax, {_X64_HOOK_SENTINEL_SAVED}\n"
        "mov rax, [rax]\n"
        "jmp rax"
    )
    data = _assemble(True, asm)
    data, table_off, saved_off = _patch_two_va_sentinels(
        data, _X64_HOOK_SENTINEL_TABLE, match_table_va, _X64_HOOK_SENTINEL_SAVED, saved_original_va, 8
    )
    return data, [table_off, saved_off]


def build_windows_getprocaddress_trampoline(
    *, module_table_va: int, saved_original_va: int
) -> Tuple[bytes, List[int]]:
    """x64 machine code for a drop-in GetProcAddress replacement, installed
    over every discovered real IAT slot for it by `build_windows_hook_
    install`.

    `module_table_va` points at a caller-built array of 24-byte entries --
    `(base_va: u64, by_name_table_va: u64, by_ordinal_table_va: u64)` --
    terminated by one all-zero sentinel entry (`base_va == 0`), one per
    hooked dependency. `rcx` (the incoming `HMODULE`) is matched against
    each entry's own `base_va`; no match at all falls through to the
    real, saved original exactly like the LoadLibrary trampolines above
    (`rcx`/`rdx` both left completely undisturbed for the real call).

    A match commits to resolving against *that* module's own tables --
    GetProcAddress's own by-name/by-ordinal convention for `rdx`
    (`lpProcName`) is used to pick which: if `rdx`'s high 48 bits are all
    zero, the whole value is really a 16-bit ordinal via
    `MAKEINTRESOURCE`, not a string pointer (this is GetProcAddress's own
    real, documented convention, not something invented here); otherwise
    it's a real ASCII C-string pointer, compared byte-for-byte,
    case-*sensitively* (export-name lookup is case-sensitive, unlike a
    DLL filename) against each `by_name_table_va` entry (16-byte
    `(name_string_va: u64, resolved_va: u64)` pairs, sentinel-terminated
    on `name_string_va == 0`) until a match or the sentinel. The ordinal
    path walks `by_ordinal_table_va` (16-byte `(ordinal: u64, resolved_
    va: u64)` pairs, sentinel-terminated on `ordinal == 0xFFFF...FFFF` --
    0 is deliberately not used as that sentinel, since real export
    ordinals are 16-bit and a real `0` is never actually reachable as a
    *value* here anyway, but `-1` is unambiguous either way and matches
    `cmp reg64, -1`'s natural sign-extended-immediate encoding) the same
    way.

    If the module matches but the specific name/ordinal doesn't appear in
    its own table (including a forwarded export this project couldn't
    resolve at embed time -- see this module's own docstring's scope-
    limits section), this returns `NULL` directly rather than falling
    through -- the real GetProcAddress has no way to recognize our fake,
    non-loader-tracked `HMODULE` value at all, so calling through to it
    at this point would be calling the real API with a bogus handle, not
    a safe fallback.

    Register usage: `rcx`/`rdx` (the incoming arguments) are read but
    never written *before* a module match is found, so the no-match
    tail-jump sees them completely undisturbed; once a module is
    matched, both are free to reuse as scratch (together with `rax`,
    `r8`, `r9`, `r10`, `r11`, all volatile) since every path from that
    point on is this function's own `ret`, not a tail-jump relying on
    the caller's original argument values. No stack frame is used.
    """
    asm = (
        f"mov r11, {_X64_HOOK_SENTINEL_TABLE}\n"
        "find_module:\n"
        "mov rax, [r11]\n"
        "test rax, rax\n"
        "jz no_match\n"
        "cmp rax, rcx\n"
        "je module_found\n"
        "add r11, 24\n"
        "jmp find_module\n"
        "module_found:\n"
        "mov rax, rdx\n"
        "shr rax, 16\n"
        "test rax, rax\n"
        "jnz by_name\n"
        "movzx r10d, dx\n"
        "mov r9, [r11+16]\n"
        "ord_scan:\n"
        "mov rax, [r9]\n"
        "cmp rax, -1\n"
        "je ret_null\n"
        "cmp rax, r10\n"
        "je ord_matched\n"
        "add r9, 16\n"
        "jmp ord_scan\n"
        "ord_matched:\n"
        "mov rax, [r9+8]\n"
        "ret\n"
        "by_name:\n"
        "mov r9, [r11+8]\n"
        "name_scan:\n"
        "mov rax, [r9]\n"
        "test rax, rax\n"
        "jz ret_null\n"
        "mov r8, rax\n"
        "mov rcx, rdx\n"
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
        f"mov rax, {_X64_HOOK_SENTINEL_SAVED}\n"
        "mov rax, [rax]\n"
        "jmp rax"
    )
    data = _assemble(True, asm)
    data, table_off, saved_off = _patch_two_va_sentinels(
        data, _X64_HOOK_SENTINEL_TABLE, module_table_va, _X64_HOOK_SENTINEL_SAVED, saved_original_va, 8
    )
    return data, [table_off, saved_off]


def build_windows_hook_install(
    entries: Sequence[Tuple[int, Sequence[int], int]],
    *,
    virtualprotect_iat_slot_va: int,
    scratch_dword_va: int,
) -> Tuple[bytes, List[int]]:
    """x64 machine code that performs steps 1-3 of this module's own
    docstring's "Hook mechanism" section for every hooked API at once:
    save each one's real, loader-resolved value, then overwrite every one
    of its discovered IAT slots with its own trampoline's address.

    `entries` is one `(saved_cell_va, slot_vas, trampoline_va)` tuple per
    hooked API (LoadLibraryW, LoadLibraryA, GetProcAddress): `slot_vas`
    is every IAT slot this run found for that API (could be more than
    one -- the host's own, and/or any number of already-merged
    dependencies' own remaining KERNEL32 imports of it, since each keeps
    its own distinct FirstThunk array rather than sharing one); an entry
    with an empty `slot_vas` is skipped entirely (nothing to hook for
    that API in this image). Every slot for the *same* API holds the
    identical real address once the real loader has resolved it
    (there's only one real KERNEL32 export by that name in the whole
    process), so only the first slot is ever actually read from.

    `VirtualProtect` around every slot write: confirmed via a real crash
    (reproduced against the simplest possible fixture, root-caused with
    `cdb`) that a plain, unprotected write into a *discovered* IAT slot
    can fault with `STATUS_ACCESS_VIOLATION` -- unlike every *newly
    created* data/code blob this project emits elsewhere (always placed
    RWX precisely to avoid this -- see e.g. the delay-import lazy
    thunk's own synthetic KERNEL32 import), a pre-existing IAT slot
    inside the host's or a dependency's own original, compiler-produced
    section is placed wherever that original toolchain happened to put
    it, commonly a read-only section (`.rdata` or merged-into-`.rdata`
    IAT, a common and legitimate layout -- the loader itself can still
    write there once, during its own one-time import-snapping, via
    privileged internal calls this project's own generated code has no
    equivalent of). So every slot write here is wrapped in a real
    `VirtualProtect(page_aligned(slot), 0x1000, PAGE_READWRITE,
    &scratch_dword) ... write ... VirtualProtect(page_aligned(slot),
    0x1000, scratch_dword, &scratch_dword)` pair (`scratch_dword_va`, a
    single caller-supplied writable qword reused -- and overwritten --
    by every such pair in turn, never read back by the caller itself; no
    reentrancy/aliasing concern since this all runs synchronously,
    single-threaded, before any embedded module's own initializer).
    `virtualprotect_iat_slot_va` -- like `loadlibrarya_iat_slot_va`/
    `getprocaddress_iat_slot_va` elsewhere in this module -- is an IAT
    slot address to call *through* (`call qword ptr [slot]`), not
    `VirtualProtect`'s own address directly; the caller resolves this the
    same way it resolves every other KERNEL32 API this mechanism needs
    (see `pe_embedder.py`'s own synthetic-KERNEL32-import handling).
    Reads (the "capture the real original value" step below) never need
    this -- only a *write* to a possibly-read-only page can fault.

    This runs with no live incoming arguments to preserve (it's spliced
    into the generated init-call stub as a synthetic, no-op-DllMain-
    signature entry -- see this module's own docstring), but deliberately
    still avoids `rcx`/`rdx`/`r8`/`r9` as anything *persistent* across a
    `VirtualProtect` call regardless (every real argument-passing
    register is treated as fully clobbered by `call qword ptr [...]`,
    exactly as x64 calling convention allows any callee to do, and
    reloaded fresh from its own sentinel immediately after every such
    call rather than ever relied on to survive one). A `sub rsp,
    0x28`/`add rsp, 0x28` prologue/epilogue reserves the 32-byte shadow
    space x64 `VirtualProtect`'s own call sites need (and restores 16-
    byte stack alignment after the `call` instruction's own implicit
    8-byte push -- the exact same idiom already used for every other
    real-API call this module makes, e.g. `_x64_call_dllmain`'s `sub
    rsp, 0x28`), omitted entirely when there is nothing at all to hook
    (every `slot_vas` empty) since no `call` is ever emitted in that
    case.
    """
    pairs: List[Tuple[int, int]] = []
    lines: List[str] = []
    # Upper bound: 2 fixed (capture + save) per API entry, plus 9 per
    # discovered slot (the protect/write/restore sequence below) -- a few
    # more than strictly necessary when some `slot_vas` are empty costs
    # nothing, since unused sentinels are simply never referenced in
    # `lines`/`pairs`.
    sentinel_budget = sum(2 + 9 * len(slot_vas) for _, slot_vas, _ in entries)
    sentinels = iter(_make_hook_install_sentinels(sentinel_budget))

    for saved_cell_va, slot_vas, trampoline_va in entries:
        if not slot_vas:
            continue
        first_slot_sentinel = next(sentinels)
        pairs.append((first_slot_sentinel, slot_vas[0]))
        lines.append(f"mov r11, {first_slot_sentinel}")
        lines.append("mov rax, [r11]")  # read-only -- never faults, no protect needed
        saved_sentinel = next(sentinels)
        pairs.append((saved_sentinel, saved_cell_va))
        lines.append(f"mov r10, {saved_sentinel}")
        lines.append("mov [r10], rax")  # our own RWX data -- never faults either

        for slot_va in slot_vas:
            page_va = slot_va & ~0xFFF

            protect_page = next(sentinels)
            pairs.append((protect_page, page_va))
            lines.append(f"mov rcx, {protect_page}")
            lines.append("mov edx, 0x1000")
            lines.append("mov r8d, 0x4")  # PAGE_READWRITE
            scratch_out = next(sentinels)
            pairs.append((scratch_out, scratch_dword_va))
            lines.append(f"mov r9, {scratch_out}")
            vp_slot_1 = next(sentinels)
            pairs.append((vp_slot_1, virtualprotect_iat_slot_va))
            lines.append(f"mov rax, {vp_slot_1}")
            lines.append("call qword ptr [rax]")

            slot_sentinel = next(sentinels)
            pairs.append((slot_sentinel, slot_va))
            lines.append(f"mov r11, {slot_sentinel}")
            trampoline_sentinel = next(sentinels)
            pairs.append((trampoline_sentinel, trampoline_va))
            lines.append(f"mov rax, {trampoline_sentinel}")
            lines.append("mov [r11], rax")  # the actual hook install, now safe to write

            scratch_in = next(sentinels)
            pairs.append((scratch_in, scratch_dword_va))
            lines.append(f"mov rax, {scratch_in}")
            lines.append("mov r8d, dword ptr [rax]")  # restore: flNewProtect = the real original value
            restore_page = next(sentinels)
            pairs.append((restore_page, page_va))
            lines.append(f"mov rcx, {restore_page}")
            lines.append("mov edx, 0x1000")
            scratch_out2 = next(sentinels)
            pairs.append((scratch_out2, scratch_dword_va))
            lines.append(f"mov r9, {scratch_out2}")
            vp_slot_2 = next(sentinels)
            pairs.append((vp_slot_2, virtualprotect_iat_slot_va))
            lines.append(f"mov rax, {vp_slot_2}")
            lines.append("call qword ptr [rax]")

    if not pairs:
        return b"", []

    lines = ["sub rsp, 0x28"] + lines + ["add rsp, 0x28", "ret"]
    data = _assemble(True, "\n".join(lines))
    data, offsets = _patch_va_sentinels(data, pairs, 8)
    return data, offsets


def build_windows_stub(
    init_order: List[str],
    hooked_names: Set[str],
    *,
    is64: bool,
    dep_entry_vas: Dict[str, Tuple[int, int]],
    original_entry_va: int,
    host_is_dll: bool = False,
) -> Tuple[bytes, List[int]]:
    """Machine code for the host's new entrypoint: one DllMain-style
    process-attach call per name in `init_order` (in that order), using
    each name's `(hinst_va, entry_va)` pair from `dep_entry_vas`, then a
    tail-jump to `original_entry_va`.

    Returns `(stub_bytes, abs_va_offsets)` -- see this module's own
    docstring for why a bare `bytes` return can't carry everything the
    caller needs.

    `hooked_names` is accepted for interface compatibility with the
    design's exact `build_windows_stub(init_order, hooked_names)`
    signature, but this function itself never reads it -- the actual
    LoadLibraryW/LoadLibraryA/GetProcAddress interception machinery is
    built by the caller and spliced into `init_order`/`dep_entry_vas` as
    one more (synthetic, hinst=0) entry *before* this is called, same as
    the per-dependency TLS-index fixup already is -- see this module's
    own docstring's "Hook mechanism" section.

    `host_is_dll` (B6-PE): when the host being embedded into is itself a
    DLL (not an EXE), this stub becomes the module's real
    DllEntryPoint/DllMain, which the OS loader calls on *every*
    DLL_PROCESS_ATTACH/_THREAD_ATTACH/_THREAD_DETACH/_PROCESS_DETACH
    notification -- not just once. Per the design spec's existing
    non-goal (thread notifications and detach are not required to be
    forwarded to each embedded dependency), the per-dependency init-call
    block must only run on DLL_PROCESS_ATTACH; every other notification
    must skip straight to the tail-jump so the host's own real DllMain
    still receives it untouched. When false (the EXE-host case), no guard
    is emitted at all -- behavior is unchanged from before this parameter
    existed.
    """
    del hooked_names  # unused here by design -- see docstring above

    call_fn = _x64_call_dllmain if is64 else _x86_call_dllmain
    tail_jmp_fn = _x64_tail_jmp if is64 else _x86_tail_jmp
    guard_fn = _x64_process_attach_guard if is64 else _x86_process_attach_guard

    init_calls_bytes = bytearray()
    init_call_abs_offsets: List[int] = []
    for name in init_order:
        hinst_va, entry_va = dep_entry_vas[name]
        block, offs = call_fn(hinst_va, entry_va)
        for off in offs:
            init_call_abs_offsets.append(len(init_calls_bytes) + off)
        init_calls_bytes += block

    stub_bytes = bytearray()
    abs_va_offsets: List[int] = []

    if host_is_dll:
        guard_bytes = guard_fn(len(init_calls_bytes))
        stub_bytes += guard_bytes

    base_offset = len(stub_bytes)
    for off in init_call_abs_offsets:
        abs_va_offsets.append(base_offset + off)
    stub_bytes += init_calls_bytes

    tail_block, tail_offs = tail_jmp_fn(original_entry_va)
    for off in tail_offs:
        abs_va_offsets.append(len(stub_bytes) + off)
    stub_bytes += tail_block

    return bytes(stub_bytes), abs_va_offsets
