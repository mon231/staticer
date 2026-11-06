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

Hook mechanism (deliberately deferred): ``hooked_names`` is accepted and
threaded through for interface compatibility with the design doc's
"runtime dynamic-loading interception" goal, but this implementation does
not yet emit the LoadLibraryW/GetProcAddress IAT-interception
trampolines it describes. Installing that correctly means generating code
that runs *before* any embedded module's own initializer and:
  1. locates KERNEL32.dll's LoadLibraryW/GetProcAddress IAT slots in the
     host's own (already-merged) import directory,
  2. saves each slot's real (loader-resolved) value somewhere our own
     trampolines can read it back from,
  3. overwrites each slot with a trampoline's own address, and
  4. in each trampoline, compares the *name* being requested at runtime
     against a table of ``hooked_names`` (a wide-string compare loop
     against each entry) to decide whether to resolve against an
     embedded module's address instead of falling through to the saved
     original.
Steps 1-3 are straightforward; step 4 is real, non-trivial machine code
(safe register preservation across stdcall/x64-fastcall boundaries for
two different APIs, a string-comparison loop, an embedded wide-string
table) with an outsized blast radius if it's subtly wrong -- *every*
embed() run that calls at least one dependency's entry point through this
same stub would run it, not just hook-specific tests. Per this task's own
scoping note (mirroring Task 3's precedent of shipping a flat,
unconditional stub and explicitly deferring full hooking), and since no
test in this task's own suite exercises runtime LoadLibraryW/
GetProcAddress interception, this ships the real, tested DllMain-ordering
mechanism now and leaves steps 1-4 as documented follow-up work.

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
"""

from typing import Dict, List, Set, Tuple

from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KS_MODE_64

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
_X64_SENTINEL_A = 0x1122334455667788
_X64_SENTINEL_B = 0x8877665544332211
_X86_SENTINEL_A = 0x11223344
_X86_SENTINEL_B = 0x44332211

# Keystone engine instances are cheap to reuse and expensive-ish to
# construct repeatedly (each wraps a native handle), so one per mode is
# cached for the lifetime of the process.
_ks_engines: Dict[int, Ks] = {}


def _ks(is64: bool) -> Ks:
    mode = KS_MODE_64 if is64 else KS_MODE_32
    engine = _ks_engines.get(mode)
    if engine is None:
        engine = Ks(KS_ARCH_X86, mode)
        _ks_engines[mode] = engine
    return engine


def _assemble(is64: bool, asm_text: str) -> bytes:
    """Assemble `asm_text` (real x86/x64 assembly source) at a nominal
    base address of 0 and return the resulting machine code as `bytes`.

    The base address matters only for instructions whose encoding depends
    on an absolute target address relative to where the instruction itself
    sits (e.g. `jne <absolute address>`, used by the process-attach guards
    below) -- assembling at 0 makes that address arithmetic exact and
    reproducible. None of these stubs otherwise care what address they're
    assembled "at", since every absolute VA they embed is a sentinel
    placeholder spliced in after the fact (see module docstring).
    """
    encoding, _count = _ks(is64).asm(asm_text, 0)
    if encoding is None:
        raise ValueError(f"keystone failed to assemble: {asm_text!r}")
    return bytes(encoding)


def _patch_immediate(data: bytes, sentinel_bytes: bytes, replacement_bytes: bytes) -> Tuple[bytes, int]:
    """Locate `sentinel_bytes` within `data`, assert it occurs exactly
    once (a coincidental second occurrence would mean some *other* fixed
    opcode/operand byte in this same short sequence happens to match the
    sentinel pattern, which would make the splice below silently wrong --
    see module docstring), and return `data` with that one occurrence
    replaced by `replacement_bytes` (same length), plus the byte offset at
    which the replacement now sits.

    Caller beware: when a single assembled sequence embeds *more than one*
    sentinel (e.g. `_x64_call_dllmain`'s two VA slots), do not call this
    repeatedly against the *already-patched* buffer -- see
    `_locate_sentinel`/`_splice_at` below and the "cross-sentinel
    collision" note on `_patch_two_sentinels` for why, and use that helper
    instead for any multi-sentinel sequence.
    """
    if len(sentinel_bytes) != len(replacement_bytes):
        raise ValueError("internal error: sentinel and replacement must be the same width")
    offset = _locate_sentinel(data, sentinel_bytes)
    return _splice_at(data, offset, replacement_bytes), offset


def _locate_sentinel(data: bytes, sentinel_bytes: bytes) -> int:
    """Find `sentinel_bytes`'s one-and-only occurrence in `data` (without
    modifying it) and return its offset. Raises `ValueError` -- an
    internal-error message in this codebase's existing style (see e.g.
    `elf_embedder.py`'s "internal error: ..." `ValueError`s for other
    should-never-happen invariant violations) -- if the pattern is absent
    or, more subtly, if it occurs more than once: a second occurrence
    would mean some *other* fixed opcode/operand byte in this same short
    sequence happens to coincide with the sentinel's own byte pattern,
    which would make a blind splice silently wrong rather than loudly
    wrong. This has never been observed for any of the sequences in this
    module (verified empirically across typical, edge-case, and
    sentinel-shaped-adversarial VA/skip_len values -- see
    `tests/windows/test_pe_stub_keystone.py`), but is checked on every
    call rather than assumed, since a future change to one of these
    assembly strings could in principle introduce it.
    """
    first = data.find(sentinel_bytes)
    if first == -1:
        raise ValueError(f"internal error: sentinel pattern {sentinel_bytes.hex()} not found in assembled code {data.hex()}")
    if data.find(sentinel_bytes, first + 1) != -1:
        raise ValueError(
            f"internal error: sentinel pattern {sentinel_bytes.hex()} occurs more than once in assembled code {data.hex()}"
        )
    return first


def _splice_at(data: bytes, offset: int, replacement_bytes: bytes) -> bytes:
    return data[:offset] + replacement_bytes + data[offset + len(replacement_bytes):]


def _patch_va_sentinel(data: bytes, sentinel: int, width: int, real_va: int) -> Tuple[bytes, int]:
    """`_patch_immediate` specialised for an absolute-VA immediate: both
    the sentinel and the real value are encoded as unsigned, `width`-byte,
    little-endian integers (matching how x86/x64 `mov reg, imm` and
    `push imm32` encode their operands).

    Single-sentinel use only -- see `_patch_two_va_sentinels` for sequences
    embedding two.
    """
    sentinel_bytes = sentinel.to_bytes(width, "little")
    real_bytes = real_va.to_bytes(width, "little")
    return _patch_immediate(data, sentinel_bytes, real_bytes)


def _patch_two_va_sentinels(
    data: bytes,
    sentinel_a: int,
    real_va_a: int,
    sentinel_b: int,
    real_va_b: int,
    width: int,
) -> Tuple[bytes, int, int]:
    """Patch two independent absolute-VA sentinels in one assembled
    sequence (`_x64_call_dllmain`/`_x86_call_dllmain`/
    `build_windows_tls_index_fixup`, each of which embeds a `hinst`-ish
    slot and an `entry`-ish slot).

    Cross-sentinel collision: locates *both* sentinels' offsets against
    the original, unmodified `data` before splicing either one in. Doing
    this instead of the simpler "patch A, then search the already-patched
    buffer for B" is deliberate: if the caller-supplied real value for
    slot A happens to equal sentinel B's own constant (astronomically
    unlikely for loader/ASLR-assigned addresses, which are not
    attacker-controlled input, but not impossible, and cheap to rule out
    here), patching A first would plant sentinel B's own byte pattern a
    *second* time, and the subsequent search for B would find two matches
    instead of one -- a real, reachable `ValueError` from
    `_locate_sentinel`, not a hypothetical one. Locating both offsets
    up front, against data neither has touched yet, and only then
    splicing each one in by its own already-known offset, makes that
    scenario structurally impossible: the second lookup is never run
    against a buffer the first patch could have perturbed.
    """
    offset_a = _locate_sentinel(data, sentinel_a.to_bytes(width, "little"))
    offset_b = _locate_sentinel(data, sentinel_b.to_bytes(width, "little"))
    data = _splice_at(data, offset_a, real_va_a.to_bytes(width, "little"))
    data = _splice_at(data, offset_b, real_va_b.to_bytes(width, "little"))
    return data, offset_a, offset_b


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
    design's LoadLibraryW/GetProcAddress interception goal but is not yet
    acted on -- see this module's docstring ("Hook mechanism").

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
    del hooked_names  # deferred -- see module docstring

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
