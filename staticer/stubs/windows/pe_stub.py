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
"""

import struct
from typing import Dict, List, Set, Tuple

# Each helper below returns (bytes, [byte offsets of embedded absolute-VA
# immediates within that block]) -- moved essentially unchanged from
# Task 3/5's inline versions in pe_embedder.py (now superseded by this
# module). Those immediates are hardcoded addresses the final image must
# keep correct if it's ever loaded somewhere other than its preferred base
# (e.g. ASLR, on by default for these fixtures) -- see this module's own
# docstring on why the caller must turn each one into a new base
# relocation entry.


def _x64_call_dllmain(hinst_va: int, entry_va: int) -> Tuple[bytes, List[int]]:
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


def _x64_tail_jmp(target_va: int) -> Tuple[bytes, List[int]]:
    mov_rax_op = b"\x48\xB8"
    data = mov_rax_op + target_va.to_bytes(8, "little") + b"\xFF\xE0"
    return data, [len(mov_rax_op)]


def _x86_call_dllmain(hinst_va: int, entry_va: int) -> Tuple[bytes, List[int]]:
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


def _x86_tail_jmp(target_va: int) -> Tuple[bytes, List[int]]:
    mov_eax_op = b"\xB8"
    data = mov_eax_op + target_va.to_bytes(4, "little") + b"\xFF\xE0"
    return data, [len(mov_eax_op)]


_DLL_PROCESS_ATTACH = 1


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
    return b"\x83\xFA\x01" + b"\x0F\x85" + skip_len.to_bytes(4, "little", signed=True)


def _x86_process_attach_guard(skip_len: int) -> bytes:
    # cmp dword [esp+8], 1 ; jne +skip_len -- same guard as the x64
    # version above, but fdwReason is __stdcall's 2nd stack argument here
    # ([esp+0]=return address, [esp+4]=hinstDLL, [esp+8]=fdwReason) rather
    # than a register, since this stub's entrypoint hasn't pushed anything
    # of its own yet at this point.
    return b"\x83\x7C\x24\x08\x01" + b"\x0F\x85" + skip_len.to_bytes(4, "little", signed=True)


def _mov_r64_imm64(reg_opcode: int, imm64: int) -> bytes:
    return bytes([0x48, reg_opcode]) + imm64.to_bytes(8, "little")


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
    """
    out = bytearray()
    abs_offsets: List[int] = []

    out += _mov_r64_imm64(0xB8, host_tlsindex_va)  # mov rax, host_tlsindex_va
    abs_offsets.append(len(out) - 8)
    out += bytes([0x8B, 0x08])  # mov ecx, [rax]
    out += _mov_r64_imm64(0xB8, dep_tlsindex_va)  # mov rax, dep_tlsindex_va
    abs_offsets.append(len(out) - 8)
    out += bytes([0x89, 0x08])  # mov [rax], ecx
    out += bytes([0xC3])  # ret

    return bytes(out), abs_offsets


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
