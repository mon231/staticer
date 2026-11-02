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


def build_windows_stub(
    init_order: List[str],
    hooked_names: Set[str],
    *,
    is64: bool,
    dep_entry_vas: Dict[str, Tuple[int, int]],
    original_entry_va: int,
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
    """
    del hooked_names  # deferred -- see module docstring

    call_fn = _x64_call_dllmain if is64 else _x86_call_dllmain
    tail_jmp_fn = _x64_tail_jmp if is64 else _x86_tail_jmp

    stub_bytes = bytearray()
    abs_va_offsets: List[int] = []
    for name in init_order:
        hinst_va, entry_va = dep_entry_vas[name]
        block, offs = call_fn(hinst_va, entry_va)
        for off in offs:
            abs_va_offsets.append(len(stub_bytes) + off)
        stub_bytes += block

    tail_block, tail_offs = tail_jmp_fn(original_entry_va)
    for off in tail_offs:
        abs_va_offsets.append(len(stub_bytes) + off)
    stub_bytes += tail_block

    return bytes(stub_bytes), abs_va_offsets
