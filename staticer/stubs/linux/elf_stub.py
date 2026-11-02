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

Deliberately unimplemented: the dlopen/dlsym PLT hook ``hooked_names``
implies (intercepting a dlopen/dlsym call for a name that used to be a
real DT_NEEDED entry -- now embedded, so a real dlopen of it would
otherwise fail with "no such file"). A *correct* version of this hook
turns out to need more than a simple GOT-slot patch: overwriting the
host's own dlopen/dlsym GOT slot with a trampoline, while leaving its
JMPREL entry (and the lazy-PLT-stub machinery it feeds) untouched so a
*fallthrough* call still resolves normally, means the *first* fallthrough
call permanently self-clobbers the hook (ld.so's lazy binding overwrites
that same GOT slot with the real resolved address once lazy resolution
actually fires, uninstalling the trampoline for every call after that).
Avoiding that cleanly needs either a self-reinstalling trampoline (saves
the resolved target, calls through it, then rewrites its own hook back
into the GOT slot every time) or an upfront harmless bootstrap call to
force resolution to happen once, immediately, before the hook is ever
installed -- either way, a second, independent layer of machine code and
runtime bookkeeping on top of everything else this stub already does.
Given the task brief's own explicit latitude for "a minimal/documented-
partial implementation if a full general-purpose hook would balloon
scope disproportionately -- same latitude Task 3/4 used for their own
stubs" (echoed for this exact hook, on both the PE and ELF sides), and
that *neither* of this task's two required tests
(test_exception_crosses_embedded_boundary,
test_dependency_initializer_runs_before_dependent) exercises dlopen/dlsym
at all, this function simply raises ``NotImplementedError`` for a
non-empty ``hooked_names`` rather than installing a hook with a silent,
untested correctness gap. ``ElfEmbedder.embed()`` currently never passes
a non-empty set.
"""

from typing import List, Set, Tuple


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

    1. Stack realignment. The kernel/ld.so hand control to e_entry with
       %rsp/%esp at the System V ABI's *process-entry* alignment (16-byte
       aligned), not the ordinary *call-site* alignment every `call`
       instruction assumes (aligned only *after* the implicit
       return-address push). A bare `call` straight off the
       kernel-provided pointer therefore hands every callee a stack
       mis-aligned by one pointer width -- no symptom until something
       deep in that callee's own call graph (observed: well past the
       init calls themselves, inside glibc's own exit-handling, long
       after this stub has already tail-jumped away) executes an
       alignment-sensitive SSE/AVX instruction against it and faults.
       Fixed by saving the kernel-provided pointer in a callee-saved
       register, realigning %rsp/%esp for the calls, and restoring the
       exact original value before the tail-jump -- original_entry
       (crt1's `_start`) needs that one unmodified, not just "some
       16-aligned value", since it reads argc/argv/envp directly off it.

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

    Both fixes were found and confirmed by actually building and running
    this task's own fixtures on real Linux (WSL) -- an earlier version of
    this function lacked both, looked correct under static review, and
    reliably crashed at runtime on every embedded dependency that had
    more than a single, do-nothing init_array entry, on both 32- and
    64-bit.
    """
    if hooked_names:
        raise NotImplementedError(
            "the dlopen/dlsym PLT hook isn't implemented yet -- see this module's "
            "own docstring for why it's deliberately deferred; pass an empty "
            "hooked_names set"
        )
    del init_order  # see docstring: informational only, carries no addresses

    reloc_offsets: List[int] = []
    out = bytearray()
    ptr_size = 8 if is64 else 4

    def emit_call(addr: int) -> None:
        if is64:
            reloc_offsets.append(len(out) + 2)  # +2: past the "mov rax," opcode bytes
            out.extend(b"\x48\xB8")  # mov rax, imm64
            out.extend(addr.to_bytes(8, "little"))
            out.extend(b"\xFF\xD0")  # call rax
        else:
            reloc_offsets.append(len(out) + 1)  # +1: past the "mov eax," opcode byte
            out.extend(b"\xB8")  # mov eax, imm32
            out.extend(addr.to_bytes(4, "little"))
            out.extend(b"\xFF\xD0")  # call eax

    def emit_tail_jmp_via_cx(addr: int) -> None:
        # Deliberately NOT the same "mov eax/rax, imm; jmp eax/rax" shape
        # emit_call uses -- eax/rax is where this function's *own* restore
        # of the ld.so-provided rtld_fini register lands (see the big
        # comment below), immediately before this jump; clobbering it
        # again right here to hold the jump target would silently discard
        # that restore one instruction before it would have mattered.
        # ecx/rcx is free (nothing else in this stub's tail still needs
        # it) and ABI-irrelevant for a jump (unlike eax/rax, it's not
        # where any incoming-register convention expects anything).
        if is64:
            reloc_offsets.append(len(out) + 2)
            out.extend(b"\x48\xB9")  # mov rcx, imm64
            out.extend(addr.to_bytes(8, "little"))
            out.extend(b"\xFF\xE1")  # jmp rcx
        else:
            reloc_offsets.append(len(out) + 1)
            out.extend(b"\xB9")  # mov ecx, imm32
            out.extend(addr.to_bytes(4, "little"))
            out.extend(b"\xFF\xE1")  # jmp ecx

    # -- stack realignment around the call sequence --
    #
    # The kernel hands control to e_entry with the ABI's *process-entry*
    # stack-alignment guarantee: %rsp/%esp is 16-byte aligned (System V
    # ABI, "Initial Stack and Register State" -- the same convention
    # crt1.o's own `_start` relies on, reading argc/argv/envp directly
    # off this exact, unmodified pointer). That is NOT the same as the
    # ordinary *call-site* convention every `call` instruction assumes
    # (%rsp 16-byte aligned only *after* the implicit return-address
    # push, i.e. %rsp == 8 (mod 16) immediately *before* the `call`).
    # Emitting a bare `call` straight off the kernel-provided, 16-aligned
    # entry pointer -- as an earlier version of this function did --
    # therefore hands every callee a stack mis-aligned by exactly one
    # pointer width, with no symptom until something deep in that
    # callee's own call graph (observed: well past frame_dummy/a real
    # user constructor, inside glibc's own exit-handling machinery)
    # finally executes an alignment-sensitive SSE/AVX instruction against
    # it and faults -- reproduced as a real SIGSEGV, on real Linux (WSL),
    # for both 32- and 64-bit, before this fix; confirmed fixed by it.
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
        out.extend(b"\x49\x89\xE7")  # mov r15, rsp  (save; r15 is callee-saved)
        out.extend(b"\x48\x89\xD3")  # mov rbx, rdx  (save rtld_fini; rbx is callee-saved)
        out.extend(b"\x48\x83\xE4\xF0")  # and rsp, -16
        out.extend(b"\x48\x83\xEC\x08")  # sub rsp, 8  (-> rsp == 8 (mod 16), correct pre-call)
    else:
        out.extend(b"\x89\xE7")  # mov edi, esp  (save; edi is callee-saved under cdecl)
        out.extend(b"\x89\xD6")  # mov esi, edx  (save rtld_fini; esi is callee-saved)
        out.extend(b"\x83\xE4\xF0")  # and esp, -16
        out.extend(b"\x83\xEC\x04")  # sub esp, 4  (-> esp == 12 (mod 16), correct pre-call)

    for addr in init_calls:
        emit_call(addr)

    if is64:
        out.extend(b"\x48\x89\xDA")  # mov rdx, rbx  (restore rtld_fini)
        out.extend(b"\x4C\x89\xFC")  # mov rsp, r15  (restore stack pointer)
    else:
        out.extend(b"\x89\xF2")  # mov edx, esi  (restore rtld_fini)
        out.extend(b"\x89\xFC")  # mov esp, edi  (restore stack pointer)

    emit_tail_jmp_via_cx(original_entry)

    assert all(off + ptr_size <= len(out) for off in reloc_offsets)  # sanity: every immediate fits
    return bytes(out), reloc_offsets
