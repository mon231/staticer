"""Unit tests for staticer/stubs/linux/elf_stub.py's byte-level output.

These exercise build_linux_stub/build_linux_init_array_stub directly, at
the Python level -- no compiled fixture, no subprocess, no Linux
required -- so they run on every platform's CI, unlike
tests/linux/test_elf_unwind.py's own end-to-end regression coverage
(which actually executes the generated stub on real Linux and is the
*only* thing that can catch the kind of ABI-register/stack-alignment bug
this module's own docstring describes).

What these tests are for: pinning the exact bytes the Keystone-based
build_linux_stub()/build_linux_init_array_stub() produce as a golden
regression -- so a future, accidental change to the assembly text (a
typo in a mnemonic, a reordered instruction, Keystone encoding the same
mnemonic differently across a version bump) is caught immediately, at
import time, on any platform -- rather than only much later, via a
run-it-on-real-Linux-and-see-if-it-crashes test. They do NOT replace
test_elf_unwind.py's own execution-based coverage; see that module's
docstring for why some of this file's own history (the rtld_fini bug,
the stack-realignment overshoot bug) was only ever caught that way.
"""

from staticer.stubs.linux.elf_stub import build_linux_init_array_stub, build_linux_stub

# Golden byte sequences -- these are exactly what the old, hand-encoded
# version of this module produced (and are still correct: the ABI facts
# they encode -- callee-saved-register choice, rtld_fini's register,
# the stack-realignment instruction -- haven't changed, only how the
# bytes are produced). Verified byte-for-byte against the pre-refactor
# implementation before this file was written.
_INITARRAY_PROLOGUE_64 = bytes.fromhex("41544989e44883e4f0")  # push r12; mov r12,rsp; and rsp,-16
_INITARRAY_PROLOGUE_32 = bytes.fromhex("5789e783e4f0")  # push edi; mov edi,esp; and esp,-16
_INITARRAY_EPILOGUE_64 = bytes.fromhex("4c89e4415cc3")  # mov rsp,r12; pop r12; ret
_INITARRAY_EPILOGUE_32 = bytes.fromhex("89fc5fc3")  # mov esp,edi; pop edi; ret

_MAIN_PROLOGUE_64 = bytes.fromhex("4989e74889d34883e4f0")  # mov r15,rsp; mov rbx,rdx; and rsp,-16
_MAIN_PROLOGUE_32 = bytes.fromhex("89e789d683e4f0")  # mov edi,esp; mov esi,edx; and esp,-16
_MAIN_EPILOGUE_64 = bytes.fromhex("4889da4c89fc")  # mov rdx,rbx; mov rsp,r15
_MAIN_EPILOGUE_32 = bytes.fromhex("89f289fc")  # mov edx,esi; mov esp,edi


def _call_seq_64(addr: int) -> bytes:
    return b"\x48\xB8" + addr.to_bytes(8, "little") + b"\xFF\xD0"  # mov rax,imm64; call rax


def _call_seq_32(addr: int) -> bytes:
    return b"\xB8" + addr.to_bytes(4, "little") + b"\xFF\xD0"  # mov eax,imm32; call eax


def _tail_jmp_seq_64(addr: int) -> bytes:
    return b"\x48\xB9" + addr.to_bytes(8, "little") + b"\xFF\xE1"  # mov rcx,imm64; jmp rcx


def _tail_jmp_seq_32(addr: int) -> bytes:
    return b"\xB9" + addr.to_bytes(4, "little") + b"\xFF\xE1"  # mov ecx,imm32; jmp ecx


def test_init_array_stub_64_bytes_and_relocs():
    calls = [0x401000, 0x7F1234560000, 0x0000555500001234]
    code, relocs = build_linux_init_array_stub(is64=True, init_calls=calls)

    expected = bytearray(_INITARRAY_PROLOGUE_64)
    expected_relocs = []
    for addr in calls:
        expected_relocs.append(len(expected) + 2)  # past "mov rax," opcode bytes
        expected.extend(_call_seq_64(addr))
    expected.extend(_INITARRAY_EPILOGUE_64)

    assert code == bytes(expected)
    assert relocs == expected_relocs
    # Every reported offset must really point at the matching call's own
    # 8-byte little-endian immediate.
    for addr, off in zip(calls, relocs):
        assert code[off : off + 8] == addr.to_bytes(8, "little")


def test_init_array_stub_32_bytes_and_relocs():
    calls = [0x08049000, 0x0804A000]
    code, relocs = build_linux_init_array_stub(is64=False, init_calls=calls)

    expected = bytearray(_INITARRAY_PROLOGUE_32)
    expected_relocs = []
    for addr in calls:
        expected_relocs.append(len(expected) + 1)  # past "mov eax," opcode byte
        expected.extend(_call_seq_32(addr))
    expected.extend(_INITARRAY_EPILOGUE_32)

    assert code == bytes(expected)
    assert relocs == expected_relocs
    for addr, off in zip(calls, relocs):
        assert code[off : off + 4] == addr.to_bytes(4, "little")


def test_init_array_stub_64_no_calls():
    # Zero embedded dependencies is a legitimate degenerate case.
    code, relocs = build_linux_init_array_stub(is64=True, init_calls=[])
    assert code == _INITARRAY_PROLOGUE_64 + _INITARRAY_EPILOGUE_64
    assert relocs == []


def test_main_stub_64_bytes_and_relocs():
    calls = [0x401000, 0x7F1234560000]
    entry = 0x400F00
    code, relocs = build_linux_stub([], set(), is64=True, init_calls=calls, original_entry=entry)

    expected = bytearray(_MAIN_PROLOGUE_64)
    expected_relocs = []
    for addr in calls:
        expected_relocs.append(len(expected) + 2)
        expected.extend(_call_seq_64(addr))
    expected.extend(_MAIN_EPILOGUE_64)
    expected_relocs.append(len(expected) + 2)
    expected.extend(_tail_jmp_seq_64(entry))

    assert code == bytes(expected)
    assert relocs == expected_relocs
    for addr, off in zip(calls + [entry], relocs):
        assert code[off : off + 8] == addr.to_bytes(8, "little")


def test_main_stub_32_bytes_and_relocs():
    calls = [0x08049000]
    entry = 0x08048000
    code, relocs = build_linux_stub([], set(), is64=False, init_calls=calls, original_entry=entry)

    expected = bytearray(_MAIN_PROLOGUE_32)
    expected_relocs = []
    for addr in calls:
        expected_relocs.append(len(expected) + 1)
        expected.extend(_call_seq_32(addr))
    expected.extend(_MAIN_EPILOGUE_32)
    expected_relocs.append(len(expected) + 1)
    expected.extend(_tail_jmp_seq_32(entry))

    assert code == bytes(expected)
    assert relocs == expected_relocs
    for addr, off in zip(calls + [entry], relocs):
        assert code[off : off + 4] == addr.to_bytes(4, "little")


def test_main_stub_hooked_names_not_implemented():
    import pytest

    with pytest.raises(NotImplementedError):
        build_linux_stub(
            [], {"dlopen"}, is64=True, init_calls=[0x1000], original_entry=0x2000
        )


def test_main_stub_sanity_assert_holds_for_large_call_count():
    # Regression guard: every reloc offset + ptr_size must stay within
    # bounds no matter how many init calls are emitted (this is exactly
    # what build_linux_stub's own trailing `assert` checks internally).
    calls = list(range(0x400000, 0x400000 + 64 * 0x1000, 0x1000))
    code, relocs = build_linux_stub(
        [], set(), is64=True, init_calls=calls, original_entry=0x401000
    )
    assert all(off + 8 <= len(code) for off in relocs)
    assert len(relocs) == len(calls) + 1  # one per call, plus the tail jump
