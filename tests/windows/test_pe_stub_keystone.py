"""Regression tests for the Keystone-assembled builders in
``staticer/stubs/windows/pe_stub.py``.

These exercise the byte-producing helpers directly (unlike the rest of
``tests/windows``, which mostly exercises ``build_windows_stub``/
``build_windows_tls_index_fixup`` end-to-end through real PE embeds) to
pin down two things the embed-level tests can't easily isolate:

1. Byte-for-byte parity with this module's own pre-Keystone, hand-encoded
   implementation, across edge-case immediate values (not just the
   "happy path" addresses a real embed would produce) -- so a change to
   the assembly source text or the sentinel-splice logic that silently
   alters the emitted opcodes gets caught here, not just as a confusing
   failure three layers up in an embedded, run binary.
2. The sentinel-splice helpers' own failure modes (missing / duplicated
   sentinel pattern), since a silent mis-splice would otherwise produce
   plausible-looking but wrong machine code. This includes the
   cross-sentinel collision case for multi-sentinel sequences
   (`_x64_call_dllmain`/`_x86_call_dllmain`/`build_windows_tls_index_fixup`,
   each of which embeds two independent VA sentinels): a caller-supplied
   real value for one slot that happens to equal the *other* slot's
   sentinel constant. `_patch_two_va_sentinels` handles this by locating
   both sentinels' offsets against the unpatched buffer before splicing
   either one in, so the second lookup never runs against a buffer the
   first splice could have perturbed -- tested directly below against
   the real builders, not just `_patch_immediate` in isolation.
"""

import pytest

from staticer.stubs.windows.pe_stub import (
    _patch_immediate,
    _X64_SENTINEL_A,
    _X64_SENTINEL_B,
    _X86_SENTINEL_A,
    _X86_SENTINEL_B,
    _x64_call_dllmain,
    _x64_process_attach_guard,
    _x64_tail_jmp,
    _x86_call_dllmain,
    _x86_process_attach_guard,
    _x86_tail_jmp,
    build_windows_tls_index_fixup,
)


def _old_x64_call_dllmain(hinst_va, entry_va):
    prefix = b"\x51\x52\x41\x50\x41\x51\x48\x83\xEC\x28"
    mov_rcx_op = b"\x48\xB9"
    hinst_off = len(prefix) + len(mov_rcx_op)
    mid = b"\xBA\x01\x00\x00\x00\x45\x31\xC0"
    mov_rax_op = b"\x48\xB8"
    entry_off = hinst_off + 8 + len(mid) + len(mov_rax_op)
    tail = b"\xFF\xD0\x48\x83\xC4\x28\x41\x59\x41\x58\x5A\x59"
    data = (
        prefix + mov_rcx_op + hinst_va.to_bytes(8, "little") + mid
        + mov_rax_op + entry_va.to_bytes(8, "little") + tail
    )
    return data, [hinst_off, entry_off]


def _old_x64_tail_jmp(target_va):
    data = b"\x48\xB8" + target_va.to_bytes(8, "little") + b"\xFF\xE0"
    return data, [2]


def _old_x86_call_dllmain(hinst_va, entry_va):
    prefix = b"\x6A\x00\x6A\x01"
    push_op = b"\x68"
    hinst_off = len(prefix) + len(push_op)
    mov_eax_op = b"\xB8"
    entry_off = hinst_off + 4 + len(mov_eax_op)
    tail = b"\xFF\xD0"
    data = (
        prefix + push_op + hinst_va.to_bytes(4, "little")
        + mov_eax_op + entry_va.to_bytes(4, "little") + tail
    )
    return data, [hinst_off, entry_off]


def _old_x86_tail_jmp(target_va):
    data = b"\xB8" + target_va.to_bytes(4, "little") + b"\xFF\xE0"
    return data, [1]


def _old_x64_process_attach_guard(skip_len):
    return b"\x83\xFA\x01" + b"\x0F\x85" + skip_len.to_bytes(4, "little", signed=True)


def _old_x86_process_attach_guard(skip_len):
    return b"\x83\x7C\x24\x08\x01" + b"\x0F\x85" + skip_len.to_bytes(4, "little", signed=True)


def _old_tls_index_fixup(host_tlsindex_va, dep_tlsindex_va):
    def mov_r64_imm64(reg_opcode, imm64):
        return bytes([0x48, reg_opcode]) + imm64.to_bytes(8, "little")

    out = bytearray()
    offs = []
    out += mov_r64_imm64(0xB8, host_tlsindex_va)
    offs.append(len(out) - 8)
    out += bytes([0x8B, 0x08])
    out += mov_r64_imm64(0xB8, dep_tlsindex_va)
    offs.append(len(out) - 8)
    out += bytes([0x89, 0x08])
    out += bytes([0xC3])
    return bytes(out), offs


# A spread of VA-shaped values: typical ASLR-relocated user-mode
# addresses, the smallest/largest representable in each width, and values
# whose own byte pattern is deliberately adversarial (e.g. repeating the
# sentinel's own alternating-nibble shape) to make sure the sentinel
# -splice logic isn't accidentally relying on the *real* value's shape.
_X64_VA_CASES = [
    (0x7FFABCDE1000, 0x7FFABCDE2000),
    (0x140001000, 0x140002000),
    (0, 0),
    (0xFFFFFFFFFFFFFFFF, 0x1),
    (0x1122334455667788, 0x8877665544332211),  # the sentinels themselves
]

_X86_VA_CASES = [
    (0x401000, 0x402000),
    (0, 0),
    (0xFFFFFFFF, 0x1),
    (0x11223344, 0x44332211),  # the sentinels themselves
]

_SKIP_LEN_CASES = [0, 9, 11, 1000, 54321, 123456, 0x7FFFFFFF - 11]


@pytest.mark.parametrize("hinst_va,entry_va", _X64_VA_CASES)
def test_x64_call_dllmain_matches_legacy_encoding(hinst_va, entry_va):
    assert _x64_call_dllmain(hinst_va, entry_va) == _old_x64_call_dllmain(hinst_va, entry_va)


@pytest.mark.parametrize("hinst_va,entry_va", _X64_VA_CASES)
def test_x64_tail_jmp_matches_legacy_encoding(hinst_va, entry_va):
    assert _x64_tail_jmp(entry_va) == _old_x64_tail_jmp(entry_va)


@pytest.mark.parametrize("hinst_va,entry_va", _X86_VA_CASES)
def test_x86_call_dllmain_matches_legacy_encoding(hinst_va, entry_va):
    assert _x86_call_dllmain(hinst_va, entry_va) == _old_x86_call_dllmain(hinst_va, entry_va)


@pytest.mark.parametrize("hinst_va,entry_va", _X86_VA_CASES)
def test_x86_tail_jmp_matches_legacy_encoding(hinst_va, entry_va):
    assert _x86_tail_jmp(entry_va) == _old_x86_tail_jmp(entry_va)


@pytest.mark.parametrize("skip_len", _SKIP_LEN_CASES)
def test_x64_process_attach_guard_matches_legacy_encoding(skip_len):
    assert _x64_process_attach_guard(skip_len) == _old_x64_process_attach_guard(skip_len)


@pytest.mark.parametrize("skip_len", _SKIP_LEN_CASES)
def test_x86_process_attach_guard_matches_legacy_encoding(skip_len):
    assert _x86_process_attach_guard(skip_len) == _old_x86_process_attach_guard(skip_len)


@pytest.mark.parametrize("host_va,dep_va", _X64_VA_CASES)
def test_tls_index_fixup_matches_legacy_encoding(host_va, dep_va):
    assert build_windows_tls_index_fixup(
        host_tlsindex_va=host_va, dep_tlsindex_va=dep_va
    ) == _old_tls_index_fixup(host_va, dep_va)


def test_patch_immediate_rejects_missing_sentinel():
    data = b"\x90\x90\x90\x90"
    with pytest.raises(ValueError):
        _patch_immediate(data, b"\x11\x22\x33\x44", b"\x55\x66\x77\x88")


def test_patch_immediate_rejects_duplicated_sentinel():
    data = b"\x11\x22\x33\x44\x00\x11\x22\x33\x44"
    with pytest.raises(ValueError):
        _patch_immediate(data, b"\x11\x22\x33\x44", b"\x55\x66\x77\x88")


def test_patch_immediate_splices_single_occurrence():
    data = b"\x90\x11\x22\x33\x44\x90"
    patched, offset = _patch_immediate(data, b"\x11\x22\x33\x44", b"\xAA\xBB\xCC\xDD")
    assert offset == 1
    assert patched == b"\x90\xAA\xBB\xCC\xDD\x90"


# Cross-sentinel collision: the real value supplied for one VA slot
# happens to equal the *other* slot's sentinel constant. This is a real,
# reachable scenario for a naive "patch A, then search the already
# -patched buffer for B" implementation (the first splice would plant
# sentinel B's own byte pattern a second time, so the search for B finds
# two matches and raises) -- not merely a hypothetical one, even though
# triggering it in practice would require a loader/ASLR-assigned address
# to coincidentally equal one of these fixed constants. `_x64_call_dllmain`
# /`_x86_call_dllmain`/`build_windows_tls_index_fixup` must produce the
# exact same bytes a direct (non-colliding) call would, for both
# directions of the collision (slot A's real value == sentinel B, and
# slot B's real value == sentinel A).

def test_x64_call_dllmain_cross_sentinel_collision_slot_a():
    hinst_va, entry_va = _X64_SENTINEL_B, 0x140002000
    assert _x64_call_dllmain(hinst_va, entry_va) == _old_x64_call_dllmain(hinst_va, entry_va)


def test_x64_call_dllmain_cross_sentinel_collision_slot_b():
    hinst_va, entry_va = 0x140001000, _X64_SENTINEL_A
    assert _x64_call_dllmain(hinst_va, entry_va) == _old_x64_call_dllmain(hinst_va, entry_va)


def test_x86_call_dllmain_cross_sentinel_collision_slot_a():
    hinst_va, entry_va = _X86_SENTINEL_B, 0x402000
    assert _x86_call_dllmain(hinst_va, entry_va) == _old_x86_call_dllmain(hinst_va, entry_va)


def test_x86_call_dllmain_cross_sentinel_collision_slot_b():
    hinst_va, entry_va = 0x401000, _X86_SENTINEL_A
    assert _x86_call_dllmain(hinst_va, entry_va) == _old_x86_call_dllmain(hinst_va, entry_va)


def test_tls_index_fixup_cross_sentinel_collision_slot_a():
    host_va, dep_va = _X64_SENTINEL_B, 0x140006000
    assert build_windows_tls_index_fixup(
        host_tlsindex_va=host_va, dep_tlsindex_va=dep_va
    ) == _old_tls_index_fixup(host_va, dep_va)


def test_tls_index_fixup_cross_sentinel_collision_slot_b():
    host_va, dep_va = 0x140005000, _X64_SENTINEL_A
    assert build_windows_tls_index_fixup(
        host_tlsindex_va=host_va, dep_tlsindex_va=dep_va
    ) == _old_tls_index_fixup(host_va, dep_va)
