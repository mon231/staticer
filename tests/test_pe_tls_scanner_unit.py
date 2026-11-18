"""Pure byte-level unit tests for `_patch_dep_tls_access_offsets` (the TLS
phase-2 merge's compiled-access-pattern scanner in `staticer/pe_embedder.py`).
No real PE build/compiler needed -- these hand-craft the exact instruction
bytes each compiler idiom produces and check the scanner finds + shifts the
right one. Runs on any OS, unlike the rest of the PE test suite.
"""

from staticer.pe_embedder import _patch_dep_tls_access_offsets


def _mingw_blob(load_reg_modrm: int, dep_index_rva: int, access_disp: int, shift: int):
    """Builds: `mov <reg>, [rip+disp32]` (the _tls_index load, at offset
    `anchor`), followed by the real mingw-w64-compiled shape confirmed
    against actual `x86_64-w64-mingw32-gcc -O2` output -- a TEB load
    (`mov rdx, gs:[0x58]`) then the scale-8 SIB-addressed load that
    combines it with the just-loaded `_tls_index` value (`mov rax,
    [rdx+rax*8]`) -- immediately (zero-gap) followed by `mov eax,
    [rax+disp32]` (the mingw-style variable-specific access
    `_try_patch_mingw_style_tls_access` looks for, now requiring that
    zero-gap scale-8 SIB load right before it as real corroboration --
    see its own docstring for why). `load_reg_modrm` is the anchor's own
    ModRM byte (varies by which register the load targets)."""
    blob = bytearray(4)  # leading padding so the REX prefix (if any) isn't at index 0
    anchor = len(blob)
    blob += bytes([0x8B, load_reg_modrm])
    disp = dep_index_rva - (anchor + 6)
    blob += disp.to_bytes(4, "little", signed=True)
    blob += bytes([0x65, 0x48, 0x8B, 0x14, 0x25, 0x58, 0x00, 0x00, 0x00])  # mov rdx, gs:[0x58]
    blob += bytes([0x48, 0x8B, 0x04, 0xC2])  # mov rax, [rdx+rax*8] -- scale-8 SIB load
    access_start = len(blob)
    blob += bytes([0x8B, 0x80])  # mov eax, [rax+disp32] (mod=10, rm=000)
    blob += access_disp.to_bytes(4, "little", signed=True)
    blob += bytes(4)  # trailing padding
    return blob, access_start + 2


def test_scanner_shifts_mingw_style_access_with_ordinary_register_load():
    dep_index_rva = 0x1000
    shift = 0x40
    blob, disp_off = _mingw_blob(load_reg_modrm=0x0D, dep_index_rva=dep_index_rva,
                                  access_disp=8, shift=shift)

    patched, anchors_found = _patch_dep_tls_access_offsets(blob, dep_index_rva, shift)

    assert (patched, anchors_found) == (1, 1)
    result = int.from_bytes(blob[disp_off:disp_off + 4], "little", signed=True)
    assert result == 8 + shift


def test_scanner_shifts_mingw_style_access_with_extended_register_load():
    """The _tls_index load itself uses an extended x64 register (r9d, via a
    REX.R prefix byte immediately before the 0x8B opcode) rather than one of
    the original 8 (eax-edi). `_try_patch_msvc_style_tls_access`'s docstring
    claims this was re-reviewed and confirmed to already work, since the
    anchor match only looks at the ModRM reg-field bits (REX-position-
    independent) -- this exercises that claim with a real byte-for-byte
    case instead of leaving it as hand-traced-only.
    """
    dep_index_rva = 0x2000
    shift = 0x80
    blob, disp_off = _mingw_blob(load_reg_modrm=0x0D, dep_index_rva=dep_index_rva,
                                  access_disp=16, shift=shift)
    # Insert a REX.R prefix (0x44) right before the anchor's 0x8B opcode --
    # this is what `mov r9d, [rip+disp32]` looks like -- and shift the
    # dep_index_rva encoding to still land on the same absolute target
    # (the opcode moves one byte later, so the disp32 field needs the same
    # +1 adjustment to its base for the same target RVA).
    anchor = 4
    rex_blob = bytearray(blob[:anchor]) + bytearray([0x44]) + bytearray(blob[anchor:])
    disp_field_off = anchor + 1 + 2
    new_disp = dep_index_rva - (anchor + 1 + 6)
    rex_blob[disp_field_off:disp_field_off + 4] = new_disp.to_bytes(4, "little", signed=True)

    patched, anchors_found = _patch_dep_tls_access_offsets(rex_blob, dep_index_rva, shift)

    assert (patched, anchors_found) == (1, 1)
    patched_off = disp_off + 1  # shifted by the inserted REX byte
    result = int.from_bytes(rex_blob[patched_off:patched_off + 4], "little", signed=True)
    assert result == 16 + shift


def _msvc_blob_with_hazardous_anchor_disp(access_offset: int, shift: int):
    """Builds the exact real-world instruction shape found in SHLWAPI.dll's
    own compiled TLS access (see `_try_patch_msvc_style_tls_access`'s own
    docstring example and `_patch_dep_tls_access_offsets`'s long comment
    about this): the anchor's own disp32 (`0x0005bde2`, the real value
    observed) has `0xbd` as its second byte -- squarely inside `0xB8-0xBF`,
    the opcode range `_try_patch_msvc_style_tls_access`'s backward window
    scan looks for a `mov r32, imm32` in. This is the regression case for
    the bug where that scan walked *into* the anchor's own 6 bytes and
    misread part of its disp32 (plus the start of the following real `mov
    r64, gs:[0x58]` instruction) as an unrelated immediate, corrupting
    both instead of finding the real `mov edx, <access_offset>` that
    follows the TEB load. Returns `(blob, imm_off, anchor_begin,
    tls_index_load_end)`.
    """
    blob = bytearray(4)  # leading padding
    anchor = len(blob)
    hazardous_disp = 0x0005BDE2
    dep_index_rva = anchor + 6 + hazardous_disp
    blob += bytes([0x8B, 0x0D])  # mov ecx, [rip+disp32]
    blob += hazardous_disp.to_bytes(4, "little", signed=True)
    tls_index_load_end = len(blob)
    blob += bytes([0x65, 0x48, 0x8B, 0x04, 0x25, 0x58, 0x00, 0x00, 0x00])  # mov rax, gs:[0x58]
    imm_off = len(blob) + 1
    blob += bytes([0xBA]) + access_offset.to_bytes(4, "little", signed=True)  # mov edx, imm32
    blob += bytes([0x48, 0x8B, 0x04, 0xC8])  # mov rax, [rax+rcx*8]
    blob += bytes(8)  # trailing padding
    return blob, imm_off, anchor, tls_index_load_end, dep_index_rva


def test_scanner_does_not_misparse_anchor_disp32_as_msvc_immediate():
    """Regression test for the real 010 Editor / SHLWAPI.dll crash: a
    hazardous anchor disp32 byte must not be mistaken for a `mov r32,
    imm32` opcode, and the anchor's own bytes (nor the following real
    instruction's opcode bytes) must come out unmodified -- only the
    genuine `mov edx, <access_offset>` later in the sequence gets shifted.
    """
    access_offset = 0x148
    shift = 0x1000
    blob, imm_off, anchor, tls_index_load_end, dep_index_rva = _msvc_blob_with_hazardous_anchor_disp(
        access_offset, shift
    )
    anchor_bytes_before = bytes(blob[anchor:tls_index_load_end])

    patched, anchors_found = _patch_dep_tls_access_offsets(blob, dep_index_rva, shift)

    assert (patched, anchors_found) == (1, 1)
    # The anchor's own 6 bytes (including its hazardous disp32) must be
    # untouched -- `_tls_index` still loads from the correct address.
    assert bytes(blob[anchor:tls_index_load_end]) == anchor_bytes_before
    # The real per-variable offset constant is the one that got shifted.
    result = int.from_bytes(blob[imm_off:imm_off + 4], "little", signed=True)
    assert result == access_offset + shift


def _msvc_blob_with_hazardous_intervening_instruction(access_offset: int, shift: int):
    """Builds the exact real-world instruction shape found in
    SHELL32.dll's own compiled TLS access (see
    `_try_patch_msvc_style_tls_access`'s own docstring): the anchor is
    immediately followed by a handful of *genuinely unrelated*
    instructions (an `inc eax`, then a `mov [rip+disp32], eax` store
    whose own disp32 happens to contain `0xba`, squarely in the
    `0xB8-0xBF` opcode range `_try_patch_msvc_style_tls_access` looks
    for), *before* the real `mov r64, gs:[0x58]` TEB load and the real
    `mov r9d, <access_offset>` offset-load that immediately precedes the
    real scale-8 SIB load. A scanner that accepts any `mov r32, imm32`-
    shaped match merely because a `gs:[0x58]` access exists *somewhere*
    in the same window (rather than requiring the match to be the one
    immediately followed by the real scale-8 SIB load) finds and
    corrupts the store's disp32 instead of the real offset-load. Returns
    `(blob, imm_off, store_disp_off, dep_index_rva)`.
    """
    blob = bytearray(4)  # leading padding
    anchor = len(blob)
    dep_index_rva = 0x1000
    disp = dep_index_rva - (anchor + 6)
    blob += bytes([0x8B, 0x15])  # mov edx, [rip+disp32] (_tls_index anchor)
    blob += disp.to_bytes(4, "little", signed=True)
    blob += bytes([0xFF, 0xC0])  # inc eax -- unrelated filler
    # mov [rip+disp32], eax -- unrelated store whose disp32 (the exact
    # real bytes found in SHELL32.dll) has 0xba as its second byte,
    # squarely in the 0xB8-0xBF range a naive scan misreads as a `mov
    # r32, imm32` opcode.
    store_disp_off = len(blob) + 2
    blob += bytes([0x89, 0x05, 0x37, 0xBA, 0x53, 0x00])
    blob += bytes([0x89, 0x03])  # mov [rbx], eax -- more unrelated filler
    blob += bytes([0x65, 0x48, 0x8B, 0x04, 0x25, 0x58, 0x00, 0x00, 0x00])  # mov rax, gs:[0x58]
    imm_off = len(blob) + 2  # +2: past the REX.B (0x41) and the 0xB9 opcode byte
    blob += bytes([0x41, 0xB9]) + access_offset.to_bytes(4, "little")  # mov r9d, imm32
    blob += bytes([0x4C, 0x8B, 0x04, 0xD0])  # mov r8, [rax+rdx*8] -- the real scale-8 SIB load
    blob += bytes(8)  # trailing padding
    return blob, imm_off, store_disp_off, dep_index_rva


def test_scanner_does_not_misparse_intervening_instruction_as_msvc_immediate():
    """Regression test for the real 010 Editor / SHELL32.dll crash: a
    false `mov r32, imm32` match inside an unrelated, intervening
    instruction (found before the real offset-load, but merely because a
    `gs:[0x58]` access exists somewhere nearby) must be rejected, and
    only the real offset-load -- the one immediately followed by the
    real scale-8 SIB load -- gets shifted.
    """
    access_offset = 0x10
    shift = 0x1000
    blob, imm_off, store_disp_off, dep_index_rva = _msvc_blob_with_hazardous_intervening_instruction(
        access_offset, shift
    )
    store_disp_before = bytes(blob[store_disp_off:store_disp_off + 4])

    patched, anchors_found = _patch_dep_tls_access_offsets(blob, dep_index_rva, shift)

    assert (patched, anchors_found) == (1, 1)
    # The unrelated store's own disp32 must be untouched.
    assert bytes(blob[store_disp_off:store_disp_off + 4]) == store_disp_before
    # The real per-variable offset constant is the one that got shifted.
    result = int.from_bytes(blob[imm_off:imm_off + 4], "little", signed=True)
    assert result == access_offset + shift


def _mingw_blob_with_hazardous_trailing_cmp():
    """Builds the exact real-world instruction bytes found at blob offset
    `0x2393bf` in the real, MSVC-compiled `Qt6Gui.dll` (see
    `_try_patch_mingw_style_tls_access`'s own docstring): the genuine
    anchor (`mov ecx, [rip+disp32]`) is immediately followed by MSVC's own
    real offset-load (`mov edx, 4`) and its real scale-8 SIB load (`mov
    rcx, [rax+rcx*8]`), then the real final variable access (`mov eax,
    [rdx+rcx*1]`) -- and a few bytes after *that*, an entirely unrelated
    `cmp dword ptr [rip+disp32], eax` instruction whose own disp32 bytes
    (`89 b6 45 00`) happen to decode as an `8B`/`89`-opcode, ModRM
    mod=10/rm!=SIB pair -- the exact byte shape
    `_try_patch_mingw_style_tls_access` looks for -- with nothing resembling
    a real scale-8 SIB load actually sitting immediately before it (just
    the tail of the real final access instruction). Before this function
    required that zero-gap preceding scale-8 SIB load as corroboration, it
    matched this `cmp`'s own disp32 and corrupted it (and the 2-byte `jg`
    immediately after it, confirmed via the real 010 Editor crash this
    regression test is for). Returns `(blob, dep_index_rva, anchor,
    tls_index_load_end, imm_off, cmp_disp_off)`.
    """
    blob = bytearray(4)  # leading padding
    blob += bytes([0x58, 0x00, 0x00, 0x00])  # tail of the real preceding `mov rax, gs:[0x58]`
    anchor = len(blob)
    hazardous_disp = 0x0045C123  # the real disp32 value, straight from Qt6Gui.dll
    dep_index_rva = anchor + 6 + hazardous_disp
    blob += bytes([0x8B, 0x0D])  # mov ecx, [rip+disp32] -- the real anchor
    blob += hazardous_disp.to_bytes(4, "little", signed=True)
    tls_index_load_end = len(blob)
    imm_off = len(blob) + 1
    blob += bytes([0xBA, 0x04, 0x00, 0x00, 0x00])  # mov edx, 4 -- the real genuine offset-load
    blob += bytes([0x48, 0x8B, 0x0C, 0xC8])  # mov rcx, [rax+rcx*8] -- real scale-8 SIB load
    blob += bytes([0x8B, 0x04, 0x0A])  # mov eax, [rdx+rcx*1] -- real final variable access
    cmp_disp_off = len(blob) + 2
    blob += bytes([0x39, 0x05, 0x89, 0xB6, 0x45, 0x00])  # cmp dword ptr [rip+disp32], eax -- unrelated
    blob += bytes([0x7F, 0x0D])  # jg -- unrelated, corrupted alongside the cmp in the old bug
    blob += bytes(8)  # trailing padding
    return blob, dep_index_rva, anchor, tls_index_load_end, imm_off, cmp_disp_off


def test_scanner_does_not_misparse_adjacent_cmp_disp32_as_mingw_access():
    """Regression test for the real 010 Editor / Qt6Gui.dll crash (third
    confirmed real-world false positive, after SHLWAPI.dll/SHELL32.dll):
    `_try_patch_mingw_style_tls_access` must not accept the unrelated
    `cmp`'s disp32 bytes merely because they happen to look like a `mov
    r32, [r64+disp32]`-shaped access -- it must require the zero-gap
    preceding scale-8 SIB load real mingw-w64 output always has, and defer
    to `_try_patch_msvc_style_tls_access` (tried second), which correctly
    finds and shifts the real `mov edx, 4` offset-load instead.
    """
    shift = 0x1000
    blob, dep_index_rva, anchor, tls_index_load_end, imm_off, cmp_disp_off = (
        _mingw_blob_with_hazardous_trailing_cmp()
    )
    cmp_disp_before = bytes(blob[cmp_disp_off:cmp_disp_off + 4])
    anchor_bytes_before = bytes(blob[anchor:tls_index_load_end])

    patched, anchors_found = _patch_dep_tls_access_offsets(blob, dep_index_rva, shift)

    assert (patched, anchors_found) == (1, 1)
    # The unrelated cmp's own disp32 (and the anchor itself) must be untouched.
    assert bytes(blob[cmp_disp_off:cmp_disp_off + 4]) == cmp_disp_before
    assert bytes(blob[anchor:tls_index_load_end]) == anchor_bytes_before
    # The real per-variable offset constant (MSVC's `mov edx, 4`) is the
    # one that got shifted, by `_try_patch_msvc_style_tls_access`.
    result = int.from_bytes(blob[imm_off:imm_off + 4], "little", signed=True)
    assert result == 4 + shift
