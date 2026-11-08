"""Pure byte-level unit tests for `_patch_dep_tls_access_offsets` (the TLS
phase-2 merge's compiled-access-pattern scanner in `staticer/pe_embedder.py`).
No real PE build/compiler needed -- these hand-craft the exact instruction
bytes each compiler idiom produces and check the scanner finds + shifts the
right one. Runs on any OS, unlike the rest of the PE test suite.
"""

from staticer.pe_embedder import _patch_dep_tls_access_offsets


def _mingw_blob(load_reg_modrm: int, dep_index_rva: int, access_disp: int, shift: int):
    """Builds: `mov <reg>, [rip+disp32]` (the _tls_index load, at offset
    `anchor`) immediately followed by `mov eax, [rcx+disp32]` (the
    mingw-style variable-specific access `_try_patch_mingw_style_tls_access`
    looks for). `load_reg_modrm` is the anchor's own ModRM byte (varies by
    which register the load targets)."""
    blob = bytearray(4)  # leading padding so the REX prefix (if any) isn't at index 0
    anchor = len(blob)
    blob += bytes([0x8B, load_reg_modrm])
    disp = dep_index_rva - (anchor + 6)
    blob += disp.to_bytes(4, "little", signed=True)
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

    count = _patch_dep_tls_access_offsets(blob, dep_index_rva, shift)

    assert count == 1
    patched = int.from_bytes(blob[disp_off:disp_off + 4], "little", signed=True)
    assert patched == 8 + shift


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

    count = _patch_dep_tls_access_offsets(rex_blob, dep_index_rva, shift)

    assert count == 1
    patched_off = disp_off + 1  # shifted by the inserted REX byte
    patched = int.from_bytes(rex_blob[patched_off:patched_off + 4], "little", signed=True)
    assert patched == 16 + shift
