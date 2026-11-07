"""Shared Keystone-assembly sentinel-splice mechanism, used by both the
Windows (``staticer/stubs/windows/pe_stub.py``) and Linux
(``staticer/stubs/linux/elf_stub.py``) generated-entrypoint-stub builders.

Both platform modules need to emit machine code containing one or more
absolute-address immediates (a dependency's entry point, the host's
original entrypoint, a TLS slot address, ...) that are only known at call
time, *and* report the exact byte offset of each one within the
assembled output (so the caller can register a base-relocation entry
there -- both platforms' final images may load somewhere other than
their preferred base). Keystone (https://www.keystone-engine.org/) needs
a concrete immediate to assemble against -- it has no notion of "leave
this slot open for later" -- so both platforms independently arrived at
the same two-step mechanism:

1. Assemble the instruction text with a distinctive placeholder
   ("sentinel") constant substituted in for the not-yet-known real value.
2. Locate the sentinel's own little-endian byte pattern in the assembled
   output (asserting it occurs *exactly once*, so a coincidental
   collision elsewhere in the same short sequence fails loudly instead of
   silently mis-patching), and splice the real value in at that offset.

This -- rather than assembling directly against the real value and
searching for *its* byte pattern -- is the more robust of the two options
considered: real VAs are caller-controlled and not guaranteed to have a
byte pattern absent elsewhere in the same short sequence, whereas the
sentinels are chosen once, verified once (by each platform's own test
suite), and never vary.

Cross-sentinel collision (two sentinels in one buffer): when a single
assembled sequence embeds *two* independent sentinels (e.g. a hinst/VA
pair and an entry-point VA in the same call sequence), patching them one
at a time against a buffer the previous patch already mutated is unsafe:
if the caller-supplied real value for slot A happens to equal slot B's
own sentinel constant, patching A first plants sentinel B's byte pattern
a *second* time, and the subsequent search for B then finds two matches
-- a real, reachable error, not a hypothetical one (astronomically
unlikely for loader/ASLR-assigned addresses, which are not
attacker-controlled input, but not impossible, and cheap to rule out).
``patch_two_va_sentinels`` below avoids this by locating *both* sentinels'
offsets against the original, unmodified buffer before splicing either
one in -- the second lookup is then never run against a buffer the first
splice could have perturbed.

This situation does not arise for every multi-immediate stub, though:
Linux's ``elf_stub.py`` never assembles more than one sentinel into the
same buffer at a time -- each immediate (one per init call, plus the
tail jump) is assembled, located and spliced in its own, separate call to
``assemble_with_immediate`` before being concatenated onto the growing
stub, so there is never a second sentinel left in a buffer for an
already-applied splice to collide with. Windows's ``pe_stub.py`` does hit
this, because `_x64_call_dllmain`/`_x86_call_dllmain`/
`build_windows_tls_index_fixup` each assemble a *single* instruction
sequence containing *two* independent VA sentinels together, then patch
both -- that's what `patch_two_va_sentinels` is for.
"""

from typing import Dict, Tuple

from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KS_MODE_64

# Keystone engine instances are cheap to reuse and expensive-ish to
# construct repeatedly (each wraps a native handle), so one per bitness is
# cached for the lifetime of the process.
_ks_engines: Dict[bool, Ks] = {}


def get_ks(is64: bool) -> Ks:
    engine = _ks_engines.get(is64)
    if engine is None:
        engine = Ks(KS_ARCH_X86, KS_MODE_64 if is64 else KS_MODE_32)
        _ks_engines[is64] = engine
    return engine


def assemble(is64: bool, asm_text: str, base_address: int = 0) -> bytes:
    """Assemble `asm_text` (real x86/x86-64 assembly source) at
    `base_address` and return the resulting machine code as `bytes`.

    The base address matters only for instructions whose encoding depends
    on an absolute target address relative to where the instruction itself
    sits (e.g. a forced-near `jne`, used by Windows's process-attach
    guards) -- assembling at a known, fixed address makes that address
    arithmetic exact and reproducible. Every absolute VA either platform
    embeds is a sentinel placeholder spliced in after the fact (see module
    docstring), so the default of 0 is correct for every other caller.
    """
    encoding, _count = get_ks(is64).asm(asm_text, base_address)
    if encoding is None:
        raise ValueError(f"keystone failed to assemble: {asm_text!r}")
    return bytes(encoding)


def locate_sentinel(data: bytes, sentinel_bytes: bytes) -> int:
    """Find `sentinel_bytes`'s one-and-only occurrence in `data` (without
    modifying it) and return its offset. Raises `ValueError` if the
    pattern is absent or, more subtly, if it occurs more than once: a
    second occurrence would mean some *other* fixed opcode/operand byte in
    this same short sequence happens to coincide with the sentinel's own
    byte pattern, which would make a blind splice silently wrong rather
    than loudly wrong. This has never been observed for any sequence
    either platform module assembles (verified empirically across typical,
    edge-case, and sentinel-shaped-adversarial VA/displacement values --
    see each platform's own test suite), but is checked on every call
    rather than assumed, since a future change to one of these assembly
    strings could in principle introduce it.
    """
    first = data.find(sentinel_bytes)
    if first == -1:
        raise ValueError(f"internal error: sentinel pattern {sentinel_bytes.hex()} not found in assembled code {data.hex()}")
    if data.find(sentinel_bytes, first + 1) != -1:
        raise ValueError(
            f"internal error: sentinel pattern {sentinel_bytes.hex()} occurs more than once in assembled code {data.hex()}"
        )
    return first


def splice_at(data: bytes, offset: int, replacement_bytes: bytes) -> bytes:
    return data[:offset] + replacement_bytes + data[offset + len(replacement_bytes):]


def patch_immediate(data: bytes, sentinel_bytes: bytes, replacement_bytes: bytes) -> Tuple[bytes, int]:
    """Locate `sentinel_bytes` within `data`, assert it occurs exactly
    once (see `locate_sentinel`), and return `data` with that one
    occurrence replaced by `replacement_bytes` (same length), plus the
    byte offset at which the replacement now sits.

    Caller beware: when a single assembled sequence embeds *more than one*
    sentinel, do not call this repeatedly against the *already-patched*
    buffer -- see the module docstring's "cross-sentinel collision"
    section and use `patch_two_va_sentinels` instead for any such
    multi-sentinel sequence.
    """
    if len(sentinel_bytes) != len(replacement_bytes):
        raise ValueError("internal error: sentinel and replacement must be the same width")
    offset = locate_sentinel(data, sentinel_bytes)
    return splice_at(data, offset, replacement_bytes), offset


def patch_va_sentinel(data: bytes, sentinel: int, width: int, real_va: int) -> Tuple[bytes, int]:
    """`patch_immediate` specialised for an absolute-VA immediate: both
    the sentinel and the real value are encoded as unsigned, `width`-byte,
    little-endian integers (matching how x86/x64 `mov reg, imm` and
    `push imm32` encode their operands).

    Single-sentinel use only -- see `patch_two_va_sentinels` for sequences
    embedding two.
    """
    sentinel_bytes = sentinel.to_bytes(width, "little")
    real_bytes = real_va.to_bytes(width, "little")
    return patch_immediate(data, sentinel_bytes, real_bytes)


def assemble_with_immediate(is64: bool, asm_template: str, sentinel: int, width: int, real_value: int) -> Tuple[bytes, int]:
    """Assemble `asm_template` (an `str.format`-style template with a
    single ``{imm}`` placeholder) with `sentinel` substituted in, then
    splice `real_value` in at the sentinel's located offset.

    Returns ``(code, offset)`` where `offset` is `real_value`'s own byte
    offset within `code`. Convenience wrapper combining `assemble` and
    `patch_va_sentinel` for the common one-sentinel-per-buffer case.
    """
    data = assemble(is64, asm_template.format(imm=sentinel))
    return patch_va_sentinel(data, sentinel, width, real_value)


def patch_two_va_sentinels(
    data: bytes,
    sentinel_a: int,
    real_va_a: int,
    sentinel_b: int,
    real_va_b: int,
    width: int,
) -> Tuple[bytes, int, int]:
    """Patch two independent absolute-VA sentinels in one assembled
    sequence.

    Cross-sentinel collision: locates *both* sentinels' offsets against
    the original, unmodified `data` before splicing either one in -- see
    the module docstring's "cross-sentinel collision" section for why
    this, rather than the simpler "patch A, then search the
    already-patched buffer for B", is required for correctness.
    """
    offset_a = locate_sentinel(data, sentinel_a.to_bytes(width, "little"))
    offset_b = locate_sentinel(data, sentinel_b.to_bytes(width, "little"))
    data = splice_at(data, offset_a, real_va_a.to_bytes(width, "little"))
    data = splice_at(data, offset_b, real_va_b.to_bytes(width, "little"))
    return data, offset_a, offset_b
