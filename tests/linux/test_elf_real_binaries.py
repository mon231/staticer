"""End-to-end tests embedding REAL Linux system binaries (not the small
synthetic ``tests/fixtures`` ones) via ``ElfEmbedder``, then actually
running the resulting output and asserting on its behavior.

Two binaries, two shapes each:
  * ``/bin/bash``, whose one *simple* direct dependency is
    ``libtinfo.so.6`` (its other direct dependency, ``libc.so.6``, is
    glibc itself -- see the full-closure xfail below for why that one
    isn't embeddable at all) -- used for the curated-subset case.
  * ``/bin/grep``, whose one *simple* direct dependency is
    ``libpcre2-8.so.0`` (its other direct dependency is again
    ``libc.so.6``) -- a genuinely different shape (a plain, no-TLS,
    no-IFUNC, no-copy-relocation PCRE2 regex engine, actually exercised
    here via a real ``-P`` Perl-compatible regex match) than
    ``libtinfo.so.6``'s own old-style termcap-global/copy-relocation
    shape above.

Real-binary bugs found and fixed in ``staticer/elf_embedder.py`` while
writing these tests (none of this project's own small, synthetic
``tests/fixtures`` .so's exercise any of these constructs -- real system
shared objects are a different animal):

  * The host's own GNU symbol-*versioning* requirement list
    (``DT_VERNEED``/``DT_VERNEEDNUM``) still listed a top-level entry for
    an embedded (``DT_NEEDED``-neutralized) dependency after embedding.
    ld.so's own ``_dl_check_map_versions`` walks that whole list
    unconditionally at load time and asserts a loaded module exists for
    *every* entry's own SONAME -- with the entry left in place (observed
    for real, embedding ``libtinfo.so.6`` into ``bash``), that assertion
    fails at process startup, before any user code runs
    ("Inconsistency detected by ld.so: ... Assertion `needed != NULL'
    failed"). Fixed by also splicing the embedded dependency's own
    Verneed entry out of that linked list (``_remove_verneed_entry``),
    mirroring ``_remove_needed``'s existing ``DT_NEEDED``-neutralization
    for the analogous version-requirement structure.
  * ``R_*_COPY`` relocations (a host executable importing a dependency's
    *data* symbol directly, by value, rather than through a GOT/PLT
    pointer slot -- real-world example: ``bash``'s own old-style
    termcap-compatibility globals ``UP``/``PC``/``BC``, imported this way
    from ``libtinfo.so.6``) weren't handled at all -- the relocation
    entry was silently left untouched, and ld.so's own attempt to copy
    the symbol's initial value from its (no-longer-loaded) defining
    module at load time failed ("symbol lookup error: ... undefined
    symbol: UP"). Fixed by resolving the copy at embed time instead (the
    dependency's already-relocated data, copied verbatim into the host's
    own reserved space) -- which in turn surfaced two more real,
    load-bearing issues of its own, both also fixed:
      - A copy-relocation target is frequently inside the host's own
        *BSS* (zero-filled at load, backed by no file bytes at all until
        this method's own "lay everything out" step grows the host's
        extended segment's filesz to cover it) -- so the actual byte
        write has to be deferred until after that step runs, not
        attempted inline during the earlier GOT/PLT-patch pass (where
        the target address isn't file-backed yet at all).
      - Growing that segment's filesz to reach the new end of file
        -- needed regardless, to append the embedded dependency's own
        blob -- also silently remaps whatever ordinary trailing content
        the *original* file already had past its own filesz (e.g. a
        stale section-header table/`.comment`/`.note` content, normal
        for any binary that isn't stripped to the bone) as real,
        non-zero memory, instead of the zero-filled BSS the ELF ABI
        promises for that whole span. An earlier version of this
        method's own docstring claimed this was safe ("inert trailing
        bytes that nothing else maps") -- true only in the *original*
        file, where filesz genuinely stopped short of them; once this
        method's own filesz growth covers that same span, the kernel
        *does* map it. Confirmed for real (embedding ``libtinfo.so.6``
        into ``bash``): a handful of bash's own ordinary BSS globals
        happened to fall inside exactly this span and came up
        initialized to leftover garbage instead of zero, crashing deep
        inside bash's own ``parse_and_execute`` on first use. Fixed by
        explicitly zeroing that whole span before growing filesz over
        it.
      - (Also fixed, found by code inspection while chasing the above
        rather than by a second observed crash): a dependency's own
        *internal* reference to one of its own exported data symbols
        that the host also copy-relocates (e.g. ``libtinfo.so.6``'s own
        code reading/writing its own ``UP`` global) has to be redirected
        to the *host's* copy-relocated storage, not the dependency's own
        now-dead original storage -- the same symbol-interposition
        principle this module's own pre-existing comments already
        discuss for a plain exported mutable data symbol, just not
        previously applied to the copy-relocation case specifically.
  * ``ElfEmbedder``'s default search dirs (used whenever ``lib_dir`` is
    ``None``) never covered a Debian/Ubuntu-style "multiarch" library
    layout (e.g. the real ``libc.so.6`` at
    ``/usr/lib/x86_64-linux-gnu/libc.so.6``, never directly under
    ``/usr/lib`` itself) -- so on any such system, ``lib_dir=None``
    (every resolvable import is a candidate) silently resolved *zero*
    real dependencies at all, making the whole "full closure" code path
    dead code there. Fixed by adding the two architecture-qualified
    multiarch directories this module's own ``_SUPPORTED_MACHINES``
    allows (``x86_64-linux-gnu``/``i386-linux-gnu``) to the default
    search dirs -- deliberately *not* a wildcard glob over every such
    directory a host happens to have (an earlier version of this exact
    fix used one, and broke for real on a host that also had an
    unrelated foreign-architecture, e.g. ``aarch64-linux-gnu``, multiarch
    directory installed: ``resolve_elf``'s plain by-name file search has
    no architecture awareness, so a same-named file in the *wrong*-
    architecture directory could resolve first purely by directory sort
    order, pulling in a whole foreign-architecture dependency subtree
    that then failed this method's own, correct, architecture-mismatch
    check several steps later).

Known, NOT fixed, open gap -- see both ``..._full_closure`` tests below:
a real modern glibc build merges ``libc.so.6`` and the dynamic linker
itself into one object (``libc.so.6`` lists ``ld-linux-x86-64.so.2`` as
its own ``DT_NEEDED``), and both make heavy use of GNU "indirect function"
(``R_X86_64_IRELATIVE``) relocations -- glibc's own mechanism for
resolving CPU-feature-tuned implementations of hot functions like
``memcpy``/``strlen`` by actually *calling* a resolver function at load
time, plus glibc's own thread-local-storage relocations
(``R_X86_64_TPOFF64``/``R_X86_64_DTPMOD64``) for its own internal TLS
state. Neither is implemented: an IRELATIVE entry's "addend" is the
*address of a resolver function to call*, not a value or symbol
reference this module can resolve by simple arithmetic or lookup the way
every other relocation type here can, and a TLS relocation needs a whole
PT_TLS block-merging mechanism this module has no equivalent of at all.
Both are needed to embed a real glibc build's own ``libc.so.6`` (every
single real binary's transitive closure, under ``lib_dir=None``, bottoms
out at it) -- `embed()` itself fails loudly, with a clear
"unsupported relocation type 37 in dependency 'ld-linux-x86-64.so.2'"
``ValueError``, rather than silently producing a broken output. Properly
supporting either construct (let alone both) is a substantially bigger
undertaking than this task's scope -- IRELATIVE in particular can't be
resolved by this module's existing "read the dependency's own bytes and
compute an address" approach at all; it would need either sandboxed
execution of the dependency's own resolver code at *build* time, or
deferring resolver calls into the generated entrypoint stub itself to run
at the embedded output's own *load* time -- so this is left as an open,
documented gap rather than a quick fix.
"""

import glob
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Set

import pytest

from staticer.elf_embedder import ElfEmbedder, list_elf_imports

pytestmark = [
    pytest.mark.skipif(platform.system() != "Linux", reason="ELF embedding is Linux-only"),
    pytest.mark.slow,
]


def _require_binary(name: str) -> Path:
    found = shutil.which(name)
    if found is None:
        pytest.skip(f"'{name}' not found on PATH")
    return Path(found)


def _find_real_lib(name: str) -> Path:
    """Locate a real system copy of `name` (a bare SONAME, e.g.
    "libtinfo.so.6") via the same Debian/Ubuntu-style multiarch
    directories ``ElfEmbedder``'s own default search dirs now check (see
    this module's docstring) -- plus plain ``/lib``/``/usr/lib`` for a
    non-multiarch system -- skipping cleanly if it isn't present
    anywhere, rather than assuming a particular distro's layout."""
    candidates = (
        glob.glob(f"/usr/lib/*-linux-gnu/{name}")
        + glob.glob(f"/lib/*-linux-gnu/{name}")
        + [f"/usr/lib/{name}", f"/lib/{name}", f"/usr/lib64/{name}", f"/lib64/{name}"]
    )
    for candidate in candidates:
        if Path(candidate).is_file():
            return Path(candidate)
    pytest.skip(f"no real '{name}' found on this system")


def _curated_lib_dir(tmp_path: Path, keep_name: str) -> Path:
    """A lib_dir containing only a real copy of `keep_name`, for the
    "embed exactly one real dependency" shape."""
    libdir = tmp_path / "curated_libs"
    libdir.mkdir()
    src = _find_real_lib(keep_name)
    shutil.copy(src, libdir / keep_name)
    return libdir


def _exclude_all_but(host: Path, keep_name: str) -> Set[str]:
    return {n for n in list_elf_imports(host) if n != keep_name}


def test_bash_curated_subset(tmp_path):
    bash = _require_binary("bash")
    lib_dir = _curated_lib_dir(tmp_path, "libtinfo.so.6")
    exclude = _exclude_all_but(bash, "libtinfo.so.6")
    out = tmp_path / "bash_static"

    ElfEmbedder(bash, out, exclude=exclude, lib_dir=lib_dir).embed()
    out.chmod(0o755)

    assert "libtinfo.so.6" not in list_elf_imports(out)

    result = subprocess.run(
        [str(out), "--norc", "--noprofile", "-c", "echo hello"],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "hello"


@pytest.mark.xfail(
    reason=(
        "Real, discovered gap (not papered over -- see this module's "
        "docstring): bash's own full resolvable closure includes "
        "libc.so.6 (glibc), which itself lists the dynamic linker "
        "(ld-linux-x86-64.so.2) as a further DT_NEEDED dependency in "
        "modern glibc builds, and both make heavy use of GNU indirect-"
        "function (R_X86_64_IRELATIVE) and thread-local-storage "
        "relocations that this module doesn't implement at all -- "
        "embed() itself fails loudly with 'unsupported relocation type "
        "37 in dependency ld-linux-x86-64.so.2' rather than producing a "
        "broken output. Properly supporting either construct (IRELATIVE "
        "would need running a dependency's own resolver code, at build "
        "or load time; TLS would need a whole PT_TLS-merging mechanism "
        "this module has no equivalent of) is a substantially bigger "
        "undertaking than this task's scope, so this is left as an "
        "open, documented gap rather than a quick fix."
    ),
    strict=True,
)
def test_bash_full_closure(tmp_path):
    bash = _require_binary("bash")
    out = tmp_path / "bash_static_full"

    ElfEmbedder(bash, out, exclude=set(), lib_dir=None).embed()
    out.chmod(0o755)

    result = subprocess.run(
        [str(out), "--norc", "--noprofile", "-c", "echo hello"],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "hello"


def test_second_real_binary_curated_subset(tmp_path):
    """grep with exactly one real dependency (libpcre2-8.so.0, a plain
    regex engine with none of libtinfo.so.6's own copy-relocation/
    symbol-versioning shape above -- just ordinary GLOB_DAT/JUMP_SLOT/
    RELATIVE relocations) statically embedded, actually exercised via a
    real Perl-compatible-regex (-P) match that only libpcre2 implements
    (grep's own built-in non-P regex engines don't support `+`-style
    quantifiers the same way) -- everything else (libc.so.6) stays an
    ordinary, normally-resolved dynamic import."""
    grep = _require_binary("grep")
    lib_dir = _curated_lib_dir(tmp_path, "libpcre2-8.so.0")
    exclude = _exclude_all_but(grep, "libpcre2-8.so.0")
    out = tmp_path / "grep_static"

    ElfEmbedder(grep, out, exclude=exclude, lib_dir=lib_dir).embed()
    out.chmod(0o755)

    assert "libpcre2-8.so.0" not in list_elf_imports(out)

    result = subprocess.run(
        [str(out), "-P", r"wor+ld"],
        input="hello world\nfoo bar\n",
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "hello world"


@pytest.mark.xfail(
    reason=(
        "Same real, discovered gap as test_bash_full_closure above (see "
        "this module's docstring): grep's own full resolvable closure "
        "likewise bottoms out at libc.so.6/ld-linux-x86-64.so.2's "
        "IRELATIVE/TLS relocations, which this module doesn't support. "
        "Left as the same open, documented gap rather than a quick fix."
    ),
    strict=True,
)
def test_second_real_binary_full_closure(tmp_path):
    grep = _require_binary("grep")
    out = tmp_path / "grep_static_full"

    ElfEmbedder(grep, out, exclude=set(), lib_dir=None).embed()
    out.chmod(0o755)

    result = subprocess.run(
        [str(out), "-P", r"wor+ld"],
        input="hello world\nfoo bar\n",
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "hello world"
