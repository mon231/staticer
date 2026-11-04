"""Real-world-*dependency* embedding test: statically embedding the
actual, genuine third-party frida-gadget DLL -- downloaded for real from
Frida's own GitHub release assets (never synthesized; see
conftest.fetch_frida_gadget) -- into a tiny while(1)-looping host
executable via PortableExecutableEmbedder, the same way a CLI user would.

The intended end-to-end story (and what this module's docstring exists to
record, having actually checked rather than assumed it): frida-gadget
supports a config-file-driven "Script" interaction that auto-runs a JS
file on load with no external Frida client needed (see
https://frida.re/docs/gadget/). Its own config-file lookup
(frida-core's gadget.vala, `derive_config_path_from_file_path` /
`detect_location`) resolves relative to *whatever module the dynamic
linker's own module list reports as containing the gadget's running
code* -- normally the gadget's own DLL. Once staticer embeds the gadget's
code/data into the host (there's no longer a separate module for it at
all -- that's the whole point of embedding), this lookup would, in
principle, instead resolve to the *host's own* path, since the embedded
code now lives inside the host's own mapped image. That's a real,
usable mechanism in principle (confirmed by reading frida-core's own
source, not guessed): the config file just needs to be named
"<host-exe-stem>.config", not after the gadget at all.

In practice, this test never gets to exercise that: embedding the real
frida-gadget DLL fails *before* any config-resolution code ever runs,
because frida-gadget carries its own PE TLS directory (confirmed via
pefile against the real downloaded binary) -- a real, independent,
already-documented staticer limitation (see PortableExecutableEmbedder's
own TLS guard, and test_pe_final_review_fixes.py's
test_tls_dependency_fails_loudly / test_pe_real_binaries.py's
KERNELBASE.dll xfail for the same class of gap against other real
system/third-party binaries). embed() raises ValueError naming the
dependency rather than silently producing a broken output, which is
exactly the documented, intended behavior -- this is not a bug to fix,
and TLS-directory merging is explicitly called out elsewhere as real,
not-yet-implemented future work.

So: this test asserts the real, current, honest outcome -- embedding a
real frida-gadget DLL fails loudly with a clear, named TLS error -- rather
than pretending the config/script/exit(845) flow works end-to-end when it
cannot yet reach that code path at all. See this module's own
`test_embedding_frida_gadget_fails_on_its_own_tls_directory` for the
actual assertion, and the sibling ELF test
(tests/linux/test_elf_frida_gadget.py) for the equivalent finding there
(a different failure *message* -- an "unsupported relocation type 16"
from the generic relocation path rather than a dedicated named guard,
since ElfEmbedder has no PE-style up-front TLS check -- but the same root
cause).
"""

import json
import platform
import shutil
import subprocess

import pytest

from conftest import (
    FIXTURES,
    FRIDA_GADGET_MODULE_NAME,
    FridaGadgetUnavailable,
    build_exe_importing_prebuilt_dll,
    fetch_frida_gadget,
)

from staticer.pe_embedder import PortableExecutableEmbedder, list_pe_imports

pytestmark = [
    pytest.mark.skipif(platform.system() != "Windows", reason="PE embedding is Windows-only"),
    pytest.mark.slow,
]


def _build_looper_importing_gadget(tmp_path, gadget_dll):
    """A tiny while(1) host exe that genuinely, statically imports the
    real frida-gadget DLL -- the host code never *calls* into it (that's
    not how frida-gadget is meant to be used; it instruments itself via
    its own DllMain, not a public API), it just needs a real PE
    import-table entry naming the dependency for PortableExecutableEmbedder
    to have something real to resolve and embed, exactly as a genuine
    `--lib-dir`/curated-subset CLI use would."""
    lib_dir = tmp_path / "gadget_libdir"
    lib_dir.mkdir()
    gadget_copy = lib_dir / FRIDA_GADGET_MODULE_NAME["windows"]
    shutil.copy(gadget_dll, gadget_copy)

    exe = build_exe_importing_prebuilt_dll(
        tmp_path, FIXTURES / "looper_gadget_win.c", "looper.exe",
        gadget_copy, "frida_gadget_load", bits=64,
    )
    return exe, lib_dir


def test_embedding_frida_gadget_fails_on_its_own_tls_directory(tmp_path, c_compiler):
    """The real, honest, execution-verified outcome: frida-gadget carries
    its own PE TLS directory, so PortableExecutableEmbedder.embed()
    refuses to embed it (ValueError naming the dependency) rather than
    silently corrupting TLS access -- the exact documented behavior
    test_pe_final_review_fixes.py's test_tls_dependency_fails_loudly
    already covers for a synthetic fixture, now reproduced against a
    real, independently-built third-party binary nobody at this project
    wrote. This is staticer correctly refusing something it genuinely
    doesn't support yet, not a bug."""
    try:
        gadget_dll = fetch_frida_gadget("windows")
    except FridaGadgetUnavailable as exc:
        pytest.skip(str(exc))

    exe, lib_dir = _build_looper_importing_gadget(tmp_path, gadget_dll)
    assert FRIDA_GADGET_MODULE_NAME["windows"] in list_pe_imports(exe)

    out = tmp_path / "looper_frida.exe"
    with pytest.raises(ValueError, match="(?i)tls"):
        PortableExecutableEmbedder(exe, out, exclude=set(), lib_dir=lib_dir).embed()


@pytest.mark.xfail(
    reason=(
        "Blocked on a real, already-documented staticer limitation, not "
        "an issue with this test or with frida-gadget itself: frida-gadget "
        "carries its own PE TLS directory, so embed() refuses it outright "
        "(see test_embedding_frida_gadget_fails_on_its_own_tls_directory "
        "above) before the config-driven script/exit(845) flow this test "
        "exercises ever gets to run. Left xfail rather than deleted: once "
        "PE TLS-directory merging is implemented (called out elsewhere as "
        "real future work), this documents exactly what should then start "
        "passing, including the config-file-naming finding in this "
        "module's own docstring (the config must be named after the "
        "HOST exe's stem, not the gadget's -- confirmed by reading "
        "frida-core's own config-resolution source, not guessed)."
    ),
    strict=True,
)
def test_embedded_frida_gadget_runs_config_driven_script_and_exits(tmp_path, c_compiler):
    try:
        gadget_dll = fetch_frida_gadget("windows")
    except FridaGadgetUnavailable as exc:
        pytest.skip(str(exc))

    exe, lib_dir = _build_looper_importing_gadget(tmp_path, gadget_dll)
    out = tmp_path / "looper_frida.exe"

    PortableExecutableEmbedder(exe, out, exclude=set(), lib_dir=lib_dir).embed()
    assert FRIDA_GADGET_MODULE_NAME["windows"] not in list_pe_imports(out)

    script = tmp_path / "exit_845.js"
    script.write_text(
        "rpc.exports = {\n"
        "  init(stage, parameters) {\n"
        "    const exitPtr = Module.getGlobalExportByName('exit');\n"
        "    const exitFn = new NativeFunction(exitPtr, 'void', ['int']);\n"
        "    exitFn(845);\n"
        "  }\n"
        "};\n"
    )

    # See this module's docstring: once embedded, frida-gadget's own
    # config-file lookup resolves relative to the HOST exe's own path,
    # not the (no-longer-separately-existing) gadget DLL's -- so the
    # config must be named after `out`'s own stem.
    config = out.with_suffix(".config")
    config.write_text(json.dumps({
        "interaction": {"type": "script", "path": str(script)},
    }))

    result = subprocess.run([str(out)], capture_output=True, timeout=15)
    assert result.returncode == 845
