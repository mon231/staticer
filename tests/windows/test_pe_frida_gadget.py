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

Historically, this test never got to exercise that: embedding the real
frida-gadget DLL used to fail *before* any config-resolution code ever
ran, because frida-gadget carries its own PE TLS directory (confirmed
via pefile against the real downloaded binary, including a non-null
AddressOfCallBacks with 3 real callback entries -- see
.superpowers/findings/2026-11-04-frida-gadget-tls-shape.md). That TLS
directory is now merged into a TLS-less host as the host's own (Task 2
of the TLS-support plan; see PortableExecutableEmbedder's TLS-handling
comment in its main embed loop, and tests/windows/test_pe_tls.py), so
this specific failure is gone -- see this module's own
`test_embedding_frida_gadget_no_longer_fails_on_its_own_tls_directory`
for the current, passing assertion.

Surprisingly (and verified, not assumed -- see that test's own updated
docstring), once past the TLS guard the full config-driven script/
exit(845) flow in `test_embedded_frida_gadget_runs_config_driven_script_
and_exits` below now passes outright too, even though the design doc's
LoadLibraryW/GetProcAddress-interception stub goal is still not
implemented (see staticer/stubs/windows/pe_stub.py's module docstring)
-- that goal apparently isn't needed for this particular minimal script.
This is a bonus finding from landing Task 2, not a claim that Task 3
(ELF)/Task 4's own scope is already done; see the sibling ELF test
(tests/linux/test_elf_frida_gadget.py) for that side's still-separate,
not-yet-done state.
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


def test_embedding_frida_gadget_no_longer_fails_on_its_own_tls_directory(tmp_path, c_compiler):
    """The real, execution-verified outcome after Task 2: frida-gadget
    carries its own PE TLS directory (with a real, 3-entry callback
    array -- not the callback-free synthetic case), and
    PortableExecutableEmbedder.embed() now adopts it as this TLS-less
    looper host's own TLS directory instead of raising. This only checks
    embed() completes and drops the dynamic import -- it does not run
    the embedded gadget (that needs the LoadLibraryW/GetProcAddress-
    interception stub work -- which turns out, per the updated test
    below, not to actually be needed for this particular minimal
    script; see test_embedded_frida_gadget_runs_config_driven_script_
    and_exits below)."""
    try:
        gadget_dll = fetch_frida_gadget("windows")
    except FridaGadgetUnavailable as exc:
        pytest.skip(str(exc))

    exe, lib_dir = _build_looper_importing_gadget(tmp_path, gadget_dll)
    assert FRIDA_GADGET_MODULE_NAME["windows"] in list_pe_imports(exe)

    out = tmp_path / "looper_frida.exe"
    PortableExecutableEmbedder(exe, out, exclude=set(), lib_dir=lib_dir).embed()
    assert FRIDA_GADGET_MODULE_NAME["windows"] not in list_pe_imports(out)


def test_embedded_frida_gadget_runs_config_driven_script_and_exits(tmp_path, c_compiler):
    """UPDATE (Task 2): this was previously xfail -- blocked entirely on
    the TLS guard raising before any of this flow could run. Once Task
    2's TLS-directory merge got embed() past that guard, this test
    turned out to pass outright, verified deterministically (run twice
    independently while landing Task 2, no flakiness observed): the
    design doc's LoadLibraryW/GetProcAddress-interception stub goal
    (still not implemented -- see staticer/stubs/windows/pe_stub.py's
    module docstring) apparently isn't needed for frida-gadget's own
    startup/config-driven script init to work for this minimal exit(845)
    script. This is a genuine, reproducible side effect of Task 2 alone,
    not a deliverable Task 2 set out to implement or fully verify end to
    end (e.g. nothing here exercises any *hooked* dynamic-load path) --
    Task 3 (ELF)/Task 4 should treat this as a useful finding to confirm
    further, not as those tasks already being done."""
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
