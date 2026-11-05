"""ELF counterpart of tests/windows/test_pe_frida_gadget.py -- see that
module's docstring for the full story (frida-gadget's documented
config-file "Script" interaction, and why its config-resolution ends up
pointing at the HOST binary's own path once embedded rather than the
gadget's).

frida-gadget carries its own TLS directory (confirmed via `readelf -l`
against the real downloaded `.so`: a PT_TLS segment, and via `readelf -r`:
14 R_X86_64_DTPMOD64 relocations, 0 DTPOFF64/TPOFF64/TLSGD/TLSLD -- see
.superpowers/findings/2026-11-04-frida-gadget-tls-shape.md). Task 3's ELF
TLS merge (tests/linux/test_elf_tls.py) now adopts that PT_TLS as the
TLS-less host's own, so embed() no longer fails on it with "unsupported
relocation type 16 in dependency 'libfrida-gadget-raw.so'" the way it
used to."""

import json
import platform
import shutil
import subprocess

import pytest

from conftest import (
    FIXTURES,
    FRIDA_GADGET_MODULE_NAME,
    FridaGadgetUnavailable,
    build_exe_importing_prebuilt_so,
    fetch_frida_gadget,
)

from staticer.elf_embedder import ElfEmbedder, list_elf_imports

pytestmark = [
    pytest.mark.skipif(platform.system() != "Linux", reason="ELF embedding is Linux-only"),
    pytest.mark.slow,
]


def _build_looper_importing_gadget(tmp_path, gadget_so):
    """A tiny while(1) host exe that genuinely links against the real
    frida-gadget .so, with a real DT_NEEDED entry naming it -- forced via
    `-Wl,--no-as-needed` since, unlike the PE test, this host never
    references any symbol from it at all (frida-gadget's real Linux
    build exports nothing beyond its own ABI-versioned marker symbols;
    confirmed for real via `readelf --dyn-syms`, it's designed to be
    loaded via LD_PRELOAD/injection, not linked against normally)."""
    lib_dir = tmp_path / "gadget_libdir"
    lib_dir.mkdir()
    gadget_copy = lib_dir / FRIDA_GADGET_MODULE_NAME["linux"]
    shutil.copy(gadget_so, gadget_copy)

    exe = build_exe_importing_prebuilt_so(
        tmp_path, FIXTURES / "looper.c", "looper", gadget_copy, bits=64,
    )
    return exe, lib_dir


def test_embedding_frida_gadget_no_longer_fails_on_its_own_tls_relocations(tmp_path, c_compiler):
    """frida-gadget's real TLS directory (a PT_TLS segment, 14
    R_X86_64_DTPMOD64 relocations -- see
    .superpowers/findings/2026-11-04-frida-gadget-tls-shape.md) is the
    case Task 3's ELF TLS merge implements: embed() must no longer raise
    ValueError naming it."""
    try:
        gadget_so = fetch_frida_gadget("linux")
    except FridaGadgetUnavailable as exc:
        pytest.skip(str(exc))

    exe, lib_dir = _build_looper_importing_gadget(tmp_path, gadget_so)
    assert FRIDA_GADGET_MODULE_NAME["linux"] in list_elf_imports(exe)

    out = tmp_path / "looper_frida"
    # Must not raise -- this is the whole point of this test. If it does,
    # pytest reports the failure with the real traceback/message.
    ElfEmbedder(exe, out, exclude=set(), lib_dir=lib_dir).embed()
    assert FRIDA_GADGET_MODULE_NAME["linux"] not in list_elf_imports(out)


@pytest.mark.xfail(
    reason=(
        "Task 3's ELF TLS merge is done (see "
        "test_embedding_frida_gadget_no_longer_fails_on_its_own_tls_"
        "relocations above -- embed() no longer raises on frida-gadget's "
        "TLS directory), but the full config-driven script/exit(845) flow "
        "doesn't pass outright the way the PE sibling test's did as a "
        "bonus (confirmed by actually running it: real exit code 77, not "
        "845) -- running the embedded gadget's config-driven script flow "
        "end to end on Linux is Task 4's own scope, not this task's. Left "
        "xfail rather than deleted: once Task 4 lands, this documents "
        "exactly what should then start passing."
    ),
    strict=True,
)
def test_embedded_frida_gadget_runs_config_driven_script_and_exits(tmp_path, c_compiler):
    try:
        gadget_so = fetch_frida_gadget("linux")
    except FridaGadgetUnavailable as exc:
        pytest.skip(str(exc))

    exe, lib_dir = _build_looper_importing_gadget(tmp_path, gadget_so)
    out = tmp_path / "looper_frida"

    ElfEmbedder(exe, out, exclude=set(), lib_dir=lib_dir).embed()
    out.chmod(0o755)
    assert FRIDA_GADGET_MODULE_NAME["linux"] not in list_elf_imports(out)

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

    # See this module's docstring/the PE sibling module's docstring: once
    # embedded, frida-gadget's own config-file lookup resolves relative to
    # the HOST binary's own path, not the (no-longer-separately-existing)
    # gadget .so's -- so the config must be named after `out`'s own stem.
    config = out.parent / (out.name + ".config")
    config.write_text(json.dumps({
        "interaction": {"type": "script", "path": str(script)},
    }))

    result = subprocess.run([str(out)], capture_output=True, timeout=15)
    assert result.returncode == 845
