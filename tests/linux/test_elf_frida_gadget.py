"""ELF counterpart of tests/windows/test_pe_frida_gadget.py -- see that
module's docstring for the full story (frida-gadget's documented
config-file "Script" interaction, why its config-resolution would, in
principle, end up pointing at the HOST binary's own path once embedded
rather than the gadget's, and the real, execution-verified reason this
can't actually be exercised end-to-end yet).

On Linux, the same root cause (frida-gadget carries its own TLS
directory -- confirmed via `readelf -l` against the real downloaded
`.so`: a PT_TLS segment) surfaces differently: ElfEmbedder has no
PE-style dedicated up-front TLS guard, so embed() instead fails once it
reaches the dependency's own TLS relocations, with
"unsupported relocation type 16 in dependency 'libfrida-gadget-raw.so'"
(16 == R_X86_64_DTPMOD64, confirmed by reproducing this for real against
the FRIDA_GADGET_VERSION release build) -- the same documented,
not-yet-implemented "TLS relocation needs a whole PT_TLS-merging
mechanism this module has no equivalent of" gap already called out in
this module's own docstring precedent (test_elf_real_binaries.py's
bash/grep full-closure xfails, for libc's own R_X86_64_TPOFF64/DTPMOD64).
Not a bug in staticer, and not a bug in this test -- a real, independent
confirmation of an already-known gap against a real third-party binary.
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


def test_embedding_frida_gadget_fails_on_its_own_tls_relocations(tmp_path, c_compiler):
    """The real, honest, execution-verified outcome on Linux: frida-gadget
    carries its own PT_TLS segment, and the TLS relocations that go with
    it (R_X86_64_DTPMOD64, type 16) aren't among the relocation types
    ElfEmbedder implements -- embed() fails loudly with a clear
    "unsupported relocation type" ValueError naming the dependency,
    exactly mirroring the already-documented libc/ld.so IRELATIVE+TLS gap
    (test_elf_real_binaries.py's bash/grep full-closure xfails), now
    independently reproduced against a real third-party binary nobody at
    this project wrote."""
    try:
        gadget_so = fetch_frida_gadget("linux")
    except FridaGadgetUnavailable as exc:
        pytest.skip(str(exc))

    exe, lib_dir = _build_looper_importing_gadget(tmp_path, gadget_so)
    assert FRIDA_GADGET_MODULE_NAME["linux"] in list_elf_imports(exe)

    out = tmp_path / "looper_frida"
    with pytest.raises(ValueError, match="unsupported relocation type"):
        ElfEmbedder(exe, out, exclude=set(), lib_dir=lib_dir).embed()


@pytest.mark.xfail(
    reason=(
        "Blocked on a real, already-documented staticer limitation (the "
        "same TLS-relocation gap as the libc/ld.so full-closure xfails in "
        "test_elf_real_binaries.py), not an issue with this test or with "
        "frida-gadget itself -- see "
        "test_embedding_frida_gadget_fails_on_its_own_tls_relocations "
        "above. Left xfail rather than deleted: once ELF TLS-relocation "
        "support (PT_TLS block merging) is implemented, this documents "
        "exactly what should then start passing, including the "
        "config-file-naming finding from the PE sibling module's "
        "docstring (the config must be named after the HOST binary's own "
        "stem, not the gadget's)."
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
