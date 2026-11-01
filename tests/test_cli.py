from pathlib import Path

import pytest

from staticer.staticer import parse_args, sniff_format, main


# ---------------------------------------------------------------------------
# parse_args
# ---------------------------------------------------------------------------


def test_parse_args_defaults():
    ns = parse_args(["in.exe", "-o", "out.exe"])
    assert ns.input == Path("in.exe") and ns.output == Path("out.exe")
    assert ns.exclude == set() and ns.lib_dir is None


def test_parse_args_exclude_is_comma_split():
    ns = parse_args(["in.exe", "-o", "out.exe", "--exclude", "a.dll,b.dll"])
    assert ns.exclude == {"a.dll", "b.dll"}


# ---------------------------------------------------------------------------
# sniff_format
# ---------------------------------------------------------------------------


def test_sniff_format_pe(tmp_path):
    p = tmp_path / "x.exe"
    p.write_bytes(b"MZ" + b"\x00" * 100)
    assert sniff_format(p) == "pe"


def test_sniff_format_elf(tmp_path):
    p = tmp_path / "x"
    p.write_bytes(b"\x7fELF" + b"\x00" * 100)
    assert sniff_format(p) == "elf"


def test_sniff_format_rejects_garbage(tmp_path):
    p = tmp_path / "x"
    p.write_bytes(b"not a binary")
    with pytest.raises(ValueError):
        sniff_format(p)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def test_main_reports_clean_error_on_garbage_input(tmp_path, capsys):
    p = tmp_path / "x"
    p.write_bytes(b"garbage")
    code = main([str(p), "-o", str(tmp_path / "out")])
    assert code == 1
    assert "unrecognized" in capsys.readouterr().err.lower()


def test_main_overwrites_existing_output(tmp_path, monkeypatch):
    out = tmp_path / "out.exe"
    out.write_bytes(b"old")
    inp = tmp_path / "in.exe"
    inp.write_bytes(b"MZ" + b"\x00" * 100)

    def fake_embed(self):
        self.output_path.write_bytes(b"new-static-executable")

    monkeypatch.setattr("staticer.staticer.PortableExecutableEmbedder.embed", fake_embed)

    code = main([str(inp), "-o", str(out)])

    assert code == 0
    assert out.read_bytes() != b"old"
