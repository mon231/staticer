import struct
import sys
from argparse import ArgumentParser, ArgumentTypeError, Namespace
from pathlib import Path
from typing import List, Literal, Optional

import pefile
from elftools.common.exceptions import ELFError

from .common.depgraph import CyclicDependencyError
from .elf_embedder import ElfEmbedder
from .pe_embedder import PortableExecutableEmbedder


def _lib_dir_arg(value: str) -> Path:
    # Path('') silently becomes Path('.'), which would restrict the search to
    # cwd instead of meaning "no restriction". Reject empty and missing values
    # loudly; omitting the flag remains the way to request an unrestricted search.
    if not value:
        raise ArgumentTypeError('must not be empty (omit --lib-dir for an unrestricted search)')
    path = Path(value)
    if not path.is_dir():
        raise ArgumentTypeError(f'directory does not exist: {value}')
    return path


def parse_args(argv: Optional[List[str]] = None) -> Namespace:
    parser = ArgumentParser('staticer', description='Embed dependencies in dynamic-executables')
    parser.add_argument('input', type=Path, help='Path to the input dynamic-executable')
    parser.add_argument('-o', '--output', type=Path, required=True, help='Path to the output static-executable')
    parser.add_argument('--exclude', type=str, default='', help='Comma-separated list of dependency names to exclude')
    parser.add_argument('--lib-dir', dest='lib_dir', type=_lib_dir_arg, default=None,
                         help='Restrict embeddable dependencies to this existing directory')

    args = parser.parse_args(argv)
    args.exclude = {name for name in args.exclude.split(',') if name}
    return args


def sniff_format(path: Path) -> Literal["pe", "elf"]:
    with open(path, 'rb') as f:
        header = f.read(4)

    if header[:2] == b"MZ":
        return "pe"
    if header[:4] == b"\x7fELF":
        return "elf"

    raise ValueError('unrecognized binary format')


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    try:
        fmt = sniff_format(args.input)

        if fmt == "pe":
            embedder = PortableExecutableEmbedder(args.input, args.output, args.exclude, args.lib_dir)
        else:
            embedder = ElfEmbedder(args.input, args.output, args.exclude, args.lib_dir)

        embedder.embed()
    except (ValueError, CyclicDependencyError, pefile.PEFormatError, ELFError, OSError, struct.error) as e:
        print(f'error: {e}', file=sys.stderr)
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
