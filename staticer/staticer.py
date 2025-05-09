import lief
from pathlib import Path
from argparse import ArgumentParser

from .elf_embedder import ElfEmbedder
from .pe_embedder import PortableExecutableEmbedder


def parse_args():
    parser = ArgumentParser('staticer', description='Embed dependencies in dynamic-executables')
    parser.add_argument('-i', '--input', type=Path, help='Path to the input dynamic-executable')
    parser.add_argument('-o', '--output', type=Path, help='Path to the output static-executable')
    return parser.parse_args()


def main():
    # TODO: shake it OFF
    lief.logging.set_level(lief.logging.LEVEL.DEBUG)

    args = parse_args()
    executable = lief.parse(args.input)

    if isinstance(executable, lief.ELF.Binary):
        ElfEmbedder(
            input_executable=executable,
            output_executable=args.output,
            search_directories=[args.input.parent]
        ).embed()
    elif isinstance(executable, lief.PE.Binary):
        PortableExecutableEmbedder(
            input_executable=executable,
            output_executable=args.output,
            search_directories=[args.input.parent]
        ).embed()
    else:
        if executable is None:
            raise ValueError('Unknown input format')

        raise ValueError('Unsupported input format', type(executable))


if __name__ == '__main__':
    main()
