import lief
from typing import List
from pathlib import Path


class PortableExecutableEmbedder:
    def __init__(self, input_executable: lief.ELF.Binary, output_executable: Path, search_directories: List[Path]):
        pass

    def embed(self):
        raise NotImplementedError('Windows PE format isn\'t supported yet')
