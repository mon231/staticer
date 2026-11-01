from pathlib import Path
from typing import Optional, Set


class PortableExecutableEmbedder:
    def __init__(self, input_path: Path, output_path: Path, exclude: Set[str], lib_dir: Optional[Path]):
        self.input_path = input_path
        self.output_path = output_path
        self.exclude = exclude
        self.lib_dir = lib_dir

    def embed(self):
        raise NotImplementedError('Windows PE format isn\'t supported yet')
