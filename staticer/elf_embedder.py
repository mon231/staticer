import os
import sys
import lief
from typing import List
from pathlib import Path
from collections import OrderedDict

class ElfEmbedder:
    def __init__(self, input_executable: lief.ELF.Binary, output_executable: Path, search_directories: List[Path]):
        self.executable = input_executable
        self.output_path = output_executable
        self.search_directories = search_directories

    def embed(self):
        pass
