# Installation

```bash
pip install staticer
```

That's it — `staticer` is pure Python (`firstclass`, `pefile`, `pyelftools`
are its only runtime dependencies). No compiler, linker, or other native
toolchain is required to install or run it.

Make sure your Python scripts folder is on `PATH` so the `staticer`
command is available after installing, and use the `pip` matching the
Python 3.9+ interpreter you want it installed for.

## Verify

```bash
staticer --help
```

## For contributors

Building and running the test suite does need a C compiler, since the
tests compile small synthetic C fixtures to embed — this is a
test/CI-only requirement, not something the installed package needs:

```bash
git clone https://github.com/mon231/staticer
cd staticer
pip install -r requirements.txt
pip install -e .
pip install pytest
pytest -v
```
