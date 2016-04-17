PLASMA
======

The old project name was **Reverse**.

`PLASMA` is an interactive disassembler. It can generate a more readable
assembly (pseudo code) with colored syntax. You can write scripts with the
available Python api.

The project is still in big development. You can see the TODO list and some
documentation on the [wiki](https://github.com/joelpx/plasma/wiki).
The `Makefile` is only used for checking tests.

It supports :
* architectures : x86, ARM, MIPS{64} (partially)
* formats : ELF, PE, RAW


## Requirements

* python >= 3.4
* [capstone](https://github.com/aquynh/capstone)
* [python-pyelftools](https://github.com/eliben/pyelftools)
* [pefile](https://github.com/erocarrera/pefile) + python3-future
* [python-msgpack](https://github.com/msgpack/msgpack-python) >= 0.4.6
* `c++filt` (available in the binutils Linux package)
* terminal with 256 colors (if not, use the option `--nocolor`)


## Installation

    ./requirements.sh
    python3 setup.py build_ext --inplace
    python3 setup.py install   # or create an alias to run_plasma.py


## Pseudo-decompilation of functions

    $ plasma -i tests/server.bin
    >> v main
    # then press tab

![plasma](/images/screenshot.png?raw=true)

![plasma](/images/visual.png?raw=true)
