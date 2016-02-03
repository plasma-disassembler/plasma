Reverse
=======

`Reverse` is a reverse engineering tool used to disassemble binaries.
It can generate a more readable code (pseudo-C) with colored syntax.
An interactive mode is still in development.

It supports :
* architectures : x86, ARM, MIPS{64} (partially)
* formats : ELF, PE, RAW

The `Makefile` is used only for checking tests.

More documentation on the [wiki](https://github.com/joelpx/reverse/wiki)


## Requirements

* python >= 3.4
* [capstone](https://github.com/aquynh/capstone)
* [python-pyelftools](https://github.com/eliben/pyelftools)
* [pefile](https://github.com/mlaferrera/python3-pefile)
* [python-msgpack](https://github.com/msgpack/msgpack-python)
* `c++filt` (available in the binutils Linux package)
* terminal with 256 colors (if not, use the option `--nocolor`)


## Installation

    ./requirements.sh
    python3 setup.py install


## Pseudo-decompilation of functions

    $ reverse -i tests/server.bin
    >> v main
    # then press tab

![reverse](/images/screenshot.png?raw=true)

![reverse](/images/visual.png?raw=true)

