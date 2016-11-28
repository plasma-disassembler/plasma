PLASMA
======

The old project name was **Reverse**.

`PLASMA` is an interactive disassembler. It can generate a more readable
assembly (pseudo code) with colored syntax. You can write scripts with the
available Python api (see an example below). The project is still in big development.

[wiki](https://github.com/joelpx/plasma/wiki) : TODO list and some documentation.

It supports :
* architectures : x86{64}, ARM, MIPS{64} (partially for ARM and MIPS)
* formats : ELF, PE, RAW


**Warning**: until structures and type definitions are not implemented, the
database compatibility could be broken.


## Requirements

* python >= 3.4
* [capstone](https://github.com/aquynh/capstone)
* [python-pyelftools](https://github.com/eliben/pyelftools)
* [pefile](https://github.com/erocarrera/pefile) + python3-future
* [python-msgpack](https://github.com/msgpack/msgpack-python) >= 0.4.6
* `c++filt` (available in the binutils Linux package)
* terminal should support UTF8 and 256 colors (if not, use the option `--nocolor`)

Optional :
* `python-qt4` used for the memory map
* [keystone](https://github.com/keystone-engine/keystone) for the script asm.py



## Installation

    ./install.sh

Or if you have already installed requirements with the previous command :

    ./install.sh --update

Check tests :

    make
    ....................................................................................
    84/84 tests passed successfully in 2.777975s
    analyzer tests...
    ...


## Pseudo-decompilation of functions

    $ plasma -i tests/server.bin
    >> v main
    # then press tab

![plasma](/images/screenshot.png?raw=true)

![plasma](/images/visual.png?raw=true)

## Qt memory map (memmap)

The image is actually static.
![plasma](/images/qt_memory.png?raw=true)


## Scripting (Python API)

See more on the [wiki](https://github.com/joelpx/plasma/wiki/api) for the API.

Some examples (these scripts are placed in plasma/scripts) :

    $ plasma -i FILE
    plasma> py !strings.py             # print all strings
    plasma> py !xrefsto.py FUNCTION    # xdot call graph
    plasma> py !crypto.py              # detect some crypto constants
    plasma> py !asm.py CODE            # assemble with keystone
    plasma> py !disasm.py HEX_STRING   # disassemble a buffer
