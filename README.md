PLASMA
======

The old project name was **Reverse**.

`PLASMA` is an interactive disassembler. It can generate a more readable
assembly (pseudo code) with colored syntax. You can write scripts with the
available Python api (see an example below). The project is still in big development.

[wiki](https://github.com/joelpx/plasma/wiki) : TODO list and some documentation.

It supports :
* architectures : x86, ARM, MIPS{64} (partially for ARM and MIPS)
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
* optional : `python-qt4` used for the memory map


## Installation

    ./install.sh

Or if you have already installed requirements with the previous command :

    ./install.sh --update

Check tests :

    make
    ....................................................................................
    84/84 tests passed successfully in 2.777975s
    analyzer tests...
    stack [OK]


## Pseudo-decompilation of functions

    $ plasma -i tests/server.bin
    >> v main
    # then press tab

![plasma](/images/screenshot.png?raw=true)

![plasma](/images/visual.png?raw=true)

## Qt memory map (memmap)

This image is the result of the libc :

![plasma](/images/qt_memory.png?raw=true)


## Python API example test

See more on the [wiki](https://github.com/joelpx/plasma/wiki/api).

Print all ascii strings :

    echo "py scripts/strings.py" | plasma -i tests/server.bin
    0x400200  "/lib64/ld-linux-x86-64.so.2"
    0x400228  "GNU"
    0x400248  "GNU"
    0x400481  "libpthread.so.0"
    0x400491  "_ITM_deregisterTMCloneTable"
    0x4004ad  "_Jv_RegisterClasses"
    0x4004c1  "_ITM_registerTMCloneTable"
    0x4004db  "write"
    ...
