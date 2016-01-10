Reverse
=======

`Reverse` is a reverse engineering tool used to disassemble binaries.
It can generate a more readable code (pseudo-C) with colored syntax.
An interactive mode is still in development.

It supports :
* architectures : x86, ARM, MIPS{64} (partially)
* formats : ELF, PE, RAW

The `Makefile` is used only for checking tests.


## Requirements

* python >= 3.4
* [capstone](https://github.com/aquynh/capstone)
* [python-pyelftools](https://github.com/eliben/pyelftools)
* [pefile](https://github.com/mlaferrera/python3-pefile)
* [python-msgpack](https://github.com/msgpack/msgpack-python)
* terminal with 256 colors (if not, use the option `--nocolor`)

You can run `requirements.sh` which will retrieve all requirements.


## Pseudo-decompilation of functions

Here the option `-x main` is optional because the binary contains the symbol main.

    $ ./reverse.py tests/server.bin

![reverse](/images/screenshot.png?raw=true)


## Interactive mode (`-i`)

More commands are available in this mode (`da`, `db`, ...). See `help`
for a full list.

TODO :

* add commands : setbe/setle (endianness of raw files), rawbase
* load raw file if the file given from the shell is raw


## Visual mode

From the interactive mode, use the command `v` to enter in the visual mode.
This mode requires `ncurses`. Use `tab` to switch between dump/decompilation.

It supports :

* definition of code/functions
* inline comments
* xrefs
* symbols renaming

TODO :

* reload automatically if the analyzer has modified the content
* multi-lines comments
* create data/arrays
* stack variables
* structure, enum
* improve analyzer performances
* ...

FIXME :

* clean PE imports
* xrefs with eip/rip + disp
* re-run analyzer on the current function after definition of a jmptable + delete wrong labels

![reverse](/images/visual.png?raw=true)


## Switch jump-tables example

Switch statements which require a jump-table are not detected automatically.
So we need to tell it which jump-table to use.

    $ ./reverse.py -i tests/others/switch.bin
    >> x
    ...
    >> jmptable 0x400526 0x400620 11 8 
    # A jump-table at 0x400620 is set with 11 entries, an address is on 8 bytes.
    >> x
    # Decompilation with switch


## Analyze shellcodes

For every `int 0x80`, the tool try to detect syscalls with parameters.

    $ ./reverse.py --raw x86 tests/shellcode.bin
    function 0x0 {
        0x0: eax = 0 # xor eax, eax
        0x2: al = '\x0b' # mov al, 0xb
        0x4: cdq
        0x5: push edx
        0x6: push 1752379246 "n/sh"
        0xb: push 1768042287 "//bi"
        0x10: ebx = esp # mov ebx, esp
        0x12: push edx
        0x13: push ebx
        0x14: ecx = esp # mov ecx, esp
        0x16: int 128 ; execve(ebx, ecx, edx) # int 0x80
    }


## Edit with vim

    $ ./reverse tests/dowhile1.bin --vim
    Run : vim dowhile1.bin.rev -S dowhile1.bin.vim
