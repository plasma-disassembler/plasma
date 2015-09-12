Reverse
=======

Reverse engineering for x86/ARM/MIPS binaries. Generate a more readable code
(pseudo-C) with colored syntax.

Supported formats : `ELF`, `PE`, `RAW`.


The `Makefile` is used only for checking tests.


## Requirements

    python >= 3.4
    capstone + python bindings (see requirements.sh)
    python-pyelftools
    https://github.com/simonzack/pefile-py3k
    terminal with 256 colors (if not use the option `--nocolor`)

For Python binding of [Capstone engine](http://www.capstone-engine.org), you 
can install it from PyPi, like followings: 

    sudo pip3 install capstone

You can also run `requirements.sh` which will retrieve all requirements.


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


## Decompile functions

    $ ./reverse.py tests/nestedloop1.bin

![reverse](http://hippersoft.fr/projects/rev2.jpg)

By opening `d3/index.html` (with the option `--graph`) you will be able to
see the flow graph :

![graph](http://hippersoft.fr/projects/graph.jpg)


## Read ascii strings

    $ reverse tests/server.bin --data -x 0x400ca0
    .rodata              [0x400ca0 - 0x400de5]
    0x400ca0: 01 00 02 00
    0x400ca4: 00 00 00 00
    0x400ca8: "Could not create socket", 0
    0x400cc0: "Socket created", 0
    0x400ccf: "bind failed. Error", 0
    0x400ce2: "bind done", 0
    0x400cec: 00 00 00 00
    0x400cf0: "Waiting for incoming connections...", 0
    0x400d14: "Connection accepted", 0
    0x400d28: "could not create thread", 0
    0x400d40: "Handler assigned", 0
    0x400d51: "accept failed", 0
    0x400d5f: 00
    0x400d60: "Greetings! I am your connection handler\n", 0
    0x400d89: 00 00 00
    0x400d8c: 00 00 00 00
    0x400d90: "Now type something and i shall repeat what you type \n", 0
    0x400dc6: "Client disconnected", 0
    0x400dda: "recv failed", 0


## Edit with vim

    $ ./reverse tests/dowhile1.bin --vim
    You can now run : vim dowhile1.bin.rev -S dowhile1.bin.vim


## Interactive mode

With the option `-i` you enter in the interactive mode. See `help`.


## Custom colors

At the first run, `reverse.py` creates a new file `custom_colors.py` with
default values. Here you can set your own colors.
