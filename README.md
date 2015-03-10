Reverse
=======

Reverse engineering for x86 binaries (elf-format). Generate a more
readable code (pseudo-C) with colored syntax.

Warning, the project is still in development, use it at your own risks.

This tool try to disassemble one function (by default `main`). The address
of the function, or its symbol, can be passed by argument.

The `Makefile` is used only for checking tests.

## Requirements

    python3
    python-capstone (>= 3.0.1)
    python-pyelftools

For Python binding of [Capstone engine](http://www.capstone-engine.org), you 
can install it from PyPi, like followings: 

    sudo pip3 install capstone

You need a terminal with 256 colors, otherwise use the option `-nc`
(or `--nocolor`).


## Screenshots

    $ ./reverse.py tests/nestedloop1.bin

![reverse](http://hippersoft.fr/projects/rev.jpg)


By opening `d3/index.html` you will be able to see the flow graph :

![graph](http://hippersoft.fr/projects/graph.jpg)

