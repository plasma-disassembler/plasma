Reverse
=======

Reverse engineering for x86 binaries (elf-format). Will generate a more
readable code will colored syntax.

Warning, the project is still in development, use it at your own risks.

## Requirements

    python3
    python-capstone (>= 3.0.1)
    python-pyelftools

You need a terminal with 256 colors, otherwise use the option `-nc`
(or `--nocolor`).


## Screenshots

    $ ./reverse.py tests/nestedloop1.bin

![reverse](http://hippersoft.fr/projects/rev.jpg)


By opening `d3/index.html` you will able to see the flow graph :

![graph](http://hippersoft.fr/projects/graph.jpg)


## Tests

The script `check.sh`  verify if all tests are correct.

