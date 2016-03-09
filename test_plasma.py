#!/usr/bin/env python3

# to run this script :
# $ nosetest3
# or
# $ python3 test_plasma.py

import os
import sys
from time import time
from contextlib import redirect_stdout
from nose.tools import assert_equal
from pathlib import Path
from io import StringIO

from plasma.lib.api import Api
from plasma.lib import GlobalContext

TESTS = Path('tests')

SYMBOLS = {
        TESTS / 'server.bin': ["main", "connection_handler"],
        TESTS / 'pendu.bin': ["_main", "___main", "__imp___cexit"],
        TESTS / 'shellcode.bin': ["0x0"],
        TESTS / 'entryloop1.bin': ["0x4041b0"],
        }

OPTIONS = {
    TESTS / 'shellcode.bin': ["--raw x86"],
    TESTS / 'entryloop1.bin': ["--raw x64", "--rawbase 0x4041b0"],
    }


def test_plasma():
    for p in TESTS.glob('*.bin'):
        for symbol in sorted(SYMBOLS.get(p, [None])):
            yield plasma_file, str(p), symbol, OPTIONS.get(p, [])

def plasma_file(filename, symbol, options):
    gctx = GlobalContext()
    gctx.sectionsname = False
    gctx.color = False
    gctx.filename = filename
    gctx.entry = symbol
    gctx.quiet = True

    for o in options:
        if o == "--raw x86":
            gctx.raw_type = "x86"
        elif o == "--raw x64":
            gctx.raw_type = "x64"
        elif o.startswith("--rawbase"):
            gctx.raw_base = int(o.split(" ")[1], 16)

    if not gctx.load_file():
        die()

    gctx.api = Api(gctx, None)

    sio = StringIO()
    with redirect_stdout(sio):
        o = gctx.get_addr_context(gctx.entry).decompile()
        if o is not None:
            o.print()
    postfix = '{0}.rev'.format('' if symbol is None else '_' + symbol)
    with open(filename.replace('.bin', postfix)) as f:
        assert_equal(sio.getvalue(), f.read())


def color(text, c):
    return "\x1b[38;5;" + str(c) + "m" + text + "\x1b[0m"


if __name__ == "__main__":
    start = time()
    passed = 0
    nb = 0
    failed = []

    for plasma_file, path, symbol, options in test_plasma():
        name = os.path.basename(path)

        nb += 1

        try:
            plasma_file(path, symbol, options)
            print(".", end="")
            passed += 1
        except AssertionError:
            print(color("F", 1), end="")
            failed.append(name)
        except Exception as e:
            print(color("E", 1), end="")
            failed.append(name)

        sys.stdout.flush()

    elapsed = time()
    elapsed = elapsed - start
    print("\n%d/%d tests passed successfully in %fs" % (passed, nb, elapsed))

    for p in failed:
        print("failed:", p)
