#!/usr/bin/env python3

from contextlib import redirect_stdout
from nose.tools import assert_equal
from pathlib import Path
from io import StringIO

from reverse import reverse
from lib.context import Context

TESTS = Path('tests')

SYMBOLS = {
        TESTS / 'server.bin': ["main", "connection_handler"],
        TESTS / 'pendu.bin': ["_main", "___main"],
        TESTS / 'shellcode.bin': ["0x0"],
        }

OPTIONS = {
    TESTS / 'shellcode.bin': ["--raw x86"]
    }


def test_reverse():
    for p in TESTS.glob('*.bin'):
        for symbol in sorted(SYMBOLS.get(p, [None])):
            yield reverse_file, str(p), symbol, OPTIONS.get(p, [])

def reverse_file(filename, symbol, options):
    ctx = Context()
    ctx.sectionsname = False
    ctx.color = False
    ctx.filename = filename
    ctx.entry = symbol

    for o in options:
        if o == "--raw x86":
            ctx.raw_type = "x86"
        elif o == "--raw x64":
            ctx.raw_type = "x64"

    sio = StringIO()
    with redirect_stdout(sio):
        reverse(ctx)
    postfix = '{0}.rev'.format('' if symbol is None else '_' + symbol)
    with open(filename.replace('.bin', postfix)) as f:
        assert_equal(sio.getvalue(), f.read())
