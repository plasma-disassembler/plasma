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
    'tests/shellcode.bin': ["--raw32"]
    }


def test_reverse():
    for p in TESTS.glob('*.bin'):
        for symbol in sorted(SYMBOLS.get(p, [None])):
            yield reverse_file, str(p), symbol

def reverse_file(filename, symbol):
    ctx = Context()
    ctx.sectionsname = False
    ctx.color = False
    ctx.filename = filename
    ctx.entry = symbol

    for o in OPTIONS.get(filename, [None]):
        if o == "--raw32":
            ctx.raw32 = True
        elif o == "--raw64":
            ctx.raw64 = True

    sio = StringIO()
    with redirect_stdout(sio):
        reverse(ctx)
    postfix = '{0}.rev'.format('' if symbol is None else '_' + symbol)
    with open(filename.replace('.bin', postfix)) as f:
        assert_equal(sio.getvalue(), f.read())
