#!/usr/bin/env python3

from contextlib import redirect_stdout
from nose.tools import assert_equal
from pathlib import Path
from io import StringIO

from reverse import reverse
import lib.ast

TESTS = Path('tests')

SYMBOLS = {
        TESTS / 'server.bin': ["main", "connection_handler"],
        TESTS / 'pendu.bin': ["_main", "___main"]
        }

def test_reverse():
    for p in TESTS.glob('*.bin'):
        for symbol in sorted(SYMBOLS.get(p, [None])):
            yield reverse_file, str(p), symbol

def reverse_file(filename, symbol):
    # FIXME horrible hack to deal with global variables
    lib.ast.local_vars_idx = {}
    lib.ast.local_vars_size = []
    lib.ast.local_vars_name = []
    lib.ast.vars_counter = 1
    lib.ast.all_fused_inst = set()
    sio = StringIO()
    params = ['--nosectionsname', '--nocolor', filename]
    if symbol is not None:
        params.insert(0, '-x')
        params.insert(1, symbol)
    with redirect_stdout(sio):
        reverse(params)
    postfix = '{0}.rev'.format('' if symbol is None else '_' + symbol)
    with open(filename.replace('.bin', postfix)) as f:
        assert_equal(sio.getvalue(), f.read())
