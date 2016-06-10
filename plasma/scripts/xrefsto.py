#!/usr/bin/env python3

import threading
import os
from tempfile import mkstemp
from subprocess import call, DEVNULL

DOT_BINARY = "/usr/bin/xdot"
links = set()


class Xdot(threading.Thread):
    def __init__(self, filename):
        threading.Thread.__init__(self)
        self.filename = filename

    def run(self):
        call([DOT_BINARY, filename], stderr=DEVNULL, stdout=DEVNULL)
        os.remove(filename)


def rec_xref(output, first_ad, ad, depth):
    global links

    label = api.get_symbol(ad)

    if label is None:
        if api.mem.is_code(ad):
            o = api.dump_asm(ad, 1)
            label = "%s" % o.lines[0]
        else:
            return

    if ad == first_ad:
        output.write('node_%x [label="%s" fillcolor="#B6FFDD"];\n' % (ad, label))
    else:
        output.write('node_%x [label="%s"];\n' % (ad, label))

    if depth != -1:
        if depth == 0:
            return
        depth -= 1

    for x in api.xrefsto(ad):
        if api.mem.is_code(x):
            f = api.get_func_addr(x)
            if f is not None:
                x = f

        if (x, ad) not in links:
            links.add((x, ad))
            output.write('node_%x -> node_%x;\n' % (x, ad))
            rec_xref(output, first_ad, x, depth)


if len(args) > 3 or len(args) <= 1:
    print("usage: xrefsto.py SYMBOL|0xXXXX|EP [maxdepth]")
else:
    ad = api.get_addr_from_symbol(args[1])
    depth = -1 if len(args) == 2 else int(args[2])

    filename = mkstemp(prefix="plasma")[1]

    output = open(filename, "w+")
    output.write('digraph {\n')
    output.write('node [fontname="liberation mono" style=filled fillcolor=white shape=box];\n')

    if api.mem.is_code(ad):
        f = api.get_func_addr(ad)
        if f is not None:
            ad = f

    rec_xref(output, ad, ad, depth)
    output.write('}')
    output.close()

    Xdot(filename).start()
