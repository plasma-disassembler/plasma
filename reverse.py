#!/usr/bin/env python3
#
# Reverse : reverse engineering for x86 binaries
# Copyright (C) 2015    Joel
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.    If not, see <http://www.gnu.org/licenses/>.
#

import sys
import os
import os.path
from argparse import ArgumentParser, FileType

from lib.utils import die
from lib.disassembler import Disassembler
from lib.generate_ast import generate_ast
from lib.vim import generate_vim_syntax
from lib.context import Context
from lib.output import Output
from lib.ast import assign_colors


def parse_args():
    # Parse arguments
    parser = ArgumentParser(description=
        'Reverse engineering for x86 binaries. Generation of pseudo-C. '
        'Supported formats : ELF, PE. https://github.com/joelpx/reverse')
    parser.add_argument('filename', metavar='FILENAME')
    parser.add_argument('-nc', '--nocolor', action='store_true')
    parser.add_argument('-g', '--graph', action='store_true',
            help='Generate an html flow graph. See d3/index.html.')
    parser.add_argument('--nocomment', action='store_true',
            help="Don't print comments")
    parser.add_argument('--noandif', action='store_true',
            help="Print normal 'if' instead of 'andif'")
    parser.add_argument('--datasize', type=int, default=30, metavar='N',
            help='default 30, maximum of chars to display for strings or bytes array.')
    parser.add_argument('-x', '--entry', metavar='SYMBOLNAME|0xXXXXX|EP',
            help='default main. EP stands for entry point.')
    parser.add_argument('--vim', action='store_true',
            help='Generate syntax colors for vim')
    parser.add_argument('-s', '--sym', action='store_true',
            help='Print all symbols')
    parser.add_argument('-c', '--call', action='store_true',
            help='Print all calls')
    parser.add_argument('--raw32', action='store_true',
            help='Consider the input file as a raw binary')
    parser.add_argument('--raw64', action='store_true',
            help='Consider the input file as a raw binary')
    parser.add_argument('--dump', action='store_true',
            help='Dump asm without decompilation')
    parser.add_argument('--lines', type=int, default=30, metavar='N',
            help='Max lines to dump')
    parser.add_argument('--symfile', metavar='FILENAME', type=FileType('r'),
            help=('Add user symbols for better readability of the analysis. '
            'Line format: ADDRESS_HEXA    SYMBOL_NAME'))
    parser.add_argument('-d', '--opt_debug', action='store_true')
    parser.add_argument('-ns', '--nosectionsname', action='store_true')
    parser.add_argument('--forcejmp', action='store_true',
            help=('Try to disassemble if a "jmp [ADDR]" or jmp rax is found.'))

    args = parser.parse_args()

    ctx = Context()
    ctx.debug           = args.opt_debug
    ctx.forcejmp        = args.forcejmp
    ctx.print_andif     = not args.noandif
    ctx.color           = not args.nocolor
    ctx.comments        = not args.nocomment
    ctx.sectionsname    = not args.nosectionsname
    ctx.max_string_data = args.datasize
    ctx.filename        = args.filename
    ctx.raw32           = args.raw32
    ctx.raw64           = args.raw64
    ctx.symfile         = args.symfile
    ctx.sym             = args.sym
    ctx.call            = args.call
    ctx.entry           = args.entry
    ctx.dump            = args.dump
    ctx.vim             = args.vim

    return ctx


def reverse(ctx):
    if not os.path.exists(ctx.filename):
        die("{ctx.filename} doesn't exist".format(ctx=ctx))

    if ctx.raw32:
        raw_bits = 32
    elif ctx.raw64:
        raw_bits = 64
    else:
        raw_bits = 0

    dis = Disassembler(ctx.filename, raw_bits, ctx.forcejmp)
    ctx.dis = dis

    if ctx.symfile:
        dis.load_user_sym_file(ctx.symfile)

    # TODO cleanup and simplify

    # Maybe ctx.entry is a symbol and doesn't exist.
    # But we need an address for disassembling. After that, if the file 
    # is PE we load imported symbols and search in the code for calls.
    if ctx.sym or ctx.call or ctx.entry == "EP":
        addr = dis.binary.get_entry_point()
    else:
        addr = dis.get_addr_from_string(ctx.entry, raw_bits)

    dis.init(addr)

    if ctx.call:
        dis.print_calls(ctx)
        return

    if ctx.sym:
        dis.print_symbols()
        return

    if ctx.dump:
        if ctx.vim:
            base = os.path.basename(ctx.filename)
            ctx.color = False
            sys.stdout = open(base + ".rev", "w+")
        dis.dump(ctx, addr, ctx.lines)
        if ctx.vim:
            generate_vim_syntax(ctx, base + ".vim")
            print("Run :  vim {0}.rev -S {0}.vim".format(base), file=sys.stderr)
        return

    ctx.gph = dis.get_graph(addr)
    paths = ctx.gph.get_paths()
    paths.gph = ctx.gph
    paths.cache_obj()

    if ctx.graph:
        ctx.gph.html_graph()

    ast = generate_ast(ctx, paths)

    if ctx.vim:
        base = os.path.basename(ctx.filename)
        # re-assign if no colors
        assign_colors(ctx, ast)
        ctx.color = False
        generate_vim_syntax(ctx, base + ".vim")
        sys.stdout = open(base + ".rev", "w+")

    o = Output(ctx)
    o.print_ast(addr, ast)

    if ctx.vim:
        print("Run :  vim {0}.rev -S {0}.vim".format(base), file=sys.stderr)


if __name__ == '__main__':
    reverse(parse_args())
