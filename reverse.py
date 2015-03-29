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

import lib.ast
import lib.output
import lib.colors
import lib.fileformat.binary
import lib.paths
from lib.utils import die, error
from lib.disassembler import Disassembler
from lib.generate_ast import generate_ast
from lib.vim import generate_vim_syntax



def reverse():
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

    lib.utils.dbg                         = args.opt_debug
    lib.disassembler.forcejmp             = args.forcejmp
    lib.generate_ast.print_andif          = not args.noandif
    lib.colors.nocolor                    = args.nocolor
    lib.output.nocomment                  = args.nocomment
    lib.output.nosectionsname             = args.nosectionsname
    lib.ast.nocomment                     = args.nocomment
    lib.fileformat.binary.MAX_STRING_DATA = args.datasize

    if not os.path.exists(args.filename):
        die("{args.filename} doesn't exist".format(args=args))

    # Reverse !

    if args.raw32:
        raw_bits = 32
    elif args.raw64:
        raw_bits = 64
    else:
        raw_bits = 0

    dis = Disassembler(args.filename, raw_bits)

    if args.symfile:
        dis.load_user_sym_file(args.symfile)

    # Maybe args.entry is a symbol and doesn't exist.
    # But we need an address for disassembling. After that, if the file 
    # is PE we load imported symbols and search in the code for calls.
    if args.sym or args.call or args.entry == "EP":
        addr = dis.binary.get_entry_point()
    else:
        addr = dis.get_addr_from_string(args.entry, raw_bits)

    # Disassemble and load imported symbols for PE
    dis.disasm(addr)

    lib.output.binary = dis.binary
    lib.ast.binary    = dis.binary

    if args.call:
        dis.print_calls()
        return

    if args.sym:
        dis.print_symbols()
        return

    if args.dump:
        if args.vim:
            base = os.path.basename(args.filename)
            lib.colors.nocolor = True
            sys.stdout = open(base + ".rev", "w+")
        dis.dump(addr, args.lines)
        if args.vim:
            generate_vim_syntax(base + ".vim")
            print("Run :  vim {0}.rev -S {0}.vim".format(base), file=sys.stderr)
        return

    gph = dis.get_graph(addr)

    lib.output.gph    = gph
    lib.ast.gph       = gph
    lib.paths.gph     = gph
    lib.ast.dis       = dis

    if args.graph:
        gph.html_graph()

    ast = generate_ast(gph)

    if args.vim:
        base = os.path.basename(args.filename)
        # re-assign if no colors
        lib.ast.assign_colors(ast)
        lib.colors.nocolor = True
        generate_vim_syntax(base + ".vim")
        sys.stdout = open(base + ".rev", "w+")

    lib.output.print_ast(addr, ast)

    if args.vim:
        print("Run :  vim {0}.rev -S {0}.vim".format(base), file=sys.stderr)


if __name__ == '__main__':
    reverse()
