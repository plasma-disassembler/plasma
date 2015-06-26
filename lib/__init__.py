#!/usr/bin/env python3
#
# Reverse : Generate an indented asm code (pseudo-C) with colored syntax.
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
from argparse import ArgumentParser, FileType

from lib.disassembler import Disassembler
from lib.utils import die, error
from lib.generate_ast import generate_ast
from lib.vim import generate_vim_syntax
from lib.context import Context
from lib.exceptions import (ExcSymNotFound, ExcNotExec, ExcArch,
     ExcFileFormat, ExcNotAddr, ExcIfelse, ExcPEFail)


def parse_args():
    # Parse arguments
    parser = ArgumentParser(description=
        'Reverse engineering for x86/ARM/MIPS binaries. Generation of pseudo-C. '
        'Supported formats : ELF, PE. https://github.com/joelpx/reverse')
    parser.add_argument('filename', nargs='?', metavar='FILENAME')
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
    parser.add_argument('-s', '--symbols', action='store_true',
            help='Print all symbols')
    parser.add_argument('-c', '--calls', action='store_true',
            help='Print all calls which are in the section containing the address '
                 'given with -x.')
    parser.add_argument('--dump', action='store_true',
            help='Dump asm without decompilation')
    parser.add_argument('--lines', type=int, default=30, metavar='N',
            help='Max lines to dump')
    parser.add_argument('-i', '--interactive', action='store_true',
            help='Interactive mode')
    parser.add_argument('--symfile', metavar='FILENAME', type=FileType('r'),
            help=('Add user symbols for better readability of the analysis. '
            'Line format: ADDRESS_HEXA    SYMBOL_NAME'))
    parser.add_argument('-d', '--opt_debug', action='store_true')
    parser.add_argument('-ns', '--nosectionsname', action='store_true')
    parser.add_argument('--raw', metavar='x86|x64|arm|mips|mips64',
            help='Consider the input file as a raw binary')
    parser.add_argument('--rawbase', metavar='0xXXXXX',
            help='Set base address of a raw file (default=0)')
    parser.add_argument('--raw-big-endian', action='store_true',
            help='If not set it\'s in little endian')

    args = parser.parse_args()

    ctx = Context()
    ctx.debug           = args.opt_debug
    ctx.print_andif     = not args.noandif
    ctx.color           = not args.nocolor
    ctx.comments        = not args.nocomment
    ctx.sectionsname    = not args.nosectionsname
    ctx.max_data_size   = args.datasize
    ctx.filename        = args.filename
    ctx.raw_type        = args.raw
    ctx.raw_base        = args.rawbase
    ctx.symfile         = args.symfile
    ctx.syms            = args.symbols
    ctx.calls           = args.calls
    ctx.entry           = args.entry
    ctx.dump            = args.dump
    ctx.vim             = args.vim
    ctx.interactive     = args.interactive
    ctx.lines           = args.lines
    ctx.graph           = args.graph
    ctx.raw_big_endian  = args.raw_big_endian

    if ctx.raw_base is not None:
        if ctx.raw_base.startswith("0x"):
            ctx.raw_base = int(ctx.raw_base, 16)
        else:
            error("--rawbase must in hex format")
            die()
    else:
        ctx.raw_base = 0

    return ctx


def load_file(ctx):
    if not os.path.exists(ctx.filename):
        error("file {ctx.filename} doesn't exists".format(ctx=ctx))
        if ctx.interactive:
           return False
        die()

    if not os.path.isfile(ctx.filename):
        error("this is not a file".format(ctx=ctx))
        if ctx.interactive:
           return False
        die()

    try:
        dis = Disassembler(ctx.filename, ctx.raw_type,
                           ctx.raw_base, ctx.raw_big_endian)
    except ExcArch as e:
        error("arch %s is not supported" % e.arch)
        if ctx.interactive:
            return False
        die()
    except ExcFileFormat:
        error("the file is not PE or ELF binary")
        if ctx.interactive:
            return False
        die()
    except ExcPEFail as e:
        error(str(e.e))
        error("It seems that pefile.parse_data_directories is bugged.")
        error("Maybe you should Retry")
        if ctx.interactive:
            return False
        die()

    ctx.dis = dis
    ctx.libarch = dis.load_arch_module()

    if ctx.symfile:
        dis.load_user_sym_file(ctx.symfile)

    return True


def init_addr(ctx):
    if ctx.entry == "EP":
        addr = ctx.dis.binary.get_entry_point()
    else:
        try:
            addr = ctx.dis.get_addr_from_string(ctx.entry, ctx.raw_type != None)
        except ExcSymNotFound as e:
            error("symbol %s not found" % e.symname)
            if ctx.interactive:
                return False
            error("Try with -s to see all symbols.")
            error("If you have set the option --dump or --calls you need to set")
            error("the option -x (see --help).")
            die()

    try:
        ctx.dis.check_addr(addr)
    except ExcNotExec as e:
        error("the address 0x%x is not in an executable section" % e.addr)
        if ctx.interactive:
            return False
        die()
    except ExcNotAddr as e:
        error("the address 0x%x cannot be found" % e.addr)
        if ctx.interactive:
            return False
        die()

    ctx.addr = addr

    return True


def disasm(ctx):
    ctx.gph = ctx.dis.get_graph(ctx.addr)
    if ctx.gph == None:
        error("capstone can't disassemble here")
        return
    paths = ctx.gph.get_paths()
    paths.gph = ctx.gph
    paths.cache_obj()
    
    if ctx.graph:
        ctx.gph.html_graph()

    try:
        ast = generate_ast(ctx, paths)
    except ExcIfelse as e:
        error("can't have a ifelse here     %x" % e.addr)
        if ctx.interactive:
            return
        die()

    if ctx.vim:
        base = os.path.basename(ctx.filename)
        # re-assign if no colors
        ctx.libarch.process_ast.assign_colors(ctx, ast)
        ctx.color = False
        generate_vim_syntax(ctx, base + ".vim")
        sys.stdout = open(base + ".rev", "w+")

    o = ctx.libarch.output.Output(ctx)
    o.print_ast(ctx.addr, ast)

    if ctx.vim:
        print("Run :  vim {0}.rev -S {0}.vim".format(base), file=sys.stderr)


def reverse(ctx):
    if not load_file(ctx):
        die()

    if ctx.syms:
        ctx.dis.print_symbols(ctx.sectionsname)
        return

    init_addr(ctx)

    if ctx.calls:
        ctx.dis.print_calls(ctx)
        return

    if ctx.dump:
        if ctx.vim:
            base = os.path.basename(ctx.filename)
            ctx.color = False
            sys.stdout = open(base + ".rev", "w+")

        ctx.dis.dump(ctx, ctx.lines)

        if ctx.vim:
            generate_vim_syntax(ctx, base + ".vim")
            print("Run :  vim {0}.rev -S {0}.vim".format(base), file=sys.stderr)
        return

    disasm(ctx)
