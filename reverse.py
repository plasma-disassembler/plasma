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

import lib.ast
import lib.output
import lib.colors
import lib.binary
from lib.utils import die, error
from lib.disassembler import Disassembler
from lib.generate_ast import generate_ast
from lib.vim import generate_vim_syntax



def usage():
    print("Usage:  reverse.py FILENAME [OPTIONS]")
    print()
    print("Reverse engineering for x86 binaries. Generation of pseudo-C.")
    print("Supported formats : ELF, PE")
    print()
    print("OPTIONS:")
    print("     --nocolor, -nc")
    print("     --graph, -g             Generate an html flow graph. See d3/index.html.")
    print("     --nocomment             Don't print comments")
    print("     --strsize=N             default 30, maximum of chars to display for")
    print("                             rodata strings.")
    print("     -x=SYMBOLNAME|0xXXXXX   default main")
    print("     --vim                   Generate syntax colors for vim")
    print("     --sym, -s               Print all symbols")
    print("     --call, -c              Print all calls")
    print("     --dump                  Dump asm without decompilation")
    print("     --lines=N               Max lines to dump")
    print("     --symfile=FILENAME      Add user symbols for better readability in")
    print("                             in the analyze. Each line has the format :")
    print("                             ADDRESS_HEXA    SYMBOL_NAME")
    print()
    sys.exit(0)


def reverse():
    filename = None
    opt_symfile = None
    opt_gen_graph = False
    opt_debug = False
    opt_addr = ""
    opt_gen_vim = False
    opt_print_sym = False
    opt_dump = False
    opt_dump_lines = 30
    opt_print_calls = False
    lib.binary.MAX_STRING_RODATA = 30

    # Parse arguments
    for i in sys.argv[1:]:
        arg = i.split("=")

        if len(arg) == 1:
            if arg[0] == "--help" or arg[0] == "-h":
                usage()
            if arg[0] == "--nocolor" or arg[0] == "-nc":
                lib.colors.nocolor = True
            elif arg[0] == "--opt_debug" or arg[0] == "-d":
                opt_debug = True
            elif arg[0] == "--graph" or arg[0] == "-g":
                opt_gen_graph = True
            elif arg[0] == "--nocomment":
                lib.output.nocomment = True
                lib.ast.nocomment = True
            elif arg[0] == "--vim":
                opt_gen_vim = True
            elif arg[0] == "--dump":
                opt_dump = True
            elif arg[0] == "--sym" or arg[0] == "-s":
                opt_print_sym = True
            elif arg[0] == "--call" or arg[0] == "-c":
                opt_print_calls = True
            elif arg[0][0] == "-":
                print("unknown option " + arg[0])
                print()
                usage()
            else:
                filename = i

        elif len(arg) == 2:
            if arg[0] == "-x":
                if arg[1] == "0x":
                    usage()
                opt_addr = arg[1]

            elif arg[0] == "--strsize":
                lib.binary.MAX_STRING_RODATA = int(arg[1])

            elif arg[0] == "--lines":
                opt_dump_lines = int(arg[1])

            elif arg[0] == "--symfile":
                opt_symfile = arg[1]

            else:
                print("unknown option " + arg[0])
                print()
                usage()

        else:
            usage()

    if filename == None:
        error("file not specified\n")
        usage()

    if not os.path.exists(filename):
        die("%s doesn't exists" % filename)


    # Reverse !

    dis = Disassembler(filename)

    # Maybe opt_addr is a symbol and doesn't exists.
    # But we need an address for disassembling. After that, if the file 
    # is PE we load imported symbols and search in the code for calls.
    if opt_print_sym or opt_print_calls:
        addr = dis.binary.get_entry_point()
    else:
        addr = dis.get_addr_from_string(opt_addr)

    # Disassemble and load imported symbols for PE
    dis.disasm(addr)

    if opt_symfile != None:
        dis.load_user_sym_file(opt_symfile)

    lib.output.binary = dis.binary
    lib.ast.binary    = dis.binary

    if opt_print_calls:
        dis.print_calls()
        return

    if opt_print_sym:
        dis.print_symbols()
        return

    if opt_dump:
        if opt_gen_vim:
            base = os.path.basename(filename)
            lib.colors.nocolor = True
            sys.stdout = open(base + ".rev", "w+")
        dis.dump(addr, opt_dump_lines)
        if opt_gen_vim:
            generate_vim_syntax(base + ".vim")
            print("Run :  vim %s.rev -S %s.vim" % (base, base), file=sys.stderr)
        return

    gph = dis.get_graph(addr)

    lib.output.gph    = gph
    lib.ast.gph       = gph
    lib.ast.dis       = dis

    if opt_gen_graph:
        gph.html_graph()

    ast = generate_ast(gph, opt_debug)

    if opt_gen_vim:
        base = os.path.basename(filename)
        # re-assign if no colors
        lib.ast.assign_colors(ast)
        lib.colors.nocolor = True
        generate_vim_syntax(base + ".vim")
        sys.stdout = open(base + ".rev", "w+")

    lib.output.print_ast(addr, ast)

    if opt_gen_vim:
        print("Run :  vim %s.rev -S %s.vim" % (base, base), file=sys.stderr)


if __name__ == '__main__':
    reverse()
