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
from lib.utils import die
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
    print()
    sys.exit(0)


if __name__ == '__main__':
    filename = ""
    gen_graph = False
    debug = False
    print_help = False
    addr = ""
    gen_vim = False
    lib.binary.MAX_STRING_RODATA = 30

    # Parse arguments
    for i in sys.argv[1:]:
        arg = i.split("=")

        if len(arg) == 1:
            if arg[0] == "--help" or arg[0] == "-h":
                usage()
            if arg[0] == "--nocolor" or arg[0] == "-nc":
                lib.colors.nocolor = True
            elif arg[0] == "--debug" or arg[0] == "-d":
                debug = True
            elif arg[0] == "--graph" or arg[0] == "-g":
                gen_graph = True
            elif arg[0] == "--nocomment":
                lib.output.nocomment = True
                lib.ast.nocomment = True
            elif arg[0] == "--vim":
                gen_vim = True
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
                addr = arg[1]

            elif arg[0] == "--strsize":
                lib.binary.MAX_STRING_RODATA = int(arg[1])

            else:
                print("unknown option " + arg[0])
                print()
                usage()

        else:
            usage()

    if filename == "":
        print("file not specified\n")
        usage()

    if not os.path.exists(filename):
        die("%s doesn't exists" % filename)


    # Reverse !

    dis = Disassembler(filename)
    addr = dis.get_addr_from_string(addr)

    dis.disasm(addr)
    gph = dis.get_graph(addr)

    lib.output.binary = dis.binary
    lib.output.gph    = gph
    lib.ast.gph       = gph
    lib.ast.binary    = dis.binary
    lib.ast.dis       = dis

    if gen_graph:
        gph.html_graph()

    ast = generate_ast(gph, debug)

    if gen_vim:
        base = os.path.basename(filename)
        # re-assign if no colors
        lib.ast.assign_colors(ast)
        lib.colors.nocolor = True
        generate_vim_syntax(base + ".vim")
        sys.stdout = open(base + ".rev", "w+")

    lib.output.print_ast(addr, ast)

    if gen_vim:
        print("Run :  vim %s.rev -S %s.vim" % (base, base), file=sys.stderr)
