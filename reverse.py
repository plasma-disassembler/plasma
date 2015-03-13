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
from lib.utils import die
from lib.disassembler import Disassembler
from lib.generate_ast import generate_ast


def usage():
    print("reverse.py FILENAME [OPTIONS]")
    print()
    print("OPTIONS:")
    print("     --nocolor, -nc")
    print("     --graph, -g             Generate an html flow graph. See d3/index.html.")
    print("     --nocomment             Don't print comments")
    print("     --strsize=N             default 30, maximum of chars to display for")
    print("                             rodata strings.")
    print("     -x=SYMBOLNAME|0xXXXXX   default main")
    print("     -b=64|32                default 64")
    print("     --debug, -d")
    sys.exit(0)


if __name__ == '__main__':
    filename = ""
    gen_graph = False
    debug = False
    print_help = False
    addr = "main"
    bits = 64
    lib.output.MAX_STRING_RODATA = 30

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
            elif arg[0][0] == "-":
                usage()
            else:
                filename = i

        elif len(arg) == 2:
            if arg[0] == "-x":
                if len(arg[1]) <= 2:
                    usage()
                addr = arg[1]

            elif arg[0] == "-b":
                if arg[1] not in ["64", "32"]:
                    usage()
                bits = int(arg[1])

            elif arg[0] == "--strsize":
                lib.output.MAX_STRING_RODATA = int(arg[1])

            else:
                usage()

        else:
            usage()

    if filename == "":
        die("file not specified")

    if not os.path.exists(filename):
        die("%s doesn't exists" % filename)


    # Reverse !

    dis = Disassembler(filename)

    if addr[:2] == "0x":
        addr = int(addr, 16)
    else:
        try:
            addr = dis.symbols[addr]
        except:
            die("symbol %s not found" % addr)

    s = dis.find_section(addr)
    if not dis.section_is_exec(s):
        die("the address 0x%x is not in an executable section" % addr)
    dis.disasm_section(s, bits)
    lib.output.dis = dis

    gph = dis.extract_func(addr)
    gph.simplify()
    gph.detect_loops()
    lib.output.gph = gph
    lib.ast.gph = gph

    if gen_graph:
        gph.html_graph()

    ast = generate_ast(gph, debug)
    ast.fuse_cmp_if()

    if not lib.colors.nocolor:
        ast.assign_colors()

    lib.output.print_ast(addr, ast)

