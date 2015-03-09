#!/bin/python3
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

REVERSEFILE = os.path.abspath(os.path.expanduser(__file__))
if os.path.islink(REVERSEFILE):
    REVERSEFILE = os.readlink(REVERSEFILE)
sys.path = [os.path.dirname(REVERSEFILE) + "/lib/"] + sys.path

import ast
from disassembler import Disassembler
from utils import *
from generate_ast import *


# TODO options
symbol = "main"
section = b".text"
bits = 64


def usage():
    print("reverse.py FILENAME [OPTIONS]")
    print()
    print("OPTIONS:")
    print("     --nocolor, -nc")
    print("     --nograph, -ng")
    print("     --debug, -d")
    # print("     --sy=SYMBOLNAME  (default=main)")
    # print("     --section=SECTIONNAME  (default=.text)")
    sys.exit(0)


filename = "a.out"
gen_graph = True
debug = False
print_help = False

for i in sys.argv[1:]:
    if i == "--help" or  i == "-h":
        usage()

    if i == "--nocolor" or i == "-nc":
        ast.nocolor = True
    elif i == "--debug" or i == "-d":
        debug = True
    elif i == "--nograph" or i == "-ng":
        gen_graph = False
    else:
        filename = i


dis = Disassembler(filename)
dis.disasm_section(section, bits)
ast.dis = dis

addr = dis.symbols[symbol]

gph = dis.extract_func(addr)
gph.simplify()
gph.detect_loops()

if gen_graph:
    gph.generate_graph()

code_ast = generate_ast(gph, debug)
ast.gph = gph
if not ast.nocolor:
    code_ast.assign_colors()
code_ast.print()

