#!/usr/bin/env python3
#
# PLASMA : Generate an indented asm code (pseudo-C) with colored syntax.
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

import os
import sys
import plasma
from plasma.lib import GlobalContext
from plasma.lib.utils import info, die
from plasma.lib.ui.vim import generate_vim_syntax
from plasma.lib.api import Api

# Generates the file custom_colors.py at the beginning
import plasma.lib.colors

def console_entry():
    gctx = GlobalContext()
    gctx.parse_args()

    if gctx.color and plasma.lib.colors.VERSION < plasma.lib.colors.CURR_VERSION:
        info("There is a new version of custom_colors.py. If you did any")
        info("modifications you can delete it. Otherwise you can copy it")
        info("somewhere, run again your command then merge the file at hand.")
        die()

    if gctx.filename is None:
        die()

    if not gctx.load_file():
        die()

    if gctx.interactive_mode:
        from plasma.lib.ui.console import Console
        gctx.is_interactive = True
        Console(gctx)

    else:
        gctx.api = Api(gctx, None)

        if gctx.list_sections:
            for s in gctx.dis.binary.iter_sections():
                s.print_header()
            sys.exit(0)

        if gctx.syms:
            gctx.dis.print_symbols(gctx.sectionsname)
            sys.exit(0)

        ctx = gctx.get_addr_context(gctx.entry)

        if ctx is None:
            sys.exit(0)

        if gctx.do_dump:
            ctx.dump_asm(gctx.nb_lines).print()
            sys.exit(0)

        o = ctx.decompile()

        if gctx.graph:
            ctx.gph.dot_graph(gctx.dis.jmptables)

        if o is not None:
            if gctx.vim:
                base = os.path.basename(gctx.filename) + "_" + gctx.entry
                # re-assign if no colors
                gctx.libarch.process_ast.assign_colors(ctx, ctx.ast)
                gctx.color = False
                generate_vim_syntax(ctx, base + ".vim")
                sys.stdout = open(base + ".rev", "w+")

            o.print()

            if gctx.vim:
                print("run :  vim {0}.rev -S {0}.vim".format(base), file=sys.stderr)
