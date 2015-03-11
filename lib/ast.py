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


from lib.utils import *
from lib.colors import pick_color, addr_color
from lib.output import *

gph = None


class Ast_Branch:
    def __init__(self):
        self.nodes = []

    def add(self, node):
        if type(node) == Ast_Branch:
            self.nodes += node.nodes
        else:
            self.nodes.append(node)

    def print(self, tab=0):
        for n in self.nodes:
            if type(n) == list:
                print_block(n, tab)
            else: # ast
                n.print(tab)

    def assign_colors(self):
        for n in self.nodes:
            if type(n) == list:
                if is_uncond_jump(n[0]):
                    nxt = gph.link_out[n[0].address][BRANCH_NEXT]
                    pick_color(nxt)
            else:
                n.assign_colors()


class Ast_IfGoto:
    def __init__(self, orig_jump, cond_id, addr_jump):
        self.orig_jump = orig_jump
        self.cond_id = cond_id
        self.addr_jump = addr_jump

    def print(self, tab=0):
        print_tabbed_no_end(color_keyword("if ") + cond_sign_str(self.cond_id), tab)
        print_no_end(color_keyword("  goto "))
        try:
            c = addr_color[self.addr_jump]
            print_no_end(color("0x%x ", c) % self.addr_jump)
        except:
            print_no_end("0x%x " % self.addr_jump)
        print_inst(self.orig_jump, 0, "# ")

    def assign_colors(self):
        pick_color(self.addr_jump)


class Ast_AndIf:
    def __init__(self, orig_jump, cond_id):
        self.orig_jump = orig_jump
        self.cond_id = cond_id

    def print(self, tab=0):
        print_tabbed_no_end(color_keyword("and ") + color_keyword("if ") + \
                cond_sign_str(self.cond_id) + " ", tab)
        print_inst(self.orig_jump, 0, "# ")

    def assign_colors(self):
        return


class Ast_Ifelse:
    def __init__(self, inst_jump, br_next, br_next_jump):
        self.inst_jump = inst_jump
        self.br_next = br_next
        self.br_next_jump = br_next_jump

    def print(self, tab=0):
        print_inst(self.inst_jump, tab, "# ")
        print_tabbed(color_keyword("if ") + 
                cond_sign_str(invert_cond(self.inst_jump.id)) + " {", tab)

        # Start with the false branch : it's directly after the jump
        # false branch == jump is not taken, so it means that the If 
        # is true !!
        self.br_next_jump.print(tab+1)

        if len(self.br_next.nodes) > 0:
            print_tabbed("} " + color_keyword("else ") + 
                    cond_sign_str(self.inst_jump.id) + " {", tab)
        
            # Print the true branch, the jump is taken (the if is false)
            self.br_next.print(tab+1)

        print_tabbed("}", tab)

    def assign_colors(self):
        self.br_next_jump.assign_colors()
        self.br_next.assign_colors()


class Ast_Loop:
    def __init__(self):
        self.branch = Ast_Branch()
        self.epilog = None
        self.is_infinite = False

    def add(self, node):
        self.branch.add(node)

    def set_epilog(self, epilog):
        self.epilog = epilog

    def set_infinite(self, v):
        self.is_infinite = v

    def set_branch(self, b):
        self.branch = b

    def print(self, tab=0):
        if self.is_infinite:
            print_tabbed(color_keyword("infiniteloop") + " {", tab)
        else:
            print_tabbed(color_keyword("loop") + " {", tab)
        self.branch.print(tab+1)
        print_tabbed("}", tab)
        if self.epilog != None:
            self.epilog.print(tab)

    def assign_colors(self):
        self.branch.assign_colors()
        if self.epilog != None:
            self.epilog.assign_colors()


class Ast_Comment:
    def __init__(self, text):
        self.text = text

    def print(self, tab=0):
        print_tabbed("# " + self.text, tab)

    def assign_colors(self):
        return

