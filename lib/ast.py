#!/bin/python3
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


from lib.colors import color_addr, color_keyword
from lib.output import (print_comment, print_no_end, print_tabbed,
        print_tabbed_no_end)


class Ast_Branch:
    def __init__(self):
        self.nodes = []

    def add(self, node):
        if isinstance(node, Ast_Branch):
            self.nodes += node.nodes
        else:
            self.nodes.append(node)

    def print(self, o, tab=0):
        for n in self.nodes:
            if isinstance(n, list):
                o.print_block(n, tab)
            else: # ast
                n.print(o, tab)


class Ast_IfGoto:
    def __init__(self, orig_jump, cond_id, addr_jump):
        self.orig_jump = orig_jump
        self.cond_id = cond_id
        self.addr_jump = addr_jump
        self.fused_inst = None

    def print(self, o, tab=0):
        o.print_commented_jump(self.orig_jump, self.fused_inst, tab)
        print_tabbed_no_end(color_keyword("if "), tab)
        o.print_if_cond(self.cond_id, self.fused_inst)
        print_no_end(color_keyword("  goto "))
        print(color_addr(self.addr_jump, False))


class Ast_AndIf:
    def __init__(self, orig_jump, cond_id):
        self.orig_jump = orig_jump
        self.cond_id = cond_id
        self.fused_inst = None

    def print(self, o, tab=0):
        o.print_commented_jump(self.orig_jump, self.fused_inst, tab)
        print_tabbed_no_end(color_keyword("and ") + color_keyword("if "), tab)
        o.print_if_cond(self.cond_id, self.fused_inst)
        print()


# This is used for ARM to fuse instructions which have the same condition
class Ast_If_cond:
    def __init__(self, cond_id, br):
        self.cond_id = cond_id
        self.br = br
        self.fused_inst = None

    def print(self, o, tab=0):
        o.print_commented_jump(None, self.fused_inst, tab)
        print_tabbed_no_end(color_keyword("if "), tab)
        o.print_if_cond(self.cond_id, self.fused_inst)

        # If it contains only one instruction
        if self.fused_inst == None and len(self.br.nodes) == 1 and \
                len(self.br.nodes[0]) == 1 and isinstance(self.br.nodes[0], list):
            print_no_end(" :  ")
            o.print_inst(self.br.nodes[0][0], 0)
        else:
            print(" {")
            self.br.print(o, tab+1)
            print_tabbed("}", tab)


class Ast_Ifelse:
    def __init__(self, jump_inst, br_next_jump, br_next):
        self.jump_inst = jump_inst
        self.br_next = br_next
        self.br_next_jump = br_next_jump
        self.fused_inst = None

    def print(self, o, tab=0, print_else_keyword=False):
        ARCH_UTILS = o.ctx.libarch.utils

        #
        # if cond {
        # } else {
        #   ...
        # }
        #
        # become
        #
        # if !cond {
        #   ...
        # }
        #

        br_next = self.br_next
        br_next_jump = self.br_next_jump
        inv_if = False

        if len(self.br_next.nodes) == 0:
            br_next, br_next_jump = br_next_jump, br_next
            inv_if = True
            
        o.print_commented_jump(self.jump_inst, self.fused_inst, tab)

        if print_else_keyword:
            print_tabbed_no_end(color_keyword("else if "), tab)
        else:
            print_tabbed_no_end(color_keyword("if "), tab)

        # jump_inst is the condition to go to the else-part
        if inv_if:
            o.print_if_cond(ARCH_UTILS.get_cond(self.jump_inst),
                            self.fused_inst)
        else:
            o.print_if_cond(ARCH_UTILS.invert_cond(self.jump_inst),
                            self.fused_inst)

        print(" {")

        # if-part
        br_next.print(o, tab+1)

        # else-part
        if len(br_next_jump.nodes) > 0:
            print_tabbed_no_end("} ", tab)
            
            # 
            # if {
            #   ...
            # } else {
            #   if {
            #     ...
            #   }
            # }
            #
            # become :
            #
            # if {
            #   ...
            # }
            # else if {
            #   ...
            # }
            #

            br = br_next_jump

            if len(br.nodes) == 1 and isinstance(br.nodes[0], Ast_Ifelse):
                print()
                br.nodes[0].print(o, tab, True)
                return

            if len(br.nodes) == 2 and isinstance(br.nodes[0], list) and \
                  len(br.nodes[0]) == 1 and ARCH_UTILS.is_cmp(br.nodes[0][0]) and \
                  isinstance(br.nodes[1], Ast_Ifelse):
                print()
                br.nodes[1].print(o, tab, True)
                return

            print(color_keyword("else ") + "{")
            br.print(o, tab+1)

        print_tabbed("}", tab)


class Ast_Goto:
    def __init__(self, addr):
        self.addr_jump = addr

    def print(self, o, tab=0):
        print_tabbed_no_end(color_keyword("goto "), tab)
        print(color_addr(self.addr_jump, False))


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

    def print(self, o, tab=0):
        if self.is_infinite:
            print_tabbed(color_keyword("infiniteloop") + " {", tab)
        else:
            print_tabbed(color_keyword("loop") + " {", tab)
        self.branch.print(o, tab+1)
        print_tabbed("}", tab)
        if self.epilog != None:
            self.epilog.print(o, tab)


class Ast_Comment:
    def __init__(self, text):
        self.text = text

    def print(self, o, tab=0):
        if o.ctx.comments:
            print_comment("# " + self.text, tab)
