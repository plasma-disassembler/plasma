#!/bin/python3
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


class Ast_Branch:
    def __init__(self):
        self.nodes = []
        self.parent = None
        self.level = 0
        self.idx_in_parent = -1 # index in nodes list in the parent branch

    def add(self, node):
        if isinstance(node, Ast_Branch):
            self.nodes += node.nodes
        else:
            self.nodes.append(node)

    def dump(self, o, tab=0):
        for n in self.nodes:
            if isinstance(n, list):
                o._asm_block(n, tab)
            else: # ast
                n.dump(o, tab)


class Ast_IfGoto:
    def __init__(self, orig_jump, cond_id, addr_jump, prefetch=None):
        self.orig_jump = orig_jump
        self.cond_id = cond_id
        self.addr_jump = addr_jump
        self.fused_inst = None
        self.prefetch = prefetch
        self.parent = None
        self.level = 0

    def dump(self, o, tab=0):
        o._comment_fused(self.orig_jump, self.fused_inst, tab)
        if self.prefetch is not None:
            o._asm_inst(self.prefetch, tab)
        o._tabs(tab)
        o._keyword("if ")
        o._if_cond(self.cond_id, self.fused_inst)
        o._keyword("  goto ")
        o._label_or_address(self.addr_jump, -1, False)
        o._new_line()


class Ast_AndIf:
    def __init__(self, orig_jump, cond_id, expected_next_addr, prefetch=None):
        self.orig_jump = orig_jump
        self.cond_id = cond_id
        self.fused_inst = None
        self.prefetch = prefetch
        self.parent = None
        self.level = 0
        self.expected_next_addr = expected_next_addr

    def dump(self, o, tab=0):
        o._comment_fused(self.orig_jump, self.fused_inst, tab)
        if self.prefetch is not None:
            o._asm_inst(self.prefetch, tab)
        o._tabs(tab)
        o._keyword("and ")
        o._keyword("if ")
        o._if_cond(self.cond_id, self.fused_inst)
        o._new_line()


# This is used for ARM to fuse instructions which have the same condition
class Ast_If_cond:
    def __init__(self, cond_id, br):
        self.cond_id = cond_id
        self.br = br
        self.fused_inst = None
        self.parent = None
        self.level = 0

    def dump(self, o, tab=0):
        o._comment_fused(None, self.fused_inst, tab)
        o._tabs(tab)
        o._keyword("if ")
        o._if_cond(self.cond_id, self.fused_inst)

        # If it contains only one instruction
        # if self.fused_inst == None and len(self.br.nodes) == 1 and \
                # len(self.br.nodes[0]) == 1 and isinstance(self.br.nodes[0], list):
            # o._add(" :  ")
            # o._asm_inst(self.br.nodes[0][0], 0)
        # else:
        o._add(" {")
        o._new_line()
        self.br.dump(o, tab+1)
        o._tabs(tab)
        o._add("}")
        o._new_line()


class Ast_Ifelse:
    def __init__(self, jump_inst, br_next_jump, br_next,
                 expected_next_addr, prefetch=None):
        self.jump_inst = jump_inst
        self.br_next = br_next
        self.br_next_jump = br_next_jump
        self.fused_inst = None
        self.prefetch = prefetch
        self.parent = None
        self.level = 0
        self.expected_next_addr = expected_next_addr

    def dump(self, o, tab=0, print_else_keyword=False):
        ARCH_UTILS = o.gctx.libarch.utils

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
            
        o._comment_fused(self.jump_inst, self.fused_inst, tab)

        if self.prefetch is not None:
            o._asm_inst(self.prefetch, tab)

        o._tabs(tab)
        if print_else_keyword:
            o._keyword("else if ")
        else:
            o._keyword("if ")

        # jump_inst is the condition to go to the else-part
        if inv_if:
            o._if_cond(ARCH_UTILS.get_cond(self.jump_inst),
                            self.fused_inst)
        else:
            o._if_cond(ARCH_UTILS.invert_cond(self.jump_inst),
                            self.fused_inst)

        o._add(" {")
        o._new_line()

        # if-part
        br_next.dump(o, tab+1)
        o._tabs(tab)
        o._add("}")

        # else-part
        if len(br_next_jump.nodes) > 0:
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
                o._new_line()
                br.nodes[0].dump(o, tab, print_else_keyword=True)
                return

            if len(br.nodes) == 2 and isinstance(br.nodes[0], list) and \
                  len(br.nodes[0]) == 1 and ARCH_UTILS.is_cmp(br.nodes[0][0]) and \
                  isinstance(br.nodes[1], Ast_Ifelse):
                o._new_line()
                br.nodes[1].dump(o, tab, print_else_keyword=True)
                return

            o._keyword(" else")
            o._add(" {")
            o._new_line()
            br.dump(o, tab+1)

            o._tabs(tab)
            o._add("}")

        o._new_line()


class Ast_Goto:
    def __init__(self, addr):
        self.addr_jump = addr
        self.parent = None
        self.level = 0

        # The algorithm can add some goto and remove some of them
        # if they are unnecessary. But sometimes, goto are added
        # for more readability, so set to True to keep them.
        self.dont_remove = False

    def dump(self, o, tab=0):
        o._tabs(tab)
        o._keyword("goto ")
        o._label_or_address(self.addr_jump, -1, False)
        o._new_line()


class Ast_Loop:
    def __init__(self):
        self.branch = Ast_Branch()
        self.is_infinite = False
        self.parent = None
        self.level = 0

    def add(self, node):
        self.branch.add(node)

    def set_infinite(self, v):
        self.is_infinite = v

    def set_branch(self, b):
        self.branch = b

    def dump(self, o, tab=0):
        o._tabs(tab)
        if self.is_infinite:
            o._keyword("for")
            o._add(" (;;) {")
        else:
            o._keyword("loop")
            o._add(" {")
        o._new_line()
        self.branch.dump(o, tab+1)
        o._tabs(tab)
        o._add("}")
        o._new_line()


# ONLY FOR DEBUG !!
class Ast_Comment:
    def __init__(self, text):
        self.text = text
        self.parent = None
        self.level = 0
        self.nodes = []

    def dump(self, o, tab=0):
        if o.gctx.comments:
            o._tabs(tab)
            o._comment("# " + self.text)
            o._new_line()
