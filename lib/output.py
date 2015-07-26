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

from lib.colors import (color_addr, color_comment, color_keyword, color_type,
        color_var, color_symbol)


# It contains any new comments added by the program.
# They are used to improve readability.
# addr -> string comment
INTERN_COMMENTS = {}


def print_tabbed(string, tab):
    print("    " * tab, end="")
    print(string)


def print_tabbed_no_end(string, tab):
    print("    " * tab, end="")
    print(string, end="")


def print_no_end(text):
    print(text, end="")


def print_comment(txt, tab=-1):
    if tab == -1:
        print(color_comment(txt))
    else:
        print_tabbed(color_comment(txt), tab)


def print_comment_no_end(txt, tab=-1):
    if tab == -1:
        print_no_end(color_comment(txt))
    else:
        print_tabbed_no_end(color_comment(txt), tab)



class OutputAbs():
    def __init__(self, ctx=None):
        self.ctx = ctx
        self.binary = ctx.dis.binary


    def var_name_exists(self, i, op_num):
        return i.operands[op_num].mem.disp in self.ctx.local_vars_idx


    def get_var_name(self, i, op_num):
        idx = self.ctx.local_vars_idx[i.operands[op_num].mem.disp]
        return self.ctx.local_vars_name[idx]


    def print_symbol(self, addr):
        print_no_end(color_symbol("<" + self.binary.reverse_symbols[addr] + ">"))


    # Only used when --nocomment is enabled and a jump point to this instruction
    def print_addr_if_needed(self, i, tab):
        if i.address in self.ctx.addr_color:
            print_tabbed_no_end(color_addr(i.address), tab)


    def print_commented_jump(self, jump_inst, fused_inst, tab):
        if self.ctx.comments:
            if fused_inst != None:
                self.print_inst(fused_inst, tab, "# ")
            if jump_inst != None:
                self.print_inst(jump_inst, tab, "# ")
        else:
            # Otherwise print only the address if referenced
            if fused_inst != None:
                self.print_addr_if_needed(fused_inst, tab)
            if jump_inst != None:
                self.print_addr_if_needed(jump_inst, tab)


    def print_vars_type(self):
        idx = 0
        for sz in self.ctx.local_vars_size:
            name = self.ctx.local_vars_name[idx]
            print_tabbed(color_type("int%d_t " % (sz*8)) + color_var(name), 1)
            idx += 1


    def print_block(self, blk, tab):
        for i in blk:
            self.print_inst(i, tab)


    def print_ast(self, entry, ast):
        print_no_end(color_keyword("function "))
        print_no_end(self.binary.reverse_symbols.get(entry, hex(entry)))
        print(" {")
        self.print_vars_type()
        ast.print(self, 1)
        print("}")


    # Return True if the operand is a variable (because the output is
    # modified, we reprint the original instruction later)
    def print_operand(self, i, num_op, hexa=False, show_deref=True):
        raise NotImplementedError


    def print_if_cond(self, jump_id, jump_cond, fused_inst):
        raise NotImplementedError


    def print_inst(self, i, tab=0, prefix=""):
        raise NotImplementedError
