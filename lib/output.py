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

from lib.utils import print_no_end
from lib.colors import color, bold
from custom_colors import *


class OutputAbs():
    def __init__(self, ctx=None):
        self.ctx = ctx
        self.binary = ctx.dis.binary
        self.lines = []


    # All functions which start with a '_' add a new token/string on
    # the current line.


    def _new_line(self):
        self.lines.append([])

    def _add(self, string):
        self.lines[-1].append((string, 0, False))

    def _tabs(self, tab):
        self.lines[-1].append((tab * "    ", 0, False))

    def _symbol(self, addr):
        s = self.binary.reverse_symbols[addr]
        self.lines[-1].append((s, COLOR_SYMBOL.val, COLOR_SYMBOL.bold))

    def _comment(self, string):
        self.lines[-1].append((string, COLOR_COMMENT.val, COLOR_COMMENT.bold))

    def _address(self, addr, print_colon=True, normal_color=False):
        s = hex(addr)
        if print_colon:
            s += ": "
        if addr in self.ctx.addr_color and not normal_color:
            col = self.ctx.addr_color[addr]
        else:
            col = COLOR_ADDR.val
        self.lines[-1].append((s, col, False))

    def _type(self, string):
        self.lines[-1].append((string, COLOR_TYPE.val, COLOR_TYPE.bold))

    def _variable(self, string):
        self.lines[-1].append((string, COLOR_VAR.val, COLOR_VAR.bold))

    def _keyword(self, string):
        self.lines[-1].append((string, COLOR_KEYWORD.val, COLOR_KEYWORD.bold))

    def _string(self, string):
        self.lines[-1].append((string, COLOR_STRING.val, COLOR_STRING.bold))

    def _section(self, string):
        self.lines[-1].append((string, COLOR_SECTION.val, COLOR_SECTION.bold))

    def _internal_comment(self, string):
        self.lines[-1].append((string, COLOR_INTERN_COMMENT.val, COLOR_INTERN_COMMENT.bold))

    def _retcall(self, string):
        self.lines[-1].append((string, COLOR_RETCALL.val, COLOR_RETCALL.bold))


    def _label(self, addr, tab=-1, print_colon=True):
        if addr not in self.ctx.labels:
            return False
        l = str(self.ctx.labels[addr])

        if print_colon:
            l += ":"

        if addr in self.ctx.addr_color:
            col = self.ctx.addr_color[addr]
        else:
            col = COLOR_ADDR.val

        if tab == -1:
            self.lines[-1].append((l, col, False))
        else:
            self._tabs(tab)
            self.lines[-1].append((l, col, False))
        return True


    def _label_or_address(self, addr, tab=-1, print_colon=True):
        if self._label(addr, tab, print_colon):
            return
        self._tabs(tab)
        self._address(addr, print_colon)


    def _label_and_address(self, addr, tab=-1, print_colon=True):
        if self._label(addr, tab, print_colon):
            self._new_line()
            if tab != -1:
                self._tabs(tab)
            self._address(addr, print_colon, True)
        else:
            self._tabs(tab)
            self._address(addr, print_colon)


    # Only used when --nocomment is enabled and a jump point to this instruction
    def _address_if_needed(self, i, tab):
        if i.address in self.ctx.addr_color:
            self._tabs(tab)
            self._address(i.address)


    def _bytes(self, i, comment_this=False):
        if self.ctx.print_bytes:
            if comment_this:
                if self.ctx.comments:
                    for c in i.bytes:
                        self._comment("%x " % c)
            else:
                for c in i.bytes:
                    self._comment("%.2x " % c)


    def _comment_fused(self, jump_inst, fused_inst, tab):
        if self.ctx.comments:
            if fused_inst != None:
                self._asm_inst(fused_inst, tab, "# ")
            if jump_inst != None:
                self._asm_inst(jump_inst, tab, "# ")
        else:
            # Otherwise print only the address if referenced
            if fused_inst != None:
                self._address_if_needed(fused_inst, tab)
            if jump_inst != None:
                self._address_if_needed(jump_inst, tab)


    def _all_vars(self):
        idx = 0
        for sz in self.ctx.local_vars_size:
            name = self.ctx.local_vars_name[idx]
            self._tabs(1)
            self._type("int%d_t " % (sz*8))
            self._variable(name)
            self._new_line()
            idx += 1


    def _asm_block(self, blk, tab):
        for i in blk:
            self._asm_inst(i, tab)


    def _bad(self, addr, tab=0):
        self._tabs(tab)
        self._address(addr)
        self._add("(bad)")
        self._new_line()


    def is_symbol(self, ad):
        return (self.ctx.dump or ad != self.ctx.entry_addr) and \
            ad in self.ctx.dis.binary.reverse_symbols


    def var_name_exists(self, i, op_num):
        return i.operands[op_num].mem.disp in self.ctx.local_vars_idx


    def get_var_name(self, i, op_num):
        idx = self.ctx.local_vars_idx[i.operands[op_num].mem.disp]
        return self.ctx.local_vars_name[idx]


    def _ast(self, entry, ast):
        self._new_line()
        self._keyword("function ")
        self._add(self.binary.reverse_symbols.get(entry, hex(entry)))
        sec_name, _ = self.binary.is_address(entry)
        if sec_name is not None:
            self._add(" (")
            self._section(sec_name)
            self._add(") {")
        else:
            self._add(" {")
        self._new_line()
        self._all_vars()
        ast.dump(self, 1)
        self._add("}")


    def print(self):
        for l in self.lines:
            for (string, col, is_bold) in l:
                if self.ctx.color:
                    if col != 0:
                        string = color(string, col)
                    if is_bold:
                        string = bold(string)
                print_no_end(string)
            print()


    # Return True if the operand is a variable (because the output is
    # modified, we reprint the original instruction later)
    def _operand(self, i, num_op, hexa=False, show_deref=True):
        raise NotImplementedError


    def _if_cond(self, jump_id, jump_cond, fused_inst):
        raise NotImplementedError


    def _asm_inst(self, i, tab=0, prefix=""):
        raise NotImplementedError
