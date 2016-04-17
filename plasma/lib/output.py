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

import struct
from ctypes import c_int, c_short, c_long

from plasma.lib.custom_colors import *
from plasma.lib.utils import unsigned, print_no_end, get_char, BYTES_PRINTABLE_SET
from plasma.lib.colors import color, bold
from plasma.lib.fileformat.binary import T_BIN_RAW
from plasma.lib.consts import *


class OutputAbs():
    def __init__(self, ctx=None):
        self.token_lines = [] # each line is separated in tokens (string, color, is_bold)
        self.lines = [] # each line contains the entire string
        self.line_addr = {} # line -> address
        self.addr_line = {} # address -> line
        self.idx_tok_inline_comm = {} # line -> (char_index, token_index)
        self.curr_index = 0

        self.section_prefix = False
        self.curr_section = None # must be updated at hand !!
        self.print_labels = True

        # Easy accesses
        self._dis = ctx.gctx.dis
        self._binary = self._dis.binary
        self.gctx = ctx.gctx
        self.ctx = ctx
        self.OP_IMM = self.gctx.libarch.utils.OP_IMM
        self.ARCH_UTILS = self.gctx.libarch.utils


    # All functions which start with a '_' add a new token/string on
    # the current line.

    def get_inst_str(self, i):
        if len(i.operands) == 0:
            return i.mnemonic
        return "%s %s" % (i.mnemonic, i.op_str)


    def inline_comm_starts_here(self):
        line = len(self.token_lines)-1
        self.idx_tok_inline_comm[line] = self.curr_index

    def is_last_2_line_empty(self):
        if len(self.lines) < 2:
            return True
        return len(self.lines[-1]) == 0 and len(self.lines[-2]) == 0

    def _new_line(self):
        self.curr_index = 0
        self.token_lines.append([])
        self.lines.append([])

    def _add(self, string):
        self.token_lines[-1].append((string, 0, False))
        self.lines[-1].append(string)
        self.curr_index += len(string)

    def _pad_width(self, w):
        if self.curr_index != w:
            self._add(" " * (w - self.curr_index))

    def _tabs(self, tab):
        # debug
        # if not self.token_lines[-1]:
            # self.token_lines[-1].append(("       ", 0, False))
        t = tab * "    "
        self.token_lines[-1].append((t, 0, False))
        self.lines[-1].append(t)
        self.curr_index += len(t)

    def _comment(self, string):
        self.token_lines[-1].append((string, COLOR_COMMENT.val, COLOR_COMMENT.bold))
        self.lines[-1].append(string)
        self.curr_index += len(string)

    def _address(self, addr, print_colon=True, normal_color=False, notprefix=False):
        if self.section_prefix and not notprefix:
            self._comment(self.curr_section.name)
            self._add(" ")

        s = hex(addr)
        if print_colon:
            s += ": "

        if not normal_color and addr in self.ctx.addr_color:
            col = self.ctx.addr_color[addr]
        else:
            if notprefix:
                col = 0
            else:
                col = COLOR_ADDR.val

        self.token_lines[-1].append((s, col, False))
        self.lines[-1].append(s)
        self.curr_index += len(s)

    def _type(self, string):
        self.token_lines[-1].append((string, COLOR_TYPE.val, COLOR_TYPE.bold))
        self.lines[-1].append(string)
        self.curr_index += len(string)

    def _variable(self, string):
        self.token_lines[-1].append((string, COLOR_VAR.val, COLOR_VAR.bold))
        self.lines[-1].append(string)
        self.curr_index += len(string)

    def _keyword(self, string):
        self.token_lines[-1].append((string, COLOR_KEYWORD.val, COLOR_KEYWORD.bold))
        self.lines[-1].append(string)
        self.curr_index += len(string)

    def _string(self, string):
        self.token_lines[-1].append((string, COLOR_STRING.val, COLOR_STRING.bold))
        self.lines[-1].append(string)
        self.curr_index += len(string)

    def _section(self, string):
        self.token_lines[-1].append((string, COLOR_SECTION.val, COLOR_SECTION.bold))
        self.lines[-1].append(string)
        self.curr_index += len(string)

    def _internal_comment(self, string):
        self.token_lines[-1].append((string, COLOR_INTERN_COMMENT.val, COLOR_INTERN_COMMENT.bold))
        self.lines[-1].append(string)
        self.curr_index += len(string)

    def _user_comment(self, string):
        self.token_lines[-1].append((string, COLOR_USER_COMMENT.val, COLOR_USER_COMMENT.bold))
        self.lines[-1].append(string)
        self.curr_index += len(string)

    def _retcall(self, string):
        self.token_lines[-1].append((string, COLOR_RETCALL.val, COLOR_RETCALL.bold))
        self.lines[-1].append(string)
        self.curr_index += len(string)

    def _data(self, string):
        self.token_lines[-1].append((string, COLOR_DATA.val, COLOR_DATA.bold))
        self.lines[-1].append(string)
        self.curr_index += len(string)

    def _data_prefix(self, size):
        if size == 1:
            self._retcall(".db")
        elif size == 2:
            self._data(".dw")
        elif size == 4:
            self._data(".dd")
        elif size == 8:
            self._data(".dq")


    def _word(self, by, size):
        self._data_prefix(size)
        if by is None:
            self._add(" ?")
        else:
            if size == 1:
                self._add(" %0.2x" % by)
                if by in BYTES_PRINTABLE_SET:
                    if by == 9:
                        self._string("  '\\t'")
                    elif by == 13:
                        self._string("  '\\r'")
                    elif by == 10:
                        self._string("  '\\n'")
                    else:
                        self._string("  '%c'" % by)
            else:
                self._add(" " + hex(by))


    def _label(self, ad, tab=-1, print_colon=True, nocolor=False):
        l = self.gctx.api.get_symbol(ad)
        if l is None:
            return False

        ty = self._dis.mem.get_type(ad)

        col = 0
        if ty == MEM_FUNC:
            col = COLOR_SYMBOL.val
        elif ty == MEM_CODE:
            if not self.ctx.is_dump:
                # It means that in decompilation mode we don't want to print
                # labels with "loc_ADDR:", but we want to print them if they are
                # referenced in an instruction, example : mov eax, loc_ADDR
                if l.startswith("loc_"):
                    if print_colon:
                        return False
                    l = hex(ad)
            col = COLOR_CODE_ADDR.val
        elif ty == MEM_UNK:
            col = COLOR_UNK.val
        elif MEM_BYTE <= ty <= MEM_OFFSET:
            col = COLOR_DATA.val

        if print_colon:
            l += ":"

        if not self.ctx.is_dump and ad in self.ctx.addr_color:
            col = self.ctx.addr_color[ad]

        if nocolor:
            col = 0

        if tab == -1:
            self.token_lines[-1].append((l, col, False))
            self.lines[-1].append(l)
            self.curr_index += len(l)
        else:
            self._tabs(tab)

            if ty == MEM_FUNC:
                flags = self._dis.functions[ad][FUNC_FLAGS]
                if flags & FUNC_FLAG_NORETURN:
                    self._comment("__noreturn__ ")

            self.token_lines[-1].append((l, col, False))
            self.lines[-1].append(l)
            self.curr_index += len(l)

        return True


    def _label_or_address(self, addr, tab=-1, print_colon=True):
        if self._label(addr, tab, print_colon):
            return
        self._tabs(tab)
        self._address(addr, print_colon)


    def _label_and_address(self, ad, tab=-1, print_colon=True, with_comment=False):
        is_first = not self.ctx.is_dump and ad == self.ctx.entry

        if not is_first and self._label(ad, tab, print_colon):
            self._new_line()

            # Print stack variables
            if self._dis.mem.is_func(ad):
                self._all_vars(ad)

            if tab != -1:
                self._tabs(tab)
            if with_comment:
                self._comment("# ")
            self._address(ad, print_colon, True)
        else:
            if tab != -1:
                self._tabs(tab)
            if with_comment:
                self._comment("# ")
            self._address(ad, print_colon)


    def _previous_comment(self, i, tab):
        if i.address in self._dis.internal_previous_comments:
            if self.ctx.is_dump and not self.is_last_2_line_empty():
                self._new_line()
            for comm in self._dis.internal_previous_comments[i.address]:
                self._tabs(tab)
                self._internal_comment("; %s" % comm)
                self._new_line()

        if i.address in self._dis.user_previous_comments:
            if self.ctx.is_dump and not self.is_last_2_line_empty():
                self._new_line()
            for comm in self._dis.user_previous_comments[i.address]:
                self._tabs(tab)
                self._user_comment("; %s" % comm)
                self._new_line()


    def _commented_inst(self, i, tab):
        self._label_and_address(i.address, tab, with_comment=True)
        self.set_line(i.address)
        self._bytes(i.bytes)
        self._comment(self.get_inst_str(i))
        self._inline_comment(i)
        self._new_line()


    def _inline_comment(self, i):
        # A user comment should always be at the end of the line

        if i.address in self._dis.internal_inline_comments:
            self._internal_comment(" ; ")
            self._internal_comment(self._dis.internal_inline_comments[i.address])

        if i.address in self._dis.user_inline_comments:
            self._user_comment(" ; ")
            self.inline_comm_starts_here()
            self._user_comment(self._dis.user_inline_comments[i.address])


    # Only used when --nocomment is enabled and a jump point to this instruction
    def _address_if_needed(self, i, tab):
        if i.address in self.ctx.addr_color:
            self._tabs(tab)
            self._address(i.address)


    def _bytes(self, by):
        if self.gctx.print_bytes:
            i = 0
            for c in by:
                i += 1
                self._comment("%.2x " % c)
                if i == self.gctx.nbytes:
                    break

            if i != self.gctx.nbytes:
                self._add("   " * (self.gctx.nbytes - i))

            self._add("   ")


    def _comment_fused(self, jump_inst, fused_inst, tab):
        if self.gctx.comments:
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


    def _all_vars(self, func_addr):
        if not self._dis.mem.is_func(func_addr):
            return

        tabs = 0 if self.ctx.is_dump else 1
        lst = list(self._dis.functions[func_addr][FUNC_OFF_VARS].keys())

        if not lst:
            return

        lst.sort()
        self._new_line()

        for off in lst:
            self._tabs(tabs)
            self._type(self.__get_var_type(func_addr, off))
            self._pad_width(11 + tabs * 4)
            self._variable(self.get_var_name(func_addr, off))
            self._pad_width(20 + tabs * 4)
            if off < 0:
                self._add(" = -0x%x" % (-off))
            else:
                self._add(" = 0x%x" % off)
            self._new_line()

        self._new_line()


    def _asm_block(self, blk, tab):
        for i in blk:
            self._asm_inst(i, tab)


    def _bad(self, addr, tab=0):
        self._tabs(tab)
        self._address(addr)
        self._add("(bad)")
        self._new_line()


    def _dash(self):
        self._user_comment("; ---------------------------------------------------------------------")
        self._new_line()


    def deref_if_offset(self, ad):
        section = self._binary.get_section(ad)
        if section is not None:
            # if ad is set as an "offset"
            sz = self.get_offset_size(ad)
            if sz != -1:
                val = section.read_int(ad, sz)
                if self.gctx.capstone_string == 0:
                    self._add("=")
                    self._imm(val, 0, True, section=section,
                              force_dont_print_data=True)
                    return True
        return False


    #
    # Print an immediate value
    # imm         the immediate to print
    # op_size     op.size is not available in arm, so it's in arguments
    # hexa        print in hexa if no symbol or something else was found
    # section     the section where `imm` is, if None a search will be done
    # print_data  print the string at the address `imm` only if `imm` is not a symbol
    # force_dont_print_data  really don't print data even if it's not a symbol
    #                        it's used for jump/call
    #
    def _imm(self, imm, op_size, hexa, section=None, print_data=True,
             force_dont_print_data=False):

        if self.gctx.capstone_string != 0:
            hexa = True

        if hexa:
            imm = unsigned(imm)

        label_printed = self._label(imm, print_colon=False)

        if label_printed:
            ty = self._dis.mem.get_type(imm)
            # ty == -1 : from the terminal (with -x) there are no xrefs if
            # the file was loaded without a database.
            if imm in self._dis.xrefs and ty != MEM_UNK and \
                    ty != MEM_ASCII or ty == -1:
                return

            if ty == MEM_ASCII:
                print_data = True
                force_dont_print_data = False

        if section is None:
            section = self._binary.get_section(imm)

        if section is not None and section.start == 0:
            section = None

        # For a raw file, if the raw base is 0 the immediate is considered
        # as an address only if it's in the symbols list.
        raw_base_zero = self._binary.type == T_BIN_RAW and self.gctx.raw_base == 0

        if section is not None and not raw_base_zero:
            if not label_printed:
                self._address(imm, print_colon=False, notprefix=True)

            if not force_dont_print_data and print_data:
                s = self._binary.get_string(imm, self.gctx.max_data_size)
                if s is not None:
                    self._add(" ")
                    self._string('"' + s + '"')

            return

        if label_printed:
            return

        if op_size == 1:
            self._string("'%s'" % get_char(imm))
        elif hexa:
            self._add(hex(imm))
        else:
            if op_size == 4:
                self._add(str(c_int(imm).value))
            elif op_size == 2:
                self._add(str(c_short(imm).value))
            else:
                self._add(str(c_long(imm).value))

            if imm > 0:
                if op_size == 4:
                    packed = struct.pack("<L", imm)
                elif op_size == 8:
                    packed = struct.pack("<Q", imm)
                else:
                    return
                if set(packed).issubset(BYTES_PRINTABLE_SET):
                    self._string(" \"" + "".join(map(chr, packed)) + "\"")

        return


    def set_line(self, addr):
        l = len(self.token_lines) - 1
        self.line_addr[l] = addr
        if addr not in self.addr_line or l < self.addr_line[addr]:
            self.addr_line[addr] = l


    def is_label(self, ad):
        return ad in self._binary.reverse_symbols or \
               ad in self._dis.xrefs


    def get_offset_size(self, ad):
        if self._dis.mem.is_offset(ad):
            return self._dis.mem.get_size(ad)
        return -1


    # Returns (func_addr, off) or None
    def get_var_offset(self, i, op_num):
        func_id  = self._dis.mem.get_func_id(i.address)
        if func_id != -1 and func_id in self._dis.func_id:
            func_addr = self._dis.func_id[func_id]
            tmp = self._dis.functions[func_addr][FUNC_INST_ADDR]
            if i.address in tmp:
                return func_addr, tmp[i.address]
        return None


    def get_var_name(self, func_addr, off):
        name = self._dis.functions[func_addr][FUNC_OFF_VARS][off][VAR_NAME]
        if name is None:
            if off < 0:
                return "var_%x" % (-off)
            return "arg_%x" % off
        return name


    def __get_var_type(self, func_addr, off):
        ty = self._dis.functions[func_addr][FUNC_OFF_VARS][off][VAR_TYPE]
        if ty == MEM_BYTE:
            t = "char"
        elif ty == MEM_WORD:
            t = "short"
        elif ty == MEM_DWORD:
            t = "int"
        elif ty == MEM_QWORD:
            t = "long int"
        else:
            t = "void *"
        return t


    def _ast(self, entry, ast):
        self._new_line()
        self._keyword("function ")

        if not self._label(entry, print_colon=False, nocolor=True):
            self._add(hex(entry))

        section = self._binary.get_section(entry)

        if section is not None:
            self._add(" (")
            self._section(section.name)
            self._add(") {")
        else:
            self._add(" {")

        self._new_line()
        self._all_vars(entry)
        ast.dump(self, 1)
        self._add("}")
        self.join_lines()


    def join_lines(self):
        # Join all lines
        for i, l in enumerate(self.lines):
            self.lines[i] = "".join(self.lines[i])
            sz = len(self.lines[i])
            if i not in self.idx_tok_inline_comm:
                self.idx_tok_inline_comm[i] = (sz + 1, len(l))


    def _asm_inst(self, i, tab=0, prefix=""):
        self._previous_comment(i, tab)

        if prefix == "# ":
            # debug
            # from lib.utils import BRANCH_NEXT
            # if i.address in self.ctx.gph.link_out:
                # self._add(hex(self.ctx.gph.link_out[i.address][BRANCH_NEXT]))
            self._commented_inst(i, tab)
            return

        if i.address in self.ctx.all_fused_inst:
            return

        if self.print_labels:
            self._label_and_address(i.address, tab)
            self._bytes(i.bytes)
        else:
            self._tabs(tab)
            self._address(i.address)

        self.set_line(i.address)

        # debug
        # from lib.utils import BRANCH_NEXT
        # if i.address in self.ctx.gph.link_out:
            # self._add(hex(self.ctx.gph.link_out[i.address][BRANCH_NEXT]))

        if self.gctx.capstone_string == 2:
            self._add(i.mnemonic)
            self._add(" ")
            self._add(i.op_str)
        else:
            tab = self._pre_asm_inst(i, tab)

            if self.ARCH_UTILS.is_ret(i):
                self._retcall(self.get_inst_str(i))

            elif self.ARCH_UTILS.is_call(i):
                self._retcall(i.mnemonic)
                self._add(" ")

                if self.gctx.sectionsname:
                    op = i.operands[0]
                    if op.type == self.OP_IMM:
                        s = self._binary.get_section(op.value.imm)
                        if s is not None:
                            self._add("(")
                            self._section(s.name)
                            self._add(") ")

                self._operand(i, 0, hexa=True, force_dont_print_data=True)

            # Here we can have conditional jump with the option --dump
            elif self.ARCH_UTILS.is_jump(i):
                self._add(i.mnemonic)
                if len(i.operands) > 0:
                    self._add(" ")

                    for num in range(len(i.operands)-1):
                        self._operand(i, num)
                        self._add(", ")

                    # WARNING: it assumes that the last operand is the address
                    if i.operands[-1].type != self.OP_IMM:
                        self._operand(i, -1, force_dont_print_data=True)
                        if self.ARCH_UTILS.is_uncond_jump(i) and \
                                not self.ctx.is_dump and \
                                i.address not in self._dis.jmptables:
                            self._add(" ")
                            self._comment("# STOPPED")
                    else:
                        self._operand(i, -1, hexa=True, force_dont_print_data=True)

            else:
                self._sub_asm_inst(i, tab)

            self._post_asm_inst(i, tab)

        self._inline_comment(i)
        self._new_line()


    def print(self):
        for l in self.token_lines:
            for (string, col, is_bold) in l:
                if self.gctx.color:
                    if col != 0:
                        string = color(string, col)
                    if is_bold:
                        string = bold(string)
                print_no_end(string)
            print()


    def _pre_asm_inst(self, i, tab):
        return tab


    def _post_asm_inst(self, i, tab):
        return

    def _operand(self, i, num_op, hexa=False, show_deref=True):
        raise NotImplementedError


    def _if_cond(self, jump_id, jump_cond, fused_inst):
        raise NotImplementedError


    # Architecture specific output
    def _sub_asm_inst(self, i, tab=0):
        raise NotImplementedError
