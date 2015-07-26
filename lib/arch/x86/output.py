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

import struct

from lib.output import (OutputAbs, print_no_end, print_tabbed_no_end,
        print_comment, print_comment_no_end, INTERN_COMMENTS)
from lib.colors import (color, color_addr, color_retcall, color_string,
        color_var, color_section, color_intern_comment)
from lib.utils import get_char, BYTES_PRINTABLE_SET
from lib.arch.x86.utils import (inst_symbol, is_call, is_jump, is_ret,
    is_uncond_jump, cond_symbol)
from capstone.x86 import (X86_INS_ADD, X86_INS_AND, X86_INS_CMP, X86_INS_DEC,
        X86_INS_IDIV, X86_INS_IMUL, X86_INS_INC, X86_INS_MOV, X86_INS_SHL,
        X86_INS_SHR, X86_INS_SUB, X86_INS_XOR, X86_OP_FP, X86_OP_IMM,
        X86_OP_INVALID, X86_OP_MEM, X86_OP_REG, X86_REG_EBP, X86_REG_EIP,
        X86_REG_RBP, X86_REG_RIP, X86_INS_CDQE, X86_INS_LEA, X86_INS_MOVSX,
        X86_INS_OR, X86_INS_NOT, X86_INS_SCASB, X86_PREFIX_REPNE,
        X86_INS_TEST, X86_INS_JNS, X86_INS_JS, X86_INS_MUL, X86_INS_JP,
        X86_INS_JNP, X86_INS_JCXZ, X86_INS_JECXZ, X86_INS_JRCXZ,
        X86_INS_SAR, X86_INS_SAL)


ASSIGNMENT_OPS = {X86_INS_XOR, X86_INS_AND, X86_INS_OR,
        X86_INS_SAR, X86_INS_SAL, X86_INS_SHR, X86_INS_SHL}


# After these instructions we need to add a zero
# example : jns ADDR -> if > 0
JMP_ADD_ZERO = {
    X86_INS_JNS,
    X86_INS_JS,
    X86_INS_JP,
    X86_INS_JNP,
    X86_INS_JCXZ,
    X86_INS_JECXZ,
    X86_INS_JRCXZ
}


INST_CHECK = {X86_INS_SUB, X86_INS_ADD, X86_INS_MOV, X86_INS_CMP,
    X86_INS_XOR, X86_INS_AND, X86_INS_SHR, X86_INS_SHL, X86_INS_IMUL,
    X86_INS_SAR, X86_INS_SAL,
    X86_INS_DEC, X86_INS_INC, X86_INS_LEA, X86_INS_MOVSX, X86_INS_OR}


class Output(OutputAbs):
    # Return True if the operand is a variable (because the output is
    # modified, we reprint the original instruction later)
    def print_operand(self, i, num_op, hexa=False, show_deref=True):
        def inv(n):
            return n == X86_OP_INVALID

        op = i.operands[num_op]

        if op.type == X86_OP_IMM:
            imm = op.value.imm
            sec_name, is_data = self.binary.is_address(imm)

            if sec_name is not None:
                print_no_end(hex(imm))
                if self.ctx.sectionsname:
                    print_no_end(" (" + color_section(sec_name) + ")")
                if is_data:
                    s = self.binary.get_string(imm, self.ctx.max_data_size)
                    print_no_end(" " + color_string(s))
                if imm in self.binary.reverse_symbols:
                    print_no_end(" ")
                    self.print_symbol(imm)
            elif op.size == 1:
                print_no_end(color_string("'%s'" % get_char(imm)))
            elif hexa:
                print_no_end(hex(imm))
            else:
                print_no_end(str(imm))

                if imm > 0:
                    packed = struct.pack("<L", imm)
                    if set(packed).issubset(BYTES_PRINTABLE_SET):
                        print_no_end(color_string(" \""))
                        print_no_end(color_string("".join(map(chr, packed))))
                        print_no_end(color_string("\""))
                        return False

                # returns True because capstone print immediate in hexa
                # it will be printed in a comment, sometimes it better
                # to have the value in hexa
                return True

            return False

        elif op.type == X86_OP_REG:
            print_no_end(i.reg_name(op.value.reg))
            return False

        elif op.type == X86_OP_FP:
            print_no_end("%f" % op.value.fp)
            return False

        elif op.type == X86_OP_MEM:
            mm = op.mem

            if not inv(mm.base) and mm.disp != 0 \
                and inv(mm.segment) and inv(mm.index):

                if (mm.base == X86_REG_RBP or mm.base == X86_REG_EBP) and \
                       self.var_name_exists(i, num_op):
                    print_no_end(color_var(self.get_var_name(i, num_op)))
                    return True
                elif mm.base == X86_REG_RIP or mm.base == X86_REG_EIP:
                    addr = i.address + i.size + mm.disp
                    print_no_end("*({0})".format(
                        self.binary.reverse_symbols.get(addr, hex(addr))))
                    return True

            printed = False
            if show_deref:
                print_no_end("*(")

            if not inv(mm.base):
                print_no_end("%s" % i.reg_name(mm.base))
                printed = True

            elif not inv(mm.segment):
                print_no_end("%s" % i.reg_name(mm.segment))
                printed = True

            if not inv(mm.index):
                if printed:
                    print_no_end(" + ")
                if mm.scale == 1:
                    print_no_end("%s" % i.reg_name(mm.index))
                else:
                    print_no_end("(%s*%d)" % (i.reg_name(mm.index), mm.scale))
                printed = True

            if mm.disp != 0:
                if mm.disp < 0:
                    if printed:
                        print_no_end(" - ")
                    print_no_end(-mm.disp)
                else:
                    if printed:
                        print_no_end(" + ")
                        print_no_end(mm.disp)
                    else:
                        if mm.disp in self.binary.reverse_symbols:
                            print_no_end(hex(mm.disp) + " ")
                            self.print_symbol(mm.disp)
                        else:
                            print_no_end(hex(mm.disp))

            if show_deref:
                print_no_end(")")
            return True


    def print_if_cond(self, jump_cond, fused_inst):
        if fused_inst is None:
            print_no_end(cond_symbol(jump_cond))
            if jump_cond in JMP_ADD_ZERO:
                print_no_end(" 0")
            return

        assignment = fused_inst.id in ASSIGNMENT_OPS

        if assignment:
            print_no_end("(")
        print_no_end("(")
        self.print_operand(fused_inst, 0)
        print_no_end(" ")

        if fused_inst.id == X86_INS_TEST:
            print_no_end(cond_symbol(jump_cond))
        elif assignment:
            print_no_end(inst_symbol(fused_inst))
            print_no_end(" ")
            self.print_operand(fused_inst, 1)
            print_no_end(") ")
            print_no_end(cond_symbol(jump_cond))
        else:
            print_no_end(cond_symbol(jump_cond))
            print_no_end(" ")
            self.print_operand(fused_inst, 1)

        if fused_inst.id == X86_INS_TEST or \
                (fused_inst.id != X86_INS_CMP and \
                 (jump_cond in JMP_ADD_ZERO or assignment)):
            print_no_end(" 0")

        print_no_end(")")


    def print_inst(self, i, tab=0, prefix=""):
        def get_inst_str():
            nonlocal i
            return "%s %s" % (i.mnemonic, i.op_str)

        if prefix == "# ":
            if self.ctx.comments:
                print_comment_no_end(prefix, tab)
                print_no_end(color_addr(i.address))
                print_comment(get_inst_str())
            return

        if i.address in self.ctx.all_fused_inst:
            return

        if i.address != self.ctx.addr and \
                i.address in self.ctx.dis.binary.reverse_symbols:
            print_tabbed_no_end("", tab)
            self.print_symbol(i.address)
            print()

        modified = self.__print_inst(i, tab, prefix)

        if i.address in INTERN_COMMENTS:
            print_no_end(color_intern_comment(" ; "))
            print_no_end(color_intern_comment(INTERN_COMMENTS[i.address]))

        if modified and self.ctx.comments:
            print_comment_no_end(" # " + get_inst_str())

        print()


    def __print_inst(self, i, tab=0, prefix=""):
        def get_inst_str():
            nonlocal i
            return "%s %s" % (i.mnemonic, i.op_str)

        print_tabbed_no_end(color_addr(i.address), tab)

        if is_ret(i):
            print_no_end(color_retcall(get_inst_str()))
            return

        if is_call(i):
            print_no_end(color_retcall(i.mnemonic) + " ")
            self.print_operand(i, 0, hexa=True)
            return

        # Here we can have conditional jump with the option --dump
        if is_jump(i):
            if i.operands[0].type != X86_OP_IMM:
                print_no_end(i.mnemonic + " ")
                self.print_operand(i, 0)
                if is_uncond_jump(i) and self.ctx.comments:
                    print_comment_no_end(" # STOPPED")
                return
            try:
                addr = i.operands[0].value.imm
                print_no_end(i.mnemonic + " " + color(hex(addr), self.ctx.addr_color[addr]))
            except KeyError:
                print_no_end(i.mnemonic + " " + hex(addr))
            return


        modified = False

        if i.id in INST_CHECK:
            if (i.id == X86_INS_OR and i.operands[1].type == X86_OP_IMM and
                    i.operands[1].value.imm == -1):
                self.print_operand(i, 0)
                print_no_end(" = -1")

            elif (i.id == X86_INS_AND and i.operands[1].type == X86_OP_IMM and
                    i.operands[1].value.imm == 0):
                self.print_operand(i, 0)
                print_no_end(" = 0")

            elif (all(op.type == X86_OP_REG for op in i.operands) and
                    len(set(op.value.reg for op in i.operands)) == 1 and
                    i.id == X86_INS_XOR):
                self.print_operand(i, 0)
                print_no_end(" = 0")

            elif i.id == X86_INS_INC or i.id == X86_INS_DEC:
                self.print_operand(i, 0)
                print_no_end(inst_symbol(i))

            elif i.id == X86_INS_LEA:
                self.print_operand(i, 0)
                print_no_end(" = &(")
                self.print_operand(i, 1)
                print_no_end(")")

            elif i.id == X86_INS_IMUL:
                if len(i.operands) == 3:
                    self.print_operand(i, 0)
                    print_no_end(" = ")
                    self.print_operand(i, 1)
                    print_no_end(" " + inst_symbol(i).rstrip('=') + " ")
                    self.print_operand(i, 2)
                elif len(i.operands) == 2:
                    self.print_operand(i, 0)
                    print_no_end(" " + inst_symbol(i) + " ")
                    self.print_operand(i, 2)
                elif len(i.operands) == 1:
                    sz = i.operands[0].size
                    if sz == 1:
                        print_no_end("ax = al * ")
                    elif sz == 2:
                        print_no_end("dx:ax = ax * ")
                    elif sz == 4:
                        print_no_end("edx:eax = eax * ")
                    elif sz == 8:
                        print_no_end("rdx:rax = rax * ")
                    self.print_operand(i, 0)

            else:
                self.print_operand(i, 0)
                print_no_end(" " + inst_symbol(i) + " ")
                self.print_operand(i, 1)

            modified = True

        elif i.id == X86_INS_CDQE:
            print_no_end("rax = eax")
            modified = True

        elif i.id == X86_INS_IDIV:
            print_no_end('eax = edx:eax / ')
            self.print_operand(i, 0)
            print_no_end('; edx = edx:eax % ')
            self.print_operand(i, 0)
            modified = True

        elif i.id == X86_INS_MUL:
            lut = {1: ("al", "ax"), 2: ("ax", "dx:ax"), 4: ("eax", "edx:eax"),
                    8: ("rax", "rdx:rax")}
            src, dst = lut[i.operands[0].size]
            print_no_end('{0} = {1} * '.format(dst, src))
            self.print_operand(i, 0)
            modified = True

        elif i.id == X86_INS_NOT:
            self.print_operand(i, 0)
            print_no_end(' ^= -1')
            modified = True

        elif i.id == X86_INS_SCASB and i.prefix[0] == X86_PREFIX_REPNE:
            print_no_end('while (')
            self.print_operand(i, 1)
            print_no_end(' != ')
            self.print_operand(i, 0)
            print_no_end(') { ')
            self.print_operand(i, 1, show_deref=False)
            print_no_end('++; cx--; } ')
            self.print_operand(i, 1, show_deref=False)
            print_no_end('++; cx--;')
            modified = True

        else:
            print_no_end("%s " % i.mnemonic)
            if len(i.operands) > 0:
                modified = self.print_operand(i, 0)
                k = 1
                while k < len(i.operands):
                    print_no_end(", ")
                    modified |= self.print_operand(i, k)
                    k += 1

        return modified
