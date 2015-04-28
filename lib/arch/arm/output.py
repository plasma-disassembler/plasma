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

from capstone.arm import (ARM_INS_EOR, ARM_INS_AND, ARM_INS_ORR, ARM_OP_IMM,
        ARM_OP_MEM, ARM_OP_REG, ARM_OP_INVALID, ARM_INS_SUB, ARM_INS_ADD,
        ARM_INS_MOV, ARM_OP_FP, ARM_INS_CMP, ARM_CC_AL, ARM_INS_LDR, ARM_CC_PL,
        ARM_CC_VS, ARM_CC_VC, ARM_CC_HI, ARM_CC_LS, ARM_CC_LO, ARM_CC_HS,
        ARM_CC_MI, ARM_INS_TST)

from lib.output import (OutputAbs, print_no_end, print_tabbed_no_end,
        print_comment, print_comment_no_end)
from lib.colors import (color, color_addr, color_retcall, color_string,
        color_var, color_section, color_keyword, color_type)
from lib.utils import get_char, BYTES_PRINTABLE_SET
from lib.arch.arm.utils import (inst_symbol, is_call, is_jump, is_ret,
    is_uncond_jump, cond_symbol)


ASSIGNMENT_OPS = {ARM_INS_EOR, ARM_INS_AND, ARM_INS_ORR}


# After these instructions we need to add a zero
# example : bpl ADDR -> if >= 0
COND_ADD_ZERO = {
    ARM_CC_PL,
    ARM_CC_MI,
}


class Output(OutputAbs):
    # Return True if the operand is a variable (because the output is
    # modified, we reprint the original instruction later)
    def print_operand(self, i, num_op, hexa=False, show_deref=True):
        def inv(n):
            return n == ARM_OP_INVALID

        op = i.operands[num_op]

        if op.type == ARM_OP_IMM:
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

        elif op.type == ARM_OP_REG:
            print_no_end(i.reg_name(op.value.reg))
            return False

        elif op.type == ARM_OP_FP:
            print_no_end("%f" % op.value.fp)
            return False

        elif op.type == ARM_OP_MEM:
            mm = op.mem

            # TODO : try to do the same thing as x86
            # if not inv(mm.base) and mm.disp != 0 \
                # and inv(mm.segment) and inv(mm.index):

                # if (mm.base == X86_REG_RBP or mm.base == X86_REG_EBP) and \
                       # self.var_name_exists(i, num_op):
                    # print_no_end(color_var(self.get_var_name(i, num_op)))
                    # return True
                # elif mm.base == X86_REG_RIP or mm.base == X86_REG_EIP:
                    # addr = i.address + i.size + mm.disp
                    # print_no_end("*({0})".format(
                        # self.binary.reverse_symbols.get(addr, hex(addr))))
                    # return True

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


    def print_if_cond(self, jump_id, jump_cond, fused_inst):
        if fused_inst is None:
            print_no_end(cond_symbol(jump_cond))
            if jump_cond in COND_ADD_ZERO:
                print_no_end(" 0")
            return

        assignment = fused_inst.id in ASSIGNMENT_OPS

        if assignment:
            print_no_end("(")
        print_no_end("(")
        self.print_operand(fused_inst, 0)
        print_no_end(" ")

        print_no_end(cond_symbol(jump_cond))
        print_no_end(" ")
        self.print_operand(fused_inst, 1)

        if (fused_inst.id != ARM_INS_CMP and \
                (jump_cond in COND_ADD_ZERO or assignment)):
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

        print_tabbed_no_end(color_addr(i.address), tab)

        if is_ret(i):
            print(color_retcall(get_inst_str()))
            return

        if is_call(i):
            print_no_end(color_retcall(i.mnemonic) + " ")
            self.print_operand(i, 0, hexa=True)
            print()
            return

        # Here we can have conditional jump with the option --dump
        if is_jump(i):
            if i.operands[0].type != ARM_OP_IMM:
                print_no_end(i.mnemonic + " ")
                self.print_operand(i, 0)
                if is_uncond_jump(i) and self.ctx.comments:
                    print_comment_no_end(" # STOPPED")
                print()
                return
            try:
                addr = i.operands[0].value.imm
                print(i.mnemonic + " " + color(hex(addr), self.ctx.addr_color[addr]))
            except KeyError:
                print(i.mnemonic + " " + hex(addr))
            return

        modified = False

        if i.cc != ARM_CC_AL:
            print_no_end(color_keyword("if "))
            print_no_end(cond_symbol(i.cc))
            if i.cc in COND_ADD_ZERO:
                print_no_end("0")
            print_no_end(" : ")

        inst_check = [ARM_INS_SUB, ARM_INS_ADD, ARM_INS_MOV, ARM_INS_AND,
                ARM_INS_EOR, ARM_INS_ORR, ARM_INS_CMP, ARM_INS_LDR]

        if i.id in inst_check:
            self.print_operand(i, 0)

            if i.id == ARM_INS_CMP:
                print_no_end(" " + inst_symbol(i) + " ")
                self.print_operand(i, 1)

            elif i.id == ARM_INS_LDR:
                # TODO
                print_no_end(" " + inst_symbol(i) + " ")
                self.print_operand(i, 1, show_deref=False)

            else:
                print_no_end(" = ")
                self.print_operand(i, 1)
                if len(i.operands) == 3:
                    print_no_end(" " + inst_symbol(i) + " ")
                    self.print_operand(i, 2)

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

        if i.update_flags and i.id != ARM_INS_CMP and i.id != ARM_INS_TST:
            print_no_end(color_type(" (FLAGS)"))

        if modified and self.ctx.comments:
            print_comment_no_end(" # " + get_inst_str())

        print()
