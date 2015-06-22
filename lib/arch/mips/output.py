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

from capstone.mips import (MIPS_OP_IMM, MIPS_OP_MEM, MIPS_OP_REG,
        MIPS_OP_INVALID, MIPS_INS_LW, MIPS_INS_SW, MIPS_INS_AND,
        MIPS_INS_LUI, MIPS_INS_MOVE, MIPS_INS_ADD, MIPS_INS_ADDU,
        MIPS_INS_ADDIU, MIPS_INS_LB, MIPS_INS_LBU, MIPS_INS_SW,
        MIPS_INS_SB, MIPS_INS_SLL, MIPS_INS_SRA, MIPS_INS_SRL,
        MIPS_INS_XOR, MIPS_INS_XORI, MIPS_INS_SUB, MIPS_INS_SUBU,
        MIPS_INS_BGTZ, MIPS_INS_BGEZ, MIPS_INS_BNEZ, MIPS_INS_BEQZ,
        MIPS_INS_BLEZ, MIPS_INS_BLTZ, MIPS_REG_ZERO)

from lib.output import (OutputAbs, print_no_end, print_tabbed_no_end,
        print_comment, print_comment_no_end)
from lib.colors import (color, color_addr, color_retcall, color_string,
        color_section, color_type)
from lib.utils import BYTES_PRINTABLE_SET
from lib.arch.mips.utils import (inst_symbol, is_call, is_jump, is_ret,
    is_uncond_jump, cond_symbol)


# ASSIGNMENT_OPS = {ARM_INS_EOR, ARM_INS_AND, ARM_INS_ORR}
ASSIGNMENT_OPS = {}

LD_TYPE = {
    MIPS_INS_LW: "word",
    MIPS_INS_LB: "byte",
    MIPS_INS_LBU: "unsigned byte",
}

ST_TYPE = {
    MIPS_INS_SW: "word",
    MIPS_INS_SB: "byte",
}


# After these instructions we need to add a zero
# example : beqz $t1, label -> if == 0
COND_ADD_ZERO = {MIPS_INS_BGTZ, MIPS_INS_BGEZ, MIPS_INS_BNEZ, MIPS_INS_BEQZ,
    MIPS_INS_BLEZ, MIPS_INS_BLTZ}

LD_CHECK = {MIPS_INS_LW, MIPS_INS_LB, MIPS_INS_LBU}
ST_CHECK = {MIPS_INS_SW, MIPS_INS_SB}

INST_CHECK = {MIPS_INS_AND, MIPS_INS_ADD, MIPS_INS_ADDU, MIPS_INS_ADDIU,
    MIPS_INS_SLL, MIPS_INS_SRA, MIPS_INS_SRL, MIPS_INS_SUB, MIPS_INS_SUBU,
    MIPS_INS_MOVE, MIPS_INS_LUI}


class Output(OutputAbs):
    # Return True if the operand is a variable (because the output is
    # modified, we reprint the original instruction later)
    def print_operand(self, i, num_op, hexa=False, show_deref=True):
        def inv(n):
            return n == MIPS_OP_INVALID

        op = i.operands[num_op]

        if op.type == MIPS_OP_IMM:
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

        elif op.type == MIPS_OP_REG:
            print_no_end("$")
            print_no_end(i.reg_name(op.value.reg))
            return False

        elif op.type == MIPS_OP_MEM:
            mm = op.mem

            printed = False
            if show_deref:
                print_no_end("*(")

            if not inv(mm.base):
                print_no_end("$%s" % i.reg_name(mm.base))
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


    def print_if_cond(self, cond, fused_inst):
        if fused_inst is None:
            print_no_end(cond_symbol(cond))
            if cond in COND_ADD_ZERO:
                print_no_end(" 0")
            return

        assignment = fused_inst.id in ASSIGNMENT_OPS

        if assignment:
            print_no_end("(")
        print_no_end("(")
        self.print_operand(fused_inst, 0)
        print_no_end(" ")

        print_no_end(cond_symbol(cond))
        print_no_end(" ")
        self.print_operand(fused_inst, 1)

        # if (fused_inst.id != ARM_INS_CMP and \
                # (cond in COND_ADD_ZERO or assignment)):
            # print_no_end(" 0")

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
            print_no_end(i.mnemonic + " ")
            if i.operands[-1].type != MIPS_OP_IMM:
                print_no_end(i.op_str)
                if is_uncond_jump(i) and self.ctx.comments:
                    print_comment_no_end(" # STOPPED")
                print()
                return

            for num in range(len(i.operands)-1):
                self.print_operand(i, num)
                print_no_end(", ")

            addr = i.operands[-1].value.imm
            if addr in self.ctx.addr_color:
                print(color(hex(addr), self.ctx.addr_color[addr]))
            else:
                print(hex(addr))
            return

        modified = False

        if i.id in LD_CHECK:
            self.print_operand(i, 0)
            print_no_end(" = (")
            print_no_end(color_type(LD_TYPE[i.id]))
            print_no_end(") ")
            self.print_operand(i, 1)
            modified = True

        elif i.id in ST_CHECK:
            self.print_operand(i, 1)
            print_no_end(" = (")
            print_no_end(color_type(ST_TYPE[i.id]))
            print_no_end(") ")
            self.print_operand(i, 0)
            modified = True

        elif i.id in INST_CHECK:
            if i.id == MIPS_INS_LUI:
                print_no_end("(load upper) ")
                self.print_operand(i, 0)
                print_no_end(" = ")
                self.print_operand(i, 1)

            elif i.id == MIPS_INS_MOVE:
                self.print_operand(i, 0)
                print_no_end(" = ")
                if i.operands[1].value.reg == MIPS_REG_ZERO:
                    print_no_end("0")
                else:
                    self.print_operand(i, 1)

            else:
                self.print_operand(i, 0)
                if i.operands[0].type == i.operands[1].type == MIPS_OP_REG and \
                    i.operands[0].value.reg == i.operands[1].value.reg:
                    print_no_end(" " + inst_symbol(i) + "= ")
                else:
                    print_no_end(" = ")
                    self.print_operand(i, 1)
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

        if modified and self.ctx.comments:
            print_comment_no_end(" # " + get_inst_str())

        print()
