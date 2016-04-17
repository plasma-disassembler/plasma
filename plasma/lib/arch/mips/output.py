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

from capstone import CS_MODE_32
from capstone.mips import (MIPS_OP_IMM, MIPS_OP_MEM, MIPS_OP_REG,
        MIPS_OP_INVALID, MIPS_INS_LW, MIPS_INS_SW, MIPS_INS_AND,
        MIPS_INS_LUI, MIPS_INS_MOVE, MIPS_INS_ADD, MIPS_INS_ADDU,
        MIPS_INS_ADDIU, MIPS_INS_LB, MIPS_INS_LBU, MIPS_INS_SB,
        MIPS_INS_SLL, MIPS_INS_SRA, MIPS_INS_SRL, MIPS_INS_SUB,
        MIPS_INS_SUBU, MIPS_INS_BGTZ, MIPS_INS_LH, MIPS_INS_LHU,
        MIPS_INS_SH, MIPS_INS_SD, MIPS_INS_LD, MIPS_GRP_MIPS64,
        MIPS_INS_BGEZ, MIPS_INS_BNEZ, MIPS_INS_BEQZ, MIPS_INS_BLEZ,
        MIPS_INS_BLTZ, MIPS_REG_ZERO, MIPS_REG_GP)

from plasma.lib.output import OutputAbs
from plasma.lib.arch.mips.utils import (inst_symbol, is_call, is_jump, is_ret,
    is_uncond_jump, cond_symbol, PseudoInst, NopInst)


# ASSIGNMENT_OPS = {ARM_INS_EOR, ARM_INS_AND, ARM_INS_ORR}
ASSIGNMENT_OPS = {}

LD_TYPE = {
    MIPS_INS_LH: "halfword",
    MIPS_INS_LHU: "unsigned halfword",
    MIPS_INS_LW: "word",
    MIPS_INS_LB: "byte",
    MIPS_INS_LBU: "unsigned byte",
    MIPS_INS_LD: "double",
}

ST_TYPE = {
    MIPS_INS_SH: "halfword",
    MIPS_INS_SW: "word",
    MIPS_INS_SB: "byte",
    MIPS_INS_SD: "double",
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
    def _operand(self, i, num_op, hexa=False, show_deref=True,
                 force_dont_print_data=False):
        def inv(n):
            return n == MIPS_OP_INVALID

        op = i.operands[num_op]

        if op.type == MIPS_OP_IMM:
            self._imm(op.value.imm, self._dis.wordsize, hexa,
                      force_dont_print_data=force_dont_print_data)

        elif op.type == MIPS_OP_REG:
            self._add("$")
            self._add(i.reg_name(op.value.reg))

        elif op.type == MIPS_OP_MEM:
            mm = op.mem

            printed = False

            ret = self.get_var_offset(i, num_op)
            if ret is not None:
                func_addr, off = ret
                self._variable(self.get_var_name(func_addr, off))
                return

            if mm.base == MIPS_REG_GP and self._dis.mips_gp != -1:
                ad = self._dis.mips_gp + mm.disp

                if self.deref_if_offset(ad):
                    return

                if show_deref:
                    self._add("*(")
                self._imm(ad, 0, True, print_data=False,
                          force_dont_print_data=force_dont_print_data)
                if show_deref:
                    self._add(")")
                return

            if show_deref:
                self._add("*(")

            if not inv(mm.base):
                self._add("$%s" % i.reg_name(mm.base))
                printed = True

            if mm.disp != 0:
                section = self._binary.get_section(mm.disp)
                is_label = self.is_label(mm.disp)

                if is_label or section is not None:
                    if printed:
                        self._add(" + ")
                    self._imm(mm.disp, 0, True,
                              section=section, print_data=False,
                              force_dont_print_data=force_dont_print_data)
                else:
                    if printed:
                        if mm.disp < 0:
                            self._add(" - %d" % (-mm.disp))
                        else:
                            self._add(" + %d" % mm.disp)
                    else:
                        self._add("%d" % mm.disp)

            if show_deref:
                self._add(")")


    def _if_cond(self, cond, fused_inst):
        if fused_inst is None:
            self._add(cond_symbol(cond))
            if cond in COND_ADD_ZERO:
                self._add(" 0")
            return
        # TODO: fusion for MIPS


    def _asm_inst(self, i, tab=0, prefix=""):
        if isinstance(i, NopInst):
            return
        OutputAbs._asm_inst(self, i, tab, prefix)


    def _sub_asm_inst(self, i, tab=0):
        if self.gctx.capstone_string == 0:
            # Pseudo instructions
            if i.id == -1:
                if i.mnemonic == "li":
                    self._operand(i, 0)
                    self._add(" = ")
                    self._operand(i, 1)
                return

            if i.id in LD_CHECK:
                self._operand(i, 0)
                self._add(" = (")
                self._type(LD_TYPE[i.id])
                self._add(") ")
                self._operand(i, 1)
                return

            if i.id in ST_CHECK:
                self._operand(i, 1)
                self._add(" = (")
                self._type(ST_TYPE[i.id])
                self._add(") ")
                self._operand(i, 0)
                return

            if i.id in INST_CHECK:
                if i.id == MIPS_INS_LUI:
                    self._operand(i, 0)
                    self._add(" = ")
                    self._operand(i, 1)
                    self._add(" << 16")

                elif i.id == MIPS_INS_MOVE:
                    self._operand(i, 0)
                    self._add(" = ")
                    if i.operands[1].value.reg == MIPS_REG_ZERO:
                        self._add("0")
                    else:
                        self._operand(i, 1)

                else:
                    op = i.operands
                    self._operand(i, 0)
                    if op[0].type == op[1].type == MIPS_OP_REG and \
                            op[0].value.reg == op[1].value.reg:
                        self._add(" " + inst_symbol(i) + "= ")
                    else:
                        self._add(" = ")
                        self._operand(i, 1)
                        self._add(" " + inst_symbol(i) + " ")
                    self._operand(i, 2)

                return

        self._add("%s " % i.mnemonic)
        if len(i.operands) > 0:
            self._operand(i, 0)
            k = 1
            while k < len(i.operands):
                self._add(", ")
                self._operand(i, k)
                k += 1
