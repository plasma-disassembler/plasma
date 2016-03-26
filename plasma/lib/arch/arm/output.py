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

from capstone.arm import (ARM_INS_EOR, ARM_INS_AND, ARM_INS_ORR, ARM_OP_IMM,
        ARM_OP_MEM, ARM_OP_REG, ARM_OP_INVALID, ARM_INS_SUB, ARM_INS_ADD,
        ARM_INS_MOV, ARM_OP_FP, ARM_INS_CMP, ARM_INS_LDR, ARM_CC_PL,
        ARM_CC_MI, ARM_INS_TST, ARM_INS_LDRB, ARM_INS_LDRSB, ARM_INS_LDRH,
        ARM_INS_LDRSH, ARM_INS_LDRD, ARM_SFT_ASR, ARM_SFT_LSL, ARM_SFT_LSR,
        ARM_SFT_ROR, ARM_SFT_RRX, ARM_SFT_ASR_REG, ARM_SFT_LSL_REG,
        ARM_SFT_LSR_REG, ARM_SFT_ROR_REG, ARM_SFT_RRX_REG, ARM_INS_STRB,
        ARM_INS_STRH, ARM_INS_STRD, ARM_INS_STR, ARM_REG_PC, ARM_INS_ASR,
        ARM_INS_LSL, ARM_INS_LSR, ARM_INS_ROR, ARM_INS_RRX)

from plasma.lib.output import OutputAbs
from plasma.lib.arch.arm.utils import (inst_symbol, is_call, is_jump, is_ret,
    is_uncond_jump, cond_symbol)


ASSIGNMENT_OPS = {ARM_INS_EOR, ARM_INS_AND, ARM_INS_ORR}

LDR_TYPE = {
    ARM_INS_LDRB: "unsigned byte",
    ARM_INS_LDRH: "unsigned short",
    ARM_INS_LDR: "unsigned word",
    ARM_INS_LDRSB: "byte",
    ARM_INS_LDRSH: "short",
    ARM_INS_LDRD: "double",
}

STR_TYPE = {
    ARM_INS_STRB: "byte",
    ARM_INS_STRH: "short",
    ARM_INS_STR: "word",
    ARM_INS_STRD: "double",
}


# After these instructions we need to add a zero
# example : bpl ADDR -> if >= 0
COND_ADD_ZERO = {
    ARM_CC_PL,
    ARM_CC_MI,
}


INST_CHECK = {ARM_INS_SUB, ARM_INS_ADD, ARM_INS_MOV, ARM_INS_AND,
    ARM_INS_EOR, ARM_INS_ORR, ARM_INS_CMP, ARM_INS_ASR, ARM_INS_LSL,
    ARM_INS_LSR, ARM_INS_ROR, ARM_INS_RRX}

LDR_CHECK = {ARM_INS_LDR, ARM_INS_LDRB, ARM_INS_LDRSB, ARM_INS_LDRH,
    ARM_INS_LDRSH, ARM_INS_LDRD}

STR_CHECK = {ARM_INS_STR, ARM_INS_STRB, ARM_INS_STRH, ARM_INS_STRD}


class Output(OutputAbs):
    def _shift(self, i, shift):
        if shift.type == ARM_SFT_LSL:
            self._add(" << %d)" % shift.value)
        elif shift.type == ARM_SFT_LSR:
            self._add(" >> %d)" % shift.value)
        elif shift.type == ARM_SFT_ROR:
            self._add(" rot>> %d)" % shift.value)
        elif shift.type == ARM_SFT_ASR:
            self._add(" arith>> %d)" % shift.value)
        elif shift.type == ARM_SFT_RRX:
            self._add(" rrx>> %s)" % shift.value)

        elif shift.type == ARM_SFT_LSL_REG:
            self._add(" << %s)" % i.reg_name(shift.value))
        elif shift.type == ARM_SFT_LSR_REG:
            self._add(" >> %s)" % i.reg_name(shift.value))
        elif shift.type == ARM_SFT_ROR_REG:
            self._add(" rot>> %s)" % i.reg_name(shift.value))
        elif shift.type == ARM_SFT_ASR_REG:
            self._add(" arith>> %s)" % i.reg_name(shift.value))
        elif shift.type == ARM_SFT_RRX_REG:
            self._add(" rrx>> %s)" % i.reg_name(shift.value))


    # Return True if the operand is a variable (because the output is
    # modified, we reprint the original instruction later)
    def _operand(self, i, num_op, hexa=False, show_deref=True,
                 force_dont_print_data=False):
        def inv(n):
            return n == ARM_OP_INVALID

        op = i.operands[num_op]

        if op.shift.type:
            self._add("(")

        if op.type == ARM_OP_IMM:
            self._imm(op.value.imm, self._dis.wordsize, hexa,
                      force_dont_print_data=force_dont_print_data)

        elif op.type == ARM_OP_REG:
            if op.value.reg == ARM_REG_PC and i.reg_read(ARM_REG_PC):
                self._add(hex(i.address))
            else:
                self._add(i.reg_name(op.value.reg))
            if op.shift.type:
                self._shift(i, op.shift)

        elif op.type == ARM_OP_FP:
            self._add("%f" % op.value.fp)
            if op.shift.type:
                self._shift(i, op.shift)

        elif op.type == ARM_OP_MEM:
            mm = op.mem

            if not inv(mm.base) and mm.disp != 0 and inv(mm.index):
                if mm.base == ARM_REG_PC:
                    ad = i.address + i.size * 2 + mm.disp

                    if self.deref_if_offset(ad):
                        return

                    if show_deref:
                        self._add("*(")
                    self._imm(ad, 4, True, print_data=False,
                              force_dont_print_data=force_dont_print_data)
                    if show_deref:
                        self._add(")")
                    return

            printed = False
            if show_deref:
                self._add("*(")

            if not inv(mm.base):
                self._add("%s" % i.reg_name(mm.base))
                printed = True

            elif not inv(mm.segment):
                self._add("%s" % i.reg_name(mm.segment))
                printed = True

            if not inv(mm.index):
                if printed:
                    self._add(" + ")

                if mm.scale == 1:
                    self._add("%s" % i.reg_name(mm.index))
                else:
                    self._add("(%s*%d)" % (i.reg_name(mm.index), mm.scale))

                if op.shift.type:
                    self._shift(i, op.shift)

                printed = True

            if mm.disp != 0:
                section = self._binary.get_section(mm.disp)
                is_label = self.is_label(mm.disp)

                if is_label or section is not None:
                    if printed:
                        self._add(" + ")
                    # is_data=False : don't print string next to the symbol
                    self._imm(mm.disp, 0, True, section=section, print_data=False,
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

        assignment = fused_inst.id in ASSIGNMENT_OPS

        if assignment:
            self._add("(")

        self._add("(")
        self._operand(fused_inst, 0)
        self._add(" ")

        if assignment:
            self._add(inst_symbol(fused_inst))
            self._add(" ")
            self._operand(fused_inst, 1)
            self._add(") ")
            self._add(cond_symbol(jump_cond))
        else:
            self._add(cond_symbol(cond))
            self._add(" ")
            self._operand(fused_inst, 1)

        if (fused_inst.id != ARM_INS_CMP and \
                (cond in COND_ADD_ZERO or assignment)):
            self._add(" 0")

        self._add(")")


    def _sub_asm_inst(self, i, tab=0):
        modified = False

        if self.gctx.capstone_string == 0:
            if i.id in LDR_CHECK:
                self._operand(i, 0)
                self._add(" = (")
                self._type(LDR_TYPE[i.id])
                self._add(") ")
                self._operand(i, 1)
                modified = True

            elif i.id in STR_CHECK:
                self._operand(i, 1)
                self._add(" = (")
                self._type(STR_TYPE[i.id])
                self._add(") ")
                self._operand(i, 0)
                modified = True

            elif i.id in INST_CHECK:
                self._operand(i, 0)

                if i.id == ARM_INS_CMP:
                    self._add(" " + inst_symbol(i) + " ")
                    self._operand(i, 1)

                else:
                    self._add(" = ")
                    self._operand(i, 1)
                    if len(i.operands) == 3:
                        self._add(" " + inst_symbol(i) + " ")
                        self._operand(i, 2)

                modified = True

        if not modified:
            self._add("%s " % i.mnemonic)
            if len(i.operands) > 0:
                self._operand(i, 0)
                k = 1
                while k < len(i.operands):
                    self._add(", ")
                    self._operand(i, k)
                    k += 1

        if i.update_flags and i.id != ARM_INS_CMP and i.id != ARM_INS_TST:
            self._add(" ")
            self._type("(FLAGS)")
