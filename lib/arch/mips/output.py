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
        MIPS_INS_ADDIU, MIPS_INS_LB, MIPS_INS_LBU, MIPS_INS_SB,
        MIPS_INS_SLL, MIPS_INS_SRA, MIPS_INS_SRL, MIPS_INS_XOR,
        MIPS_INS_XORI, MIPS_INS_SUB, MIPS_INS_SUBU, MIPS_INS_BGTZ,
        MIPS_INS_BGEZ, MIPS_INS_BNEZ, MIPS_INS_BEQZ, MIPS_INS_BLEZ,
        MIPS_INS_BLTZ, MIPS_REG_ZERO)

from lib.output import OutputAbs
from lib.utils import BYTES_PRINTABLE_SET
from lib.arch.mips.utils import (inst_symbol, is_call, is_jump, is_ret,
    is_uncond_jump, cond_symbol, PseudoInst, NopInst)


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
    def _operand(self, i, num_op, hexa=False, show_deref=True):
        def inv(n):
            return n == MIPS_OP_INVALID

        op = i.operands[num_op]

        if op.type == MIPS_OP_IMM:
            imm = op.value.imm
            sec_name, is_data = self.binary.is_address(imm)

            if sec_name is not None:
                modified = False

                if self.ctx.sectionsname:
                    self._add("(")
                    self._section(sec_name)
                    self._add(") ")

                if imm in self.binary.reverse_symbols:
                    self._symbol(imm)
                    self._add(" ")
                    modified = True

                if imm in self.ctx.labels:
                    self._label(imm, print_label=False)
                    self._add(" ")
                    modified = True

                if not modified:
                    self._add(hex(imm))

                if is_data:
                    s = self.binary.get_string(imm, self.ctx.max_data_size)
                    if s != "\"\"":
                        self._add(" ")
                        self._string(s)

                return modified

            elif hexa:
                self._add(hex(imm))
            else:
                self._add(str(imm))

                if imm > 0:
                    packed = struct.pack("<L", imm)
                    if set(packed).issubset(BYTES_PRINTABLE_SET):
                        self._string(" \"" + "".join(map(chr, packed)) + "\"")
                        return False

                # returns True because capstone print immediate in hexa
                # it will be printed in a comment, sometimes it's better
                # to have the value in hexa
                return True

            return False

        elif op.type == MIPS_OP_REG:
            self._add("$")
            self._add(i.reg_name(op.value.reg))
            return False

        elif op.type == MIPS_OP_MEM:
            mm = op.mem

            printed = False
            if show_deref:
                self._add("*(")

            if not inv(mm.base):
                self._add("$%s" % i.reg_name(mm.base))
                printed = True

            if mm.disp != 0:
                sec_name, is_data = self.binary.is_address(mm.disp)
                if sec_name is not None:
                    if printed:
                        self._add(" + ")
                    if mm.disp in self.binary.reverse_symbols:
                        self._symbol(mm.disp)
                    else:
                        self._add(hex(mm.disp))
                else:
                    if printed:
                        if mm.disp < 0:
                            self._add(" - %d" % (-mm.disp))
                        else:
                            self._add(" + %d" % mm.disp)

            if show_deref:
                self._add(")")
            return True


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

        self._add(cond_symbol(cond))
        self._add(" ")
        self._operand(fused_inst, 1)

        # if (fused_inst.id != ARM_INS_CMP and \
                # (cond in COND_ADD_ZERO or assignment)):
            # self._add(" 0")

        self._add(")")


    def _asm_inst(self, i, tab=0, prefix=""):
        def get_inst_str():
            nonlocal i
            return "%s %s" % (i.mnemonic, i.op_str)

        if isinstance(i, NopInst):
            return

        if isinstance(i, PseudoInst):
            for i2 in i.real_inst_list:
                self._asm_inst(i2, tab, "# ")
            self._label_and_address(i.real_inst_list[0].address, tab)
            self._add(i.pseudo)
            self._new_line()
            return

        if i.address in self.ctx.dis.previous_comments:
            for comm in self.ctx.dis.previous_comments[i.address]:
                self._tabs(tab)
                self._internal_comment("; %s" % comm)

        if prefix == "# ":
            if self.ctx.comments:
                if i.address in self.ctx.labels:
                    self._label(i.address, tab)
                    self._new_line()
                    self._tabs(tab)
                    self._comment(prefix)
                    self._address(i.address, normal_color=True)
                else:
                    self._tabs(tab)
                    self._comment(prefix)
                    self._address(i.address)
                self._bytes(i, True)
                self._comment(get_inst_str())
                self._new_line()
            return

        if i.address in self.ctx.all_fused_inst:
            return

        if self.is_symbol(i.address):
            self._tabs(tab)
            self._symbol(i.address)
            self._new_line()

        modified = self.__sub_asm_inst(i, tab, prefix)

        if i.address in self.ctx.dis.inline_comments:
            self._internal_comment(" ; %s" %
                    self.ctx.dis.inline_comments[i.address])

        if modified and self.ctx.comments:
            self._comment(" # %s" % get_inst_str())

        self._new_line()


    def __sub_asm_inst(self, i, tab=0, prefix=""):
        def get_inst_str():
            nonlocal i
            return "%s %s" % (i.mnemonic, i.op_str)

        self._label_and_address(i.address, tab)
        self._bytes(i)

        if is_ret(i):
            self._retcall(get_inst_str())
            return False

        if is_call(i):
            self._retcall(i.mnemonic)
            self._add(" ")
            return self._operand(i, 0, hexa=True)

        # Here we can have conditional jump with the option --dump
        if is_jump(i):
            self._add(i.mnemonic + " ")
            if i.operands[-1].type != MIPS_OP_IMM:
                self._add(i.op_str)
                if is_uncond_jump(i) and self.ctx.comments and not self.ctx.dump \
                        and not i.address in self.ctx.dis.jmptables:
                    self._comment(" # STOPPED")
                return False

            for num in range(len(i.operands)-1):
                self._operand(i, num)
                self._add(", ")

            addr = i.operands[0].value.imm
            if addr in self.ctx.addr_color:
                self._label_or_address(addr, -1, False)
            else:
                self._add(hex(addr))
            return False


        modified = False

        if i.id in LD_CHECK:
            self._operand(i, 0)
            self._add(" = (")
            self._type(LD_TYPE[i.id])
            self._add(") ")
            self._operand(i, 1)
            modified = True

        elif i.id in ST_CHECK:
            self._operand(i, 1)
            self._add(" = (")
            self._type(ST_TYPE[i.id])
            self._add(") ")
            self._operand(i, 0)
            modified = True

        elif i.id in INST_CHECK:
            if i.id == MIPS_INS_LUI:
                self._add("(load upper) ")
                self._operand(i, 0)
                self._add(" = ")
                self._operand(i, 1)

            elif i.id == MIPS_INS_MOVE:
                self._operand(i, 0)
                self._add(" = ")
                if i.operands[1].value.reg == MIPS_REG_ZERO:
                    self._add("0")
                else:
                    self._operand(i, 1)

            else:
                self._operand(i, 0)
                if i.operands[0].type == i.operands[1].type == MIPS_OP_REG and \
                    i.operands[0].value.reg == i.operands[1].value.reg:
                    self._add(" " + inst_symbol(i) + "= ")
                else:
                    self._add(" = ")
                    self._operand(i, 1)
                    self._add(" " + inst_symbol(i) + " ")
                self._operand(i, 2)

            modified = True

        else:
            self._add("%s " % i.mnemonic)
            if len(i.operands) > 0:
                modified = self._operand(i, 0)
                k = 1
                while k < len(i.operands):
                    self._add(", ")
                    modified |= self._operand(i, k)
                    k += 1

        return modified
