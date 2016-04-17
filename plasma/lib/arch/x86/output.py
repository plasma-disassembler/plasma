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

from capstone.x86 import (X86_INS_ADD, X86_INS_AND, X86_INS_CMP, X86_INS_DEC,
        X86_INS_IDIV, X86_INS_IMUL, X86_INS_INC, X86_INS_MOV, X86_INS_SHL,
        X86_INS_SHR, X86_INS_SUB, X86_INS_XOR, X86_OP_FP, X86_OP_IMM,
        X86_OP_INVALID, X86_OP_MEM, X86_OP_REG, X86_REG_EBP, X86_REG_EIP,
        X86_REG_RBP, X86_REG_RIP, X86_INS_CDQE, X86_INS_LEA, X86_INS_MOVSX,
        X86_INS_OR, X86_INS_NOT, X86_PREFIX_REP, X86_PREFIX_REPNE,
        X86_INS_TEST, X86_INS_JNS, X86_INS_JS, X86_INS_MUL, X86_INS_JP,
        X86_INS_JNP, X86_INS_JCXZ, X86_INS_JECXZ, X86_INS_JRCXZ,
        X86_INS_SAR, X86_INS_SAL, X86_INS_MOVZX, X86_INS_STOSB,
        X86_INS_STOSW, X86_INS_STOSD, X86_INS_STOSQ, X86_INS_MOVSB,
        X86_INS_MOVSW, X86_INS_MOVSD, X86_INS_MOVSQ, X86_INS_LODSB,
        X86_INS_LODSW, X86_INS_LODSD, X86_INS_LODSQ, X86_INS_CMPSB,
        X86_INS_CMPSW, X86_INS_CMPSD, X86_INS_CMPSQ, X86_INS_SCASB,
        X86_INS_SCASW, X86_INS_SCASD, X86_INS_SCASQ)

from plasma.lib.output import OutputAbs
from plasma.lib.arch.x86.utils import (inst_symbol, is_call, is_jump, is_ret,
    is_uncond_jump, cond_symbol)


ASSIGNMENT_OPS = {X86_INS_XOR, X86_INS_AND, X86_INS_OR,
        X86_INS_SAR, X86_INS_SAL, X86_INS_SHR, X86_INS_SHL}


# After these instructions we need to add a zero
# example : jns ADDR -> if > 0
COND_ADD_ZERO = {
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
    X86_INS_SAR, X86_INS_SAL, X86_INS_MOVZX,
    X86_INS_DEC, X86_INS_INC, X86_INS_LEA, X86_INS_MOVSX, X86_INS_OR}


INST_STOS = {X86_INS_STOSB, X86_INS_STOSW, X86_INS_STOSD, X86_INS_STOSQ}
INST_LODS = {X86_INS_LODSB, X86_INS_LODSW, X86_INS_LODSD, X86_INS_LODSQ}
INST_MOVS = {X86_INS_MOVSB, X86_INS_MOVSW, X86_INS_MOVSD, X86_INS_MOVSQ}
INST_CMPS = {X86_INS_CMPSB, X86_INS_CMPSW, X86_INS_CMPSD, X86_INS_CMPSQ}
INST_SCAS = {X86_INS_SCASB, X86_INS_SCASW, X86_INS_SCASD, X86_INS_SCASQ}

REP_PREFIX = {X86_PREFIX_REPNE, X86_PREFIX_REP}


class Output(OutputAbs):
    # Return True if the operand is a variable (because the output is
    # modified, we reprint the original instruction later)
    def _operand(self, i, num_op, hexa=False, show_deref=True,
                 force_dont_print_data=False):
        def inv(n):
            return n == X86_OP_INVALID

        op = i.operands[num_op]

        if op.type == X86_OP_IMM:
            self._imm(op.value.imm, op.size, hexa,
                      force_dont_print_data=force_dont_print_data)

        elif op.type == X86_OP_REG:
            self._add(i.reg_name(op.value.reg))

        elif op.type == X86_OP_FP:
            self._add("%f" % op.value.fp)

        elif op.type == X86_OP_MEM:
            mm = op.mem

            ret = self.get_var_offset(i, num_op)
            if ret is not None:
                func_addr, off = ret
                if i.id == X86_INS_LEA:
                    self._add("&(")
                self._variable(self.get_var_name(func_addr, off))
                if i.id == X86_INS_LEA:
                    self._add(")")
                return

            if inv(mm.segment) and inv(mm.index) and mm.disp != 0:
                if mm.base == X86_REG_RIP or mm.base == X86_REG_EIP:
                    ad = i.address + i.size + mm.disp

                    if i.id != X86_INS_LEA and self.deref_if_offset(ad):
                        return

                    if show_deref:
                        self._add("*(")
                    self._imm(ad, 4, True,
                              force_dont_print_data=force_dont_print_data)
                    if show_deref:
                        self._add(")")
                    return

                elif inv(mm.base):
                    if i.id != X86_INS_LEA and self.deref_if_offset(mm.disp):
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
                printed = True

            if mm.disp != 0:
                section = self._binary.get_section(mm.disp)
                is_label = self.is_label(mm.disp)

                if is_label or section is not None:
                    if printed:
                        self._add(" + ")
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


    def _if_cond(self, jump_cond, fused_inst):
        if fused_inst is None:
            self._add(cond_symbol(jump_cond))
            if jump_cond in COND_ADD_ZERO:
                self._add(" 0")
            return

        assignment = fused_inst.id in ASSIGNMENT_OPS

        if assignment:
            self._add("(")
        self._add("(")
        self._operand(fused_inst, 0)
        self._add(" ")

        if fused_inst.id == X86_INS_TEST:
            self._add(cond_symbol(jump_cond))
        elif assignment:
            self._add(inst_symbol(fused_inst))
            self._add(" ")
            self._operand(fused_inst, 1)
            self._add(") ")
            self._add(cond_symbol(jump_cond))
        else:
            self._add(cond_symbol(jump_cond))
            self._add(" ")
            self._operand(fused_inst, 1)

        if fused_inst.id == X86_INS_TEST or \
                (fused_inst.id != X86_INS_CMP and \
                 (jump_cond in COND_ADD_ZERO or assignment)):
            self._add(" 0")

        self._add(")")


    def _rep_begin(self, i, tab):
        if i.prefix[0] in REP_PREFIX:
            self._new_line()
            self._tabs(tab)
            self._keyword("while")
            # TODO: for 16 and 32 bits
            self._add(" (!rcx)) {")
            self._new_line()
            self._tabs(tab + 1)
            self._address(i.address)
            tab += 1
        return tab


    def _rep_end(self, i, tab):
        if i.prefix[0] in REP_PREFIX:
            self._new_line()
            self._tabs(tab)
            self._address(i.address)
            self._add("rcx--")
            self._new_line()
            if i.prefix[0] == X86_PREFIX_REPNE:
                self._tabs(tab)
                self._keyword("if")
                self._add(" (!Z) ")
                self._keyword("break")
                self._new_line()
            tab -= 1
            self._tabs(tab)
            self._add("}")
        return tab


    def _pre_asm_inst(self, i, tab):
        return self._rep_begin(i, tab)


    def _post_asm_inst(self, i, tab):
        self._rep_end(i, tab)


    def _sub_asm_inst(self, i, tab=0):
        modified = False

        if self.gctx.capstone_string == 0:
            if i.id in INST_CHECK:
                if (i.id == X86_INS_OR and i.operands[1].type == X86_OP_IMM and
                        i.operands[1].value.imm == -1):
                    self._operand(i, 0)
                    self._add(" = -1")

                elif (i.id == X86_INS_AND and i.operands[1].type == X86_OP_IMM and
                        i.operands[1].value.imm == 0):
                    self._operand(i, 0)
                    self._add(" = 0")

                elif (all(op.type == X86_OP_REG for op in i.operands) and
                        len(set(op.value.reg for op in i.operands)) == 1 and
                        i.id == X86_INS_XOR):
                    self._operand(i, 0)
                    self._add(" = 0")

                elif i.id == X86_INS_INC or i.id == X86_INS_DEC:
                    self._operand(i, 0)
                    self._add(inst_symbol(i))

                elif i.id == X86_INS_LEA:
                    self._operand(i, 0)
                    self._add(" = ")
                    self._operand(i, 1, show_deref=False)

                elif i.id == X86_INS_MOVZX:
                    self._operand(i, 0)
                    self._add(" = (zero ext) ")
                    self._operand(i, 1)

                elif i.id == X86_INS_IMUL:
                    if len(i.operands) == 3:
                        self._operand(i, 0)
                        self._add(" = ")
                        self._operand(i, 1)
                        self._add(" " + inst_symbol(i).rstrip('=') + " ")
                        self._operand(i, 2)
                    elif len(i.operands) == 2:
                        self._operand(i, 0)
                        self._add(" " + inst_symbol(i) + " ")
                        self._operand(i, 1)
                    elif len(i.operands) == 1:
                        sz = i.operands[0].size
                        if sz == 1:
                            self._add("ax = al * ")
                        elif sz == 2:
                            self._add("dx:ax = ax * ")
                        elif sz == 4:
                            self._add("edx:eax = eax * ")
                        elif sz == 8:
                            self._add("rdx:rax = rax * ")
                        self._operand(i, 0)

                else:
                    self._operand(i, 0)
                    self._add(" " + inst_symbol(i) + " ")
                    self._operand(i, 1)

                modified = True

            elif i.id == X86_INS_CDQE:
                self._add("rax = eax")
                modified = True

            elif i.id == X86_INS_IDIV:
                self._add('eax = edx:eax / ')
                self._operand(i, 0)
                self._add('; edx = edx:eax % ')
                self._operand(i, 0)
                modified = True

            elif i.id == X86_INS_MUL:
                lut = {1: ("al", "ax"), 2: ("ax", "dx:ax"), 4: ("eax", "edx:eax"),
                        8: ("rax", "rdx:rax")}
                src, dst = lut[i.operands[0].size]
                self._add('{0} = {1} * '.format(dst, src))
                self._operand(i, 0)
                modified = True

            elif i.id == X86_INS_NOT:
                self._operand(i, 0)
                self._add(' ^= -1')
                modified = True

            elif i.id in INST_SCAS:
                self._operand(i, 0)
                self._add(" cmp ")
                self._operand(i, 1)
                self._new_line()
                self._tabs(tab)
                self._address(i.address)
                self._operand(i, 1, show_deref=False)
                self._add(" += D")
                modified = True

            elif i.id in INST_STOS:
                self._operand(i, 0)
                self._add(" = ")
                self._operand(i, 1)
                self._new_line()
                self._tabs(tab)
                self._address(i.address)
                self._operand(i, 0, show_deref=False)
                self._add(" += D")
                modified = True

            elif i.id in INST_LODS:
                self._operand(i, 0)
                self._add(" = ")
                self._operand(i, 1)
                self._new_line()
                self._tabs(tab)
                self._address(i.address)
                self._operand(i, 1, show_deref=False)
                self._add(" += D")
                modified = True

            elif i.id in INST_CMPS:
                self._operand(i, 0)
                self._add(" cmp ")
                self._operand(i, 1)
                self._new_line()
                self._tabs(tab)
                self._address(i.address)
                self._operand(i, 0, show_deref=False)
                self._add(" += D")
                self._new_line()
                self._tabs(tab)
                self._address(i.address)
                self._operand(i, 1, show_deref=False)
                self._add("' += D")
                modified = True

            elif i.id in INST_MOVS:
                self._operand(i, 0)
                self._add(" = ")
                self._operand(i, 1)
                self._new_line()
                self._tabs(tab)
                self._address(i.address)
                self._operand(i, 0, show_deref=False)
                self._add(" += D")
                self._new_line()
                self._tabs(tab)
                self._address(i.address)
                self._operand(i, 1, show_deref=False)
                self._add(" += D")
                modified = True

        if not modified:
            if len(i.operands) > 0:
                self._add("%s " % i.mnemonic)
                self._operand(i, 0)
                k = 1
                while k < len(i.operands):
                    self._add(", ")
                    self._operand(i, k)
                    k += 1
            else:
                self._add(i.mnemonic)
