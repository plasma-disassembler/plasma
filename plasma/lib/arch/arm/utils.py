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

from capstone import CS_GRP_CALL, CS_GRP_RET
from capstone.arm import (ARM_CC_EQ, ARM_CC_NE, ARM_CC_HS, ARM_CC_LO,
        ARM_CC_MI, ARM_CC_PL, ARM_CC_VS, ARM_CC_VC, ARM_CC_HI,
        ARM_CC_LS, ARM_CC_GE, ARM_CC_LT, ARM_CC_GT, ARM_CC_LE, ARM_CC_AL,
        ARM_INS_EOR, ARM_INS_ADD, ARM_INS_ORR, ARM_INS_AND, ARM_INS_MOV,
        ARM_INS_CMP, ARM_INS_SUB, ARM_INS_LDR, ARM_INS_B, ARM_INS_BLX,
        ARM_INS_BL, ARM_INS_BX, ARM_REG_LR, ARM_OP_REG, ARM_REG_PC, ARM_INS_POP,
        ARM_OP_IMM, ARM_OP_MEM)


JUMPS = {ARM_INS_B, ARM_INS_BX}
JUMPS_LINK = {ARM_INS_BL, ARM_INS_BLX}

OP_IMM = ARM_OP_IMM
OP_MEM = ARM_OP_MEM
OP_REG = ARM_OP_REG


# Warning: before adding new prolog check in lib.analyzer.has_prolog
PROLOGS = [
    [b"\xe9\x2d"], # push registers
]


def is_cmp(i):
    return i.id == ARM_INS_CMP

def is_jump(i):
    # Suppose that the written register is the first operand
    op = i.operands[0]

    if op.type == ARM_OP_REG and op.value.reg == ARM_REG_PC:
        return True

    if i.id == ARM_INS_POP:
        for o in i.operands:
            if o.type == ARM_OP_REG and o.value.reg == ARM_REG_PC:
                return True
        return False

    return i.id in JUMPS and not (op.type == ARM_OP_REG and \
        op.value.reg == ARM_REG_LR)

def is_cond_jump(i):
    return is_jump(i) and i.cc != ARM_CC_AL

def is_uncond_jump(i):
    return is_jump(i) and i.cc == ARM_CC_AL

def is_ret(i):
    op = i.operands[0]
    return i.group(CS_GRP_RET) or i.id == ARM_INS_BX and \
        op.type == ARM_OP_REG and op.value.reg == ARM_REG_LR

def is_call(i):
    return i.group(CS_GRP_CALL) or i.id in JUMPS_LINK


OPPOSITES = [
        [ARM_CC_EQ, ARM_CC_NE],
        [ARM_CC_GE, ARM_CC_LT],
        [ARM_CC_LE, ARM_CC_GT],
        [ARM_CC_HI, ARM_CC_LS],
        [ARM_CC_HS, ARM_CC_LO],
        [ARM_CC_PL, ARM_CC_MI],
        [ARM_CC_VS, ARM_CC_VC],
    ]
OPPOSITES = dict(OPPOSITES + [i[::-1] for i in OPPOSITES])

def invert_cond(i):
    return OPPOSITES.get(i.cc, -1)


def get_cond(i):
    return i.cc


COND_SYMB = {
    ARM_CC_EQ: "==",
    ARM_CC_NE: "!=",
    ARM_CC_GE: ">=",
    ARM_CC_LT: "<",
    ARM_CC_LE: "<=",
    ARM_CC_GT: ">",
    ARM_CC_HI: "(unsigned) >",
    ARM_CC_LS: "(unsigned) <=",
    ARM_CC_HS: "(unsigned) >=",
    ARM_CC_LO: "(unsigned) <",
    ARM_CC_VS: "overflow",
    ARM_CC_VC: "!overflow",
    ARM_CC_PL: ">=",
    ARM_CC_MI: "<",
}


INST_SYMB = {
    ARM_INS_EOR: "^",
    ARM_INS_ORR: "|",
    ARM_INS_AND: "&",
    ARM_INS_ADD: "+",
    ARM_INS_MOV: "=",
    ARM_INS_SUB: "-",
    ARM_INS_CMP: "cmp",
    ARM_INS_LDR: "=",
}


def cond_symbol(ty):
    return COND_SYMB.get(ty, "UNKNOWN")


def inst_symbol(i):
    return INST_SYMB.get(i.id, "UNKNOWN")
