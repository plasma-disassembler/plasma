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

from capstone.mips import (MIPS_INS_BEQ, MIPS_INS_BNE, MIPS_INS_BGTZ,
        MIPS_INS_BGEZ, MIPS_INS_BNEZ, MIPS_INS_BEQZ, MIPS_INS_BLEZ,
        MIPS_INS_BLTZ, MIPS_INS_B, MIPS_INS_BAL, MIPS_INS_J,
        MIPS_INS_JAL, MIPS_INS_JALR, MIPS_INS_JR, MIPS_REG_RA,
        MIPS_INS_AND, MIPS_INS_ADD, MIPS_INS_ADDU, MIPS_INS_ADDIU,
        MIPS_INS_SLL, MIPS_INS_SRL, MIPS_INS_SRA, MIPS_INS_BLTZAL,
        MIPS_INS_XOR, MIPS_INS_XORI, MIPS_INS_SUB, MIPS_INS_SUBU,
        MIPS_INS_LD, MIPS_INS_LW, MIPS_REG_T9, MIPS_OP_IMM, MIPS_OP_MEM,
        MIPS_OP_REG)

# TODO
# MIPS_INS_BEQC, MIPS_INS_BEQL, MIPS_INS_BEQZALC, MIPS_INS_BEQZC, MIPS_INS_BGEC,
# MIPS_INS_BGEUC, MIPS_INS_BGEZAL, MIPS_INS_BGEZALC, MIPS_INS_BGEZALL,
# MIPS_INS_BGEZALS, MIPS_INS_BGEZC, MIPS_INS_BGEZL, MIPS_INS_BGTZALC,
# MIPS_INS_BGTZC, MIPS_INS_BGTZL, MIPS_INS_BLEZALC, MIPS_INS_BLEZC,
# MIPS_INS_BLEZL, MIPS_INS_BLTC, MIPS_INS_BLTUC,
# MIPS_INS_BLTZALC, MIPS_INS_BLTZALL, MIPS_INS_BLTZALS, MIPS_INS_BLTZC,
# MIPS_INS_BLTZL, MIPS_INS_BMNZI, MIPS_INS_BMNZ, MIPS_INS_BMZI, MIPS_INS_BMZ,
# MIPS_INS_BNEC, MIPS_INS_BNEGI, MIPS_INS_BNEG, MIPS_INS_BNEL,
# MIPS_INS_BNEZALC, MIPS_INS_BNEZC, MIPS_INS_BNVC, MIPS_INS_BNZ,
# MIPS_INS_BOVC, MIPS_INS_JALRS, MIPS_INS_JALS, MIPS_INS_JALX,
# MIPS_INS_JIALC, MIPS_INS_JIC, MIPS_INS_JRADDIUSP, MIPS_INS_JRC,
# MIPS_INS_JALRC, MIPS_INS_BZ, MIPS_INS_BTEQZ, MIPS_INS_BTNEZ

JUMPS_COND = {MIPS_INS_BEQ, MIPS_INS_BNE, MIPS_INS_BGTZ, MIPS_INS_BGEZ,
              MIPS_INS_BNEZ, MIPS_INS_BEQZ, MIPS_INS_BLEZ, MIPS_INS_BLTZ}
JUMPS_UNCOND = {MIPS_INS_B, MIPS_INS_J}
JUMPS_LINK = {MIPS_INS_BAL, MIPS_INS_JAL, MIPS_INS_JALR, MIPS_INS_BLTZAL}
CMP = {}

OP_IMM = MIPS_OP_IMM
OP_MEM = MIPS_OP_MEM
OP_REG = MIPS_OP_REG


# Warning: before adding new prolog check in lib.analyzer.has_prolog
PROLOGS = [
    [b"\x27\xbd", b"\xaf\xbf"], # addiu $sp, $sp, VALUE; sw $ra, VALUE
    [b"\x3c\x1c", b"\x27\x9c"], # lw $gp, VALUE
    [b"\x67\xbd", b"\xff\xbc"], # daddiu $sp, $sp, VALUE; sd $gp, VALUE
    [b"\x67\xbd", b"\xff\xbf"], # daddiu $sp, $sp, VALUE; sd $ra, VALUE
]


def is_cmp(i):
    return i.id in CMP

def is_jump(i):
    if i.id in JUMPS_COND or i.id in JUMPS_UNCOND:
        return True
    if i.id == MIPS_INS_JR:
        op = i.operands[0]
        if op.value.reg != MIPS_REG_RA:
            return True
    return False

def is_cond_jump(i):
    return i.id in JUMPS_COND

def is_uncond_jump(i):
    return i.id in JUMPS_UNCOND

def is_ret(i):
    if i.id == MIPS_INS_JR:
        op = i.operands[0]
        return op.value.reg == MIPS_REG_RA
    return False

def is_call(i):
    return i.id in JUMPS_LINK


OPPOSITES = [
        [MIPS_INS_BEQ, MIPS_INS_BNE],
        [MIPS_INS_BNEZ, MIPS_INS_BEQZ],
        [MIPS_INS_BGTZ, MIPS_INS_BLEZ],
        [MIPS_INS_BGEZ, MIPS_INS_BLTZ],
    ]
OPPOSITES = dict(OPPOSITES + [i[::-1] for i in OPPOSITES])

def invert_cond(i):
    return OPPOSITES.get(i.id, -1)


def get_cond(i):
    return i.id


COND_SYMB = {
    MIPS_INS_BEQ: "==",
    MIPS_INS_BNE: "!=",
    MIPS_INS_BNEZ: "!=",
    MIPS_INS_BEQZ: "==",
    MIPS_INS_BGTZ: ">",
    MIPS_INS_BLEZ: "<=",
    MIPS_INS_BGEZ: ">=",
    MIPS_INS_BLTZ: "<",
}


INST_SYMB = {
    MIPS_INS_AND: "&",
    MIPS_INS_ADD: "+",
    MIPS_INS_ADDU: "+",
    MIPS_INS_ADDIU: "+",
    MIPS_INS_SLL: "<<",
    MIPS_INS_SRL: ">>",
    MIPS_INS_SRA: "arith>>",
    MIPS_INS_XOR: "^",
    MIPS_INS_XORI: "^",
    MIPS_INS_SUB: "-",
    MIPS_INS_SUBU: "-",
}


def cond_symbol(ty):
    return COND_SYMB.get(ty, "UNKNOWN")


def inst_symbol(i):
    return INST_SYMB.get(i.id, "UNKNOWN")


class PseudoValue():
    def __init__(self, val):
        self.imm = val
        self.reg = val


class PseudoOp():
    def __init__(self, type, value):
        self.value = PseudoValue(value)
        self.type = type


class PseudoInst():
    def __init__(self, address, mnemonic, op_str, real_inst_list):
        self.real_inst_list = real_inst_list
        self.mnemonic = mnemonic
        self.id = -1
        self.address = address
        self.operands = []
        self.size = 0
        self.bytes = b""
        self.op_str = op_str
        for i in real_inst_list:
            self.size += i.size
            self.bytes += i.bytes
        self.reg_name = real_inst_list[0].reg_name


class NopInst():
    def __init__(self):
        self.id = -1
        self.operands = []
