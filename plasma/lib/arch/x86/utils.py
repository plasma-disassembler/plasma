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

from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from capstone.x86 import (X86_INS_ADD, X86_INS_AND, X86_INS_CMP, X86_INS_DEC,
        X86_INS_IMUL, X86_INS_INC, X86_INS_JA, X86_INS_JAE, X86_INS_JE,
        X86_INS_JGE, X86_INS_JL, X86_INS_JLE, X86_INS_JG, X86_INS_JBE,
        X86_INS_JB, X86_INS_JMP, X86_INS_JCXZ, X86_INS_JECXZ,
        X86_INS_JNE, X86_INS_JNO, X86_INS_JNP, X86_INS_JNS, X86_INS_JO,
        X86_INS_JP, X86_INS_JRCXZ, X86_INS_JS, X86_INS_MOV, X86_INS_SHL,
        X86_INS_SAL, X86_INS_SAR, X86_OP_IMM, X86_OP_MEM, X86_OP_REG,
        X86_INS_SHR, X86_INS_SUB, X86_INS_XOR, X86_INS_OR, X86_INS_MOVSX)


OP_IMM = X86_OP_IMM
OP_MEM = X86_OP_MEM
OP_REG = X86_OP_REG


# Warning: before adding new prolog check in lib.analyzer.has_prolog
PROLOGS = [
    [b"\x55\x89\xe5"], # push ebp; mov ebp, esp
    [b"\x55\x48\x89\xe5"], # push rbp; mov rbp, rsp
]


def is_cmp(i):
    return i.id == X86_INS_CMP

def is_jump(i):
    return i.group(CS_GRP_JUMP)

def is_cond_jump(i):
    return i.group(CS_GRP_JUMP) and i.id != X86_INS_JMP

def is_uncond_jump(i):
    return i.id == X86_INS_JMP

def is_ret(i):
    # TODO more ret  ??
    return i.group(CS_GRP_RET)

def is_call(i):
    return i.group(CS_GRP_CALL)


OPPOSITES = [
        [X86_INS_JE, X86_INS_JNE],
        [X86_INS_JGE, X86_INS_JL],
        [X86_INS_JLE, X86_INS_JG],
        [X86_INS_JNS, X86_INS_JS],
        [X86_INS_JAE, X86_INS_JB],
        [X86_INS_JBE, X86_INS_JA],
        [X86_INS_JP, X86_INS_JNP],
        [X86_INS_JO, X86_INS_JNO],
        [X86_INS_JS, X86_INS_JNS],
    ]
OPPOSITES = dict(OPPOSITES + [i[::-1] for i in OPPOSITES])

def invert_cond(i):
    return OPPOSITES.get(i.id, -1)


def get_cond(i):
    return i.id


# used most of the time
INST_SYMB = {
    X86_INS_JE: "==",
    X86_INS_JNE: "!=",

    # signed
    X86_INS_JGE: ">=",
    X86_INS_JL: "<",
    X86_INS_JLE: "<=",
    X86_INS_JG: ">",

    # unsigned
    X86_INS_JAE: "(unsigned) >=",
    X86_INS_JA: "(unsigned) >",
    X86_INS_JBE: "(unsigned) <=",
    X86_INS_JB: "(unsigned) <",

    # other flags
    X86_INS_JNS: ">",
    X86_INS_JS: "<",
    X86_INS_JP: "% 2 ==",
    X86_INS_JNP: "% 2 !=",
    X86_INS_JCXZ: "cx ==",
    X86_INS_JECXZ: "ecx ==",
    X86_INS_JRCXZ: "rxc ==",
    X86_INS_JNO: "overflow",
    X86_INS_JO: "!overflow",

    # other instructions
    X86_INS_XOR: "^=",
    X86_INS_OR: "|=",
    X86_INS_AND: "&=",
    X86_INS_SAR: ">>=",
    X86_INS_SHR: ">>=",
    X86_INS_SAL: "<<=",
    X86_INS_SHL: "<<=",
    X86_INS_IMUL: "*=",
    X86_INS_ADD: "+=",
    X86_INS_MOV: "=",
    X86_INS_MOVSX: "=",
    X86_INS_SUB: "-=",
    X86_INS_CMP: "cmp",
    X86_INS_DEC: "--",
    X86_INS_INC: "++",
}


def cond_symbol(ty):
    return INST_SYMB.get(ty, "UNKNOWN")


def inst_symbol(i):
    return INST_SYMB.get(i.id, "UNKNOWN")
