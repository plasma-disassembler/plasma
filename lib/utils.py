#!/bin/python3
#
# Reverse : reverse engineering for x86 binaries
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

import sys
from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from capstone.x86 import (X86_INS_ADD, X86_INS_AND, X86_INS_CMP, X86_INS_DEC,
        X86_INS_IMUL, X86_INS_INC, X86_INS_JA, X86_INS_JAE, X86_INS_JE,
        X86_INS_JGE, X86_INS_JL, X86_INS_JLE, X86_INS_JG, X86_INS_JBE,
        X86_INS_JB, X86_INS_JMP, X86_INS_JCXZ, X86_INS_JECXZ,
        X86_INS_JNE, X86_INS_JNO, X86_INS_JNP, X86_INS_JNS, X86_INS_JO,
        X86_INS_JP, X86_INS_JRCXZ, X86_INS_JS, X86_INS_MOV, X86_INS_SHL,
        X86_INS_SHR, X86_INS_SUB, X86_INS_XOR, X86_INS_OR, X86_INS_MOVSX)

# X86_INS_JAE = 257
# X86_INS_JA = 258
# X86_INS_JBE = 259
# X86_INS_JB = 260
# X86_INS_JCXZ = 261
# X86_INS_JECXZ = 262
# X86_INS_JE = 263
# X86_INS_JGE = 264
# X86_INS_JG = 265
# X86_INS_JLE = 266
# X86_INS_JL = 267
# X86_INS_JMP = 268
# X86_INS_JNE = 269
# X86_INS_JNO = 270
# X86_INS_JNP = 271
# X86_INS_JNS = 272
# X86_INS_JO = 273
# X86_INS_JP = 274
# X86_INS_JRCXZ = 275
# X86_INS_JS = 276


ctx = None


def debug__(obj="", end="\n"):
    if ctx.debug:
        if isinstance(obj, str):
            print(obj, end=end, file=sys.stderr)
        elif isinstance(obj, list):
            print_list(obj)
        elif isinstance(obj, dict):
            print_dict(obj)
        elif isinstance(obj, set):
            print_set(obj)



# In each array nxt (from gph.link_out)
BRANCH_NEXT = 0        # or for the if part
BRANCH_NEXT_JUMP = 1   # or for the else part


# Here, I don't use string.printable because it contains \r \n \t
# and I want to print backslashed strings.
PRINTABLE = [r'\x{0:02x}'.format(i) for i in range(256)]
for c in ("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLM"
        "NOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ "):
    PRINTABLE[ord(c)] = c
PRINTABLE[0] = r'\0'
PRINTABLE[9] = r'\t'
PRINTABLE[10] = r'\n'
PRINTABLE[13] = r'\r'

get_char = PRINTABLE.__getitem__


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

def invert_cond(ty):
    return OPPOSITES.get(ty, -1)


# def cond_inst_str(ty):
    # conds = {
        # -1: "UNKNOWN",
        # X86_INS_JAE: "jae",
        # X86_INS_JA: "ja",
        # X86_INS_JBE: "jbe",
        # X86_INS_JB: "jb",
        # X86_INS_JCXZ: "jcxz",
        # X86_INS_JECXZ: "jecxz",
        # X86_INS_JE: "je",
        # X86_INS_JGE: "jge",
        # X86_INS_JG: "jg",
        # X86_INS_JLE: "jle",
        # X86_INS_JL: "jl",
        # X86_INS_JMP: "jmp",
        # X86_INS_JNE: "jne",
        # X86_INS_JNO: "jno",
        # X86_INS_JNP: "jnp",
        # X86_INS_JNS: "jns",
        # X86_INS_JO: "jo",
        # X86_INS_JP: "jp",
        # X86_INS_JRCXZ: "jrcxz",
        # X86_INS_JS: "jz",
    # }
    # return conds[ty]

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
    X86_INS_SHR: ">>=",
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

def inst_symbol(ty):
    return INST_SYMB.get(ty, "UNKNOWN")


def index(L, obj, k=0):
    try:
        return L.index(obj, k)
    except ValueError:
        return -1


def error(txt):
    print("ERROR: " + txt, file=sys.stderr)


def die(txt):
    print("ERROR: " + txt, file=sys.stderr)
    sys.exit(1)



# Debug functions

def print_set(s, end="\n"):
    print("{", end="", file=sys.stderr)
    for i in s:
        print(" %x" % i, end="", file=sys.stderr)
    print(" }" + end, end="", file=sys.stderr)


def print_dict(dic, end="\n"):
    print("[", file=sys.stderr)
    for i in dic:
        if isinstance(i, str):
            print("%s: " % i, end="", file=sys.stderr)
        else:
            print("%x: " % i, end="", file=sys.stderr)
        v = dic[i]
        if isinstance(v, list):
            print_list(v)
        elif isinstance(v, dict):
            print_dict(v)
        elif isinstance(v, set):
            print_set(v)
        elif isinstance(v, str):
            print("%s: " % v, file=sys.stderr)
        else:
            print("0x%x, " % v, end="", file=sys.stderr)

    print("]" + end, end="", file=sys.stderr)


def print_list(lst, end="\n"):
    print("[", end="", file=sys.stderr)
    for i in lst[:-1]:
        if isinstance(i, list):
            print_list(i, "")
            print(",\n ", end="")
        elif isinstance(i, dict):
            print_dict(i)
            print(",\n ", end="", file=sys.stderr)
        elif isinstance(i, set):
            print(i, file=sys.stderr)
        else:
            print("0x%x, " % i, end="", file=sys.stderr)

    if len(lst) > 0:
        if isinstance(lst[-1], list):
            print_list(lst[-1], "")
        elif isinstance(lst[-1], dict):
            print_dict(lst[-1])
        elif isinstance(lst[-1], set):
            print(lst[-1], file=sys.stderr)
        else:
            print("0x%x" % lst[-1], end="", file=sys.stderr)

    print("]" + end, end="", file=sys.stderr)
