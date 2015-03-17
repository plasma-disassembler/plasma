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
from capstone import *
from capstone.x86 import *

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


# In each array nxt (from gph.link_out)
BRANCH_NEXT = 0        # or for the if part
BRANCH_NEXT_JUMP = 1   # or for the else part


# Here, I don't use string.printable because it contains \r \n \t
# and I want to print backslashed strings.
PRINTABLE = set(map(ord, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLM"
    "NOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ "))


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
    ]
OPPOSITES = dict(OPPOSITES + [i[::-1] for i in OPPOSITES])

def invert_cond(ty):
    try:
        return OPPOSITES[ty]
    except:
        return -1


def cond_inst_str(ty):
    conds = {
        -1: "UNKNOWN",
        X86_INS_JAE: "jae",
        X86_INS_JA: "ja",
        X86_INS_JBE: "jbe",
        X86_INS_JB: "jb",
        X86_INS_JCXZ: "jcxz",
        X86_INS_JECXZ: "jecxz",
        X86_INS_JE: "je",
        X86_INS_JGE: "jge",
        X86_INS_JG: "jg",
        X86_INS_JLE: "jle",
        X86_INS_JL: "jl",
        X86_INS_JMP: "jmp",
        X86_INS_JNE: "jne",
        X86_INS_JNO: "jno",
        X86_INS_JNP: "jnp",
        X86_INS_JNS: "jns",
        X86_INS_JO: "jo",
        X86_INS_JP: "jp",
        X86_INS_JRCXZ: "jrcxz",
        X86_INS_JS: "jz",
    }
    return conds[ty]


def cond_sign_str(ty, has_cmp=False):
    conds = {
        X86_INS_JE: "==",
        X86_INS_JNE: "!=",
        X86_INS_JGE: ">=",
        X86_INS_JL: "<",
        X86_INS_JLE: "<=",
        X86_INS_JG: ">",
        X86_INS_ADD: "+=",
        X86_INS_MOV: "=",
        X86_INS_SUB: "-=",
        X86_INS_CMP: "cmp",
        X86_INS_JNS: "> 0",
        X86_INS_JS: "< 0"
    }

    conds_cmp = {
        X86_INS_JE: "==",
        X86_INS_JNE: "!=",
        X86_INS_JGE: ">=",
        X86_INS_JL: "<",
        X86_INS_JLE: "<=",
        X86_INS_JG: ">",
        X86_INS_ADD: "+=",
        X86_INS_MOV: "=",
        X86_INS_SUB: "-=",
        X86_INS_CMP: "cmp",
        X86_INS_JNS: ">",
        X86_INS_JS: "<"
    }

    try:
        if has_cmp:
            return conds_cmp[ty]
        else:
            return conds[ty]
    except:
        return "UNKNOWN"

    # TODO : invert_cond need to be updated too
    # X86_INS_JAE
    # X86_INS_JA
    # X86_INS_JBE
    # X86_INS_JB
    # X86_INS_JCXZ
    # X86_INS_JECXZ
    # X86_INS_JNO
    # X86_INS_JNP
    # X86_INS_JO
    # X86_INS_JP
    # X86_INS_JRCXZ



def print_dict(dic, end="\n"):
    print("[")
    for i in dic:
        if isinstance(i, str):
            print("%s: " % i, end="")
        else:
            print("%x: " % i, end="")
        v = dic[i]
        if isinstance(v, list):
            print_list(v)
        elif isinstance(v, dict):
            print_dict(v)
        elif isinstance(v, str):
            print("%s: " % v)
        else:
            print("0x%x" % v)

    print("]" + end, end="")



def print_list(lst, end="\n"):
    print("[", end="")
    for i in lst[:-1]:
        if isinstance(i, list):
            print_list(i, "")
            print(", ", end="")
        else:
            print("0x%x, " % i, end="")

    if len(lst) > 0:
        if isinstance(lst[-1], list):
            print_list(lst[-1], "")
        else:
            print("0x%x" % lst[-1], end="")

    print("]" + end, end="")


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


def get_char(c):
    if c in PRINTABLE:
        return chr(c)
    if c == 10:
        return "\\n"
    if c == 9:
        return "\\t"
    if c == 13:
        return "\\r"
    return "\\x%02x" % (c % 256)
