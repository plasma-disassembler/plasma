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


from lib.colors import *
from lib.utils import *
from capstone.x86 import *


# Here, I don't use string.printable because it contains \r \n \t
# and I want to print backslashed strings.
printable = {}
for c in "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ ":
    printable[ord(c)] = 1


local_vars = {}
vars_counter = 1
MAX_STRING_RODATA = 30


# Disassembler
dis = None


def print_block(blk, tab):
    for i in blk:
        print_inst(i, tab)


def print_tabbed(string, tab):
    print("    " * tab, end="")
    if string[0] == "#":
        print(color_comment(string))
    else:
        print(string)


def print_tabbed_no_end(string, tab):
    print("    " * tab, end="")
    print(string, end="")


def print_no_end(text):
    print(text, end="")


# Return True if the operand is a variable
# (The original instruction will be printed later)
def print_operand(i, num_op, hexa=False):
    def inv(n):
        return n == X86_OP_INVALID

    op = i.operands[num_op]

    if op.type == X86_OP_IMM:
        imm = op.value.imm

        if dis.is_rodata(imm):
            print_no_end("0x%x " % imm)
            print_no_end(color_string(get_str_rodata(imm)))

        elif imm in dis.reverse_symbols:
            print_no_end("0x%x " % imm)
            print_no_end(color_string("<" + dis.reverse_symbols[imm] + ">"))

        else:
            if hexa:
                print_no_end("0x%x" % imm)
            else:
                print_no_end(str(imm))
        return False

    elif op.type == X86_OP_REG:
        print_no_end(i.reg_name(op.value.reg))
        return False

    elif op.type == X86_OP_FP:
        print_no_end("%f" % op.value.fp)
        return False

    elif op.type == X86_OP_MEM:
        mm = op.mem

        if not inv(mm.base) and mm.disp != 0 \
            and inv(mm.segment) and inv(mm.index) \
            and mm.base == X86_REG_RBP:
            print_no_end(color_var(get_var_name(i, num_op)))
            return True

        printed = False
        print_no_end("[")

        if not inv(mm.base):
            print_no_end("%s" % i.reg_name(mm.base))
            printed = True

        elif not inv(mm.segment):
            print_no_end("%s" % i.reg_name(mm.segment))
            printed = True

        if not inv(mm.index):
            if printed:
                print_no_end(" + ")
            if mm.scale == 1:
                print_no_end("%s" % i.reg_name(mm.index))
            else:
                print_no_end("(%s*%d)" % (i.reg_name(mm.index), mm.scale))
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

        print_no_end("]")
        return True


def get_str_rodata(addr):
    global printable

    off = addr - dis.rodata.header.sh_addr
    txt = "\""

    i = 0
    while i < MAX_STRING_RODATA:
        v = dis.rodata_data[off]
        if v == 0:
            break
        if v in printable:
            txt += chr(v)
        else:
            if v == 10:
                txt += "\\n"
            elif v == 9:
                txt += "\\t"
            elif v == 13:
                txt += "\\r"
            else:
                txt += "\\x%02x" % v
        off += 1
        i += 1

    if v != 0:
        txt += "..."

    return txt + "\""


def get_var_name(i, op_num):
    global vars_counter, local_vars
    try:
        return local_vars[i.operands[op_num].mem.disp]
    except:
        local_vars[i.operands[op_num].mem.disp] = "var" + str(vars_counter)
        vars_counter += 1
        return local_vars[i.operands[op_num].mem.disp]


def print_inst(i, tab, prefix=""):
    def get_inst_str():
        nonlocal i
        return "%s %s" % (i.mnemonic, i.op_str)

    def get_addr_str():
        nonlocal i
        global addr_color
        addr_str = "0x%x: " % i.address
        if i.address in addr_color:
            addr_str = color(addr_str, addr_color[i.address])
        elif prefix == "":
            addr_str = color_comment(addr_str)
        return addr_str


    if prefix == "# ":
        print_tabbed(color_comment(prefix + get_addr_str() + get_inst_str()), tab)
        return

    print_tabbed_no_end(get_addr_str(), tab)

    if is_ret(i):
        print(color_keyword(get_inst_str()))
        return

    if is_call(i):
        print_no_end(i.mnemonic + " ")
        print_operand(i, 0, hexa=True)
        print()
        return

    if is_uncond_jump(i):
        if i.operands[0].type != X86_OP_IMM:
            print(get_inst_str())
            return
        try:
            addr = i.operands[0].value.imm
            print("jmp " + color("0x%x" % addr, addr_color[addr]))
        except:
            print("jmp 0x%x" % addr)
        return
    
    print_comment = False

    inst_check = [X86_INS_SUB, X86_INS_ADD, X86_INS_MOV, X86_INS_CMP]

    if i.id in inst_check:
        print_operand(i, 0)
        print_no_end(" " + cond_sign_str(i.id) + " ")
        print_operand(i, 1)
        print_comment = True
    else:
        print_no_end("%s " % i.mnemonic)
        if len(i.operands) > 0:
            print_comment = print_operand(i, 0)
            k = 1
            while k < len(i.operands):
                print_no_end(", ")
                print_comment |= print_operand(i, k)
                k += 1

    if print_comment:
        print_no_end(color_comment(" # " + get_inst_str()))

    print()


