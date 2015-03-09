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

import random

from utils import *
from capstone.x86 import *


printable = {}

for c in "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ ":
    printable[ord(c)] = 1



jumps = {}
local_vars = {}
vars_counter = 1
color_counter = 112

# Disassembler
dis = None

nocolor = False



def pick_color():
    global color_counter
    if color_counter == 230:
        color_counter = 112
    else:
        color_counter += 2
    return color_counter

def color(text, c):
    if nocolor:
        return text
    return "\x1b[38;5;" + str(c) + "m" + text + "\x1b[0m"

def yellow(text):
    if nocolor:
        return text
    return "\x1b[;33m" + text + "\x1b[0m"

def red(text):
    if nocolor:
        return text
    return "\x1b[;31m" + text + "\x1b[0m"

def bold(text):
    if nocolor:
        return text
    return "\x1b[1m" + text + "\x1b[0m"

def color_keyword(text):
    if nocolor:
        return text
    return bold(color(text, 161))

def color_var(text):
    if nocolor:
        return text
    return bold(color(text, 208))

def color_comment(text):
    if nocolor:
        return text
    return color(text, 242)

def color_string(text):
    if nocolor:
        return text
    return color(text, 144)


# If reg_base_l is the base of an address access
# ex: mov [rbp + 1], 123
def pattern_lbase(inst, lst_inst_id, reg_base_l, op_r):
    if inst.id in lst_inst_id and len(inst.operands) == 2:
        if inst.operands[0].type == X86_OP_MEM and inst.operands[1].type == op_r:
            if inst.operands[0].mem.base == reg_base_l:
                return True
    return False


# ex: mov eax, [rbp + 1]
def pattern_rbase(inst, lst_inst_id, op_l, reg_base_r):
    if inst.id in lst_inst_id and len(inst.operands) == 2:
        if inst.operands[1].type == X86_OP_MEM and inst.operands[0].type == op_l:
            if inst.operands[1].mem.base == reg_base_r:
                return True
    return False


def print_tabbed(string, tab):
    print("    " * tab, end="")
    if string[0] == "#":
        print(color_comment(string))
    else:
        print(string)


def print_tabbed_no_end(string, tab):
    print("    " * tab, end="")
    if string[0] == "#":
        print(color_comment(string), end="")
    else:
        print(string, end="")


def print_no_end(text):
    print(text, end="")


def print_block(blk, tab):
    for i in blk:
        print_inst(i, tab)


def print_inst(i, tab, prefix=""):
    def get_inst_str():
        nonlocal i
        return "%s %s" % (i.mnemonic, i.op_str)

    def get_var_name(op_num):
        global vars_counter, local_vars
        nonlocal i
        try:
            return local_vars[i.operands[op_num].mem.disp]
        except:
            local_vars[i.operands[op_num].mem.disp] = "var" + str(vars_counter)
            vars_counter += 1
            return local_vars[i.operands[op_num].mem.disp]

    def get_addr_str():
        global jumps
        nonlocal i, prefix

        addr_str = "0x%x: " % i.address

        if i.address in jumps:
            addr_str = color(addr_str, jumps[i.address])
        elif prefix == "":
            addr_str = color_comment(addr_str)

        return prefix + addr_str

    def print_rodata():
        global dis, printable
        nonlocal i

        for o in i.operands:
            if o.type == X86_OP_IMM and dis.is_rodata(o.value.imm):
                addr = o.value.imm

                off = addr - dis.rodata.header.sh_addr
                txt = "\""

                i = 0
                while i < 20:
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

                if v != 0:
                    txt += "..."

                print_no_end("  " + color_string(txt + "\""))

    def print_access_local_vars():
        nonlocal i
        v = []
        for k, o in enumerate(i.operands):
            if o.type == X86_OP_MEM and o.mem.base == X86_REG_RBP:
                v.append(k)

        if len(v) > 0:
            print_no_end("  [")
            for k in v[:-1]:
                print_no_end(color_var(get_var_name(k)) + ", ")
            print_no_end(color_var(get_var_name(v[-1])))
            print_no_end("]")

    if is_ret(i):
        print_tabbed(get_addr_str() + color_keyword(get_inst_str()), tab)
        return

    if is_call(i):
        print_tabbed_no_end(get_addr_str() + get_inst_str(), tab)
        if i.operands[0].type != X86_OP_IMM:
            print()
            return
        try:
            addr = i.operands[0].value.imm
            print(" " + color_string("<" + dis.reverse_symbols[addr] + ">"))
        except:
            print()
        return

    if is_uncond_jump(i):
        print_tabbed_no_end(get_addr_str(), tab)
        if i.operands[0].type != X86_OP_IMM:
            print(get_inst_str())
            return
        try:
            addr = i.operands[0].value.imm
            print("jmp " + color("0x%x" % addr, jumps[addr]))
        except:
            print("jmp 0x%x" % addr)
        return
    
    # Detection of local variables : rewrite the instruction 
    # to be more readdable

    inst_check = [X86_INS_SUB, X86_INS_ADD, X86_INS_MOV, X86_INS_CMP]

    if pattern_lbase(i, inst_check, X86_REG_RBP, X86_OP_IMM):
        print_tabbed_no_end(get_addr_str(), tab)
        print_no_end(color_var(get_var_name(0)))
        print_no_end(" " + cond_sign_str(i.id) + " ")
        print_no_end(str(i.operands[1].value.imm))
        print(color_comment(" # " + get_inst_str()))
        return

    if pattern_lbase(i, inst_check, X86_REG_RBP, X86_OP_REG):
        print_tabbed_no_end(get_addr_str(), tab)
        print_no_end(color_var(get_var_name(0)))
        print_no_end(" " + cond_sign_str(i.id) + " ")
        print_no_end(i.reg_name(i.operands[1].value.reg))
        print(color_comment(" # " + get_inst_str()))
        return

    if pattern_rbase(i, inst_check, X86_OP_IMM, X86_REG_RBP):
        print_tabbed_no_end(get_addr_str(), tab)
        print_no_end(str(i.operands[0].value.imm))
        print_no_end(" " + cond_sign_str(i.id) + " ")
        print_no_end(color_var(get_var_name(1)))
        print(color_comment(" # " + get_inst_str()))
        return

    if pattern_rbase(i, inst_check, X86_OP_REG, X86_REG_RBP):
        print_tabbed_no_end(get_addr_str(), tab)
        print_no_end(i.reg_name(i.operands[0].value.reg))
        print_no_end(" " + cond_sign_str(i.id) + " ")
        print_no_end(color_var(get_var_name(1)))
        print(color_comment(" # " + get_inst_str()))
        return

    print_tabbed_no_end(get_addr_str() + get_inst_str(), tab)
    print_access_local_vars()
    print_rodata()
    print()




class Ast_Branch:
    def __init__(self):
        self.nodes = []

    def add(self, node):
        if type(node) == Ast_Branch:
            self.nodes += node.nodes
        else:
            self.nodes.append(node)

    def print(self, tab=0):
        for n in self.nodes:
            if type(n) == list:
                print_block(n, tab)
            else: # ast
                n.print(tab)

    def assign_colors(self):
        for n in self.nodes:
            if type(n) == list:
                if is_uncond_jump(n[0]):
                    nxt = gph.link_out[n[0].address][BRANCH_NEXT]
                    if nxt not in jumps:
                        jumps[nxt] = pick_color()
            else:
                n.assign_colors()


class Ast_IfGoto:
    def __init__(self, orig_jump, cond_id, addr_jump):
        self.orig_jump = orig_jump
        self.cond_id = cond_id
        self.addr_jump = addr_jump

    def print(self, tab=0):
        print_tabbed_no_end(color_keyword("if ") + cond_sign_str(self.cond_id), tab)
        print_no_end(color_keyword("  goto "))
        try:
            c = jumps[self.addr_jump]
            print_no_end(color("0x%x ", c) % self.addr_jump)
        except:
            print_no_end("0x%x " % self.addr_jump)
        print_inst(self.orig_jump, 0, "# ")

    def assign_colors(self):
        if self.addr_jump not in jumps:
            jumps[self.addr_jump] = pick_color()


class Ast_AndIf:
    def __init__(self, orig_jump, cond_id):
        self.orig_jump = orig_jump
        self.cond_id = cond_id

    def print(self, tab=0):
        print_tabbed_no_end(color_keyword("and ") + color_keyword("if ") + \
                cond_sign_str(self.cond_id) + " ", tab)
        print_inst(self.orig_jump, 0, "# ")

    def assign_colors(self):
        return


class Ast_Ifelse:
    def __init__(self, inst_jump, brtrue, brfalse):
        self.inst_jump = inst_jump
        self.brtrue = brtrue
        self.brfalse = brfalse

    def print(self, tab=0):
        print_inst(self.inst_jump, tab, "# ")
        print_tabbed(color_keyword("if ") + 
                cond_sign_str(invert_cond(self.inst_jump.id)) + " {", tab)

        # Start with the false branch : it's directly after the jump
        # false branch == jump is not taken, so it means that the If 
        # is true !!
        self.brfalse.print(tab+1)

        if len(self.brtrue.nodes) > 0:
            print_tabbed("} " + color_keyword("else ") + 
                    cond_sign_str(self.inst_jump.id) + " {", tab)
        
            # Print the true branch, the jump is taken (the if is false)
            self.brtrue.print(tab+1)

        print_tabbed("}", tab)

    def assign_colors(self):
        self.brfalse.assign_colors()
        self.brtrue.assign_colors()


class Ast_Loop:
    def __init__(self):
        self.branch = Ast_Branch()
        self.epilog = None
        self.is_infinite = False

    def add(self, node):
        self.branch.add(node)

    def set_epilog(self, epilog):
        self.epilog = epilog

    def set_infinite(self, v):
        self.is_infinite = v

    def set_branch(self, b):
        self.branch = b

    def print(self, tab=0):
        if self.is_infinite:
            print_tabbed(color_keyword("infiniteloop") + " {", tab)
        else:
            print_tabbed(color_keyword("loop") + " {", tab)
        self.branch.print(tab+1)
        print_tabbed("}", tab)
        if self.epilog != None:
            self.epilog.print(tab)

    def assign_colors(self):
        self.branch.assign_colors()
        if self.epilog != None:
            self.epilog.assign_colors()


class Ast_Comment:
    def __init__(self, text):
        self.text = text

    def print(self, tab=0):
        print_tabbed("# " + self.text, tab)

    def assign_colors(self):
        return

