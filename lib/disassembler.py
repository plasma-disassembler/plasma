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

from capstone import *
from capstone.x86 import *

from lib.graph import Graph
from lib.utils import *
from lib.binary import *
from lib.output import print_inst, print_symbol
from lib.colors import pick_color


class Disassembler():
    def __init__(self, filename):
        self.code = {}
        self.code_idx = []
        self.binary = Binary(filename)

        arch = self.binary.get_arch()
        if arch == ARCH_x86:
            self.bits = 32
        elif arch == ARCH_x64:
            self.bits = 64
        else:
            die("only x86 and x64 are supported")


    def disasm(self, addr):
        (data, virtual_addr, flags) = self.binary.get_section(addr)

        if not flags["exec"]:
            die("the address 0x%x is not in an executable section" % addr)

        mode = CS_MODE_64 if self.bits == 64 else CS_MODE_32
        md = Cs(CS_ARCH_X86, mode)
        md.detail = True

        for i in md.disasm(data, virtual_addr):
            self.code[i.address] = i
            self.code_idx.append(i.address)

        # Now load imported symbols for PE.
        # This cannot be done before, because we need the code.
        if self.binary.get_type() == T_BIN_PE:
            self.binary.load_import_symbols(self.code)


    def get_addr_from_string(self, opt_addr):
        search = [opt_addr]
        if opt_addr == "main":
            search.append("_main")

        found = False
        for s in search:
            if opt_addr.startswith("0x"):
                a = int(opt_addr, 16)
            else:
                try:
                    a = self.binary.symbols[s]
                except:
                    a = -1

            if a != -1:
                found = True
                break

        if not found:
            error("symbol %s not found" % search[0])
            die("Try with --sym to see all symbols.")
        
        return a


    def dump(self, addr, lines):

        i_init = index(self.code_idx, addr)
        end = min(len(self.code_idx), i_init + lines)

        # set jumps color
        i = i_init
        while i < end:
            inst = self.code[self.code_idx[i]]
            if is_jump(inst) and inst.operands[0].type == X86_OP_IMM:
                pick_color(inst.operands[0].value.imm)
            i += 1

        i = i_init
        while i < end:
            inst = self.code[self.code_idx[i]]
            if inst.address in self.binary.reverse_symbols:
                print_symbol(inst.address)
                print()
            print_inst(inst, 0)
            i += 1


    def print_calls(self):
        for i in self.code_idx:
            inst = self.code[i]
            if is_call(inst):
                print_inst(inst)


    def get_graph(self, addr):
        graph = self.__extract_func(addr)
        graph.simplify()
        graph.detect_loops()
        return graph


    def print_symbols(self):
        for addr in self.binary.reverse_symbols:
            sy = self.binary.reverse_symbols[addr]
            print("0x%x   %s" % (addr, sy))


    def __error_jmp_reg(self, i):
        error("failed on 0x%x: %s %s" % 
                (i.address, i.mnemonic, i.op_str))
        error("Sorry, I can't generate the flow graph.")
        die("Try with --dump")


    def load_user_sym_file(self, fd):
        for l in fd:
            arg = l.split()
            addr = int(arg[0], 16)
            self.binary.reverse_symbols[addr] = arg[1]
            self.binary.symbols[arg[1]] = addr


    # Generate a flow graph of the given function (addr)
    def __extract_func(self, addr):
        curr = self.code[addr]
        gph = Graph(self, addr)

        rest = []

        while 1:
            if not gph.exists(curr):
                if is_uncond_jump(curr) and len(curr.operands) > 0:
                    if curr.operands[0].type == X86_OP_IMM:
                        addr = curr.operands[0].value.imm
                        nxt = self.code[addr]
                        gph.set_next(curr, nxt)
                        rest.append(nxt.address)
                    else:
                        self.__error_jmp_reg(curr)

                elif is_cond_jump(curr) and len(curr.operands) > 0:
                    if curr.operands[0].type == X86_OP_IMM:
                        nxt_jump = self.code[curr.operands[0].value.imm]
                        direct_nxt = self.code[curr.address + curr.size]
                        gph.set_cond_next(curr, nxt_jump, direct_nxt)
                        rest.append(nxt_jump.address)
                        rest.append(direct_nxt.address)
                    else:
                        self.__error_jmp_reg(curr)

                elif is_ret(curr):
                    gph.add_node(curr)

                else:
                    nxt = self.code[curr.address + curr.size]
                    gph.set_next(curr, nxt)
                    rest.append(nxt.address)

            try:
                curr = self.code[rest.pop()]
            except:
                break

        return gph
