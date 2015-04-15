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

import time
import sys

from capstone import CS_MODE_32, CS_MODE_64, CS_ARCH_X86, Cs
from capstone.x86 import X86_OP_IMM

from lib.graph import Graph
from lib.utils import (is_call, is_cond_jump, is_uncond_jump, is_jump, 
        is_ret, debug__)
from lib.fileformat.binary import Binary, ARCH_x86, ARCH_x64, T_BIN_PE
from lib.output import Output
from lib.colors import pick_color
from lib.exceptions import ExcJmpReg, ExcSymNotFound, ExcNotExec, ExcArch


class Disassembler():
    def __init__(self, filename, raw_bits, forcejmp):
        self.forcejmp = forcejmp
        self.code = {}
        self.code_idx = []
        self.binary = Binary(filename, raw_bits)

        arch = self.binary.get_arch()
        if arch == ARCH_x86:
            self.bits = 32
        elif arch == ARCH_x64:
            self.bits = 64
        else:
            raise ExcArch()

        mode = CS_MODE_64 if self.bits == 64 else CS_MODE_32
        self.md = Cs(CS_ARCH_X86, mode)
        self.md.detail = True


    def init(self, addr):
        # Get section data
        (self.data, self.virtual_addr, flags) = self.binary.get_section(addr)
        if not flags["exec"]:
            raise ExcNotExec(addr)


    def get_addr_from_string(self, opt_addr, raw=False):
        if opt_addr is None:
            if raw:
                return 0
            search = ["main", "_main"]
        else:
            search = [opt_addr]

        for s in search:
            if s.startswith("0x"):
                a = int(opt_addr, 16)
            else:
                a = self.binary.symbols.get(s, -1)

            if a != -1:
                return a

        raise ExcSymNotFound(search[0])


    def dump(self, ctx, addr, lines):
        # set jumps color
        i = self.lazy_disasm(addr)
        l = 0
        while i is not None and l < lines:
            if is_jump(i) and i.operands[0].type == X86_OP_IMM:
                pick_color(i.operands[0].value.imm)
            i = self.lazy_disasm(i.address + i.size)
            l += 1

        # Here we have loaded all instructions we want to print
        if self.binary.get_type() == T_BIN_PE:
            self.binary.pe_reverse_stripped_symbols(self)

        o = Output(ctx)

        # dump
        i = self.lazy_disasm(addr)
        l = 0
        while i is not None and l < lines:
            if i.address in self.binary.reverse_symbols:
                o.print_symbol(i.address)
                print()
            o.print_inst(i, 0)
            i = self.lazy_disasm(i.address + i.size)
            l += 1


    def print_calls(self, ctx):
        for i in self.md.disasm(self.data, self.virtual_addr):
            if is_call(i):
                self.code[i.address] = i

        # Here we have loaded all instructions we want to print
        if self.binary.get_type() == T_BIN_PE:
            self.binary.pe_reverse_stripped_symbols(self)

        o = Output(ctx)

        for ad, i in self.code.items():
            if is_call(i):
                o.print_inst(i)


    def print_symbols(self):
        for addr in self.binary.reverse_symbols:
            sy = self.binary.reverse_symbols[addr]
            print("0x%x   %s" % (addr, sy))


    def __error_jmp_reg(self, i):
        raise ExcJmpReg(i)


    def load_user_sym_file(self, fd):
        for l in fd:
            arg = l.split()
            addr = int(arg[0], 16)
            self.binary.reverse_symbols[addr] = arg[1]
            self.binary.symbols[arg[1]] = addr


    def lazy_disasm(self, addr):
        if addr in self.code:
            return self.code[addr]
        
        # Disasm by block of 16 instructions

        first = None
        off = addr - self.virtual_addr

        gen = self.md.disasm(self.data[off:off+64], addr)

        try:
            first = next(gen)
            self.code[first.address] = first
            self.code_idx.append(first.address)

            for n in range(15):
                i = next(gen)
                self.code[i.address] = i
                self.code_idx.append(i.address)
        except StopIteration:
            pass

        return first


    # Generate a flow graph of the given function (addr)
    def get_graph(self, addr):
        curr = self.lazy_disasm(addr)
        gph = Graph(self, addr)
        rest = []

        start = time.clock()

        while 1:
            if not gph.exists(curr):
                if is_uncond_jump(curr) and len(curr.operands) > 0:
                    if curr.operands[0].type == X86_OP_IMM:
                        addr = curr.operands[0].value.imm
                        nxt = self.lazy_disasm(addr)
                        gph.set_next(curr, nxt)
                        rest.append(nxt.address)
                    else:
                        if not self.forcejmp:
                            self.__error_jmp_reg(curr)
                        gph.add_node(curr)
                    gph.uncond_jumps_set.add(curr.address)

                elif is_cond_jump(curr) and len(curr.operands) > 0:
                    if curr.operands[0].type == X86_OP_IMM:
                        nxt_jump = self.lazy_disasm(curr.operands[0].value.imm)
                        direct_nxt = self.lazy_disasm(curr.address + curr.size)
                        gph.set_cond_next(curr, nxt_jump, direct_nxt)
                        rest.append(nxt_jump.address)
                        rest.append(direct_nxt.address)
                    else:
                        if not self.forcejmp:
                            self.__error_jmp_reg(curr)
                        gph.add_node(curr)
                    gph.cond_jumps_set.add(curr.address)

                elif is_ret(curr):
                    gph.add_node(curr)

                else:
                    try:
                        nxt = self.lazy_disasm(curr.address + curr.size)
                        gph.set_next(curr, nxt)
                        rest.append(nxt.address)
                    except:
                        gph.add_node(curr)
                        pass

            try:
                curr = self.lazy_disasm(rest.pop())
            except IndexError:
                break

        if self.binary.get_type() == T_BIN_PE:
            self.binary.pe_reverse_stripped_symbols(self)

        elapsed = time.clock()
        elapsed = elapsed - start
        debug__("Graph built in %fs" % elapsed)

        return gph
