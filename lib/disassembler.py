#!/usr/bin/env python3
#
# Reverse : Generate an indented asm code (pseudo-C) with colored syntax.
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

from lib.graph import Graph
from lib.utils import debug__
from lib.fileformat.binary import Binary, T_BIN_PE
from lib.output import print_no_end
from lib.colors import pick_color, color_addr, color_symbol, color_section
from lib.exceptions import ExcJmpReg, ExcSymNotFound, ExcNotExec, ExcArch


class Disassembler():
    def __init__(self, filename, raw_bits, forcejmp):
        import capstone as CAPSTONE

        self.forcejmp = forcejmp
        self.code = {}
        self.code_idx = []
        self.binary = Binary(filename, raw_bits)

        arch, mode = self.binary.get_arch()

        if arch is None or mode is None:
            raise ExcArch(self.binary.get_arch_string())

        self.md = CAPSTONE.Cs(arch, mode)
        self.md.detail = True
        self.arch = arch
        self.mode = mode


    def load_arch_module(self):
        import capstone as CAPSTONE
        if self.arch == CAPSTONE.CS_ARCH_X86:
            import lib.arch.x86 as ARCH
        elif self.arch == CAPSTONE.CS_ARCH_ARM:
            import lib.arch.arm as ARCH
        else:
            raise NotImplementedError
        return ARCH


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
        from capstone import CS_OP_IMM
        ARCH = self.load_arch_module()
        ARCH_UTILS = ARCH.utils
        ARCH_OUTPUT = ARCH.output

        # set jumps color
        i = self.lazy_disasm(addr)
        l = 0
        while i is not None and l < lines:
            if ARCH_UTILS.is_jump(i) and i.operands[0].type == CS_OP_IMM:
                pick_color(i.operands[0].value.imm)
            i = self.lazy_disasm(i.address + i.size)
            l += 1

        # Here we have loaded all instructions we want to print
        if self.binary.type == T_BIN_PE:
            self.binary.pe_reverse_stripped_symbols(self)

        o = ARCH_OUTPUT.Output(ctx)

        # dump
        i = self.lazy_disasm(addr)
        l = 0
        while i is not None and l < lines:
            o.print_inst(i, 0)
            i = self.lazy_disasm(i.address + i.size)
            l += 1


    def print_calls(self, ctx):
        ARCH = self.load_arch_module()
        ARCH_UTILS = ARCH.utils
        ARCH_OUTPUT = ARCH.output

        for i in self.md.disasm(self.data, self.virtual_addr):
            if ARCH_UTILS.is_call(i):
                self.code[i.address] = i

        # Here we have loaded all instructions we want to print
        if self.binary.type == T_BIN_PE:
            self.binary.pe_reverse_stripped_symbols(self)

        o = ARCH_OUTPUT.Output(ctx)

        for ad, i in self.code.items():
            if ARCH_UTILS.is_call(i):
                o.print_inst(i)


    def print_symbols(self, print_sections, sym_filter=None):
        if sym_filter is not None:
            sym_filter = sym_filter.lower()

        for addr in self.binary.reverse_symbols:
            sy = self.binary.reverse_symbols[addr]
            if sym_filter is None or sym_filter in sy.lower():
                sec_name, _ = self.binary.is_address(addr)
                print_no_end(color_addr(addr) + " " + color_symbol("<" + sy + ">"))
                if print_sections and sec_name is not None:
                    print_no_end(" (" + color_section(sec_name) + ")")
                print()


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
        from capstone import CS_OP_IMM
        ARCH_UTILS = self.load_arch_module().utils

        curr = self.lazy_disasm(addr)
        gph = Graph(self, addr)
        rest = []

        start = time.clock()

        while 1:
            if not gph.exists(curr):
                if ARCH_UTILS.is_uncond_jump(curr) and len(curr.operands) > 0:
                    if curr.operands[0].type == CS_OP_IMM:
                        addr = curr.operands[0].value.imm
                        nxt = self.lazy_disasm(addr)
                        gph.set_next(curr, nxt)
                        rest.append(nxt.address)
                    else:
                        if not self.forcejmp:
                            self.__error_jmp_reg(curr)
                        gph.add_node(curr)
                    gph.uncond_jumps_set.add(curr.address)

                elif ARCH_UTILS.is_cond_jump(curr) and len(curr.operands) > 0:
                    if curr.operands[0].type == CS_OP_IMM:
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

                elif ARCH_UTILS.is_ret(curr):
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

        if self.binary.type == T_BIN_PE:
            self.binary.pe_reverse_stripped_symbols(self)

        elapsed = time.clock()
        elapsed = elapsed - start
        debug__("Graph built in %fs" % elapsed)

        return gph
