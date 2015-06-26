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
from lib.exceptions import ExcSymNotFound, ExcArch, ExcNotAddr, ExcNotExec


class Disassembler():
    def __init__(self, filename, raw_type, raw_base, raw_big_endian):
        import capstone as CAPSTONE

        self.code = {}
        self.binary = Binary(filename, raw_type, raw_base, raw_big_endian)

        arch, mode = self.binary.get_arch()

        if arch is None or mode is None:
            raise ExcArch(self.binary.get_arch_string())

        self.binary.load_extra()

        self.md = CAPSTONE.Cs(arch, mode)
        self.md.detail = True
        self.arch = arch
        self.mode = mode


    def check_addr(self, addr):
        addr_exists, is_exec = self.binary.check_addr(addr)
        if not is_exec:
            raise ExcNotExec(addr)
        if not addr_exists:
            raise ExcNotAddr(addr)


    def load_arch_module(self):
        import capstone as CAPSTONE
        if self.arch == CAPSTONE.CS_ARCH_X86:
            import lib.arch.x86 as ARCH
        elif self.arch == CAPSTONE.CS_ARCH_ARM:
            import lib.arch.arm as ARCH
        elif self.arch == CAPSTONE.CS_ARCH_MIPS:
            import lib.arch.mips as ARCH
        else:
            raise NotImplementedError
        return ARCH


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


    def print_section_meta(self, name, start, end):
        print_no_end(color_section(name))
        print_no_end(" [")
        print_no_end(hex(start))
        print_no_end(" - ")
        print_no_end(hex(end))
        print("]")


    def dump(self, ctx, lines):
        from capstone import CS_OP_IMM
        ARCH = self.load_arch_module()
        ARCH_UTILS = ARCH.utils
        ARCH_OUTPUT = ARCH.output

        s_name, s_start, s_end = self.binary.get_section_meta(ctx.addr)
        self.print_section_meta(s_name, s_start, s_end)

        # WARNING: this assume that on every architectures the jump
        # address is the last operand (operands[-1])

        # set jumps color
        i = self.lazy_disasm(ctx.addr, s_start)
        l = 0
        while i is not None and l < lines:
            if ARCH_UTILS.is_jump(i) and i.operands[-1].type == CS_OP_IMM:
                pick_color(i.operands[-1].value.imm)
            i = self.lazy_disasm(i.address + i.size, s_start)
            l += 1

        # Here we have loaded all instructions we want to print
        if self.binary.type == T_BIN_PE:
            self.binary.pe_reverse_stripped_symbols(self)

        o = ARCH_OUTPUT.Output(ctx)

        # dump
        i = self.lazy_disasm(ctx.addr, s_start)
        l = 0
        while i is not None and l < lines:
            o.print_inst(i)
            i = self.lazy_disasm(i.address + i.size, s_start)
            l += 1


    def print_calls(self, ctx):
        # Print all calls which are in the section containing ctx.addr

        ARCH = self.load_arch_module()
        ARCH_UTILS = ARCH.utils
        ARCH_OUTPUT = ARCH.output

        s_name, s_start, s_end = self.binary.get_section_meta(ctx.addr)
        self.print_section_meta(s_name, s_start, s_end)
        o = ARCH_OUTPUT.Output(ctx)

        i = self.lazy_disasm(s_start, s_start)
        while i is not None:
            if ARCH_UTILS.is_call(i):
                o.print_inst(i)
            i = self.lazy_disasm(i.address + i.size, s_start)


    def print_symbols(self, print_sections, sym_filter=None):
        if sym_filter is not None:
            sym_filter = sym_filter.lower()

        for addr in self.binary.reverse_symbols:
            sy = self.binary.reverse_symbols[addr]
            if sym_filter is None or sym_filter in sy.lower():
                sec_name, _ = self.binary.is_address(addr)
                if sy:
                    print_no_end(color_addr(addr) + " " +
                                 color_symbol("<" + sy + ">"))
                    if print_sections and sec_name is not None:
                        print_no_end(" (" + color_section(sec_name) + ")")
                    print()


    def load_user_sym_file(self, fd):
        for l in fd:
            arg = l.split()
            addr = int(arg[0], 16)
            self.binary.reverse_symbols[addr] = arg[1]
            self.binary.symbols[arg[1]] = addr


    def lazy_disasm(self, addr, stay_in_section=-1):
        _, start, _ = self.binary.get_section_meta(addr)
        if stay_in_section != -1 and start != stay_in_section:
            return None

        if addr in self.code:
            return self.code[addr]
        
        # Disassemble by block of N bytes
        N = 1024

        d = self.binary.section_stream_read(addr, N)
        gen = self.md.disasm(d, addr)

        first = None
        try:
            first = next(gen)
            self.code[first.address] = first

            # Max N instructions (N is in bytes)
            for n in range(N):
                i = next(gen)
                if i.address in self.code:
                    return first
                self.code[i.address] = i
        except StopIteration:
            pass

        return first


    # Generate a flow graph of the given function (addr)
    def get_graph(self, addr):
        from capstone import CS_OP_IMM
        ARCH_UTILS = self.load_arch_module().utils

        curr = self.lazy_disasm(addr)
        if curr == None:
            return None

        gph = Graph(self, addr)
        rest = []
        start = time.clock()

        # WARNING: this assume that on every architectures the jump
        # address is the last operand (operands[-1])

        while 1:
            if not gph.exists(curr):
                if ARCH_UTILS.is_uncond_jump(curr) and len(curr.operands) > 0:
                    if curr.operands[-1].type == CS_OP_IMM:
                        addr = curr.operands[-1].value.imm
                        nxt = self.lazy_disasm(addr)
                        gph.set_next(curr, nxt)
                        rest.append(nxt.address)
                    else:
                        # Can't interpret jmp ADDR|reg
                        gph.add_node(curr)
                    gph.uncond_jumps_set.add(curr.address)

                elif ARCH_UTILS.is_cond_jump(curr) and len(curr.operands) > 0:
                    if curr.operands[-1].type == CS_OP_IMM:
                        nxt_jump = self.lazy_disasm(curr.operands[-1].value.imm)
                        direct_nxt = self.lazy_disasm(curr.address + curr.size)
                        gph.set_cond_next(curr, nxt_jump, direct_nxt)
                        rest.append(nxt_jump.address)
                        rest.append(direct_nxt.address)
                    else:
                        # Can't interpret jmp ADDR|reg
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
