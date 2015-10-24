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
import struct

from lib.graph import Graph
from lib.utils import debug__, BYTES_PRINTABLE_SET, get_char
from lib.fileformat.binary import Binary, T_BIN_PE
from lib.output import print_no_end
from lib.colors import (pick_color, color_addr, color_symbol,
        color_section, color_string, color_comment)
from lib.exceptions import ExcSymNotFound, ExcArch, ExcNotAddr, ExcNotExec


class Disassembler():
    def __init__(self, filename, raw_type, raw_base,
                 raw_big_endian, load_symbols=True):
        import capstone as CAPSTONE

        self.code = {}
        self.binary = Binary(filename, raw_type, raw_base, raw_big_endian)

        arch, mode = self.binary.get_arch()

        if arch is None or mode is None:
            raise ExcArch(self.binary.get_arch_string())

        if load_symbols:
            self.binary.load_symbols()

        self.binary.load_data_sections()

        self.capstone = CAPSTONE
        self.md = CAPSTONE.Cs(arch, mode)
        self.md.detail = True
        self.arch = arch
        self.mode = mode


    def check_addr(self, ctx, addr):
        addr_exists, is_exec = self.binary.check_addr(addr)
        if not ctx.print_data and not is_exec:
            raise ExcNotExec(addr)
        if not addr_exists:
            raise ExcNotAddr(addr)


    def load_arch_module(self):
        if self.arch == self.capstone.CS_ARCH_X86:
            import lib.arch.x86 as ARCH
        elif self.arch == self.capstone.CS_ARCH_ARM:
            import lib.arch.arm as ARCH
        elif self.arch == self.capstone.CS_ARCH_MIPS:
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
        print_no_end(color_section(name.ljust(20)))
        print_no_end(" [ ")
        print_no_end(hex(start))
        print_no_end(" - ")
        print_no_end(hex(end))
        print_no_end(" - %d" % (end - start + 1))
        print(" ]")


    def dump_asm(self, ctx, lines):
        from capstone import CS_OP_IMM
        ARCH = self.load_arch_module()
        ARCH_UTILS = ARCH.utils
        ARCH_OUTPUT = ARCH.output

        s_name, s_start, s_end = self.binary.get_section_meta(ctx.entry_addr)
        self.print_section_meta(s_name, s_start, s_end)

        # WARNING: this assume that on every architectures the jump
        # address is the last operand (operands[-1])

        # set jumps color
        ad = ctx.entry_addr
        l = 0
        while l < lines and ad < s_end:
            i = self.lazy_disasm(ad, s_start)
            if i is None:
                ad += 1
            else:
                if ARCH_UTILS.is_jump(i) and i.operands[-1].type == CS_OP_IMM:
                    pick_color(i.operands[-1].value.imm)
                ad += i.size
            l += 1

        # Here we have loaded all instructions we want to print
        if self.binary.type == T_BIN_PE:
            self.binary.pe_reverse_stripped_symbols(self)

        o = ARCH_OUTPUT.Output(ctx)

        # dump
        ad = ctx.entry_addr
        l = 0
        while l < lines and ad < s_end:
            i = self.lazy_disasm(ad, s_start)
            if i is None:
                ad += 1
                o.print_bad(ad)
            else:
                o.print_inst(i)
                ad += i.size
            l += 1


    def dump_data_ascii(self, ctx, lines):
        N = 128 # read by block of 128 bytes
        addr = ctx.entry_addr

        s_name, s_start, s_end = self.binary.get_section_meta(ctx.entry_addr)
        self.print_section_meta(s_name, s_start, s_end)

        l = 0
        ascii_str = []
        addr_str = -1

        while l < lines:
            buf = self.binary.section_stream_read(addr, N)
            if not buf:
                break

            i = 0
            while i < len(buf):

                if addr > s_end:
                    return

                j = i
                while j < len(buf):
                    c = buf[j]
                    if c not in BYTES_PRINTABLE_SET:
                        break
                    if addr_str == -1:
                        addr_str = addr
                    ascii_str.append(c)
                    j += 1

                if c != 0 and j == len(buf):
                    addr += j - i
                    break

                if c == 0 and len(ascii_str) >= 2:
                    print_no_end(color_addr(addr_str))
                    print_no_end(color_string(
                            "\"" + "".join(map(get_char, ascii_str)) + "\""))
                    print(", 0")
                    addr += j - i
                    i = j
                else:
                    print_no_end(color_addr(addr))
                    print("0x%.2x " % buf[i])
                    addr += 1
                    i += 1

                addr_str = -1
                ascii_str = []
                l += 1
                if l >= lines:
                    return


    def dump_data(self, ctx, lines, size_word):
        _, mode = self.binary.get_arch()

        if mode & self.capstone.CS_MODE_BIG_ENDIAN:
            endian = ">"
        else:
            endian = "<"

        if size_word == 1:
            unpack_str = endian + "B"
        elif size_word == 2:
            unpack_str = endian + "H"
        elif size_word == 4:
            unpack_str = endian + "L"
        elif size_word == 8:
            unpack_str = endian + "Q"

        N = size_word * 64
        addr = ctx.entry_addr

        s_name, s_start, s_end = self.binary.get_section_meta(ctx.entry_addr)
        self.print_section_meta(s_name, s_start, s_end)

        l = 0

        while l < lines:
            buf = self.binary.section_stream_read(addr, N)
            if not buf:
                break

            i = 0
            while i < len(buf):
                b = buf[i:i + size_word]

                if addr > s_end:
                    return

                if len(b) != size_word:
                    for c in buf:
                        print_no_end(color_addr(addr))
                        print("0x%.2x" % c)
                    return

                if addr in self.binary.reverse_symbols:
                    print(color_symbol(self.binary.reverse_symbols[addr]))

                print_no_end(color_addr(addr))

                w = struct.unpack(unpack_str, b)[0]
                print_no_end("0x%.2x" % w)

                sec_name, is_data = self.binary.is_address(w)
                if sec_name is not None:
                    print_no_end(" (")
                    print_no_end(color_section(sec_name))
                    print_no_end(")")
                    if size_word >= 4 and w in self.binary.reverse_symbols:
                        print_no_end(" ")
                        print_no_end(color_symbol(self.binary.reverse_symbols[w]))

                print()
                addr += size_word
                i += size_word
                l += 1
                if l >= lines:
                    return


    def print_calls(self, ctx):
        ARCH = self.load_arch_module()
        ARCH_UTILS = ARCH.utils
        ARCH_OUTPUT = ARCH.output

        s_name, s_start, s_end = self.binary.get_section_meta(ctx.entry_addr)
        self.print_section_meta(s_name, s_start, s_end)
        o = ARCH_OUTPUT.Output(ctx)

        ad = s_start
        while ad < s_end:
            i = self.lazy_disasm(ad, s_start)
            if i is None:
                ad += 1
            else:
                ad += i.size
                if ARCH_UTILS.is_call(i):
                    o.print_inst(i)


    def print_symbols(self, print_sections, sym_filter=None):
        if sym_filter is not None:
            sym_filter = sym_filter.lower()

        for addr in self.binary.reverse_symbols:
            sy = self.binary.reverse_symbols[addr]
            if sym_filter is None or sym_filter in sy.lower():
                sec_name, _ = self.binary.is_address(addr)
                if sy:
                    print_no_end(color_addr(addr) + " " + sy)
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
        meta  = self.binary.get_section_meta(addr)
        if meta is None:
            return None

        _, start, _ = meta

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


    def __prefetch_inst(self, inst):
        return self.lazy_disasm(inst.address + inst.size)


    # Generate a flow graph of the given function (addr)
    def get_graph(self, entry_addr):
        from capstone import CS_OP_IMM, CS_ARCH_MIPS

        ARCH_UTILS = self.load_arch_module().utils

        curr = self.lazy_disasm(entry_addr)
        if curr is None:
            return None

        gph = Graph(self, entry_addr)
        rest = []
        start = time.clock()
        prefetch = None

        # WARNING: this assume that on every architectures the jump
        # address is the last operand (operands[-1])

        while 1:
            if not gph.exists(curr):
                if self.arch == CS_ARCH_MIPS:
                    prefetch = self.__prefetch_inst(curr)

                if ARCH_UTILS.is_uncond_jump(curr) and len(curr.operands) > 0:
                    if curr.operands[-1].type == CS_OP_IMM:
                        addr = curr.operands[-1].value.imm
                        nxt = self.lazy_disasm(addr)
                        if nxt is None:
                            gph.add_node(curr, prefetch)
                        else:
                            gph.set_next(curr, nxt, prefetch)
                            rest.append(nxt.address)
                    else:
                        # Can't interpret jmp ADDR|reg
                        gph.add_node(curr, prefetch)
                    gph.uncond_jumps_set.add(curr.address)

                elif ARCH_UTILS.is_cond_jump(curr) and len(curr.operands) > 0:
                    if curr.operands[-1].type == CS_OP_IMM:
                        nxt_jump = self.lazy_disasm(curr.operands[-1].value.imm)

                        if self.arch == CS_ARCH_MIPS:
                            direct_nxt = \
                                self.lazy_disasm(prefetch.address + prefetch.size)
                        else:
                            direct_nxt = \
                                self.lazy_disasm(curr.address + curr.size)

                        if nxt_jump is not None:
                            rest.append(nxt_jump.address)
                            if direct_nxt is not None:
                                rest.append(direct_nxt.address)
                                gph.set_cond_next(curr, nxt_jump, direct_nxt, prefetch)
                            else:
                                gph.set_next(curr, nxt_jump, prefetch)
                        else:
                            if direct_nxt is not None:
                                rest.append(direct_nxt.address)
                                gph.set_next(curr, direct_nxt, prefetch)
                            else:
                                gph.add_node(curr, prefetch)
                    else:
                        # Can't interpret jmp ADDR|reg
                        gph.add_node(curr, prefetch)
                    gph.cond_jumps_set.add(curr.address)

                elif ARCH_UTILS.is_ret(curr):
                    gph.add_node(curr, prefetch)

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
