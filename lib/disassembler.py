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

import struct
from time import time

from lib.graph import Graph
from lib.utils import debug__, BYTES_PRINTABLE_SET, get_char, print_no_end
from lib.fileformat.binary import Binary, T_BIN_PE, SYM_UNK, SYM_FUNC
from lib.colors import (pick_color, color_addr, color_symbol,
        color_section, color_string)
from lib.exceptions import ExcSymNotFound, ExcArch
from lib.memory import Memory, MEM_UNK


NB_LINES_TO_DISASM = 200 # without comments, ...
CAPSTONE_CACHE_SIZE = 60000


class Jmptable():
    def __init__(self, inst_addr, table_addr, table, name):
        self.inst_addr = inst_addr
        self.table_addr = table_addr
        self.table = table
        self.name = name


class Disassembler():
    def __init__(self, filename, raw_type, raw_base, raw_big_endian, database):
        import capstone as CAPSTONE

        self.capstone_inst = {} # capstone instruction cache

        self.binary = Binary(filename, raw_type, raw_base, raw_big_endian)

        arch, mode = self.binary.get_arch()

        if arch is None or mode is None:
            raise ExcArch(self.binary.get_arch_string())

        if database.loaded:
            self.binary.symbols = database.symbols
            self.binary.reverse_symbols = database.reverse_symbols
            self.mem = database.mem
        else:
            self.binary.load_symbols()
            database.symbols = self.binary.symbols
            database.reverse_symbols = self.binary.reverse_symbols
            self.mem = Memory()
            database.mem = self.mem

        self.jmptables = database.jmptables
        self.user_inline_comments = database.user_inline_comments
        self.internal_inline_comments = database.internal_inline_comments
        self.user_previous_comments = database.user_previous_comments
        self.internal_previous_comments = database.internal_previous_comments
        self.functions = database.functions
        self.end_functions = database.end_functions
        # TODO: is it a global constant or $gp can change during the execution ?
        self.mips_gp = database.mips_gp

        self.binary.load_section_names()

        self.capstone = CAPSTONE
        self.md = CAPSTONE.Cs(arch, mode)
        self.md.detail = True
        self.arch = arch
        self.mode = mode

        for s in self.binary.iter_sections():
            s.big_endian = self.mode & self.capstone.CS_MODE_BIG_ENDIAN

            if not database.loaded:
                self.mem.add(s.start, s.end, MEM_UNK)


    def get_unpack_str(self, size_word):
        if self.mode & self.capstone.CS_MODE_BIG_ENDIAN:
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
        else:
            return None
        return unpack_str


    def add_symbol(self, addr, name):
        if name in self.binary.symbols:
            last = self.binary.symbols[name]
            del self.binary.reverse_symbols[last]

        self.binary.symbols[name] = [addr, SYM_UNK]
        self.binary.reverse_symbols[addr] = [name, SYM_UNK]

        return name


    # TODO: create a function in SectionAbs
    def read_array(self, ad, array_max_size, size_word, s=None):
        unpack_str = self.get_unpack_str(size_word)
        N = size_word * array_max_size

        if s is None:
            s = self.binary.get_section(ad)

        array = []
        l = 0

        while l < array_max_size:
            buf = s.read(ad, N)
            if not buf:
                break

            i = 0
            while i < len(buf):
                b = buf[i:i + size_word]

                if ad > s.end or len(b) != size_word:
                    return array

                w = struct.unpack(unpack_str, b)[0]
                array.append(w)

                ad += size_word
                i += size_word
                l += 1
                if l >= array_max_size:
                    return array
        return array


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
                try:
                    a = int(opt_addr, 16)
                except:
                    raise ExcSymNotFound(search[0])
            else:
                a = self.binary.symbols.get(s, -1)
                if a == -1:
                    a = self.binary.section_names.get(s, -1)
                else:
                    a = a[0] # it contains [ad, type]

            if a != -1:
                return a

        raise ExcSymNotFound(search[0])


    def dump_asm(self, ctx, lines=NB_LINES_TO_DISASM, until=-1):
        from capstone import CS_OP_IMM
        ARCH = self.load_arch_module()
        ARCH_UTILS = ARCH.utils
        ARCH_OUTPUT = ARCH.output

        ad = ctx.entry_addr
        s = self.binary.get_section(ctx.entry_addr)

        if s is None:
            # until is != -1 only from the visual mode
            # It allows to not go before the first section.
            if until != -1: 
                return None
            # Get the next section, it's not mandatory that sections
            # are consecutives !
            s = self.binary.get_next_section(ad)
            if s is None:
                return None
            ad = s.start

        o = ARCH_OUTPUT.Output(ctx)
        o._new_line()
        o.section_prefix = True
        o.curr_section = s
        l = 0

        while 1:
            if ad == s.start:
                o._new_line()
                o._dash()
                o._section(s.name)
                o._add("  0x%x -> 0x%x" % (s.start, s.end))
                o._new_line()
                o._new_line()

            while ((l < lines and until == -1) or (ad < until and until != -1)) \
                    and ad <= s.end:
                if self.mem.is_code(ad): # TODO optimize
                    if ad in self.functions:
                        if not o.is_last_2_line_empty():
                            o._new_line()
                        o._dash()
                        o._user_comment("; SUBROUTINE")
                        o._new_line()
                        o._dash()

                    i = self.lazy_disasm(ad, s.start)
                    o._asm_inst(i)

                    if ad in self.end_functions:
                        for fad in self.end_functions[ad]:
                            sy = self.binary.reverse_symbols[fad][0]
                            o._user_comment("; end function %s" % sy)
                            o._new_line()
                        o._new_line()

                    ad += i.size

                else:
                    if o.is_symbol(ad):
                        o._symbol(ad)
                        o._new_line()
                    o.set_line(ad)
                    o._address(ad)
                    o._db(s.read_byte(ad))
                    o._new_line()
                    ad += 1

                l += 1

            if (l >= lines and until == -1) or (ad >= until and until != -1):
                break

            s = self.binary.get_section(ad)
            if s is None:
                # Get the next section, it's not mandatory that sections
                # are consecutives !
                s = self.binary.get_next_section(ad)
                if s is None:
                    break
                ad = s.start
                if ad >= until:
                    break
            o.curr_section = s

        if until in self.functions:
            o._new_line()

        # remove the last empty line
        o.lines.pop(-1)
        o.token_lines.pop(-1)

        o.join_lines()

        # TODO: move it in the analyzer
        if self.binary.type == T_BIN_PE:
            # TODO: if ret != 0 : database is modified
            self.binary.pe_reverse_stripped_symbols(self, o.addr_line)

        return o


    def find_addr_before(self, ad):
        l = 0
        s = self.binary.get_section(ad)

        while l < NB_LINES_TO_DISASM:
            if self.mem.is_code(ad):
                size = self.mem.code[ad][0]
                l += 1
                l -= size
            else:
                l += 1

            if ad == s.start:
                s = self.binary.get_prev_section(ad)
                if s is None:
                    return ad
                ad = s.end
            ad -= 1

        return ad


    def dump_data_ascii(self, ctx, lines):
        N = 128 # read by block of 128 bytes
        addr = ctx.entry_addr

        s = self.binary.get_section(ctx.entry_addr)
        s.print_header()

        l = 0
        ascii_str = []
        addr_str = -1

        while l < lines:
            buf = s.read(addr, N)
            if not buf:
                break

            i = 0
            while i < len(buf):

                if addr > s.end:
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
        s = self.binary.get_section(ctx.entry_addr)
        s.print_header()

        ad = ctx.entry_addr

        for w in self.read_array(ctx.entry_addr, lines, size_word, s):
            if ad in self.binary.reverse_symbols:
                print(color_symbol(self.binary.reverse_symbols[ad][0]))
            print_no_end(color_addr(ad))
            print_no_end("0x%.2x" % w)

            section = self.binary.get_section(w)

            if section is not None:
                print_no_end(" (")
                print_no_end(color_section(section.name))
                print_no_end(")")
                if size_word >= 4 and w in self.binary.reverse_symbols:
                    print_no_end(" ")
                    print_no_end(color_symbol(self.binary.reverse_symbols[w][0]))

            ad += size_word
            print()


    def print_calls(self, ctx):
        ARCH = self.load_arch_module()
        ARCH_UTILS = ARCH.utils
        ARCH_OUTPUT = ARCH.output

        s = self.binary.get_section(ctx.entry_addr)
        s.print_header()

        o = ARCH_OUTPUT.Output(ctx)
        o._new_line()

        ad = s.start
        while ad < s.end:
            i = self.lazy_disasm(ad, s.start)
            if i is None:
                ad += 1
            else:
                ad += i.size
                if ARCH_UTILS.is_call(i):
                    o._asm_inst(i)

        o.print()


    #
    # sym_filter : search a symbol, non case-sensitive
    #    if it starts with '-', it prints non-matching symbols
    #
    def print_symbols(self, print_sections, sym_filter=None, only_func=False):
        if sym_filter is not None:
            sym_filter = sym_filter.lower()
            if sym_filter[0] == "-":
                invert_match = True
                sym_filter = sym_filter[1:]
            else:
                invert_match = False

        total = 0

        # TODO: race condition with the analyzer
        for sy in list(self.binary.symbols):
            addr, ty = self.binary.symbols[sy]
            if only_func and ty != SYM_FUNC:
                continue
            if sym_filter is None or \
                    (invert_match and sym_filter not in sy.lower()) or \
                    (not invert_match and sym_filter in sy.lower()):

                if sy:
                    section = self.binary.get_section(addr)
                    print_no_end(color_addr(addr) + " " + sy)
                    if print_sections and section is not None:
                        print_no_end(" (" + color_section(section.name) + ")")
                    print()
                    total += 1

        print("Total:", total)


    def lazy_disasm(self, addr, stay_in_section=-1, s=None):
        s = self.binary.get_section(addr)
        if s is None:
            return None

        # if stay_in_section != -1 and s.start != stay_in_section:
            # return None, s

        if addr in self.capstone_inst:
            return self.capstone_inst[addr]

        # TODO: remove when it's too big ?
        if len(self.capstone_inst) > CAPSTONE_CACHE_SIZE:
            self.capstone_inst.clear()

        # Disassemble by block of N bytes
        N = 128
        d = s.read(addr, N)
        gen = self.md.disasm(d, addr)

        try:
            first = next(gen)
        except StopIteration:
            return None

        self.capstone_inst[first.address] = first
        for i in gen:
            if i.address in self.capstone_inst:
                break
            self.capstone_inst[i.address] = i

        return first


    def __prefetch_inst(self, inst):
        return self.lazy_disasm(inst.address + inst.size)


    # Generate a flow graph of the given function (addr)
    def get_graph(self, entry_addr):
        from capstone import CS_OP_IMM, CS_ARCH_MIPS

        ARCH_UTILS = self.load_arch_module().utils

        gph = Graph(self, entry_addr)
        stack = [entry_addr]
        start = time()
        prefetch = None
        addresses = set()

        # WARNING: this assume that on every architectures the jump
        # address is the last operand (operands[-1])

        # Here each instruction is a node. Blocks will be created in the
        # function __simplify.

        while stack:
            ad = stack.pop()
            inst = self.lazy_disasm(ad)

            if inst is None:
                # Remove all previous instructions which have a link
                # to this instruction.
                if ad in gph.link_in:
                    for i in gph.link_in[ad]:
                        gph.link_out[i].remove(ad)
                    for i in gph.link_in[ad]:
                        if not gph.link_out[i]:
                            del gph.link_out[i]
                    del gph.link_in[ad]
                continue

            if gph.exists(inst):
                continue

            addresses.add(ad)

            if ARCH_UTILS.is_ret(inst):
                if self.arch == CS_ARCH_MIPS:
                    prefetch = self.__prefetch_inst(inst)
                    addresses.add(prefetch.address)
                gph.new_node(inst, prefetch, None)

            elif ARCH_UTILS.is_uncond_jump(inst):
                if self.arch == CS_ARCH_MIPS:
                    prefetch = self.__prefetch_inst(inst)
                    addresses.add(prefetch.address)
                gph.uncond_jumps_set.add(ad)
                op = inst.operands[-1]
                if op.type == CS_OP_IMM:
                    nxt = op.value.imm
                    stack.append(nxt)
                    gph.new_node(inst, prefetch, [nxt])
                else:
                    if inst.address in self.jmptables:
                        table = self.jmptables[inst.address].table
                        stack += table
                        gph.new_node(inst, prefetch, table)
                    else:
                        # Can't interpret jmp ADDR|reg
                        gph.new_node(inst, prefetch, None)

            elif ARCH_UTILS.is_cond_jump(inst):
                if self.arch == CS_ARCH_MIPS:
                    prefetch = self.__prefetch_inst(inst)
                    addresses.add(prefetch.address)
                gph.cond_jumps_set.add(ad)
                op = inst.operands[-1]
                if op.type == CS_OP_IMM:
                    if self.arch == CS_ARCH_MIPS:
                        direct_nxt = prefetch.address + prefetch.size
                    else:
                        direct_nxt = inst.address + inst.size

                    nxt_jmp = op.value.imm

                    stack.append(direct_nxt)
                    stack.append(nxt_jmp)
                    gph.new_node(inst, prefetch, [direct_nxt, nxt_jmp])
                else:
                    # Can't interpret jmp ADDR|reg
                    gph.new_node(inst, prefetch, None)

            else:
                nxt = inst.address + inst.size
                stack.append(nxt)
                gph.new_node(inst, None, [nxt])

        if len(gph.nodes) == 0:
            return None, 0

        if self.binary.type == T_BIN_PE:
            nb_new_syms = self.binary.pe_reverse_stripped_symbols(self, addresses)
        else:
            nb_new_syms = 0

        elapsed = time()
        elapsed = elapsed - start
        debug__("Graph built in %fs (%d instructions)" % (elapsed, len(gph.nodes)))

        return gph, nb_new_syms


    def add_jmptable(self, inst_addr, table_addr, entry_size, nb_entries):
        name = self.add_symbol(table_addr, "jmptable_0x%x" % table_addr)

        table = self.read_array(table_addr, nb_entries, entry_size)
        self.jmptables[inst_addr] = Jmptable(inst_addr, table_addr, table, name)

        self.internal_inline_comments[inst_addr] = "switch statement %s" % name

        all_cases = {}
        for ad in table:
            all_cases[ad] = []

        case = 0
        for ad in table:
            all_cases[ad].append(case)
            case += 1

        for ad in all_cases:
            self.internal_previous_comments[ad] = \
                ["case %s  %s" % (
                    ", ".join(map(str, all_cases[ad])),
                    name
                )]
