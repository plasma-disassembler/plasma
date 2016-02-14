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
from ctypes import c_char, POINTER, cast, c_voidp

from reverse.lib.graph import Graph
from reverse.lib.utils import (unsigned, debug__, BYTES_PRINTABLE_SET,
                               get_char, print_no_end)
from reverse.lib.fileformat.binary import Binary, T_BIN_PE
from reverse.lib.colors import (color_addr, color_symbol, color_comment,
                                color_section, color_string)
from reverse.lib.exceptions import ExcArch
from reverse.lib.memory import (Memory, MEM_UNK, MEM_FUNC, MEM_CODE, MEM_BYTE,
                                MEM_WORD, MEM_DWORD, MEM_QWORD, MEM_ASCII,
                                MEM_OFFSET)
from reverse.lib.analyzer import (FUNC_FLAG_NORETURN, FUNC_END, FUNC_FLAGS,
                                  FUNC_VARS, VAR_NAME)


NB_LINES_TO_DISASM = 256 # without comments, ...
CAPSTONE_CACHE_SIZE = 60000

RESERVED_PREFIX = ["loc_", "sub_", "unk_", "byte_", "word_",
                   "dword_", "qword_", "asc_", "off_", "ret_", "loop_",
                   "var_"]


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
        self.db = database

        if database.loaded:
            self.mem = database.mem
        else:
            self.mem = Memory()
            database.mem = self.mem

        self.binary = Binary(self.mem, filename, raw_type, raw_base, raw_big_endian)

        self.binary.load_section_names()
        arch, mode = self.binary.get_arch()

        if arch is None or mode is None:
            raise ExcArch(self.binary.get_arch_string())

        self.jmptables = database.jmptables
        self.user_inline_comments = database.user_inline_comments
        self.internal_inline_comments = database.internal_inline_comments
        self.user_previous_comments = database.user_previous_comments
        self.internal_previous_comments = database.internal_previous_comments
        self.functions = database.functions
        self.func_id = database.func_id
        self.end_functions = database.end_functions
        self.xrefs = database.xrefs

        # TODO: is it a global constant or $gp can change during the execution ?
        self.mips_gp = database.mips_gp

        if not database.loaded:
            self.binary.load_symbols()
            database.symbols = self.binary.symbols
            database.reverse_symbols = self.binary.reverse_symbols
            database.demangled = self.binary.demangled
            database.reverse_demangled = self.binary.reverse_demangled
            database.imports = self.binary.imports

        self.capstone = CAPSTONE
        self.md = CAPSTONE.Cs(arch, mode)
        self.md.detail = True
        self.arch = arch
        self.mode = mode

        for s in self.binary.iter_sections():
            s.big_endian = self.mode & self.capstone.CS_MODE_BIG_ENDIAN


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


    def add_xref(self, from_ad, to_ad):
        if isinstance(to_ad, list):
            for x in to_ad:
                if x in self.xrefs:
                    if from_ad not in self.xrefs[x]:
                        self.xrefs[x].append(from_ad)
                else:
                    self.xrefs[x] = [from_ad]
        else:
            if to_ad in self.xrefs:
                if from_ad not in self.xrefs[to_ad]:
                    self.xrefs[to_ad].append(from_ad)
            else:
                self.xrefs[to_ad] = [from_ad]


    def rm_xrefs(self, from_ad, to_ad):
        if isinstance(to_ad, list):
            for x in to_ad:
                if from_ad in self.xrefs[x]:
                    self.xrefs[x].remove(from_ad)
                if not self.xrefs[x]:
                    del self.xrefs[x]
        else:
            if from_ad in self.xrefs[to_ad]:
                self.xrefs[to_ad].remove(from_ad)
            if not self.xrefs[to_ad]:
                del self.xrefs[to_ad]


    def rm_xrefs_range(self, start, end):
        while start < end:
            if start in self.xrefs:
                del self.xrefs[start]
            start += 1


    def add_symbol(self, ad, name):
        if name in self.db.symbols:
            last = self.db.symbols[name]
            del self.db.reverse_symbols[last]

        if ad in self.db.reverse_symbols:
            last = self.db.reverse_symbols[ad]
            del self.db.symbols[last]

        self.db.symbols[name] = ad
        self.db.reverse_symbols[ad] = name

        if not self.mem.exists(ad):
            self.mem.add(ad, 1, MEM_UNK)

        return name


    def rm_symbol(self, ad):
        if ad in self.db.reverse_symbols:
            name = self.db.reverse_symbols[ad]
            del self.db.reverse_symbols[ad]

        if name in self.db.symbols:
            del self.db.symbols[name]


    def has_reserved_prefix(self, name):
        for n in RESERVED_PREFIX:
            if name.startswith(n):
                return True
        return False


    # `func_ad` is the function address where the variable `name`
    # is supposed to be.
    def var_get_offset(self, func_ad, name):
        if func_ad in self.functions:
            for off, val in self.functions[func_ad][FUNC_VARS].items():
                if val[VAR_NAME] == name:
                    return off
        return None


    def var_rename(self, func_ad, off, name):
        if func_ad in self.functions:
            self.functions[func_ad][FUNC_VARS][off][VAR_NAME] = name


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
            import reverse.lib.arch.x86 as ARCH
        elif self.arch == self.capstone.CS_ARCH_ARM:
            import reverse.lib.arch.arm as ARCH
        elif self.arch == self.capstone.CS_ARCH_MIPS:
            import reverse.lib.arch.mips as ARCH
        else:
            raise NotImplementedError
        return ARCH


    def dump_xrefs(self, ctx, ad):
        ARCH = self.load_arch_module()
        ARCH_OUTPUT = ARCH.output

        o = ARCH_OUTPUT.Output(ctx)
        o._new_line()
        o.print_labels = False

        for x in ctx.gctx.dis.xrefs[ad]:
            s = self.binary.get_section(x)

            ty = self.mem.get_type(x)

            # A PE import should not be displayed as a subroutine
            if not(self.binary.type == T_BIN_PE and ad in self.binary.imports) \
                   and (ty == MEM_FUNC or ty == MEM_CODE):

                func_id = self.mem.get_func_id(x)
                if func_id != -1:
                    fad = self.func_id[func_id]
                    o._label(fad)
                    diff = x - fad
                    if diff >= 0:
                        o._add(" + %d " % diff)
                    else:
                        o._add(" - %d " % (-diff))

                    o._pad_width(20)

                i = self.lazy_disasm(x, s.start)
                o._asm_inst(i)

            elif ty == MEM_OFFSET:
                o._address(x)
                o.set_line(x)
                sz = self.mem.get_size(x)
                off = s.read_int(x, sz)
                if off is None:
                    continue
                o._data_prefix(sz)
                o._add(" ")
                o._imm(off, sz, True, print_data=False, force_dont_print_data=True)
                o._new_line()

            else:
                o._address(x)
                o.set_line(x)
                sz = self.mem.get_size_from_type(ty)
                o._word(s.read_int(x, sz), sz)
                o._new_line()

        # remove the last empty line
        o.lines.pop(-1)
        o.token_lines.pop(-1)

        o.join_lines()

        return o


    def is_label(self, ad):
        return ad in self.db.reverse_symbols or ad in self.xrefs


    def get_symbol(self, ad, gctx=None):
        if ad in self.db.reverse_symbols:
            if gctx is not None and gctx.show_mangling:
                s = self.db.reverse_demangled.get(ad, None)
                if s is not None:
                    return s
            return self.db.reverse_symbols[ad]

        ty = self.mem.get_type(ad)
        if ty == MEM_FUNC:
            return "sub_%x" % ad
        if ty == MEM_CODE:
            return "loc_%x" % ad
        if ty == MEM_DWORD:
            return "dword_%x" % ad
        if ty == MEM_BYTE:
            return "byte_%x" % ad
        if ty == MEM_QWORD:
            return "qword_%x" % ad
        if ty == MEM_UNK:
            return "unk_%x" % ad
        if ty == MEM_WORD:
            return "word_%x" % ad
        if ty == MEM_ASCII:
            return "asc_%x" % ad
        if ty == MEM_OFFSET:
            return "off_%x" % ad


    def dump_asm(self, ctx, lines=NB_LINES_TO_DISASM, until=-1):
        from capstone import CS_OP_IMM

        ARCH = self.load_arch_module()
        ARCH_OUTPUT = ARCH.output
        ARCH_UTILS = ARCH.utils

        ad = ctx.entry
        s = self.binary.get_section(ad)

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
        o.mode_dump = True
        l = 0

        while 1:
            if ad == s.start:
                if not o.is_last_2_line_empty():
                    o._new_line()
                o._dash()
                o._section(s.name)
                o._add("  0x%x -> 0x%x" % (s.start, s.end))
                o._new_line()
                o._new_line()

            while ((l < lines and until == -1) or (ad < until and until != -1)) \
                    and ad <= s.end:

                ty = self.mem.get_type(ad)
                is_func = ad in self.functions

                # A PE import should not be displayed as a subroutine
                if not(self.binary.type == T_BIN_PE and ad in self.binary.imports) \
                        and (ty == MEM_FUNC and is_func or ty == MEM_CODE):

                    if is_func:
                        if not o.is_last_2_line_empty():
                            o._new_line()
                        o._dash()
                        o._user_comment("; SUBROUTINE")
                        o._new_line()
                        o._dash()

                    i = self.lazy_disasm(ad, s.start)

                    if not is_func and ad in self.xrefs and \
                            not o.is_last_2_line_empty():
                        o._new_line()

                    o._asm_inst(i)

                    if ad in self.end_functions:
                        for fad in self.end_functions[ad]:
                            sy = self.get_symbol(fad, ctx.gctx)
                            o._user_comment("; end function %s" % sy)
                            o._new_line()
                        o._new_line()

                    elif ARCH_UTILS.is_uncond_jump(i) or ARCH_UTILS.is_ret(i):
                        o._new_line()

                    elif ARCH_UTILS.is_call(i):
                        op = i.operands[0]
                        if op.type == CS_OP_IMM:
                            imm = unsigned(op.value.imm)
                            if imm in self.functions and self.is_noreturn(imm):
                                o._new_line()

                    ad += i.size

                elif ty == MEM_OFFSET:
                    o._label_and_address(ad)
                    o.set_line(ad)
                    sz = self.mem.get_size(ad)
                    off = s.read_int(ad, sz)
                    if off is None:
                        continue
                    if ctx.gctx.print_bytes:
                        o._bytes(s.read(ad, sz))
                    o._data_prefix(sz)
                    o._add(" ")
                    o._imm(off, sz, True, print_data=False, force_dont_print_data=True)
                    o._new_line()
                    ad += sz

                elif ty == MEM_ASCII:
                    o._label_and_address(ad)
                    o.set_line(ad)
                    sz = self.mem.get_size(ad)
                    buf = self.binary.get_string(ad, sz)
                    if buf is not None:
                        if ctx.gctx.print_bytes:
                            o._bytes(s.read(ad, sz))
                        o._string(buf)
                    o._add(", 0")
                    o._new_line()
                    ad += sz

                else:
                    o._label_and_address(ad)
                    o.set_line(ad)
                    sz = self.mem.get_size_from_type(ty)
                    if ctx.gctx.print_bytes:
                        o._bytes(s.read(ad, sz))
                    o._word(s.read_int(ad, sz), sz)
                    o._new_line()
                    ad += sz

                l += 1

            s = self.binary.get_section(ad)
            if s is None:
                # Get the next section, it's not mandatory that sections
                # are consecutives !
                s = self.binary.get_next_section(ad)
                if s is None:
                    break
                o._new_line()
                ad = s.start
                if until != -1 and ad >= until:
                    break

            if (l >= lines and until == -1) or (ad >= until and until != -1):
                break

            o.curr_section = s

        if until == ad:
            if self.mem.is_code(ad) and ad in self.xrefs or ad == s.start:
                if not o.is_last_2_line_empty():
                    o._new_line()

        # remove the last empty line
        o.lines.pop(-1)
        o.token_lines.pop(-1)

        o.join_lines()

        return o


    def find_addr_before(self, ad):
        l = 0
        s = self.binary.get_section(ad)

        # TODO: because we don't know addresses before, it will be
        # necessary to add in memory.py an offset to tell that there is
        # a known address at n previous bytes. It will allows to not set
        # an offset on each byte (the database will increase too much).

        while l < NB_LINES_TO_DISASM:
            if self.mem.is_code(ad):
                size = self.mem.mm[ad][0]
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
        ad = ctx.entry

        s = self.binary.get_section(ad)
        print(hex(ad))
        s.print_header()

        l = 0
        ascii_str = []
        ad_str = -1

        while l < lines:
            buf = s.read(ad, N)
            if not buf:
                break

            i = 0
            while i < len(buf):

                if ad > s.end:
                    return

                j = i
                while j < len(buf):
                    c = buf[j]
                    if c not in BYTES_PRINTABLE_SET:
                        break
                    if ad_str == -1:
                        ad_str = ad
                    ascii_str.append(c)
                    j += 1

                if c != 0 and j == len(buf):
                    ad += j - i
                    break

                if c == 0 and len(ascii_str) >= 2:
                    if self.is_label(ad_str):
                        print(color_symbol(self.get_symbol(ad_str)))
                    print_no_end(color_addr(ad_str))
                    print_no_end(color_string(
                            "\"" + "".join(map(get_char, ascii_str)) + "\""))
                    print(", 0")
                    ad += j - i
                    i = j
                else:
                    if self.is_label(ad):
                        print(color_symbol(self.get_symbol(ad)))
                    print_no_end(color_addr(ad))
                    print("0x%.2x " % buf[i])
                    ad += 1
                    i += 1

                ad_str = -1
                ascii_str = []
                l += 1
                if l >= lines:
                    return


    def dump_data(self, ctx, lines, size_word):
        ad = ctx.entry
        s = self.binary.get_section(ad)
        s.print_header()

        for w in self.read_array(ad, lines, size_word, s):
            if self.is_label(ad):
                print(color_symbol(self.get_symbol(ad)))
            print_no_end(color_addr(ad))
            print_no_end("0x%.2x" % w)

            section = self.binary.get_section(w)

            if section is not None:
                print_no_end(" (")
                print_no_end(color_section(section.name))
                print_no_end(")")
                if size_word >= 4 and self.is_label(w):
                    print_no_end(" ")
                    print_no_end(color_symbol(self.get_symbol(w)))

            ad += size_word
            print()


    def print_functions(self):
        total = 0

        lst = list(self.functions)
        lst.sort()

        # TODO: race condition with the analyzer ?
        for ad in lst:
            print_no_end(color_addr(ad))
            sy = self.get_symbol(ad)

            if ad in self.db.reverse_demangled:
                print_no_end(" %s (%s) " % (self.db.reverse_demangled[ad],
                                           color_comment(sy)))
            else:
                print_no_end(" " + sy)
            print()

            total += 1

        print("Total:", total)

    #
    # sym_filter : search a symbol, non case-sensitive
    #    if it starts with '-', it prints non-matching symbols
    #
    def print_symbols(self, print_sections, sym_filter=None):
        if sym_filter is not None:
            sym_filter = sym_filter.lower()
            if sym_filter[0] == "-":
                invert_match = True
                sym_filter = sym_filter[1:]
            else:
                invert_match = False

        total = 0

        # TODO: race condition with the analyzer ?
        for sy in list(self.db.symbols):
            ad = self.db.symbols[sy]

            if ad in self.db.reverse_demangled:
                dem = self.db.reverse_demangled[ad]
            else:
                dem = None

            print_sym = True

            if sym_filter is None or \
                    (invert_match and sym_filter not in sy.lower()) or \
                    (not invert_match and sym_filter in sy.lower()) or \
                    (dem is not None and
                     ((invert_match and sym_filter not in dem.lower()) or \
                      (not invert_match and sym_filter in dem.lower()))):

                if sy:
                    print_no_end(color_addr(ad))

                    if dem is not None:
                        print_no_end(" %s (%s) " % (dem, color_comment(sy)))
                    else:
                        print_no_end(" " + sy)

                    section = self.binary.get_section(ad)
                    if print_sections and section is not None:
                        print_no_end(" (" + color_section(section.name) + ")")
                    print()
                    total += 1

        print("Total:", total)


    def lazy_disasm(self, ad, stay_in_section=-1, s=None):
        s = self.binary.get_section(ad)
        if s is None:
            return None

        # if stay_in_section != -1 and s.start != stay_in_section:
            # return None, s

        if ad in self.capstone_inst:
            return self.capstone_inst[ad]

        # TODO: remove when it's too big ?
        if len(self.capstone_inst) > CAPSTONE_CACHE_SIZE:
            self.capstone_inst.clear()

        # Disassemble by block of N bytes
        N = 128
        d = s.read(ad, N)
        gen = self.md.disasm(d, ad)

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


    def __add_prefetch(self, addr_set, inst):
        if self.arch == self.CS_ARCH_MIPS:
            prefetch = self.lazy_disasm(inst.address + inst.size)
            addr_set.add(prefetch.address)
            return prefetch
        return None


    def is_noreturn(self, ad):
        return self.functions[ad][FUNC_FLAGS] & FUNC_FLAG_NORETURN


    # Generate a flow graph of the given function (addr)
    def get_graph(self, entry):
        from capstone import CS_OP_IMM, CS_ARCH_MIPS

        self.CS_ARCH_MIPS = CS_ARCH_MIPS
        ARCH_UTILS = self.load_arch_module().utils

        gph = Graph(self, entry)
        stack = [entry]
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
                prefetch = self.__add_prefetch(addresses, inst)
                gph.new_node(inst, prefetch, None)

            elif ARCH_UTILS.is_uncond_jump(inst):
                prefetch = self.__add_prefetch(addresses, inst)

                gph.uncond_jumps_set.add(ad)
                op = inst.operands[-1]

                if op.type == CS_OP_IMM:
                    nxt = unsigned(op.value.imm)

                    if nxt in self.functions:
                        gph.new_node(inst, prefetch, None)
                    else:
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
                prefetch = self.__add_prefetch(addresses, inst)

                gph.cond_jumps_set.add(ad)
                op = inst.operands[-1]

                if op.type == CS_OP_IMM:
                    if prefetch is None:
                        direct_nxt = inst.address + inst.size
                    else:
                        direct_nxt = prefetch.address + prefetch.size

                    nxt_jmp = unsigned(op.value.imm)
                    stack.append(direct_nxt)

                    if nxt_jmp in self.functions:
                        gph.new_node(inst, prefetch, [direct_nxt])
                    else:
                        stack.append(nxt_jmp)
                        gph.new_node(inst, prefetch, [direct_nxt, nxt_jmp])
                else:
                    # Can't interpret jmp ADDR|reg
                    gph.new_node(inst, prefetch, None)

            else:
                if ad != entry and ARCH_UTILS.is_call(inst):
                    op = inst.operands[0]
                    if op.type == CS_OP_IMM:
                        imm = unsigned(op.value.imm)
                        if imm in self.functions and self.is_noreturn(imm):
                            prefetch = self.__add_prefetch(addresses, inst)
                            gph.new_node(inst, prefetch, None)
                            continue

                nxt = inst.address + inst.size
                stack.append(nxt)
                gph.new_node(inst, None, [nxt])

        if len(gph.nodes) == 0:
            return None, 0

        if self.binary.type == T_BIN_PE:
            nb_new_syms = self.binary.pe_reverse_stripped_list(self, addresses)
        else:
            nb_new_syms = 0

        elapsed = time()
        elapsed = elapsed - start
        debug__("Graph built in %fs (%d instructions)" % (elapsed, len(gph.nodes)))

        return gph, nb_new_syms


    def add_jmptable(self, inst_addr, table_addr, entry_size, nb_entries):
        name = self.add_symbol(table_addr, "jmptable_%x" % table_addr)

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
