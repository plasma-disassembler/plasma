#!/usr/bin/env python3
#
# PLASMA : Generate an indented asm code (pseudo-C) with colored syntax.
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

from plasma.lib.graph import Graph
from plasma.lib.utils import (unsigned, debug__, BYTES_PRINTABLE_SET,
                              get_char, print_no_end)
from plasma.lib.fileformat.binary import Binary, T_BIN_PE, T_BIN_ELF, T_BIN_RAW
from plasma.lib.colors import (color_addr, color_symbol, color_comment,
                               color_section, color_string)
from plasma.lib.exceptions import ExcArch, ExcFileFormat
from plasma.lib.memory import Memory
from plasma.lib.consts import *


class Disassembler():
    def __init__(self, filename, raw_type, raw_base, raw_big_endian, database):
        import capstone as CAPSTONE

        arch_lookup = {
            "x86": CAPSTONE.CS_ARCH_X86,
            "x64": CAPSTONE.CS_ARCH_X86,
            "ARM": CAPSTONE.CS_ARCH_ARM,
            "MIPS32": CAPSTONE.CS_ARCH_MIPS,
            "MIPS64": CAPSTONE.CS_ARCH_MIPS,
        }

        mode_lookup = {
            "x86": CAPSTONE.CS_MODE_32,
            "x64": CAPSTONE.CS_MODE_64,
            "ARM": CAPSTONE.CS_ARCH_ARM,
            "MIPS32": CAPSTONE.CS_MODE_MIPS32,
            "MIPS64": CAPSTONE.CS_MODE_MIPS64,
        }

        word_size_lookup = {
            "x86": 4,
            "x64": 8,
            "ARM": 4,
            "MIPS32": 4,
            "MIPS64": 8,
        }

        self.capstone_inst = {} # capstone instruction cache
        self.db = database

        if database.loaded:
            self.mem = database.mem
        else:
            self.mem = Memory()
            database.mem = self.mem

        self.instanciate_binary(filename, raw_type, raw_base, raw_big_endian)

        if self.binary.arch not in ("x86", "x64", "MIPS32", "MIPS64", "ARM"):
            raise ExcArch(arch)

        self.wordsize = word_size_lookup.get(self.binary.arch, None)
        self.binary.wordsize = self.wordsize

        self.is_mips = self.binary.arch in ("MIPS32", "MIPS64")
        self.is_x86 = self.binary.arch in ("x86", "x64")
        self.is_arm = self.binary.arch in ("ARM")
        self.is_big_endian = self.binary.is_big_endian()

        self.binary.load_section_names()

        self.jmptables = database.jmptables
        self.user_inline_comments = database.user_inline_comments
        self.internal_inline_comments = database.internal_inline_comments
        self.user_previous_comments = database.user_previous_comments
        self.internal_previous_comments = database.internal_previous_comments
        self.functions = database.functions
        self.func_id = database.func_id
        self.end_functions = database.end_functions
        self.xrefs = database.xrefs

        self.mips_gp = database.mips_gp

        if not database.loaded:
            self.load_symbols()
            database.symbols = self.binary.symbols
            database.reverse_symbols = self.binary.reverse_symbols
            database.demangled = self.binary.demangled
            database.reverse_demangled = self.binary.reverse_demangled
            database.imports = self.binary.imports

        cs_arch = arch_lookup.get(self.binary.arch, None)
        cs_mode = mode_lookup.get(self.binary.arch, None)

        if self.is_big_endian:
            cs_mode |= CAPSTONE.CS_MODE_BIG_ENDIAN
        else:
            cs_mode |= CAPSTONE.CS_MODE_LITTLE_ENDIAN

        self.capstone = CAPSTONE
        self.md = CAPSTONE.Cs(cs_arch, cs_mode)
        self.md.detail = True

        for s in self.binary.iter_sections():
            s.big_endian = cs_mode & CAPSTONE.CS_MODE_BIG_ENDIAN


    def instanciate_binary(self, filename, raw_type, raw_base, raw_big_endian):
        if raw_type != None:
            import plasma.lib.fileformat.raw as LIB_RAW
            self.binary = LIB_RAW.Raw(filename, raw_type, raw_base, raw_big_endian)
            self.type = T_BIN_RAW
            return

        start = time()
        ty = self.get_magic(filename)

        if ty == T_BIN_ELF:
            import plasma.lib.fileformat.elf as LIB_ELF
            self.binary = LIB_ELF.ELF(self.db, filename)
        elif ty == T_BIN_PE:
            import plasma.lib.fileformat.pe as LIB_PE
            self.binary = LIB_PE.PE(self.db, filename)
        else:
            raise ExcFileFormat()

        self.binary.type = ty

        elapsed = time()
        elapsed = elapsed - start
        debug__("Binary loaded in %fs" % elapsed)


    def load_symbols(self):
        start = time()
        self.binary.load_static_sym()
        self.binary.load_dyn_sym()
        self.binary.demangle_symbols()
        elapsed = time()
        elapsed = elapsed - start
        debug__("Found %d symbols in %fs" % (len(self.binary.symbols), elapsed))


    def get_magic(self, filename):
        f = open(filename, "rb")
        magic = f.read(8)
        f.close()
        if magic.startswith(b"\x7fELF"):
            return T_BIN_ELF
        elif magic.startswith(b"MZ"):
            return T_BIN_PE
        return None


    # `func_ad` is the function address where the variable `name`
    # is supposed to be.
    def var_get_offset(self, func_ad, name):
        if func_ad not in self.functions:
            return None
        func_obj = self.functions[func_ad]
        if func_obj is None:
            return None
        for off, val in func_obj[FUNC_OFF_VARS].items():
            if val[VAR_NAME] == name:
                return off
        return None


    def var_rename(self, func_ad, off, name):
        if func_ad not in self.functions:
            return
        func_obj = self.functions[func_ad]
        if func_obj is None:
            return
        func_obj[FUNC_OFF_VARS][off][VAR_NAME] = name


    def load_arch_module(self):
        if self.binary.arch in ("x86", "x64"):
            import plasma.lib.arch.x86 as ARCH
        elif self.binary.arch == "ARM":
            import plasma.lib.arch.arm as ARCH
        elif self.binary.arch in ("MIPS32", "MIPS64"):
            import plasma.lib.arch.mips as ARCH
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


    def dump_asm(self, ctx, lines=NB_LINES_TO_DISASM, until=-1):
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
        api = ctx.gctx.api

        # For mips: after a jump we add a newline, but for mips we should
        # add this newline after the prefetch instruction.
        prefetch_after_branch = False

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

                # A PE import should not be displayed as a subroutine
                if not(self.binary.type == T_BIN_PE and ad in self.binary.imports) \
                        and self.mem.is_code(ad):

                    is_func = ad in self.functions

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

                    is_end = ad in self.end_functions

                    # mips
                    if prefetch_after_branch:
                        prefetch_after_branch = False
                        if not is_end:
                            o._new_line()

                    if is_end:
                        for fad in self.end_functions[ad]:
                            sy = api.get_symbol(fad)
                            o._user_comment("; end function %s" % sy)
                            o._new_line()
                        o._new_line()

                    elif ARCH_UTILS.is_uncond_jump(i) or ARCH_UTILS.is_ret(i):
                        if self.is_mips:
                            prefetch_after_branch = True
                        else:
                            o._new_line()

                    elif ARCH_UTILS.is_call(i):
                        op = i.operands[0]
                        if op.type == self.capstone.CS_OP_IMM:
                            imm = unsigned(op.value.imm)
                            if imm in self.functions and self.is_noreturn(imm):
                                if self.is_mips:
                                    prefetch_after_branch = True
                                else:
                                    o._new_line()

                    ad += i.size

                elif ty == MEM_OFFSET:
                    prefetch_after_branch = False
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
                    prefetch_after_branch = False
                    o._label_and_address(ad)
                    o.set_line(ad)
                    sz = self.mem.get_size(ad)
                    buf = self.binary.get_string(ad, sz)
                    if buf is not None:
                        if ctx.gctx.print_bytes:
                            o._bytes(s.read(ad, sz))
                        o._string('"' + buf + '"')
                    o._add(", 0")
                    o._new_line()
                    ad += sz

                else:
                    prefetch_after_branch = False
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


    def hexdump(self, ctx, lines):
        MAX_NB_BYTES = 16

        def print_line(ad, line):
            if not line:
                return

            print_no_end(color_addr(ad))

            for by in line:
                print_no_end("%.2x " % by)

            if len(line) != MAX_NB_BYTES:
                print_no_end("   " * (MAX_NB_BYTES - len(line)))

            print_no_end("| ")

            for by in line:
                if by in BYTES_PRINTABLE_SET and by != 13 and by != 9 and by != 10:
                    print_no_end("%c" % by)
                else:
                    print_no_end(".")

            print()

        ad = ctx.entry
        s = self.binary.get_section(ad)
        off = ad - s.start
        l = 0
        buf = []
        first_ad = ad

        while off < s.real_size and l < lines:
            buf.append(s.data[off])
            if len(buf) == MAX_NB_BYTES:
                l += 1
                print_line(first_ad, buf)
                buf.clear()
                first_ad = s.start + off

            off += 1

        print_line(first_ad, buf)


    def print_functions(self, api):
        total = 0

        lst = list(self.functions)
        lst.sort()

        # TODO: race condition with the analyzer ?
        for ad in lst:
            print_no_end(color_addr(ad))
            sy = api.get_symbol(ad)

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
        if self.is_mips:
            prefetch = self.lazy_disasm(inst.address + inst.size)
            addr_set.add(prefetch.address)
            return prefetch
        return None


    def is_noreturn(self, ad):
        func_obj = self.functions[ad]
        if func_obj is None:
            return False
        return self.functions[ad][FUNC_FLAGS] & FUNC_FLAG_NORETURN


    # Generate a flow graph of the given function (addr)
    def get_graph(self, entry):
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

                if op.type == self.capstone.CS_OP_IMM:
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

                if op.type == self.capstone.CS_OP_IMM:
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
                    if op.type == self.capstone.CS_OP_IMM:
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
            nb_new_syms = self.binary.reverse_stripped_list(self, addresses)
        else:
            nb_new_syms = 0

        elapsed = time()
        elapsed = elapsed - start
        debug__("Graph built in %fs (%d instructions)" % (elapsed, len(gph.nodes)))

        return gph, nb_new_syms
