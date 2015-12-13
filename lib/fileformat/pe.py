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

import bisect

import pefile
from capstone.x86 import (X86_OP_INVALID, X86_OP_IMM, X86_OP_MEM, X86_REG_RIP,
        X86_REG_EIP)
from ctypes import sizeof

from lib.exceptions import ExcPEFail
from lib.fileformat.pefile2 import PE2, SymbolEntry, PE_DT_FCN
from lib.fileformat.binary import SectionAbs, SYM_UNK, SYM_FUNC
from lib.utils import warning

try:
    # This folder is not present in simonzack/pefile-py3k
    import ordlookup
except:
    warning("you should use the most recent port of pefile")
    warning("https://github.com/mlaferrera/python3-pefile")
    pass


class PE:
    def __init__(self, classbinary, filename):
        import capstone as CAPSTONE

        self.classbinary = classbinary
        self.pe = PE2(filename, fast_load=True)
        self.__data_sections = []
        self.__data_sections_content = []
        self.__exec_sections = []

        self.arch_lookup = {
            # See machine_types in pefile.py
            0x014c: CAPSTONE.CS_ARCH_X86, # i386
            0x8664: CAPSTONE.CS_ARCH_X86, # AMD64
            # TODO ARM
        }

        self.arch_mode_lookup = {
            pefile.OPTIONAL_HEADER_MAGIC_PE: CAPSTONE.CS_MODE_32,
            pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS: CAPSTONE.CS_MODE_64,
        }

        self.__sections = {} # start address -> pe section

        base = self.pe.OPTIONAL_HEADER.ImageBase

        for s in self.pe.sections:
            start = base + s.VirtualAddress

            self.__sections[start] = s
            is_data = self.__section_is_data(s)
            is_exec = self.__section_is_exec(s)

            if is_data or is_exec:
                bisect.insort_left(classbinary._sorted_sections, start)

            classbinary._abs_sections[start] = SectionAbs(
                    s.Name.decode().rstrip(' \0'),
                    start,
                    s.Misc_VirtualSize,
                    s.SizeOfRawData,
                    is_exec,
                    is_data,
                    s.get_data())


    def load_section_names(self):
        # Used for the auto-completion
        for s in self.pe.sections:
            name = s.Name.decode().rstrip(' \0')
            ad = self.pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress
            self.classbinary.section_names[name] = ad


    def load_static_sym(self):
        # http://wiki.osdev.org/COFF
        # http://www.delorie.com/djgpp/doc/coff/symtab.html

        sym_table_off = self.pe.FILE_HEADER.PointerToSymbolTable
        n_sym = self.pe.FILE_HEADER.NumberOfSymbols
        string_table_off = sym_table_off + sizeof(SymbolEntry) * n_sym
        base = self.pe.OPTIONAL_HEADER.ImageBase + \
               self.pe.OPTIONAL_HEADER.SectionAlignment

        off = sym_table_off
        i = 0

        while i < n_sym:
            sym = self.pe.get_sym_at_offset(off)

            if sym.sclass == 2:  # static symbol
                name = \
                    sym.sym.name.decode() if sym.sym.addr.zeroes != 0 else \
                    self.pe.get_string_at_offset(string_table_off + \
                                                 sym.sym.addr.offset)

                # print("%d   %s" % (sym.scnum, name))

                ad = sym.value + base

                if name in self.classbinary.symbols:
                    name = self.classbinary.rename_sym(name)

                ty = SYM_FUNC if sym.type & PE_DT_FCN else SYM_UNK
                self.classbinary.reverse_symbols[ad] = [name, ty]
                self.classbinary.symbols[name] = [ad, ty]

                
            if sym.numaux != 0:
                off += sym.numaux * sizeof(SymbolEntry)
                i += sym.numaux

            off += sizeof(SymbolEntry)
            i += 1


    def load_dyn_sym(self):
        try:
            self.pe.parse_data_directories(
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'])
        except Exception as e:
            raise ExcPEFail(e)

        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name is None:
                    continue

                name = imp.name
                if name in self.classbinary.symbols:
                    name = self.classbinary.rename_sym(name)

                # TODO: always unk ?
                self.classbinary.reverse_symbols[imp.address] = [name, SYM_UNK]
                self.classbinary.symbols[name] = [imp.address, SYM_UNK]


    def pe_reverse_stripped_symbols(self, dis, addr_to_analyze):
        def inv(n):
            return n == X86_OP_INVALID

        # Now try to find the real call. For each SYMBOL address 
        # we have this :
        #
        # call ADDRESS
        # ...
        # ADDRESS:  	jmp    DWORD PTR SYMBOL
        #
        # we need to assign SYMBOL to ADDRESS, because in the code
        # we have "call ADDRESS" and not "call SYMBOL"
        #

        # Search in the code every call which point to a "jmp SYMBOL"

        ARCH_UTILS = dis.load_arch_module().utils
        count = 0

        for ad in addr_to_analyze:
            i = dis.lazy_disasm(ad)
            if i is None:
                break

            if ARCH_UTILS.is_call(i) and i.operands[0].type == X86_OP_IMM:
                goto = i.operands[0].value.imm

                if goto in self.classbinary.reverse_symbols:
                    continue

                nxt = dis.lazy_disasm(goto)

                if nxt is None:
                    continue

                if not ARCH_UTILS.is_uncond_jump(nxt) or \
                        nxt.operands[0].type != X86_OP_MEM:
                    continue
               
                mm = nxt.operands[0].mem
                next_ip = nxt.address + nxt.size

            elif ARCH_UTILS.is_uncond_jump(i) and \
                    i.address in self.classbinary.reverse_symbols:
                goto = i.address
                mm = i.operands[0].mem
                next_ip = i.address + i.size

            else:
                continue

            ptr = mm.disp
            if mm.base == X86_REG_RIP or mm.base == X86_REG_EIP:
                ptr += next_ip

            if ptr in self.classbinary.reverse_symbols \
                    and inv(mm.segment) and inv(mm.index):
                name = "_" + self.classbinary.reverse_symbols[ptr][0]
                ty = self.classbinary.reverse_symbols[ptr][1]

                if name in self.classbinary.symbols:
                    name = self.classbinary.rename_sym(name)

                self.classbinary.reverse_symbols[goto] = [name, ty]
                self.classbinary.symbols[name] = [goto, ty]
                count += 1

        return count


    def __section_is_data(self, s):
             # INITIALIZED_DATA | MEM_READ   | MEM_WRITE
        mask = 0x00000040       | 0x40000000 | 0x80000000
        return s.Characteristics & mask and not self.__section_is_exec(s)


    def __section_is_exec(self, s):
        if s is None:
            return 0
        return s.Characteristics & 0x20000000


    def section_stream_read(self, addr, size):
        s = self.classbinary.get_section(addr)
        if s is None:
            return b""
        s = self.__sections[s.start]
        base = self.pe.OPTIONAL_HEADER.ImageBase
        off = addr - base
        end = base + s.VirtualAddress + s.SizeOfRawData
        return s.get_data(off, min(size, end - addr))


    def get_arch(self):
        return self.arch_lookup.get(self.pe.FILE_HEADER.Machine, None), \
               self.arch_mode_lookup.get(self.pe.OPTIONAL_HEADER.Magic, None)


    def get_arch_string(self):
        return pefile.MACHINE_TYPE[self.pe.FILE_HEADER.Machine]


    def get_entry_point(self):
        return self.pe.OPTIONAL_HEADER.ImageBase + \
               self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
