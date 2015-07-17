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


import pefile
from capstone.x86 import X86_OP_INVALID, X86_OP_IMM, X86_OP_MEM
from ctypes import sizeof

from lib.utils import get_char
from lib.exceptions import ExcPEFail
from lib.fileformat.pefile2 import PE2, SymbolEntry


class PE:
    def __init__(self, classbinary, filename):
        import capstone as CAPSTONE

        self.classbinary = classbinary
        self.pe = PE2(filename, fast_load=True)
        self.__data_sections = []
        self.__data_sections_content = []
        self.__exec_sections = []
        self.__imported_syms = {}

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

                self.classbinary.reverse_symbols[sym.value + base] = name
                self.classbinary.symbols[name] = sym.value + base
                
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
                self.__imported_syms[imp.address] = imp.name
                self.classbinary.reverse_symbols[imp.address] = imp.name
                self.classbinary.symbols[imp.name] = imp.address


    def pe_reverse_stripped_symbols(self, dis):
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
        k = list(dis.code.keys())
        count = 0

        for ad in k:
            i = dis.code[ad]

            if ARCH_UTILS.is_call(i) and i.operands[0].type == X86_OP_IMM:
                goto = i.operands[0].value.imm
                nxt = dis.lazy_disasm(goto)

                if not ARCH_UTILS.is_uncond_jump(nxt) or \
                        nxt.operands[0].type != X86_OP_MEM:
                    continue
               
                mm = nxt.operands[0].mem

            elif ARCH_UTILS.is_uncond_jump(i) and \
                    i.address in self.classbinary.reverse_symbols:
                goto = i.address
                mm = i.operands[0].mem

            else:
                continue

            if inv(mm.base) and mm.disp in self.__imported_syms \
                    and inv(mm.segment) and inv(mm.index):
                name = "jmp_" + self.__imported_syms[mm.disp]
                self.classbinary.reverse_symbols[goto] = name
                self.classbinary.symbols[name] = goto
                count += 1

        return count


    def load_data_sections(self):
        for s in self.pe.sections:
            if self.__section_is_data(s):
                self.__data_sections.append(s)
                self.__data_sections_content.append(s.get_data())


    def __section_is_data(self, s):
             # INITIALIZED_DATA | MEM_READ   | MEM_WRITE
        mask = 0x00000040       | 0x40000000 | 0x80000000
        return s.Characteristics & mask and not self.__section_is_exec(s)


    def is_data(self, addr):
        base = self.pe.OPTIONAL_HEADER.ImageBase
        for s in self.__data_sections:
            start = base + s.VirtualAddress
            end = start + s.SizeOfRawData
            if start <= addr < end:
                return True
        return False


    def __get_data_section(self, addr):
        base = self.pe.OPTIONAL_HEADER.ImageBase
        for i, s in enumerate(self.__data_sections):
            start = base + s.VirtualAddress
            end = start + s.SizeOfRawData
            if start <= addr < end:
                return i
        return -1


    def __get_cached_exec_section(self, addr):
        base = self.pe.OPTIONAL_HEADER.ImageBase
        for s in self.__exec_sections:
            start = base + s.VirtualAddress
            end = start + s.SizeOfRawData
            if start <= addr < end:
                return s
        return None


    def __get_section(self, addr):
        s = self.__get_cached_exec_section(addr)
        if s is not None:
            return s
        base = self.pe.OPTIONAL_HEADER.ImageBase
        s = self.pe.get_section_by_rva(addr - base)
        if s is None:
            return None
        self.__exec_sections.append(s)
        return s


    def check_addr(self, addr):
        s = self.__get_section(addr)
        return (s is not None, self.__section_is_exec(s))


    def get_section_meta(self, addr):
        s = self.__get_section(addr)
        if s is None:
            return 0
        n = s.Name.decode().rstrip(' \0')
        a = s.VirtualAddress + self.pe.OPTIONAL_HEADER.ImageBase
        return n, a, a + s.SizeOfRawData - 1


    def section_stream_read(self, addr, size):
        s = self.__get_section(addr)
        base = self.pe.OPTIONAL_HEADER.ImageBase
        off = addr - base
        end = base + s.VirtualAddress + s.SizeOfRawData
        return s.get_data(off, min(size, end - addr))


    def is_address(self, imm):
        base = self.pe.OPTIONAL_HEADER.ImageBase
        if imm > base:
            s = self.pe.get_section_by_rva(imm - base)
            if s is not None:
                return s.Name.decode().rstrip(' \0'), self.__section_is_data(s)
        return None, False


    def __section_is_exec(self, s):
        return s.Characteristics & 0x20000000


    def get_string(self, addr, max_data_size, may_be_utf16le=True):
        i = self.__get_data_section(addr)
        if i == -1:
            return ""

        s = self.__data_sections[i]
        data = self.__data_sections_content[i]
        base = self.pe.OPTIONAL_HEADER.ImageBase
        off = addr - s.VirtualAddress - base
        txt = ['"']

        i = 0
        skipped = 0
        while i - skipped < max_data_size and \
              off < s.SizeOfRawData:
            c = data[off]
            if c == 0:
                if may_be_utf16le and i % 2 == 1:
                    skipped += 1
                else:
                    break
            else:
                if may_be_utf16le and i % 2 == 1:
                    return self.get_string(addr, max_data_size, False)
                txt.append(get_char(c))
            off += 1
            i += 1

        if c != 0 and off != s.SizeOfRawData:
            txt.append("...")

        return ''.join(txt) + '"'


    def get_arch(self):
        return self.arch_lookup.get(self.pe.FILE_HEADER.Machine, None), \
               self.arch_mode_lookup.get(self.pe.OPTIONAL_HEADER.Magic, None)


    def get_arch_string(self):
        return pefile.MACHINE_TYPE[self.pe.FILE_HEADER.Machine]


    def get_entry_point(self):
        return self.pe.OPTIONAL_HEADER.ImageBase + \
               self.pe.OPTIONAL_HEADER.AddressOfEntryPoint


    def iter_sections(self):
        base = self.pe.OPTIONAL_HEADER.ImageBase
        for i, s in enumerate(self.__data_sections):
            start = base + s.VirtualAddress
            end = start + s.SizeOfRawData
            if s.Name != b"":
                yield (s.Name.decode().rstrip(' \0'), start, end)
