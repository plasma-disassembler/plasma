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

import bisect

import pefile
from capstone.x86 import (X86_OP_INVALID, X86_OP_MEM, X86_REG_RIP, X86_REG_EIP)
from ctypes import sizeof

from plasma.lib.exceptions import ExcPEFail
from plasma.lib.fileformat.pefile2 import PE2, SymbolEntry, PE_DT_FCN, PE_DT_PTR
from plasma.lib.fileformat.binary import Binary
from plasma.lib.utils import warning

if not pefile.__version__.startswith("201"):
    warning("you should use the most recent port of pefile")
    warning("https://github.com/erocarrera/pefile")


class PE(Binary):
    def __init__(self, db, filename):
        Binary.__init__(self)

        self.db = db

        self.pe = PE2(filename, fast_load=True)
        self.__data_sections = []
        self.__data_sections_content = []
        self.__exec_sections = []

        self.set_arch_name()

        base = self.pe.OPTIONAL_HEADER.ImageBase

        for s in self.pe.sections:
            self.add_section(
                base + s.VirtualAddress,
                s.Name.decode().rstrip(' \0'),
                s.Misc_VirtualSize,
                s.SizeOfRawData,
                self.__section_is_exec(s),
                self.__section_is_data(s),
                s.get_data())


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
                ad = sym.value + base

                if self.is_address(ad):
                    if name in self.symbols:
                        name = self.rename_sym(name)

                    self.reverse_symbols[ad] = name
                    self.symbols[name] = ad

                    if sym.type & PE_DT_FCN and not sym.type & PE_DT_PTR:
                        self.db.functions[ad] = None

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

                # erocarrera/pefile returns a bytes but mlaferrera/prefile
                # returns a string.
                if isinstance(name, bytes):
                    name = name.decode()

                if name in self.symbols:
                    continue
                    name = self.rename_sym(name)

                self.imports[imp.address] = True
                self.reverse_symbols[imp.address] = name
                self.symbols[name] = imp.address

                # TODO: always a function ?
                self.db.functions[imp.address] = None


    def reverse_stripped(self, dis, first_inst):
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
        # first_inst is the instruction at ADDRESS
        #

        def inv(n):
            return n == X86_OP_INVALID

        ARCH_UTILS = dis.load_arch_module().utils

        if not ARCH_UTILS.is_uncond_jump(first_inst) or \
                first_inst.operands[0].type != X86_OP_MEM:
            return -1

        mm = first_inst.operands[0].mem
        next_ip = first_inst.address + first_inst.size

        ptr = mm.disp
        if mm.base == X86_REG_RIP or mm.base == X86_REG_EIP:
            ptr += next_ip

        if ptr not in self.imports or not inv(mm.segment) or \
                not inv(mm.index):
            return -1

        name = "_" + self.reverse_symbols[ptr]
        ty = self.db.mem.get_type(ptr)

        self.reverse_symbols[first_inst.address] = name
        self.symbols[name] = first_inst.address

        if ty != -1:
            self.db.mem.add(first_inst.address, 1, ty)

        return ptr


    def reverse_stripped_list(self, dis, addr_to_analyze):
        count = 0
        for ad in addr_to_analyze:
            i = dis.lazy_disasm(ad)
            if i is None:
                continue
            if self.reverse_stripped(dis, i):
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


    def set_arch_name(self):
        # TODO ARM

        # TODO Should we check these flags ?
        # pefile.OPTIONAL_HEADER_MAGIC_PE
        # pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS

        # return pefile.MACHINE_TYPE[self.pe.FILE_HEADER.Machine]

        if self.pe.FILE_HEADER.Machine == 0x014c:
            self.arch = "x86"

        if self.pe.FILE_HEADER.Machine == 0x8664:
            self.arch = "x64"


    def is_big_endian(self):
        return False # only x86 supported


    def get_entry_point(self):
        return self.pe.OPTIONAL_HEADER.ImageBase + \
               self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
