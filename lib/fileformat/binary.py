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
from time import time

from lib.utils import debug__, print_no_end, get_char
from lib.colors import color_section
from lib.exceptions import ExcFileFormat

T_BIN_ELF = 0
T_BIN_PE  = 1
T_BIN_RAW = 2
T_BIN_UNK = 3


class SectionAbs():
    # virt_size: size of the mapped section in memory
    def __init__(self, name, start, virt_size, real_size, is_exec, is_data, data):
        self.name = name
        self.start = start
        self.virt_size = virt_size
        self.real_size = real_size
        self.end = start + virt_size - 1
        self.is_exec = is_exec
        self.is_data = is_data
        self.data = data

    def print_header(self):
        print_no_end(color_section(self.name.ljust(20)))
        print_no_end(" [ ")
        print_no_end(hex(self.start))
        print_no_end(" - ")
        print_no_end(hex(self.end))
        print_no_end(" - %d - %d" % (self.virt_size, self.real_size))
        print(" ]")


class Binary(object):
    def __init__(self, filename, raw_type=None, raw_base=None, raw_big_endian=None):
        self.__binary = None
        self.reverse_symbols = {}
        self.symbols = {}
        self.section_names = {}
        self.type = None

        self._abs_sections = {} # start section -> SectionAbs
        self._sorted_sections = [] # bisect list, contains section start address

        if raw_type != None:
            import lib.fileformat.raw as LIB_RAW
            self.__binary = LIB_RAW.Raw(self, filename, raw_type,
                                        raw_base, raw_big_endian)
            self.type = T_BIN_RAW
            return

        start = time()
        self.load_magic(filename)

        if self.type == T_BIN_ELF:
            import lib.fileformat.elf as LIB_ELF
            self.__binary = LIB_ELF.ELF(self, filename)
        elif self.type == T_BIN_PE:
            import lib.fileformat.pe as LIB_PE
            self.__binary = LIB_PE.PE(self, filename)
        else:
            raise ExcFileFormat()

        elapsed = time()
        elapsed = elapsed - start
        debug__("Binary loaded in %fs" % elapsed)


    def load_magic(self, filename):
        f = open(filename, "rb")
        magic = f.read(8)
        if magic.startswith(b"\x7fELF"):
            self.type = T_BIN_ELF
        elif magic.startswith(b"MZ"):
            self.type = T_BIN_PE
        f.close()


    def get_section(self, ad):
        i = bisect.bisect_right(self._sorted_sections, ad)
        if not i:
            return None
        start = self._sorted_sections[i-1]
        s = self._abs_sections[start]
        if ad <= s.end:
            return s
        return None


    def read(self, ad, size):
        s = self.get_section(ad)
        if s is None:
            return b""
        off = ad - s.start
        return s.data[off:off + size]


    def read_byte(self, ad):
        s = self.get_section(ad)
        if s is None:
            return b""
        off = ad - s.start
        return s.data[off]


    # not optimized
    def get_section_by_name(self, name):
        for s in self._abs_sections.values():
            if s.name == name:
                return s
        return None


    def iter_sections(self):
        starts = list(self._abs_sections.keys())
        starts.sort()
        for ad in starts:
            yield self._abs_sections[ad]


    def get_string(self, addr, max_data_size):
        s = self.get_section(addr)
        if s is None:
            return ""

        data = s.data
        off = addr - s.start
        txt = ['"']

        c = 0
        i = 0
        while i < max_data_size and \
              off < len(data):
            c = data[off]
            if c == 0:
                break
            txt.append(get_char(c))
            off += 1
            i += 1

        if c != 0 and off != len(data):
            txt.append("...")

        return ''.join(txt) + '"'


    # Wrappers to the real class


    def load_symbols(self):
        start = time()
        self.__binary.load_static_sym()
        self.__binary.load_dyn_sym()
        elapsed = time()
        elapsed = elapsed - start
        debug__("Found %d symbols in %fs" % (len(self.symbols), elapsed))


    def load_section_names(self):
        self.__binary.load_section_names()


    def section_stream_read(self, addr, size):
        return self.__binary.section_stream_read(addr, size)


    def get_arch(self):
        return self.__binary.get_arch()


    def get_arch_string(self):
        return self.__binary.get_arch_string()


    def get_entry_point(self):
        return self.__binary.get_entry_point()


    # Only for PE !
    def pe_reverse_stripped_symbols(self, dis):
        start = time()
        n = self.__binary.pe_reverse_stripped_symbols(dis)
        elapsed = time()
        elapsed = elapsed - start
        debug__("Found %d imported symbols (PE) in %fs" % (n, elapsed))
