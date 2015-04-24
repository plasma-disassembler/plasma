#
# Reverse : reverse engineering for x86 binaries
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

from lib.utils import debug__
from lib.exceptions import ExcFileFormat


ARCH_x64 = 0
ARCH_x86 = 1
ARCH_INVALID = -1

T_BIN_ELF = 0
T_BIN_PE  = 1
T_BIN_RAW = 2
T_BIN_UNK = 3


class Binary(object):
    def __init__(self, filename, raw_bits=0):
        self.__binary = None
        self.reverse_symbols = {}
        self.symbols = {}
        self.type = None

        if raw_bits != 0:
            import lib.fileformat.raw as LIB_RAW
            self.__binary = LIB_RAW.Raw(filename, raw_bits)
            self.type = T_BIN_RAW
            return

        start = time.clock()
        self.load_magic(filename)

        try:
            if self.type == T_BIN_ELF:
                import lib.fileformat.elf as LIB_ELF
                self.__binary = LIB_ELF.ELF(self, filename)
            elif self.type == T_BIN_PE:
                import lib.fileformat.pe as LIB_PE
                self.__binary = LIB_PE.PE(self, filename)
            else:
                raise ExcFileFormat()
        except Exception:
            raise ExcFileFormat()

        elapsed = time.clock()
        elapsed = elapsed - start
        debug__("Binary loaded in %fs" % elapsed)

        start = time.clock()

        self.__binary.load_static_sym()
        self.__binary.load_dyn_sym()
        self.__binary.load_data_sections()

        elapsed = time.clock()
        elapsed = elapsed - start
        debug__("Found %d symbols in %fs" % (len(self.symbols), elapsed))


    def load_magic(self, filename):
        f = open(filename, "rb")
        magic = f.read(8)
        if magic.startswith(b"\x7fELF"):
            self.type = T_BIN_ELF
        elif magic.startswith(b"MZ"):
            self.type = T_BIN_PE
        f.close()


    def is_data(self, addr):
        return self.__binary.is_data(addr)


    def get_section(self, addr):
        return self.__binary.get_section(addr)


    def get_string(self, addr, max_string_data):
        return self.__binary.get_string(addr, max_string_data)


    def get_arch(self):
        return self.__binary.get_arch()


    # Returns the name of the section if the value is an address
    # and a bool if it's a data section.
    # (name, is_data)
    def is_address(self, imm):
        return self.__binary.is_address(imm)


    def get_entry_point(self):
        return self.__binary.get_entry_point()


    def iter_sections(self):
        return self.__binary.iter_sections()


    # Only for PE !
    def pe_reverse_stripped_symbols(self, dis):
        start = time.clock()

        n = self.__binary.pe_reverse_stripped_symbols(dis)

        elapsed = time.clock()
        elapsed = elapsed - start
        debug__("Found %d imported symbols (PE) in %fs" % (n, elapsed))
