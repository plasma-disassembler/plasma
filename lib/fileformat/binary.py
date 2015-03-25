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

import lib.fileformat.elf
import lib.fileformat.pe
from lib.utils import *


MAX_STRING_RODATA = 30

ARCH_x64 = 0
ARCH_x86 = 1
ARCH_INVALID = -1


T_BIN_ELF = 0
T_BIN_PE = 1
T_BIN_UNK = 2


class Binary(object):
    def __init__(self, filename):
        self.__binary = None
        self.reverse_symbols = {}
        self.symbols = {}

        try:
            self.__binary = lib.fileformat.elf.ELF(self, filename)
        except Exception:
            try:
                self.__binary = lib.fileformat.pe.PE(self, filename)
            except Exception:
                die("the file is not PE or ELF binary")

        self.__binary.load_static_sym()
        self.__binary.load_dyn_sym()
        self.__binary.load_rodata()


    def is_rodata(self, addr):
        return self.__binary.is_rodata(addr)


    def get_section(self, addr):
        return self.__binary.get_section(addr)


    def get_string(self, addr):
        return self.__binary.get_string(addr)


    def get_arch(self):
        return self.__binary.get_arch()


    def get_type(self):
        if isinstance(self.__binary, lib.fileformat.elf.ELF):
            return T_BIN_ELF
        if isinstance(self.__binary, lib.fileformat.pe.PE):
            return T_BIN_PE
        return T_BIN_UNK


    def get_entry_point(self):
        return self.__binary.get_entry_point()


    # Only for PE !
    def load_import_symbols(self, code):
        self.__binary.load_import_symbols(code)
