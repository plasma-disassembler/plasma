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

import lib.elf
from lib.utils import *


class Binary(object):
    def __init__(self, filename):
        self.__binary = None
        self.rodata = None
        self.rodata_data = None
        self.reverse_symbols = {}
        self.symbols = {}

        fd = open(filename, 'rb')
        try:
            self.__binary = lib.elf.ELF(self, fd)
        except:
            die("it seems that the file is not an elf-binary")

        self.__binary.load_static_sym()
        self.__binary.load_dyn_sym()
        self.__binary.load_rodata()


    def is_rodata(self, addr):
        return self.__binary.is_rodata(addr)


    def find_section(self, addr):
        return self.__binary.find_section(addr)


    def get_section(self, addr):
        return self.__binary.get_section(addr)
