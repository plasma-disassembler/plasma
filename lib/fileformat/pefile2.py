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
from ctypes import (c_char, c_short, c_ubyte, c_uint, c_ushort, sizeof,
        Structure, Union)



class SymAddr(Structure):
    _fields_ = [
        ("zeroes", c_uint),
        ("offset", c_uint)
    ]


class SymUnion(Union):
    _fields_ = [
        ("name", c_char * 8),
        ("addr", SymAddr)
    ]


class SymbolEntry(Structure):
    _pack_ = 1
    _fields_ = [
        ("sym", SymUnion),
        ("value", c_uint),
        ("scnum", c_short),
        ("type", c_ushort),
        ("sclass", c_ubyte),
        ("numaux", c_ubyte),
    ]



class PE2(pefile.PE):
    def get_sym_at_offset(self, off):
        end = off + sizeof(SymbolEntry)
        if end > len(self.__data__):
            return None
        return SymbolEntry.from_buffer_copy(self.__data__[off:end])


    def get_string_at_offset(self, off):
        s = ""
        while self.__data__[off] != 0:
            s += chr(self.__data__[off])
            off += 1
        return s
