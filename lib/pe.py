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


import sys
import pefile
import lib.utils
import lib.binary


class PE:
    def __init__(self, classbinary, filename):
        self.classbinary = classbinary
        self.pe = pefile.PE(filename, fast_load=True)
        self.rodata = None
        self.rodata_data = None


    def load_static_sym(self):
        # self.classbinary.reverse_symbols[sy.entry.st_value] = sy.name.decode()
        # self.classbinary.symbols[sy.name.decode()] = sy.entry.st_value
        return


    def load_dyn_sym(self):
        # self.classbinary.reverse_symbols[off] = name + "@plt"
        return


    def load_rodata(self):
        for s in self.pe.sections:
            if s.Name.rstrip(b"\0") == b".rdata":
                # TODO more read-only data ?
                self.rodata = s
                self.rodata_data = s.get_data()
                break


    def is_rodata(self, addr):
        if self.rodata == None:
            return False
        base = self.pe.OPTIONAL_HEADER.ImageBase
        start = base + self.rodata.VirtualAddress
        end = start + self.rodata.SizeOfRawData
        return  start <= addr <= end


    def get_section(self, addr):
        base = self.pe.OPTIONAL_HEADER.ImageBase
        s = self.pe.get_section_by_rva(addr - base)
        flags = {
            "exec": self.__section_is_exec(s)
        }
        return (s.get_data(), base + s.VirtualAddress, flags)


    def __section_is_exec(self, s):
        return s.Characteristics & 0x20000000


    def get_string(self, addr):
        base = self.pe.OPTIONAL_HEADER.ImageBase
        off = addr - self.rodata.VirtualAddress - base
        txt = "\""

        i = 0
        while i < lib.binary.MAX_STRING_RODATA:
            c = self.rodata_data[off]
            if c == 0:
                break
            txt += lib.utils.get_char(c)
            off += 1
            i += 1

        if c != 0:
            txt += "..."

        return txt + "\""


    # pe.parse_data_directories()
    # for entry in pe.DIRECTORY_ENTRY_IMPORT:
        # print(entry.dll)
        # for imp in entry.imports:
            # print(lib.colors.red(imp.name))
            # print(imp)
            # for a in attrs:
                # v = getattr(imp, a)
                # if isinstance(v, int):
                    # print("\t %s %x" % (a, v))
                # else:
                    # print("\t %s " % a, end="")
                    # print(v)
            # print()


    def get_arch(self):
        arch = self.pe.OPTIONAL_HEADER.Magic
        if arch == pefile.OPTIONAL_HEADER_MAGIC_PE:
            return lib.binary.ARCH_x86
        if arch == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS:
            return lib.binary.ARCH_x64
        return lib.binary.ARCH_INVALID
