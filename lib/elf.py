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

from elftools.common.py3compat import bytes2str
from elftools.elf.elffile import ELFFile
from elftools.elf.constants import *

import lib.binary
import lib.utils


# SHF_WRITE=0x1
# SHF_ALLOC=0x2
# SHF_EXECINSTR=0x4
# SHF_MERGE=0x10
# SHF_STRINGS=0x20
# SHF_INFO_LINK=0x40
# SHF_LINK_ORDER=0x80
# SHF_OS_NONCONFORMING=0x100
# SHF_GROUP=0x200
# SHF_TLS=0x400
# SHF_MASKOS=0x0ff00000
# SHF_EXCLUDE=0x80000000
# SHF_MASKPROC=0xf0000000


class ELF:
    def __init__(self, classbinary, filename):
        fd = open(filename, "rb")
        self.elf = ELFFile(fd)
        self.classbinary = classbinary
        self.rodata = None
        self.rodata_data = None


    def load_static_sym(self):
        symtab = self.elf.get_section_by_name(b".symtab")
        try:
            if symtab == None:
                return
        except:
            pass
        for sy in symtab.iter_symbols():
            if sy.entry.st_value != 0 and sy.name != b"":
                self.classbinary.reverse_symbols[sy.entry.st_value] = sy.name.decode()
                self.classbinary.symbols[sy.name.decode()] = sy.entry.st_value
            # print("%x\t%s" % (sy.entry.st_value, sy.name.decode()))


    def load_dyn_sym(self):
        rel = (self.elf.get_section_by_name(b".rela.plt") or
                self.elf.get_section_by_name(b".rel.plt"))
        dyn = self.elf.get_section_by_name(b".dynsym")

        relitems = list(rel.iter_relocations())
        dynsym = list(dyn.iter_symbols())

        plt = self.elf.get_section_by_name(b".plt") 
        plt_entry_size = 16 # TODO

        off = plt.header.sh_addr + plt_entry_size
        k = 0

        while off < plt.header.sh_addr + plt.header.sh_size :
            idx = relitems[k].entry.r_info_sym
            name = dynsym[idx].name.decode()
            self.classbinary.reverse_symbols[off] = name + "@plt"
            off += plt_entry_size
            k += 1


    def load_rodata(self):
        # TODO more read-only data ?
        self.rodata = self.elf.get_section_by_name(b".rodata")
        self.rodata_data = self.rodata.data()


    def is_rodata(self, addr):
        # exception if rodata != None
        try:
            if self.rodata == None:
                return False
        except:
            pass
        start = self.rodata.header.sh_addr
        end = start + self.rodata.header.sh_size
        return  start <= addr <= end


    def __find_section(self, addr):
        for s in self.elf.iter_sections():
            start = s.header.sh_addr
            end = start + s.header.sh_size
            if  start <= addr <= end:
                return s
        return None


    def get_section(self, addr):
        s = self.__find_section(addr)
        flags = {
            "exec": self.__section_is_exec(s)
        }
        return (s.data(), s.header.sh_addr, flags)


    def __section_is_exec(self, s):
        return s.header.sh_flags & SH_FLAGS.SHF_EXECINSTR


    def get_string(self, addr):
        off = addr - self.rodata.header.sh_addr
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
