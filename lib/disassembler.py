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

from capstone import *
from capstone.x86 import *

from elftools.common.py3compat import bytes2str
from elftools.elf.elffile import ELFFile
from elftools.elf.constants import *
from graph import *
from utils import *


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

# X86_OP_INVALID = 0
# X86_OP_REG = 1
# X86_OP_IMM = 2
# X86_OP_MEM = 3
# X86_OP_FP = 4



class Disassembler():
    def __init__(self, filename):
        fd = open(filename, "rb")
        self.elf = ELFFile(fd)
        self.reverse_symbols = {}
        self.symbols = {}
        self.section_addr = {}
        self.disas = []
        self.deep = 0
        self.code = {}


        # load static symbols
        symtab = self.elf.get_section_by_name(b".symtab")
        for sy in symtab.iter_symbols():
            if sy.entry.st_value != 0 and sy.name != b"":
                self.reverse_symbols[sy.entry.st_value] = sy.name.decode()
                self.symbols[sy.name.decode()] = sy.entry.st_value
            # print("%x\t%s" % (sy.entry.st_value, sy.name.decode()))

        # load dynamic symbols
        dyn = self.elf.get_section_by_name(b".dynsym")
        plt = self.elf.get_section_by_name(b".plt") 
        dynsym = list(dyn.iter_symbols())
        plt_entry_size = 16 # TODO
        off = plt.header.sh_addr + plt_entry_size
        k = 1
        while off < plt.header.sh_addr + plt.header.sh_size :
            self.reverse_symbols[off] = dynsym[k].name.decode() + "@plt"
            off += plt_entry_size
            k += 1

        self.rodata = self.elf.get_section_by_name(b".rodata")
        self.rodata_data = self.rodata.data()


    def is_rodata(self, addr):
        start = self.rodata.header.sh_addr
        end = start + self.rodata.header.sh_size
        return  start <= addr <= end


    def is_in_section(self, addr, sect):
        start = sect.header.sh_addr
        end = start + sect.header.sh_size
        return  start <= addr <= end


    def find_exec_section(self):
        for s in self.elf.iter_sections():
            if s.header.sh_flags & SH_FLAGS.SHF_EXECINSTR:
                print(s.name)


    def disasm_section(self, name, mode):
        s = self.elf.get_section_by_name(name)

        mode = CS_MODE_64 if mode == 64 else CS_MODE_32

        md = Cs(CS_ARCH_X86, mode)
        md.detail = True

        for i in md.disasm(s.data(), s.header.sh_addr):
            self.code[i.address] = i


    def get_disasm_section(self, name, mode):
        s = self.elf.get_section_by_name(name)

        mode = CS_MODE_64 if mode == 64 else CS_MODE_32

        md = Cs(CS_ARCH_X86, mode)
        md.detail = True
        code = []

        for i in md.disasm(s.data(), s.header.sh_addr):
            code.append(i)

        return code


    def dump_code(self, code): #, code):
        # addr = code[0].address
        # addr_sy = self.find_symbol(addr)
        # addr_str = "<%s+%d>" % (self.reverse_symbols[addr_sy], addr - addr_sy)
        # print(addr_str)

        for i in code:
            # if is_call(i) or is_uncond_jump(i):
                # self.print_address(i)
            # else:
            print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))


    def find_section(self, addr):
        for s in self.elf.iter_sections():
            start = s.header.sh_addr
            end = start + s.header.sh_size
            if  start <= addr <= end:
                return s
        return None


    # Can take any address. The nearest symbol is returned.
    def find_symbol(self, addr):
        found = False
        key = 0
        
        if addr in self.reverse_symbols:
            return addr

        for s in self.reverse_symbols:
            if key <= s <= addr:
                key = s
                found = True

        if found:
            return key
        return None


    def print_address(self, i):
        if i.operands[0].type == X86_OP_IMM:
            print("0x%x:\t%s\t" % (i.address, red(i.mnemonic)), end="")

            addr = i.operands[0].value.imm

            addr_sy = self.find_symbol(addr)
            addr_str = "<%s+%d>" % (self.reverse_symbols[addr_sy], addr - addr_sy)

            # if addr_sy == None:
                # sect = self.find_section(addr)
                # addr_str = "<%s+%d>" % (sect.name.decode(), addr - sect.header.sh_addr)
            # else:

            print(("0x%x " % addr) + addr_str)
        else:
            print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))


    # Generate a flow graph of the given function (addr)
    def extract_func(self, addr):
        curr = self.code[addr]
        gph = Graph(self, addr)

        rest = []

        while 1:
            if not gph.exists(curr):
                if is_uncond_jump(curr) and len(curr.operands) > 0:
                    if curr.operands[0].type == X86_OP_IMM:
                        addr = curr.operands[0].value.imm
                        nxt = self.code[addr]
                        gph.set_next(curr, nxt)
                        rest.append(nxt.address)

                elif is_cond_jump(curr) and len(curr.operands) > 0:
                    if curr.operands[0].type == X86_OP_IMM:
                        nxt_true = self.code[curr.operands[0].value.imm]
                        nxt_false = self.code[curr.address + curr.size]
                        gph.set_cond_next(curr, nxt_true, nxt_false)
                        rest.append(nxt_true.address)
                        rest.append(nxt_false.address)

                elif is_ret(curr):
                    gph.add_node(curr)

                else:
                    nxt = self.code[curr.address + curr.size]
                    gph.set_next(curr, nxt)
                    rest.append(nxt.address)

            try:
                curr = self.code[rest.pop()]
            except:
                break

        return gph


