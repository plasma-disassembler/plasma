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

from lib.graph import Graph
from lib.utils import *
from lib.binary import Binary


class Disassembler():
    def __init__(self, filename, str_start_addr, bits):
        self.code = {}
        self.binary = Binary(filename)
        self.start_addr = 0

        if str_start_addr.startswith("0x"):
            self.start_addr = int(str_start_addr, 16)
        else:
            try:
                self.start_addr = self.binary.symbols[str_start_addr]
            except:
                die("symbol %s not found" % str_start_addr)

        (data, virtual_addr, flags) = self.binary.get_section(self.start_addr)

        if not flags["exec"]:
            die("the address 0x%x is not in an executable section" % self.start_addr)

        mode = CS_MODE_64 if bits == 64 else CS_MODE_32
        md = Cs(CS_ARCH_X86, mode)
        md.detail = True

        for i in md.disasm(data, virtual_addr):
            self.code[i.address] = i

        self.graph = self.extract_func(self.start_addr)
        self.graph.simplify()
        self.graph.detect_loops()


    def dump_code(self):
        for i in self.code:
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
                    else:
                        die("failed on 0x%x: %s %s\nSorry, I can't generate the flow graph." % (curr.address, curr.mnemonic, curr.op_str))

                elif is_cond_jump(curr) and len(curr.operands) > 0:
                    if curr.operands[0].type == X86_OP_IMM:
                        nxt_jump = self.code[curr.operands[0].value.imm]
                        direct_nxt = self.code[curr.address + curr.size]
                        gph.set_cond_next(curr, nxt_jump, direct_nxt)
                        rest.append(nxt_jump.address)
                        rest.append(direct_nxt.address)
                    else:
                        die("failed on 0x%x: %s %s\nSorry, I can't generate the flow graph." % (curr.address, curr.mnemonic, curr.op_str))

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
