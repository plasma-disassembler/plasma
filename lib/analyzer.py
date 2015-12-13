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

import threading
from queue import Queue

from lib.utils import debug__
from lib.memory import Memory, MEM_CODE
from lib.fileformat.binary import SYM_FUNC

# TODO: cleanup...


class Analyzer(threading.Thread):
    def reset(self):
        self.dis = None
        self.msg = Queue()


    def set(self, dis, db):
        self.dis = dis
        self.db = db


    def __prefetch_inst(self, inst):
        return self.dis.lazy_disasm(inst.address + inst.size)


    def run(self):
        self.reset()
        while 1:
            item = self.msg.get()
            if isinstance(item, tuple):
                if self.dis is not None:
                    (ad, entry_is_func, queue_response) = item
                    self.analyze_flow(ad, entry_is_func)
                    if queue_response is not None:
                        queue_response.put(1)
            elif isinstance(item, str):
                if item == "exit":
                    break


    def analyze_flow(self, entry, entry_is_func):
        from capstone import CS_OP_IMM, CS_ARCH_MIPS
        ARCH_UTILS = self.dis.load_arch_module().utils

        func = [entry]

        # cache
        arch = self.dis.arch
        is_ret = ARCH_UTILS.is_ret
        is_uncond_jump = ARCH_UTILS.is_uncond_jump
        is_cond_jump = ARCH_UTILS.is_cond_jump
        is_call = ARCH_UTILS.is_call
        disasm = self.dis.lazy_disasm
        jmptables = self.dis.jmptables
        mem = self.dis.mem
        functions = self.dis.functions
        end_functions = self.dis.end_functions

        inner_code = {} # ad -> instruction size
        stack = []

        while func:
            fad = func.pop(-1)

            if fad in functions:
                continue

            stack.append(fad)

            while stack:
                ad = stack.pop()
                inst = disasm(ad)

                if inst is None:
                    continue

                if ad in inner_code:
                    continue

                inner_code[ad] = inst.size

                if is_ret(inst):
                    if arch == CS_ARCH_MIPS:
                        prefetch = self.__prefetch_inst(inst)
                        inner_code[prefetch.address] = prefetch.size

                elif is_uncond_jump(inst):
                    if arch == CS_ARCH_MIPS:
                        prefetch = self.__prefetch_inst(inst)
                        inner_code[prefetch.address] = prefetch.size

                    op = inst.operands[-1]
                    if op.type == CS_OP_IMM:
                        nxt = op.value.imm
                        stack.append(nxt)
                    else:
                        if inst.address in jmptables:
                            table = jmptables[inst.address].table
                            stack += table

                elif is_cond_jump(inst):
                    if arch == CS_ARCH_MIPS:
                        prefetch = self.__prefetch_inst(inst)
                        inner_code[prefetch.address] = prefetch.size

                    op = inst.operands[-1]
                    if op.type == CS_OP_IMM:
                        if arch == CS_ARCH_MIPS:
                            direct_nxt = prefetch.address + prefetch.size
                        else:
                            direct_nxt = inst.address + inst.size

                        nxt_jmp = op.value.imm
                        stack.append(direct_nxt)
                        stack.append(nxt_jmp)

                elif is_call(inst):
                    op = inst.operands[-1]
                    if op.type == CS_OP_IMM and op.value.imm not in functions:
                        func.append(op.value.imm)
                    nxt = inst.address + inst.size
                    stack.append(nxt)

                else:
                    nxt = inst.address + inst.size
                    stack.append(nxt)

            if inner_code:
                if entry_is_func:
                    e = max(inner_code)
                    func_id = self.db.func_id_counter

                    functions[fad] = [e, func_id]
                    self.db.func_id_counter += 1

                    if e in end_functions:
                        end_functions[e].append(fad)
                    else:
                        end_functions[e] = [fad]

                    if fad not in self.db.reverse_symbols:
                        sy = "sub_%x" % fad
                        self.db.reverse_symbols[fad] = (sy, SYM_FUNC)
                        self.db.symbols[sy] = (fad, SYM_FUNC)
                else:
                    func_id = -1

                for ad, size in inner_code.items():
                    mem.add(ad, size, MEM_CODE)

                inner_code.clear()

            entry_is_func = True
