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

from lib.fileformat.binary import T_BIN_PE, T_BIN_ELF
from lib.memory import MEM_CODE, MEM_FUNC, MEM_UNK


FUNC_FLAG_NORETURN = 1


NORETURN_ELF = {
    "exit@plt", "_exit@plt", "__stack_chk_fail@plt",
    "abort@plt", "__assert_fail@plt"
}

NORETURN_PE = {
    "exit", "ExitProcess", "_exit", "quick_exit", "_Exit", "abort"
}



# TODO: generic way, some functions are copied or a bit
# modified from lib.disassembler


class Analyzer(threading.Thread):
    def reset(self):
        self.dis = None
        self.msg = Queue()


    def set(self, gctx):
        self.gctx = gctx
        self.dis = gctx.dis
        self.db = gctx.db
        self.ARCH_UTILS = self.dis.load_arch_module().utils


    def __add_prefetch(self, addr_set, inst):
        if self.dis.arch == self.CS_ARCH_MIPS:
            prefetch = self.dis.lazy_disasm(inst.address + inst.size)
            addr_set[prefetch.address] = prefetch.size
            return prefetch
        return None


    def import_flags(self, ad):
        # Check all known functions which never return
        if ad not in self.dis.binary.imports:
            return 0
        name = self.dis.binary.reverse_symbols[ad]
        if self.dis.binary.type == T_BIN_PE:
            return FUNC_FLAG_NORETURN if name in NORETURN_PE else 0
        elif self.dis.binary.type == T_BIN_ELF:
            return FUNC_FLAG_NORETURN if name in NORETURN_ELF else 0
        return 0


    def run(self):
        from capstone import CS_OP_IMM, CS_OP_MEM, CS_ARCH_MIPS
        self.CS_OP_IMM = CS_OP_IMM
        self.CS_OP_MEM = CS_OP_MEM
        self.CS_ARCH_MIPS = CS_ARCH_MIPS

        self.reset()

        while 1:
            item = self.msg.get()

            if isinstance(item, tuple):
                if self.dis is not None:
                    # Run analysis
                    (ad, entry_is_func, queue_response) = item
                    self.pending = set() # prevent recursive loops
                    self.analyze_flow(ad, entry_is_func)

                    # Send a notification
                    if queue_response is not None:
                        queue_response.put(1)

            elif isinstance(item, str):
                if item == "exit":
                    break


    def analyze_operands(self, i):
        b = self.dis.binary
        for op in i.operands:
            if op.type == self.CS_OP_IMM and b.get_section(op.value.imm) is not None:
                self.dis.add_xref(i.address, op.value.imm)
                if not self.dis.mem.exists(op.value.imm):
                    self.dis.mem.add(op.value.imm, 1, MEM_UNK)

            elif op.type == self.CS_OP_MEM and op.mem.disp != 0 and \
                    b.get_section(op.mem.disp) is not None:
                self.dis.add_xref(i.address, op.mem.disp)
                if not self.dis.mem.exists(op.mem.disp):
                    self.dis.mem.add(op.mem.disp, 1, MEM_UNK)


    # inner_code : ad -> instruction size
    def __add_analyzed_code(self, mem, entry, inner_code, entry_is_func, flags):
        functions = self.dis.functions

        if entry_is_func:
            e = max(inner_code) if inner_code else -1
            func_id = self.db.func_id_counter
            functions[entry] = [e, flags]

            self.db.func_id[func_id] = entry
            self.db.func_id_counter += 1

            if e in self.dis.end_functions:
                self.dis.end_functions[e].append(entry)
            else:
                self.dis.end_functions[e] = [entry]
        else:
            func_id = -1

        for ad, size in inner_code.items():
            if ad in functions:
                mem.add(ad, size, MEM_FUNC, func_id)
            else:
                mem.add(ad, size, MEM_CODE, func_id)


    def is_noreturn(self, ad, entry):
        return ad !=entry and self.dis.functions[ad][1] & FUNC_FLAG_NORETURN


    def analyze_flow(self, entry, entry_is_func):
        if entry in self.pending:
            return

        if entry in self.dis.functions:
            return

        self.pending.add(entry)

        mem = self.dis.mem
        inner_code = {} # ad -> instruction size

        is_pe_import = False

        # Check if it's a jump to an imported symbol
        # jmp *(IMPORT)
        if self.dis.binary.type == T_BIN_PE:
            if entry in self.dis.binary.imports:
                is_pe_import = True
                flags = self.import_flags(entry)
            else:
                inst = self.dis.lazy_disasm(entry)
                if inst is not None:
                    ptr = self.dis.binary.pe_reverse_stripped(self.dis, inst)
                    if ptr != -1:
                        inner_code[inst.address] = inst.size
                        flags = self.import_flags(ptr)

        if not is_pe_import and not inner_code:
            flags = self.__sub_analyze_flow(entry, inner_code)

        self.__add_analyzed_code(self.dis.mem, entry, inner_code,
                                 entry_is_func, flags)

        inner_code.clear()
        self.pending.remove(entry)


    def __sub_analyze_flow(self, entry, inner_code):
        stack = [entry]
        has_ret = False

        # cache
        is_ret = self.ARCH_UTILS.is_ret
        is_uncond_jump = self.ARCH_UTILS.is_uncond_jump
        is_cond_jump = self.ARCH_UTILS.is_cond_jump
        is_call = self.ARCH_UTILS.is_call
        disasm = self.dis.lazy_disasm
        jmptables = self.dis.jmptables
        functions = self.dis.functions

        while stack:
            ad = stack.pop()
            inst = disasm(ad)

            if inst is None:
                continue

            if ad in inner_code:
                continue

            self.analyze_operands(inst)
            inner_code[ad] = inst.size

            if is_ret(inst):
                self.__add_prefetch(inner_code, inst)
                has_ret = True

            elif is_uncond_jump(inst):
                self.__add_prefetch(inner_code, inst)

                op = inst.operands[-1]

                if op.type == self.CS_OP_IMM:
                    nxt = op.value.imm
                    self.dis.add_xref(ad, nxt)
                    if nxt in functions:
                        has_ret = not self.is_noreturn(nxt, entry)
                    else:
                        stack.append(nxt)
                else:
                    if inst.address in jmptables:
                        table = jmptables[inst.address].table
                        stack += table
                        self.dis.add_xref(ad, table)
                    else:
                        # TODO
                        # This is a register or a memory access
                        # we can't say if the function really returns
                        has_ret = True

            elif is_cond_jump(inst):
                prefetch = self.__add_prefetch(inner_code, inst)

                op = inst.operands[-1]
                if op.type == self.CS_OP_IMM:
                    if prefetch is None:
                        direct_nxt = inst.address + inst.size
                    else:
                        direct_nxt = prefetch.address + prefetch.size

                    nxt_jmp = op.value.imm
                    self.dis.add_xref(ad, nxt_jmp)
                    stack.append(direct_nxt)

                    if nxt_jmp in functions:
                        has_ret = not self.is_noreturn(nxt_jmp, entry)
                    else:
                        stack.append(nxt_jmp)

            elif is_call(inst):
                op = inst.operands[-1]
                if op.type == self.CS_OP_IMM:
                    self.dis.add_xref(ad, op.value.imm)
                    ad = op.value.imm

                    if ad not in functions:
                        self.analyze_flow(ad, True)

                    if ad in functions and self.is_noreturn(ad, entry):
                        self.__add_prefetch(inner_code, inst)
                        continue

                nxt = inst.address + inst.size
                stack.append(nxt)

            else:
                nxt = inst.address + inst.size
                stack.append(nxt)

        # for ELF
        if entry in self.dis.binary.imports:
            flags = self.import_flags(entry)
        elif has_ret:
            flags = 0
        else:
            flags = FUNC_FLAG_NORETURN

        return flags

