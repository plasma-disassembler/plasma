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

from reverse.lib.fileformat.binary import T_BIN_PE, T_BIN_ELF
from reverse.lib.memory import MEM_CODE, MEM_FUNC, MEM_UNK, MEM_ASCII, MEM_OFFSET

# database.functions[ADDR] contains a list, here are the indexes
FUNC_END = 0
FUNC_FLAGS = 1
FUNC_VARS = 2
FUNC_ID = 3

VAR_TYPE = 0
VAR_NAME = 1

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
    def init(self):
        self.dis = None
        self.msg = Queue()


    def set(self, gctx):
        self.gctx = gctx
        self.dis = gctx.dis
        self.db = gctx.db
        self.ARCH_UTILS = self.dis.load_arch_module().utils

        # TODO: find a better solution, globally ? The problem
        # is that I want the --help fast as possible.
        from capstone import (CS_OP_IMM, CS_OP_MEM, CS_ARCH_MIPS, CS_ARCH_X86,
                              CS_MODE_32, CS_MODE_64, CS_ARCH_ARM)
        self.CS_OP_IMM = CS_OP_IMM
        self.CS_OP_MEM = CS_OP_MEM

        self.is_mips = self.dis.arch == CS_ARCH_MIPS
        self.is_x86 = self.dis.arch == CS_ARCH_X86
        self.is_arm = self.dis.arch == CS_ARCH_ARM

        if self.is_x86:
            from capstone.x86 import (X86_REG_EIP, X86_REG_RIP,
                                      X86_REG_EBP, X86_REG_RBP)
            self.X86_REG_EIP = X86_REG_EIP
            self.X86_REG_RIP = X86_REG_RIP
            self.X86_REG_RBP = X86_REG_RBP
            self.X86_REG_EBP = X86_REG_EBP
        elif self.is_mips:
            from capstone.mips import MIPS_REG_GP
            self.MIPS_REG_GP = MIPS_REG_GP
            if self.dis.mode & CS_MODE_32:
                self.default_size = 4
            else:
                self.default_size = 8
        elif self.is_arm:
            from capstone.arm import ARM_REG_PC
            self.ARM_REG_PC = ARM_REG_PC
            self.default_size = 4

        self.has_op_size = self.dis.arch == CS_ARCH_X86


    def __add_prefetch(self, addr_set, inst):
        if self.is_arm:
            prefetch = self.dis.lazy_disasm(inst.address + inst.size)
            addr_set[prefetch.address] = prefetch
            return prefetch
        return None


    def import_flags(self, ad):
        # Check all known functions which never return
        if ad not in self.dis.binary.imports:
            return 0
        name = self.db.reverse_symbols[ad]
        if self.dis.binary.type == T_BIN_PE:
            return FUNC_FLAG_NORETURN if name in NORETURN_PE else 0
        elif self.dis.binary.type == T_BIN_ELF:
            return FUNC_FLAG_NORETURN if name in NORETURN_ELF else 0
        return 0


    def run(self):
        while 1:
            item = self.msg.get()

            if isinstance(item, tuple):
                if self.dis is not None:
                    # Run analysis
                    (ad, entry_is_func, force, queue_response) = item
                    self.pending = set() # prevent recursive loops

                    self.analyze_flow(ad, entry_is_func, force)

                    # Send a notification
                    if queue_response is not None:
                        queue_response.put(1)

            elif isinstance(item, str):
                if item == "exit":
                    break


    def analyze_operands(self, i, func_obj):
        b = self.dis.binary

        for op in i.operands:
            if op.type == self.CS_OP_IMM:
                val = op.value.imm

            elif op.type == self.CS_OP_MEM and op.mem.disp != 0:

                if self.is_x86:
                    if op.mem.segment != 0:
                        continue
                    if op.mem.index == 0:
                        # Compute the rip register
                        if op.mem.base == self.X86_REG_EIP or \
                            op.mem.base == self.X86_REG_RIP:
                            val = i.address + i.size + op.mem.disp

                        # Check if it's a stack variable
                        elif (op.mem.base == self.X86_REG_EBP or \
                              op.mem.base == self.X86_REG_RBP):
                            if func_obj is not None:
                                ty = self.dis.mem.find_type(op.size)
                                func_obj[FUNC_VARS][op.mem.disp] = [ty, None]
                            # Continue the loop !!
                            continue
                        else:
                            val = op.mem.disp
                    else:
                        val = op.mem.disp

                # TODO: stack variables for arm/mips

                elif self.is_arm:
                    if op.mem.index == 0 and op.mem.base == self.ARM_REG_PC:
                        val = i.address + i.size * 2 + op.mem.disp
                    else:
                        val = op.mem.disp

                elif self.is_mips:
                    if op.mem.base == self.MIPS_REG_GP:
                        if self.dis.mips_gp == -1:
                            continue
                        val = op.mem.disp + self.dis.mips_gp
                    else:
                        val = op.mem.disp
            else:
                continue

            s = b.get_section(val)
            if s is None:
                continue

            self.dis.add_xref(i.address, val)

            if not self.dis.mem.exists(val):
                sz = op.size if self.has_op_size else self.default_size
                deref = s.read_int(val, sz)
                if deref is not None and b.get_section(deref) is not None:
                    ty = MEM_OFFSET
                    self.dis.add_xref(val, deref)
                    if not self.dis.mem.exists(deref):
                        self.dis.mem.add(deref, 1, MEM_UNK)
                else:
                    # Check if this is an address to a string
                    sz = b.is_string(val)
                    if sz != 0:
                        ty = MEM_ASCII
                    else:
                        sz = op.size if self.has_op_size else self.default_size
                        if op.type == self.CS_OP_MEM:
                            ty = self.dis.mem.find_type(sz)
                        else:
                            ty = MEM_UNK

                self.dis.mem.add(val, sz, ty)


    def __add_analyzed_code(self, mem, entry, inner_code, entry_is_func, flags):
        functions = self.dis.functions

        if entry_is_func:
            if entry in functions:
                last_end = functions[entry][FUNC_END]
                self.dis.end_functions[last_end].remove(entry)
                if not self.dis.end_functions[last_end]:
                    del self.dis.end_functions[last_end]

            e = max(inner_code) if inner_code else -1
            func_id = self.db.func_id_counter
            functions[entry] = [e, flags, {}, func_id]
            func_obj = functions[entry]

            self.db.func_id[func_id] = entry
            self.db.func_id_counter += 1

            if e in self.dis.end_functions:
                self.dis.end_functions[e].append(entry)
            else:
                self.dis.end_functions[e] = [entry]

        else:
            func_id = -1
            func_obj = None

        for ad, inst in inner_code.items():
            self.analyze_operands(inst, func_obj)

            if ad in functions:
                mem.add(ad, inst.size, MEM_FUNC, func_id)
            else:
                mem.add(ad, inst.size, MEM_CODE, func_id)

            if ad in self.db.reverse_symbols:
                name = self.db.reverse_symbols[ad]
                if name.startswith("ret_") or name.startswith("loop_"):
                    self.dis.rm_symbol(ad)


    def is_noreturn(self, ad, entry):
        return ad !=entry and self.dis.functions[ad][FUNC_FLAGS] & FUNC_FLAG_NORETURN


    def analyze_flow(self, entry, entry_is_func, force):
        if entry in self.pending:
            return

        if not force and entry in self.dis.functions:
            return

        self.pending.add(entry)

        mem = self.dis.mem
        inner_code = {} # ad -> capstone instruction

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
                        inner_code[inst.address] = inst
                        flags = self.import_flags(ptr)

        if not is_pe_import and not inner_code:
            flags = self.__sub_analyze_flow(entry, inner_code)

        if inner_code:
            self.__add_analyzed_code(self.dis.mem, entry, inner_code,
                                     entry_is_func, flags)

        inner_code.clear()
        self.pending.remove(entry)


    def __sub_analyze_flow(self, entry, inner_code):
        if self.dis.binary.get_section(entry) is None:
            return 0

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

            inner_code[ad] = inst

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
                        self.analyze_flow(ad, True, False)

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

