#!/usr/bin/env python3
#
# PLASMA : Generate an indented asm code (pseudo-C) with colored syntax.
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

from plasma.lib.utils import unsigned
from plasma.lib.fileformat.binary import T_BIN_PE, T_BIN_ELF
from plasma.lib.consts import *


class Analyzer(threading.Thread):
    def init(self):
        self.dis = None
        self.msg = Queue()
        self.pending = set() # prevent recursive call

        self.running_second_pass = False
        self.where = 0 # cursor when parsing memory
        self.second_pass_done = False


    def set(self, gctx, arch_analyzer):
        # cache
        self.gctx = gctx
        self.dis = gctx.dis
        self.db = gctx.db
        self.api = gctx.api
        self.ARCH_UTILS = self.gctx.libarch.utils
        self.is_ret = self.ARCH_UTILS.is_ret
        self.is_jump = self.ARCH_UTILS.is_jump
        self.is_uncond_jump = self.ARCH_UTILS.is_uncond_jump
        self.is_cond_jump = self.ARCH_UTILS.is_cond_jump
        self.is_call = self.ARCH_UTILS.is_call
        self.disasm = self.dis.lazy_disasm
        self.jmptables = self.db.jmptables
        self.functions = self.db.functions
        self.prologs = self.ARCH_UTILS.PROLOGS
        self.arch_analyzer = arch_analyzer


    # Should be rewritten for mips
    def __add_prefetch(self, addr_set, inst):
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
                    (ad, entry_is_func, force, add_if_code, queue_response) = item
                    self.analyze_flow(ad, entry_is_func, force, add_if_code)

                    # Send a notification
                    if queue_response is not None:
                        queue_response.put(1)

            elif isinstance(item, str):
                if item == "exit":
                    break

                if item == "pass_scan_mem":
                    if not self.second_pass_done and self.msg.qsize() == 0:
                        self.second_pass_done = True
                        self.running_second_pass = True
                        self.pass_detect_unk_data()
                        self.pass_detect_functions()
                        self.running_second_pass = False
                    else:
                        self.msg.put(item)


    def pass_detect_unk_data(self):
        b = self.dis.binary
        mem = self.db.mem
        wait = Queue()

        for s in b.iter_sections():
            if s.is_exec:
                continue

            ad = s.start
            end = ad + s.real_size

            while ad < end:
                self.where = ad

                if not mem.is_unk(ad):
                    ad += mem.get_size(ad)
                    continue

                val = s.read_int(ad, self.dis.wordsize)

                # Detect if it's an address
                if val is not None:
                    s2 = b.get_section(val)
                    if s2 is not None and s2.is_exec:
                        self.api.add_xref(ad, val)
                        self.db.mem.add(ad, self.dis.wordsize, MEM_OFFSET)
                        ad += self.dis.wordsize

                        if not self.db.mem.exists(val):
                            self.db.mem.add(val, self.dis.wordsize, MEM_UNK)

                            # Do an analysis on this value.
                            if val not in self.pending and \
                                    self.first_inst_are_code(val):
                                self.analyze_flow(val, self.has_prolog(val), False, True)
                        continue

                # Detect if it's a string
                n = b.is_string(ad, s=s)
                if n != 0:
                    self.db.mem.add(ad, n, MEM_ASCII)
                    ad += n
                    continue

                ad += 1


    def pass_detect_functions(self):
        b = self.dis.binary
        mem = self.db.mem

        for s in b.iter_sections():
            if not s.is_exec:
                continue

            ad = s.start
            end = ad + s.real_size

            while ad < end:
                self.where = ad

                if not mem.is_unk(ad):
                    ad += mem.get_size(ad)
                    continue

                # Do an analysis on this value.
                # Don't run first_inst_are_code, it's too slow on big sections.
                if ad not in self.pending and self.has_prolog(ad):
                    # Don't push, run directly the analyzer. Otherwise
                    # we will re-analyze next instructions.
                    self.analyze_flow(ad, True, False, True)

                ad += 1


    # Do an analysis if the immediate is an address
    def analyze_imm(self, i, op, imm):
        s = self.dis.binary.get_section(imm)
        if s is None or s.start == 0:
            return

        self.api.add_xref(i.address, imm)

        if self.db.mem.exists(imm):
            return

        sz = op.size if self.dis.is_x86 else self.dis.wordsize
        deref = s.read_int(imm, sz)

        # If (*imm) is an address
        if deref is not None and self.dis.binary.is_address(deref):
            ty = MEM_OFFSET
            self.api.add_xref(imm, deref)

            if not self.db.mem.exists(deref):
                self.db.mem.add(deref, 1, MEM_UNK)

                # Do an analysis on this value.
                if deref not in self.pending and \
                        self.first_inst_are_code(deref):
                    self.analyze_flow(deref, self.has_prolog(deref), False, True)
        else:
            # Check if this is an address to a string
            sz = self.dis.binary.is_string(imm)
            if sz != 0:
                ty = MEM_ASCII
            else:
                sz = op.size if self.dis.is_x86 else self.dis.wordsize
                if op.type == self.ARCH_UTILS.OP_MEM:
                    ty = self.db.mem.find_type(sz)
                else:
                    ty = MEM_UNK

        self.db.mem.add(imm, sz, ty)

        if ty == MEM_UNK:
            # Do an analysis on this value, if this is not code
            # nothing will be done.
            if imm not in self.pending and \
                    self.first_inst_are_code(imm):
                self.analyze_flow(imm, self.has_prolog(imm), True, True)


    # Check if the five first instructions can be disassembled.
    # Each instruction must be different of null bytes.
    def first_inst_are_code(self, ad):
        for i in range(5):
            inst = self.disasm(ad)
            if inst is None:
                return False
            if inst.bytes.count(0) == len(inst.bytes):
                return False
            ad += inst.size
        return True


    # This function tries to optimize calls to lazy_disasm.
    def has_prolog(self, ad):
        match = False
        buf = self.dis.binary.read(ad, 4)

        if buf is None:
            return False

        if not self.dis.is_big_endian:
            buf = bytes(reversed(buf))

        for lst in self.prologs:
            for p in lst:
                if buf.startswith(p):
                    match = True
                    break

        if not match:
            return False

        inst = self.disasm(ad)
        if inst is None:
            return False

        # Don't disassemble the second instruction, just get a copy of bytes.
        buf = self.dis.binary.read(ad + inst.size, 4)

        if not self.dis.is_big_endian:
            buf = bytes(reversed(buf))

        for lst in self.prologs:
            for p in lst:
                if buf.startswith(p[inst.size:]):
                    return True

        return False


    def __add_analyzed_code(self, func_obj, mem, entry, inner_code, entry_is_func, flags):
        if func_obj is not None:
            e = max(inner_code) if inner_code else -1
            func_id = func_obj[FUNC_ID]
            func_obj[FUNC_FLAGS] = flags
            func_obj[FUNC_END] = e
            self.functions[entry] = func_obj
            self.db.func_id[func_id] = entry

            if e in self.db.end_functions:
                self.db.end_functions[e].append(entry)
            else:
                self.db.end_functions[e] = [entry]
        else:
            func_id = -1

        for ad, inst in inner_code.items():
            if ad == entry and func_id != -1:
                mem.add(ad, inst.size, MEM_FUNC, func_id)
            else:
                mem.add(ad, inst.size, MEM_CODE, func_id)

            if ad in self.db.reverse_symbols:
                name = self.db.reverse_symbols[ad]
                if name.startswith("ret_") or name.startswith("loop_"):
                    self.api.rm_symbol(ad)


    def is_noreturn(self, ad, entry):
        return ad != entry and self.functions[ad][FUNC_FLAGS] & FUNC_FLAG_NORETURN


    #
    # analyze_flow:
    # entry             address of the code to analyze.
    # entry_is_func     if true a function will be created, otherwise
    #                   instructions will be set only as "code".
    # force             if true and entry is already functions, the analysis
    #                   is forced.
    # add_if_code       if true, it means that we are not sure that entry is an
    #                   address to a code location. In this case, if the control
    #                   flow contains a bad instruction, the functions or
    #                   instructions will not be added.
    #
    def analyze_flow(self, entry, entry_is_func, force, add_if_code):
        if entry in self.pending:
            return

        if not force:
            if not entry_is_func and self.db.mem.is_loc(entry) or \
                    entry_is_func and self.db.mem.is_func(entry):
                return

            # Check if is not inside a function
            if self.db.mem.get_func_id(entry) != -1:
                return

        mem = self.db.mem

        if mem.is_inside_mem(entry):
            return

        self.pending.add(entry)

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
                    ptr = self.dis.binary.reverse_stripped(self.dis, inst)
                    if ptr != -1:
                        inner_code[inst.address] = inst
                        flags = self.import_flags(ptr)

        # Create a function object (see in Database)
        is_def = entry in self.functions

        if entry_is_func or is_def:
            # It can be None because when symbols are loaded functions are
            # set to None initially.
            if is_def and self.functions[entry] is not None:
                last_end = self.functions[entry][FUNC_END]
                self.db.end_functions[last_end].remove(entry)
                if not self.db.end_functions[last_end]:
                    del self.db.end_functions[last_end]

            # [func_end, flags, var_offsets, func_id, inst.addresses]
            func_obj = [-1, 0, {}, self.db.func_id_counter, {}]
            self.db.func_id_counter += 1

        else:
            func_obj = None

        if not is_pe_import and not inner_code:
            flags = self.__sub_analyze_flow(func_obj, entry, inner_code, add_if_code)

        if inner_code and flags != -1:
            self.__add_analyzed_code(func_obj, self.db.mem, entry, inner_code,
                                     entry_is_func, flags)

        inner_code.clear()
        self.pending.remove(entry)


    def __sub_analyze_flow(self, func_obj, entry, inner_code, add_if_code):
        if self.dis.binary.get_section(entry) is None:
            return -1

        has_ret = False

        # If entry is not "code", we have to rollback added xrefs
        has_bad_inst = False
        if add_if_code:
            added_xrefs = []

        regsctx = self.arch_analyzer.new_regs_context()
        if regsctx is None:
            # fatal error, but don't quit to let the user save the database
            return 0

        # FIXME : this is a hack for the cdecl calling convention
        # if the stack pointer move after a call, this is probably a cdecl
        # call, so we will ignore the add instruction.
        one_call_called = False

        stack = [(regsctx, entry)]

        while stack:
            (regsctx, ad) = stack.pop()
            inst = self.disasm(ad)

            if inst is None:
                has_bad_inst = True
                if add_if_code:
                    break
                continue

            if ad in inner_code:
                continue

            inner_code[ad] = inst

            self.arch_analyzer.analyze_operands(
                    self, regsctx, inst, func_obj, one_call_called)

            if self.is_ret(inst):
                self.__add_prefetch(inner_code, inst)
                has_ret = True

            elif self.is_uncond_jump(inst):
                self.__add_prefetch(inner_code, inst)

                op = inst.operands[-1]

                if op.type == self.ARCH_UTILS.OP_IMM:
                    nxt = unsigned(op.value.imm)
                    self.api.add_xref(ad, nxt)
                    if self.db.mem.is_func(nxt):
                        has_ret = not self.is_noreturn(nxt, entry)
                    else:
                        stack.append((regsctx, nxt))
                    if add_if_code:
                        added_xrefs.append((ad, nxt))
                else:
                    if inst.address in self.jmptables:
                        table = self.jmptables[inst.address].table
                        # TODO : dupplicate regsctx ??
                        for n in table:
                            stack.append((regsctx, n))
                        self.api.add_xref(ad, table)
                        if add_if_code:
                            added_xrefs.append((ad, table))
                    else:
                        # TODO
                        # This is a register or a memory access
                        # we can't say if the function really returns
                        has_ret = True

            elif self.is_cond_jump(inst):
                prefetch = self.__add_prefetch(inner_code, inst)

                op = inst.operands[-1]
                if op.type == self.ARCH_UTILS.OP_IMM:
                    if prefetch is None:
                        direct_nxt = inst.address + inst.size
                    else:
                        direct_nxt = prefetch.address + prefetch.size

                    nxt_jmp = unsigned(unsigned(op.value.imm))
                    self.api.add_xref(ad, nxt_jmp)
                    stack.append((regsctx, direct_nxt))

                    if add_if_code:
                        added_xrefs.append((ad, nxt_jmp))

                    if self.db.mem.is_func(nxt_jmp):
                        has_ret = not self.is_noreturn(nxt_jmp, entry)
                    else:
                        newctx = self.arch_analyzer.clone_regs_context(regsctx)
                        stack.append((newctx, nxt_jmp))

            elif self.is_call(inst):
                one_call_called = True
                op = inst.operands[-1]
                value = None

                if op.type == self.ARCH_UTILS.OP_IMM:
                    value = unsigned(op.value.imm)
                elif op.type == self.ARCH_UTILS.OP_REG:
                    # FIXME : for MIPS, addresses are loaded in t9 (generally)
                    # then jalr t9 is executed. The problem here is that we
                    # will analyze twice the function. The first time is done
                    # by the function analyze_imm.
                    value = self.arch_analyzer.reg_value(regsctx, op.value.reg)

                if value is not None:
                    self.api.add_xref(ad, value)

                    if add_if_code:
                        added_xrefs.append((ad, value))

                    if not self.db.mem.is_func(value):
                        self.analyze_flow(value, True, False, add_if_code)

                    if self.db.mem.is_func(value) and self.is_noreturn(value, entry):
                        self.__add_prefetch(inner_code, inst)
                        continue

                nxt = inst.address + inst.size
                stack.append((regsctx, nxt))

            else:
                nxt = inst.address + inst.size
                stack.append((regsctx, nxt))

        if add_if_code and has_bad_inst:
            for from_ad, to_ad in added_xrefs:
                self.api.rm_xrefs(from_ad, to_ad)
            return -1

        # for ELF
        if entry in self.dis.binary.imports:
            flags = self.import_flags(entry)
        elif has_ret:
            flags = 0
        else:
            flags = FUNC_FLAG_NORETURN

        return flags
