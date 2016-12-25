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

ALL_SP = {}


class Analyzer(threading.Thread):
    def init(self):
        self.dis = None
        self.msg = Queue()
        self.pending = set() # to avoid recursion

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
        self.arch_analyzer.set_wordsize(self.dis.wordsize)

        if self.dis.wordsize == 2:
            self.OFFSET_TYPE = MEM_WOFFSET
        elif self.dis.wordsize == 4:
            self.OFFSET_TYPE = MEM_DOFFSET
        elif self.dis.wordsize == 8:
            self.OFFSET_TYPE = MEM_QOFFSET


    def __add_prefetch(self, regsctx, inst, func_obj, addr_set):
        if self.dis.is_mips:
            prefetch = self.disasm(inst.address + inst.size)
            if prefetch is not None:
                addr_set[prefetch.address] = prefetch
                self.arch_analyzer.analyze_operands(
                        self, regsctx, prefetch, func_obj, False)
            return prefetch
        return None


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

                elif item == "rename_entry_point":
                    self.rename_entry_point()

                    
    def rename_entry_point(self):
        def new_function(ad, name):
            if name not in self.db.symbols:
                self.api.add_symbol(imm, name)
            self.analyze_flow(
                    imm,
                    entry_is_func=True,
                    force=False,
                    add_if_code=False)

        if self.dis.binary.type != T_BIN_ELF or not self.dis.is_x86:
            return

        from capstone.x86 import (X86_REG_RDI, X86_REG_RCX, X86_REG_R8,
                                  X86_INS_MOV, X86_OP_REG, X86_OP_IMM,
                                  X86_INS_PUSH)

        ep = self.api.entry_point()
        insn_count = 10
        arg_count = 0 # counter for x86

        if "_start" not in self.db.symbols:
            self.api.add_symbol(ep, "_start")

        ad = self.api.get_addr_from_symbol("__libc_start_main")
        if ad == -1:
            return

        try:
            ad = next(iter(self.api.xrefsto(ad)))
        except:
            return

        while insn_count != 0 and ad != ep:
            if self.db.mem.is_code(ad):
                insn = self.api.disasm(ad)

                if self.dis.binary.arch == "x86":
                    if insn.id == X86_INS_PUSH and \
                            insn.operands[0].type == X86_OP_IMM:
                        imm = insn.operands[0].value.imm

                        if arg_count == 0:
                            new_function(imm, "main")
                        elif arg_count == 1:
                            new_function(imm, "__libc_csu_init")
                        elif arg_count == 2:
                            new_function(imm, "__libc_csu_fini")
                        arg_count += 1

                else: # x64
                    if insn.id == X86_INS_MOV and \
                            insn.operands[0].type == X86_OP_REG and \
                            insn.operands[1].type == X86_OP_IMM:

                        reg = insn.operands[0].value.reg
                        imm = insn.operands[1].value.imm

                        if reg == X86_REG_RDI:
                            new_function(imm, "main")
                        elif reg == X86_REG_RCX:
                            new_function(imm, "__libc_csu_init")
                        elif reg == X86_REG_R8:
                            new_function(imm, "__libc_csu_fini")

                insn_count -= 1

            ad -= 1


    def pass_detect_unk_data(self):
        b = self.dis.binary
        mem = self.db.mem
        wait = Queue()

        for s in b.iter_sections():
            if s.is_exec or s.is_bss:
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
                        self.db.mem.add(ad, self.dis.wordsize, self.OFFSET_TYPE)
                        ad += self.dis.wordsize

                        # is_overlapping is sufficient but exists is faster
                        # and should be check first.
                        if not self.db.mem.exists(val) and \
                                not self.db.mem.is_overlapping(val):
                            self.db.mem.add(val, 1, MEM_UNK)
                            # Do an analysis on this value.
                            if s.is_exec and self.first_inst_are_code(val):
                                self.analyze_flow(
                                        val,
                                        entry_is_func=self.has_prolog(val),
                                        force=False,
                                        add_if_code=True)

                        continue

                # Detect if it's a string
                n = b.is_string(ad, s=s)
                if n != 0:
                    # is_overlapping is sufficient but exists is faster
                    # and should be check first.
                    if ad not in self.db.imports and \
                            not self.db.mem.exists(ad) and \
                            not self.db.mem.is_overlapping(ad):
                        self.db.mem.add(ad, n, MEM_ASCII)
                    ad += n
                    continue

                ad += 1


    def pass_detect_functions(self):
        b = self.dis.binary
        mem = self.db.mem

        for s in b.iter_sections():
            if not s.is_exec or s.is_bss:
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
                if self.has_prolog(ad):
                    # Don't push, run directly the analyzer. Otherwise
                    # we will re-analyze next instructions.
                    self.analyze_flow(
                            ad,
                            entry_is_func=True,
                            force=False,
                            add_if_code=True)

                ad += 1


    def add_stack_variable(self, func_obj, inst, offset, op_size):
        ty = self.db.mem.get_type_from_size(op_size)
        func_obj[FUNC_VARS][offset] = [ty, None]
        func_obj[FUNC_INST_VARS_OFF][inst.address] = offset


    # Do an analysis if the immediate is an address
    # If from_save_imm is true, op is the destination where we save imm
    # -> inst op, computed_imm
    def analyze_imm(self, i, op, imm, from_save_imm):
        if imm <= 1024:
            return False

        if not from_save_imm and op.type == self.ARCH_UTILS.OP_REG:
            return False

        # imm must be an address
        s = self.dis.binary.get_section(imm)
        if s is None or s.start == 0:
            return False

        self.api.add_xref(i.address, imm)
        ad = imm

        # is_overlapping is sufficient but exists is faster
        # and should be checked first.
        if self.db.mem.exists(ad) or self.db.mem.is_overlapping(ad):
            return True

        if not s.is_bss:
            sz = self.dis.wordsize

            # If *(*ad) is an address
            deref = s.read_int(ad, sz)
            if deref is not None and self.dis.binary.is_address(deref):
                ty = self.db.mem.get_type_from_size(sz)
                self.api.set_offset(ad, ty, async_analysis=False)
                return True

            # Check if this is an address to a string
            if ad not in self.db.imports:
                sz = self.dis.binary.is_string(ad)
                if sz != 0:
                    self.db.mem.add(ad, sz, MEM_ASCII)
                    return True

        sz = op.size if self.dis.is_x86 else self.dis.wordsize
        if op.type == self.ARCH_UTILS.OP_MEM:
            ty = self.db.mem.get_type_from_size(sz)
        else:
            ty = MEM_UNK
            sz = 1

        self.db.mem.add(ad, sz, ty)

        if ty == MEM_UNK:
            # Do an analysis on this value, if this is not code
            # nothing will be done.
            if s.is_exec and self.first_inst_are_code(ad):
                self.analyze_flow(
                        ad,
                        entry_is_func=self.has_prolog(ad),
                        force=True,
                        add_if_code=True)

        return True


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


    def __add_analyzed_code(self, func_obj, mem, entry, inner_code,
                            entry_is_func):
        if func_obj is not None:
            e = max(inner_code) if inner_code else -1
            func_id = func_obj[FUNC_ID]
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


    # Before calling this function, check self.db.mem.is_func
    def is_func_noreturn(self, ad, entry):
        if ad in self.db.imports:
            return self.db.imports[ad] & FUNC_FLAG_NORETURN
        if ad == entry:
            # Can't say during the analysis
            return False
        return self.functions[ad][FUNC_FLAGS] & FUNC_FLAG_NORETURN


    def auto_jump_table(self, i, inner_code):
        table_ad = self.ARCH_UTILS.search_jmptable_addr(self, i, inner_code)
        if table_ad is None:
            return False

        s_orig = self.dis.binary.get_section(table_ad)
        nb_entries = 0
        ad = table_ad

        while 1:
            val = s_orig.read_int(ad, self.dis.wordsize)
            if val is None:
                return False

            if not self.dis.binary.is_address(val):
                break

            nb_entries += 1
            ad += self.dis.wordsize

            # TODO : here the program is not completely analyzed, so new xrefs
            # can appears later.
            if ad in self.db.xrefs:
                break

            s = self.dis.binary.get_section(ad)

            if s is None or s.start != s_orig.start:
                break

        if nb_entries:
            return self.api.create_jmptable(
                i.address, table_ad, nb_entries, self.dis.wordsize, dont_analyze=True)

        return False


    #
    # analyze_flow:
    # entry             address of the code to analyze.
    # entry_is_func     if true a function will be created, otherwise
    #                   instructions will be set only as "code".
    # force             if true and entry is already functions, the analysis
    #                   is forced.
    # add_if_code       if true, it means that we are not sure the entry is an
    #                   address to a code location. In this case, if the control
    #                   flow contains a bad instruction, the functions or
    #                   instructions will not be added.
    # return stack offset : if this is not a function, it returns any value.
    #
    def analyze_flow(self, entry, entry_is_func, force, add_if_code):
        if entry in self.pending:
            return

        if self.dis.binary.get_section(entry) is None:
           return

        is_def = entry in self.functions

        if not force:
            if not entry_is_func and self.db.mem.is_loc(entry) or \
                    entry_is_func and self.db.mem.is_func(entry):
                return

            # Check if this is not inside a function
            if self.db.mem.get_func_id(entry) != -1:
                return

        # If the address is in the symbol table there is an entry in
        # self.functions but the value is init to None.
        if not entry_is_func and is_def and self.functions[entry] is None:
            entry_is_func = True

        mem = self.db.mem

        if mem.is_overlapping(entry):
            return

        self.pending.add(entry)

        inner_code = {} # ad -> capstone instruction

        is_pe_import = False


        # Create a function object (see in Database)

        if entry_is_func:
            # It can be None because when symbols are loaded functions are
            # set to None initially.
            if is_def and self.functions[entry] is not None:
                func_obj = self.functions[entry]
                last_end = func_obj[FUNC_END]
                self.db.end_functions[last_end].remove(entry)
                if not self.db.end_functions[last_end]:
                    del self.db.end_functions[last_end]
                func_obj[FUNC_VARS].clear()
                func_obj[FUNC_INST_VARS_OFF].clear()
            else:
                # [func_end,
                #  flags,
                #  var_offsets,
                #  func_id,
                #  inst.addresses,
                #  stack_offset,
                #  frame_size,
                #  args_restore]
                func_obj = [-1, 0, {}, self.db.func_id_counter, {}, -1, 0]
                self.db.func_id_counter += 1

            # Check if it's a jump to an imported symbol : jmp|call *(IMPORT)
            if self.dis.binary.type == T_BIN_PE:
                if entry in self.db.imports:
                    is_pe_import = True
                    func_obj[FUNC_FLAGS] = self.db.imports[entry]
                else:
                    inst = self.dis.lazy_disasm(entry)
                    if inst is not None:
                        ptr = self.dis.binary.reverse_stripped(self.dis, inst)
                        if ptr != -1:
                            inner_code[inst.address] = inst
                            func_obj[FUNC_FLAGS] = self.db.imports[ptr]
        else:
            func_obj = None

        do_save = True

        if not is_pe_import and not inner_code:
            do_save = self.__sub_analyze_flow(func_obj, entry, inner_code, add_if_code)

        if inner_code and do_save:
            self.__add_analyzed_code(func_obj, self.db.mem, entry, inner_code,
                                     entry_is_func)

        inner_code.clear()
        self.pending.remove(entry)


    # Returns a tuple (flags, sp) or None if an error occurs
    # flags is equal to 
    def __sub_analyze_flow(self, func_obj, entry, inner_code, add_if_code):
        # If entry is not "code", we have to rollback added xrefs
        has_bad_inst = False
        if add_if_code:
            added_xrefs = []

        regsctx = self.arch_analyzer.new_regs_context()
        if regsctx is None:
            # fatal error, but don't quit to let the user save the database
            return False

        flags = 0
        stack_err = False
        args_restore = 0
        if func_obj is not None:
            frame_size = func_obj[FUNC_FRAME_SIZE]
            if frame_size == -1:
                frame_size = self.ARCH_UTILS.guess_frame_size(self, entry)
                # used in arch/*/analyzer.c
                func_obj[FUNC_FRAME_SIZE] = frame_size
        else:
            frame_size = -1

        ret_found = False
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

            if self.gctx.debugsp:
                ALL_SP[ad] = self.arch_analyzer.get_sp(regsctx)

            inner_code[ad] = inst

            ##### RETURN #####
            if self.is_ret(inst):
                self.__add_prefetch(regsctx, inst, func_obj, inner_code)
                ret_found = True

                if self.dis.is_x86 and len(inst.operands) == 1:
                    args_restore = inst.operands[0].value.imm
                    flags |= FUNC_FLAG_STDCALL

                if self.arch_analyzer.get_sp(regsctx) != 0:
                    flags |= FUNC_FLAG_ERR_STACK_ANALYSIS

            ##### UNCONDITIONAL JUMP #####
            elif self.is_uncond_jump(inst):
                self.__add_prefetch(regsctx, inst, func_obj, inner_code)
                op = inst.operands[-1]
                jmp_ad = None

                if op.type == self.ARCH_UTILS.OP_IMM:
                    jmp_ad = unsigned(op.value.imm)

                else:
                    is_jmptable = inst.address in self.jmptables

                    # Create a jumptable if necessary
                    if not is_jmptable:
                        if op.type == self.ARCH_UTILS.OP_REG:
                            jmp_ad = self.arch_analyzer.reg_value(regsctx, op.value.reg)
                            if jmp_ad is None:
                                is_jmptable = self.auto_jump_table(inst, inner_code)

                        elif op.type == self.ARCH_UTILS.OP_MEM:
                            self.arch_analyzer.analyze_operands(
                                    self, regsctx, inst, func_obj, False)
                            is_jmptable = self.auto_jump_table(inst, inner_code)

                    if is_jmptable:
                        table = self.jmptables[inst.address].table
                        for n in table:
                            r = self.arch_analyzer.clone_regs_context(regsctx)
                            stack.append((r, n))
                        self.api.add_xrefs_table(ad, table)
                        if add_if_code:
                            added_xrefs.append((ad, table))
                        continue

                    self.arch_analyzer.analyze_operands(
                            self, regsctx, inst, func_obj, False)
                    # TODO: assume there is return
                    if jmp_ad is None:
                        if entry in self.db.imports:
                            ret_found |= self.db.imports[entry] & FUNC_FLAG_NORETURN
                        else:
                            ret_found = True
                        continue

                self.api.add_xref(ad, jmp_ad)
                if self.db.mem.is_func(jmp_ad):
                    ret_found |= not self.is_func_noreturn(jmp_ad, entry)
                    fo = self.functions[jmp_ad]
                    flags = fo[FUNC_FLAGS]
                    frame_size = max(fo[FUNC_FRAME_SIZE], frame_size)
                    args_restore = fo[FUNC_ARGS_RESTORE]
                else:
                    stack.append((regsctx, jmp_ad))
                if add_if_code:
                    added_xrefs.append((ad, jmp_ad))

            ##### CONDITIONAL JUMP #####
            elif self.is_cond_jump(inst):
                prefetch = self.__add_prefetch(regsctx, inst, func_obj, inner_code)

                op = inst.operands[-1]
                if op.type == self.ARCH_UTILS.OP_IMM:
                    if prefetch is None:
                        direct_nxt = inst.address + inst.size
                    else:
                        direct_nxt = prefetch.address + prefetch.size

                    nxt_jmp = unsigned(unsigned(op.value.imm))
                    self.api.add_xref(ad, nxt_jmp)

                    if self.db.mem.is_func(direct_nxt):
                        ret_found |= not self.is_func_noreturn(direct_nxt, entry)
                        fo = self.functions[direct_nxt]
                        flags = fo[FUNC_FLAGS]
                        frame_size = max(fo[FUNC_FRAME_SIZE], frame_size)
                        args_restore = fo[FUNC_ARGS_RESTORE]
                    else:
                        stack.append((regsctx, direct_nxt))

                    if add_if_code:
                        added_xrefs.append((ad, nxt_jmp))

                    if self.db.mem.is_func(nxt_jmp):
                        ret_found |= not self.is_func_noreturn(nxt_jmp, entry)
                    else:
                        newctx = self.arch_analyzer.clone_regs_context(regsctx)
                        stack.append((newctx, nxt_jmp))
                else:
                    self.arch_analyzer.analyze_operands(
                            self, regsctx, inst, func_obj, False)
                    # TODO : jump tables for conditional jumps ?

            ##### CALL #####
            elif self.is_call(inst):
                op = inst.operands[-1]
                call_ad = None
                sp_before = self.arch_analyzer.get_sp(regsctx)

                if op.type == self.ARCH_UTILS.OP_IMM:
                    call_ad = unsigned(op.value.imm)
                elif op.type == self.ARCH_UTILS.OP_REG:
                    # FIXME : for MIPS, addresses are loaded in t9 (generally)
                    # then jalr t9 is executed. The problem here is that we
                    # will analyze twice the function. The first time is done
                    # by the function analyze_imm.
                    call_ad = self.arch_analyzer.reg_value(regsctx, op.value.reg)
                else:
                    self.arch_analyzer.analyze_operands(
                            self, regsctx, inst, func_obj, False)
                    if self.db.mem.is_func(op.mem.disp) and \
                            self.is_func_noreturn(op.mem.disp, entry):
                        self.__add_prefetch(regsctx, inst, func_obj, inner_code)
                        continue

                if call_ad is not None:
                    self.api.add_xref(ad, call_ad)

                    if add_if_code:
                        added_xrefs.append((ad, call_ad))

                    self.analyze_flow(
                            call_ad,
                            entry_is_func=True,
                            force=False,
                            add_if_code=add_if_code)

                    # TODO: if the address was alredy in the pending list
                    # we don't have a computed args size
                    # Reset the stack pointer to frame_size to handle stdcall.
                    if frame_size != -1 and call_ad in self.functions:
                        fo = self.functions[call_ad]
                        if fo is not None:
                            n = fo[FUNC_ARGS_RESTORE]
                            if n:
                                self.arch_analyzer.set_sp(regsctx, sp_before + n)

                    if self.db.mem.is_func(call_ad) and \
                            self.is_func_noreturn(call_ad, entry):
                        self.__add_prefetch(regsctx, inst, func_obj, inner_code)
                        continue

                # It seems it doesn't matter for the prefetched instruction
                nxt = inst.address + inst.size
                stack.append((regsctx, nxt))

            ##### OTHERS #####
            else:
                self.arch_analyzer.analyze_operands(
                        self, regsctx, inst, func_obj, False)

                nxt = inst.address + inst.size
                if nxt not in self.functions:
                    stack.append((regsctx, nxt))

        # Remove all xrefs, this is not a correct flow
        if add_if_code and has_bad_inst:
            for from_ad, to_ad in added_xrefs:
                if isinstance(to_ad, list):
                    self.api.rm_xrefs_table(from_ad, to_ad)
                else:
                    self.api.rm_xref(from_ad, to_ad)
            return False

        if func_obj is not None:
            if entry in self.db.imports:
                if self.db.imports[entry] & FUNC_FLAG_NORETURN:
                    flags |= FUNC_FLAG_NORETURN
            elif not ret_found:
                flags |= FUNC_FLAG_NORETURN

            func_obj[FUNC_FLAGS] = flags
            func_obj[FUNC_FRAME_SIZE] = frame_size
            func_obj[FUNC_ARGS_RESTORE] = args_restore

        return True
