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

from plasma.lib.consts import *

#
# Values stored in self.mm for each type :
# The third element is type specific.
#
# MEM_UNK:
#   nothing is saved
#
# MEM_CODE:
# MEM_FUNC:
#     [insn_size, MEM_CODE|MEM_FUNC, function_id (-1 if not set)]
#
# MEM_BYTE:
#     if the address is not in xrefs nothing is saved, otherwise :
#     [1, MEM_BYTE]
#
# MEM_WORD:
# MEM_DWORD:
# MEM_QWORD:
#     [2|4|8, MEM_WORD|MEM_DWORD|MEM_QWORD]
#
# MEM_WOFFSET:
# MEM_DOFFSET:
# MEM_QOFFSET:
#     [2|4|8, MEM_WOFFSET|MEM_DOFFSET|MEM_QOFFSET]
#
# MEM_ASCII: (null terminated)
#     [size, MEM_ASCII]
#
# MEM_HEAD: (refernce to the head of the data, used for big strings/data)
#     [size_until_end, MEM_HEAD, head_address]
#
# MEM_ARRAY:
#     [size_in_bytes, MEM_ARRAY, entry_type]
#


class Memory():
    def __init__(self):
        #
        # Each item contains a list :
        # [size, type, value]
        #
        # type == MEM_CODE
        # the value is the function id where the instruction is.
        #

        self.mm = {}
        self.size_lookup = {
            MEM_BYTE: 1,
            MEM_WORD: 2,
            MEM_DWORD: 4,
            MEM_QWORD: 8,
            MEM_WOFFSET: 2,
            MEM_DOFFSET: 4,
            MEM_QOFFSET: 8,
        }
        self.rev_size_lookup = {
            1: MEM_BYTE,
            2: MEM_WORD,
            4: MEM_DWORD,
            8: MEM_QWORD,
        }

        # Set by lib.disassembler
        self.xrefs = None
        self.data_sub_xrefs = None


    def __len__(self):
        return len(self.mm)


    # If you are not sure about what you do, don't use this function.
    # Maybe you should see in lib.api.
    def add(self, ad, size, ty, val=None):
        self.rm_range(ad, max(self.get_size(ad), size))

        if val is None:
            self.mm[ad] = [size, ty]
        else:
            self.mm[ad] = [size, ty, val]

        if ty == MEM_UNK:
            return

        if size > 1 and (ty == MEM_ARRAY or ty == MEM_ASCII):
            # Set the MEM_HEAD if it's a big data
            # Save inside xrefs

            end = ad + size
            self.data_sub_xrefs[ad] = {}
            i = ad

            if i in self.xrefs:
                self.data_sub_xrefs[ad][i] = True

            i += 1
            while i < end:
                if i in self.xrefs:
                    self.data_sub_xrefs[ad][i] = True
                if i in self.mm:
                    self.mm[i] = [end - i, MEM_HEAD, ad]
                elif i % BLOCK_SIZE == 0:
                    self.mm[i] = [end - i, MEM_HEAD, ad]
                i += 1

            self.mm[end - 1] = [1, MEM_HEAD, ad]


    def __rm_block_heads(self, ad, sz):
        end = ad + sz
        while ad < end:
            if ad in self.mm:
                if ad in self.xrefs:
                    self.mm[ad][0] = 1
                    self.mm[ad][1] = MEM_UNK
                else:
                    del self.mm[ad]
            ad += 1


    def rm_range(self, ad, sz):
        end = ad + sz
        while ad < end:
            if ad in self.mm:
                obj = self.mm[ad]
                ty = obj[1]
                if ty == MEM_ARRAY or ty == MEM_ASCII:
                    if ad in self.data_sub_xrefs:
                        del self.data_sub_xrefs[ad]
                    self.__rm_block_heads(ad, obj[0])
                    ad += obj[0]
                    continue
                if ty == MEM_HEAD:
                    ad = obj[2]
                    obj = self.mm[ad]
                    if ad in self.data_sub_xrefs:
                        del self.data_sub_xrefs[ad]
                    self.__rm_block_heads(ad, obj[0])
                    ad += obj[0]
                    continue

                if ad in self.xrefs:
                    obj[0] = 1
                    obj[1] = MEM_UNK
                else:
                    del self.mm[ad]
            ad += 1


    def type(self, ad, ty):
        self.mm[ad][1] = ty


    def is_code(self, ad):
        if ad in self.mm:
            ty = self.mm[ad][1]
            return ty == MEM_CODE or ty == MEM_FUNC
        return False


    def is_func(self, ad):
        if ad in self.mm:
            return self.mm[ad][1] == MEM_FUNC
        return False


    def is_loc(self, ad):
        if ad in self.mm:
            return self.mm[ad][1] == MEM_CODE
        return False


    def is_offset(self, ad):
        if ad in self.mm:
            ty = self.mm[ad][1]
            return  MEM_WOFFSET <= ty <= MEM_QOFFSET
        return False


    def is_data(self, ad):
        if ad in self.mm:
            ty = self.mm[ad][1]
            return MEM_BYTE <= ty <= MEM_QWORD or ty == MEM_ARRAY
        return False


    def is_unk(self, ad):
        if ad in self.mm:
            return self.mm[ad][1] == MEM_UNK
        return True


    def is_array(self, ad):
        if ad in self.mm:
            return self.mm[ad][1] == MEM_ARRAY
        return False


    def get_func_id(self, ad):
        if not self.is_code(ad):
            return -1
        return self.mm[ad][2]


    def get_type(self, ad):
        if ad in self.mm:
            return self.mm[ad][1]
        return -1


    def exists(self, ad):
        return ad in self.mm


    def get_size_from_type(self, ty):
        return self.size_lookup.get(ty, 1)


    def get_size(self, ad):
        if ad in self.mm:
            return self.mm[ad][0]
        return 1


    def get_type_from_size(self, sz):
        return self.rev_size_lookup.get(sz, 1)


    def get_array_entry_type(self, ad):
        if self.is_array(ad):
            return self.mm[ad][2]
        return -1


    def get_head_addr(self, ad):
        # Now check if need to go backward (maybe we are inside an instruction
        # or a string/data) : we should return the head of the data.

        end = ad - BLOCK_SIZE
        i = ad

        while i >= end:
            if i in self.mm:
                m = self.mm[i]
                # Check if the address is in the range
                if ad < i + m[0]:
                    if m[1] == MEM_HEAD:
                        # The head address is stored at the offset 2
                        return m[2]
                    return i
                return ad
            i -= 1

        # Nothing found: it's an unknown data or byte
        return ad


    def is_overlapping(self, ad):
        return ad != self.get_head_addr(ad)
