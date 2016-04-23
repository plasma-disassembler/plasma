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
        }
        self.rev_size_lookup = {
            1: MEM_BYTE,
            2: MEM_WORD,
            4: MEM_DWORD,
            8: MEM_QWORD,
        }


    def __len__(self):
        return len(self.mm)


    def add(self, ad, size, ty, val=0):
        self.mm[ad] = [size, ty, val]

        if ty == MEM_UNK:
            return

        # don't call rm_range, it will be called so many times
        end = ad + size
        i = ad + 1
        while i < end:
            if i in self.mm:
                del self.mm[i]
            i += 1

        # Set the MEM_HEAD if it's a big data
        if size > MEM_QWORD:
            end = ad + size
            i = ad + BLOCK_SIZE
            while i < end:
                self.mm[i] = [i - ad, MEM_HEAD, ad]
                i += BLOCK_SIZE
            self.mm[end - 1] = [end - ad, MEM_HEAD, ad]


    def rm_range(self, ad, end):
        while ad < end:
            if ad in self.mm:
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
            return self.mm[ad][1] == MEM_OFFSET
        return False


    def is_data(self, ad):
        if ad in self.mm:
            ty = self.mm[ad][1]
            return MEM_BYTE <= ty <= MEM_QWORD
        return False


    def is_unk(self, ad):
        if ad in self.mm:
            return self.mm[ad][1] == MEM_UNK
        return True


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


    def find_type(self, sz):
        return self.rev_size_lookup.get(sz, 1)


    def get_head_addr(self, ad):
        # Now check if need to go backward (maybe we are inside an instruction
        # or a string)

        end = ad - BLOCK_SIZE
        i = ad

        while i >= end:
            if i in self.mm:
                m = self.mm[i]
                if m[1] == MEM_HEAD:
                    # The head address is stored at the offset 2
                    return m[2]
                # Check if the address is in the range
                if i + m[0] > ad:
                    return i
                return ad
            i -= 1

        # It's only unknown data or .db
        return ad


    def is_inside_mem(self, ad):
        return ad != self.get_head_addr(ad)
