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

MEM_UNK = 1
MEM_CODE = 2
MEM_FUNC = 3


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


    def add(self, ad, size, ty, val=0):
        self.mm[ad] = [size, ty, val]


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
