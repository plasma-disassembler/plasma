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


class Memory():
    def __init__(self):
        self.code = {}


    def add(self, ad, size, ty=MEM_CODE):
        self.code[ad] = (size, ty)


    def is_code(self, ad):
        if ad in self.code:
            return self.code[ad][1] == MEM_CODE
        return False
