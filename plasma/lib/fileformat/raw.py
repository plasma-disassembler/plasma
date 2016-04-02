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

from plasma.lib.fileformat.binary import SectionAbs, Binary


class Raw(Binary):
    def __init__(self, filename, raw_type, raw_base, raw_big_endian):
        Binary.__init__(self)

        self.raw = open(filename, "rb").read()
        self.raw_base = raw_base
        self.raw_big_endian = raw_big_endian

        arch_lookup = {
            "x86": "x86",
            "x64": "x64",
            "arm": "ARM",
            "mips": "MIPS32",
            "mips64": "MIPS64",
        }

        self.arch = arch_lookup.get(raw_type, None)

        self.add_section(
            raw_base,
            "raw",
            len(self.raw),
            len(self.raw),
            False, # is_exec
            True, # is_data
            self.raw)


    def is_big_endian(self):
        return self.raw_big_endian


    def get_entry_point(self):
        return self.raw_base
