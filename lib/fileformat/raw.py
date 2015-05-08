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


class Raw:
    def __init__(self, filename, raw_type):
        import capstone as CAPSTONE

        self.raw = open(filename, "rb").read()
        self.raw_type = raw_type

        self.arch_lookup = {
            "x86": CAPSTONE.CS_ARCH_X86,
            "x64": CAPSTONE.CS_ARCH_X86,
            "arm": CAPSTONE.CS_ARCH_ARM,
        }

        self.arch_mode_lookup = {
            "x86": CAPSTONE.CS_MODE_32,
            "x64": CAPSTONE.CS_MODE_64,
            "arm": CAPSTONE.CS_ARCH_ARM,
        }


    def load_static_sym(self):
        return


    def load_dyn_sym(self):
        return


    def load_data_sections(self):
        return


    def is_address(self, imm):
        return None, False


    def get_section_start(self, addr):
        return 0


    def section_stream_read(self, addr, size):
        if addr >= len(self.raw):
            raise ExcNotAddr(addr)
        return self.raw[addr:addr+size]


    def get_string(self, addr):
        return ""


    def get_arch(self):
        return self.arch_lookup.get(self.raw_type, None), \
               self.arch_mode_lookup.get(self.raw_type, None)


    def get_arch_string(self):
        return ""


    def get_entry_point(self):
        return 0


    def iter_sections(self):
        return []
