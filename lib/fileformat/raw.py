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
    def __init__(self, filename, raw_type, raw_base, raw_big_endian):
        import capstone as CAPSTONE

        self.raw = open(filename, "rb").read()
        self.raw_type = raw_type
        self.raw_base = raw_base
        self.raw_big_endian = raw_big_endian

        self.arch_lookup = {
            "x86": CAPSTONE.CS_ARCH_X86,
            "x64": CAPSTONE.CS_ARCH_X86,
            "arm": CAPSTONE.CS_ARCH_ARM,
            "mips": CAPSTONE.CS_ARCH_MIPS,
            "mips64": CAPSTONE.CS_ARCH_MIPS,
        }

        self.arch_mode_lookup = {
            "x86": CAPSTONE.CS_MODE_32,
            "x64": CAPSTONE.CS_MODE_64,
            "arm": CAPSTONE.CS_ARCH_ARM,
            "mips": CAPSTONE.CS_MODE_MIPS32,
            "mips64": CAPSTONE.CS_MODE_MIPS64,
        }


    def load_static_sym(self):
        return


    def load_dyn_sym(self):
        return


    def load_data_sections(self):
        return


    def is_address(self, imm):
        return None, False


    def get_section_meta(self, addr):
        return "", self.raw_base, self.raw_base + len(self.raw) - 1


    def check_addr(self, addr):
        ad = addr - self.raw_base
        if ad >= len(self.raw) or ad < 0:
            return (False, False)
        return (True, True)


    def section_stream_read(self, addr, size):
        ad = addr - self.raw_base
        if ad >= len(self.raw) or ad < 0:
            return b""
        end = self.raw_base + len(self.raw)
        return self.raw[ad:ad + min(size, end - ad)]


    def get_string(self, addr):
        return ""


    def get_arch(self):
        import capstone as CAPSTONE
        arch = self.arch_lookup.get(self.raw_type, None)
        mode = self.arch_mode_lookup.get(self.raw_type, None)
        if self.raw_big_endian:
            mode |= CAPSTONE.CS_MODE_BIG_ENDIAN
        else:
            mode |= CAPSTONE.CS_MODE_LITTLE_ENDIAN
        return arch, mode


    def get_arch_string(self):
        return ""


    def get_entry_point(self):
        return 0


    def iter_sections(self):
        return []
