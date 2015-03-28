#
# Reverse : reverse engineering for x86 binaries
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


import lib.fileformat.binary


class Raw:
    def __init__(self, filename, bits):
        self.raw = open(filename, "rb").read()
        self.bits = bits
        self.arch_lookup = {
          32: lib.fileformat.binary.ARCH_x86,
          64: lib.fileformat.binary.ARCH_x64
        }


    def load_static_sym(self):
        return


    def load_dyn_sym(self):
        return


    def load_data_sections(self):
        return


    def is_address(self, imm):
        return None, False


    def get_section(self, addr):
        flags = {
            "exec": True
        }
        return (self.raw, 0, flags)


    def get_string(self, addr):
        return ""


    def get_arch(self):
        return self.arch_lookup[self.bits]


    def get_entry_point(self):
        return 0
