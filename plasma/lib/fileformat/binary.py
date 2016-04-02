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

import bisect
from time import time
import subprocess

from plasma.lib.utils import debug__, print_no_end, get_char, BYTES_PRINTABLE_SET
from plasma.lib.colors import color_section

T_BIN_ELF = 0
T_BIN_PE  = 1
T_BIN_RAW = 2
T_BIN_UNK = 3


class SectionAbs():
    # virt_size: size of the mapped section in memory
    def __init__(self, name, start, virt_size, real_size, is_exec, is_data, data):
        self.name = name
        self.start = start
        self.virt_size = virt_size
        self.real_size = real_size
        self.end = start + virt_size - 1
        self.real_end = start + real_size - 1
        self.is_exec = is_exec
        self.is_data = is_data
        self.data = data
        self.big_endian = False # set in lib.disassembler

    def print_header(self):
        print_no_end(color_section(self.name.ljust(20)))
        print_no_end(" [ ")
        print_no_end(hex(self.start))
        print_no_end(" - ")
        print_no_end(hex(self.end))
        print_no_end(" - %d - %d" % (self.virt_size, self.real_size))
        print(" ]")

    def read(self, ad, size):
        if ad >= self.real_end:
            return b""
        off = ad - self.start
        return self.data[off:off + size]

    def read_int(self, ad, size):
        if size == 1:
            return self.read_byte(ad)
        if size == 2:
            return self.read_word(ad)
        if size == 4:
            return self.read_dword(ad)
        if size == 8:
            return self.read_qword(ad)
        return None

    def read_byte(self, ad):
        if ad >= self.real_end:
            return None
        off = ad - self.start
        return self.data[off]

    def read_word(self, ad):
        if ad >= self.real_end:
            return None
        off = ad - self.start
        w = self.data[off:off+2]
        if len(w) != 2:
            return None
        if self.big_endian:
            return (w[0] << 8) + w[1]
        return (w[1] << 8) + w[0]

    def read_dword(self, ad):
        if ad >= self.real_end:
            return None
        off = ad - self.start
        w = self.data[off:off+4]
        if len(w) != 4:
            return None
        if self.big_endian:
            return (w[0] << 24) + (w[1] << 16) + (w[2] << 8) + w[3]
        return (w[3] << 24) + (w[2] << 16) + (w[1] << 8) + w[0]

    def read_qword(self, ad):
        if ad >= self.real_end:
            return None
        off = ad - self.start
        w = self.data[off:off+8]
        if len(w) != 8:
            return None
        if self.big_endian:
            return (w[0] << 56) + (w[1] << 48) + (w[2] << 40) + (w[3] << 32) + \
                   (w[4] << 24) + (w[5] << 16) + (w[6] << 8) + w[7]
        return (w[7] << 56) + (w[6] << 48) + (w[5] << 40) + (w[4] << 32) + \
               (w[3] << 24) + (w[2] << 16) + (w[1] << 8) + w[0]


class SegmentAbs(SectionAbs):
    def __init__(self, name, start, virt_size, real_size, is_exec, is_data,
                 data, file_offset, big_endian):
        self.name = name
        self.start = start
        self.virt_size = virt_size
        self.real_size = real_size
        self.end = start + virt_size - 1
        self.real_end = start + real_size - 1
        self.is_exec = is_exec
        self.is_data = is_data
        self.file_offset = file_offset
        self.data = data
        self.big_endian = big_endian



class Binary(object):
    def __init__(self):
        self.reverse_symbols = {} # ad -> name
        self.symbols = {} # name -> ad
        self.section_names = {}
        self.demangled = {} # name -> ad
        self.reverse_demangled = {} # ad -> name
        self.imports = {} # ad -> True (the bool is just for msgpack to save the database)
        self._abs_sections = {} # start section -> SectionAbs
        self._sorted_sections = [] # bisect list, contains section start address

        # for elf
        self._abs_segments = {}
        self._sorted_segments = []

        # To be compatible with CLE, used only in ELF
        self.rebase_addr = 0

        # It will be set in Disassembler !
        self.wordsize = 0
        self.type = -1


    def get_section(self, ad):
        i = bisect.bisect_right(self._sorted_sections, ad)
        if not i:
            return None
        start = self._sorted_sections[i - 1]
        s = self._abs_sections[start]
        if ad <= s.end:
            return s
        return None


    def add_section(self, start_address, name, virt_size, real_size,
                    is_exec, is_data, data):
        if is_exec or is_data:
            bisect.insort_left(self._sorted_sections, start_address)
        self._abs_sections[start_address] = SectionAbs(
                name,
                start_address,
                virt_size,
                real_size,
                is_exec,
                is_data,
                data)


    # for elf
    def get_segment(self, ad):
        i = bisect.bisect_right(self._sorted_segments, ad)
        if not i:
            return None
        start = self._sorted_segments[i - 1]
        s = self._abs_segments[start]
        if ad <= s.end:
            return s
        return None


    def is_address(self, ad):
        s = self.get_section(ad)
        return s is not None and s.start != 0


    def get_next_section(self, ad):
        i = bisect.bisect_right(self._sorted_sections, ad)
        if i >= len(self._sorted_sections):
            return None
        start = self._sorted_sections[i]
        s = self._abs_sections[start]
        if ad <= s.end:
            return s
        return None


    def get_first_addr(self):
        return self._sorted_sections[0]


    def get_last_addr(self):
        ad = self._sorted_sections[-1]
        return self._abs_sections[ad].end


    def read(self, ad, size):
        s = self.get_section(ad)
        if s is None:
            return b""
        return s.read(ad, size)


    def read_byte(self, ad):
        s = self.get_section(ad)
        if ad >= s.real_end:
            return None
        return s.read_byte(ad)


    def rename_sym(self, name):
        count = 0
        n = "%s_%d" % (name, count)
        while n in self.symbols:
            n = "%s_%d" % (name, count)
            count += 1
        return n


    # not optimized
    def get_section_by_name(self, name):
        for s in self._abs_sections.values():
            if s.name == name:
                return s
        return None


    def get_prev_section(self, ad):
        s = self.get_section(ad)
        i = bisect.bisect_right(self._sorted_sections, s.start - 1)
        if i == 0:
            return None
        start = self._sorted_sections[i - 1]
        return self._abs_sections[start]


    def iter_sections(self):
        for ad in self._sorted_sections:
            yield self._abs_sections[ad]


    # TODO : move in SectionAbs
    def get_string(self, addr, max_data_size=-1, s=None):
        if s is None:
            s = self.get_section(addr)
            if s is None:
                return None

        data = s.data
        off = addr - s.start
        txt = []

        c = 0
        i = 0
        while (i < max_data_size or max_data_size == -1) and off < len(data):
            c = data[off]
            if c == 0:
                break
            if c not in BYTES_PRINTABLE_SET:
                break
            txt.append(get_char(c))
            off += 1
            i += 1

        if i == max_data_size:
            if c != 0:
                txt.append("...")
        elif c != 0 or i == 0:
            return None

        return ''.join(txt)


    # Returns the size of the string or 0 if it's not an ascii string
    def is_string(self, addr, min_bytes=3, s=None):
        if s is None:
            s = self.get_section(addr)
            if s is None:
                return 0

        data = s.data
        off = addr - s.start
        n = 0
        c = 0
        while off < len(data):
            c = data[off]
            if c == 0:
                n += 1
                break
            if c in BYTES_PRINTABLE_SET:
                n += 1
            else:
                break
            off += 1

        # consider this is a string when there are more than 2 chars
        # with a null byte
        if c == 0 and n >= min_bytes:
            return n
        return 0


    def load_section_names(self):
        # Used for the auto-completion
        for ad, sec in self._abs_sections.items():
            self.section_names[sec.name] = ad


    def demangle_symbols(self):
        addr = []
        lookup_names = []
        for n, ad in self.symbols.items():
            if n.startswith("_Z") or n.startswith("__Z"):
                addr.append(ad)
                lookup_names.append(n.split("@@")[0])

        if not addr:
            return

        # http://stackoverflow.com/questions/6526500/c-name-mangling-library-for-python
        args = ['c++filt']
        args.extend(lookup_names)
        pipe = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        stdout, _ = pipe.communicate()
        demangled = stdout.split(b"\n")[:-1]

        self.reverse_demangled = dict(zip(addr, demangled))

        for ad, n in self.reverse_demangled.items():
            n = n.decode()
            i = n.find("(")
            # remove the protoype
            if i != -1:
                n = n[:i]
            self.reverse_demangled[ad] = n
            self.demangled[n] = ad


    def load_static_sym(self):
        return


    def load_dyn_sym(self):
        return


    def is_big_endian(self):
        raise NotImplementedError


    def get_entry_point(self):
        raise NotImplementedError
