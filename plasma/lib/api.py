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

from queue import Queue

from plasma.lib.fileformat.binary import SectionAbs
from plasma.lib.consts import *


class Jmptable():
    def __init__(self, inst_addr, table_addr, table, name):
        self.inst_addr = inst_addr
        self.table_addr = table_addr
        self.table = table
        self.name = name


class Api():
    def __init__(self, gctx, analyzer):
        self.__gctx = gctx
        self.__binary = gctx.dis.binary
        self.__dis = gctx.dis
        self.__analyzer = analyzer
        self.__db = gctx.db
        self.mem = gctx.db.mem
        self.__queue_wait = Queue()


    def entry_point(self):
        """
        Returns the address of the entry point.
        """
        return self.__binary.get_entry_point()


    def __undefine(self, ad, end_range):
        # TODO : check if instructions contains an address with xrefs
        if ad in self.__db.functions:
            # TODO : undefine all func_id of each instructions
            func_obj = self.__db.functions[ad]
            del self.__db.functions[ad]
            if func_obj is not None:
                del self.__db.end_functions[func_obj[FUNC_END]]
                del self.__db.func_id[func_obj[FUNC_ID]]


    def set_code(self, ad):
        """
        Analyze and create instructions at the address ad.
        TODO: check if nothing is erased before.
        returns True if ok
        """
        if self.mem.is_code(ad):
            return False
        self.__analyzer.msg.put((ad, False, False, False, self.__queue_wait))
        self.__queue_wait.get()
        return True


    def set_function(self, ad):
        """
        Define and analyze a function at the address ad.
        TODO: check if nothing is erased before.
        returns True if ok
        """
        if self.mem.is_func(ad):
            return False
        if self.mem.get_func_id(ad) != -1:
            return False
        self.__analyzer.msg.put((ad, True, True, False, self.__queue_wait))
        self.__queue_wait.get()
        return True


    # To avoid too much references to a byte in the memory class, we keep
    # only bytes with an xref, otherwise a byte is equivalent to an unknown
    # data.
    def set_byte(self, ad):
        """
        Define a byte at ad. If there is no xref to ad, the byte is
        deleted from memory.
        returns True if ok
        """
        self.__undefine(ad, 1)
        if ad in self.__db.xrefs:
            self.mem.add(ad, 1, MEM_BYTE)
        else:
            # not useful to store it in the database
            self.mem.rm_range(ad, ad + 1)
        return True


    def set_word(self, ad):
        """
        Define a word at ad (2 bytes).
        returns True if ok
        """
        self.__undefine(ad, 2)
        self.mem.add(ad, 2, MEM_WORD)
        return True


    def set_dword(self, ad):
        """
        Define a double word at ad (4 bytes).
        returns True if ok
        """
        self.__undefine(ad, 4)
        self.mem.add(ad, 4, MEM_DWORD)
        return True


    def set_qword(self, ad):
        """
        Define a qword at ad (8 bytes).
        returns True if ok
        """
        self.__undefine(ad, 8)
        self.mem.add(ad, 8, MEM_QWORD)
        return True


    def set_ascii(self, ad):
        """
        Define an ascii string at ad (null terminated).
        returns True if ok
        """
        sz = self.__binary.is_string(ad, min_bytes=1)
        if not sz:
            return False
        self.__undefine(ad, sz)
        self.mem.add(ad, sz, MEM_ASCII)
        return True


    def set_offset(self, ad):
        """
        Define ad as a pointer. If the value is an address to a
        code location, an analysis will be done. ad must be set as
        WORD, DWORD or QWORD.
        returns True if ok
        """
        ty = self.mem.get_type(ad)
        if ty == -1 or ty < MEM_WORD or ty > MEM_QWORD:
            return False

        sz = self.mem.get_size(ad)

        s = self.__binary.get_section(ad)
        off = s.read_int(ad, sz)
        if off is None:
            return False

        s = self.__binary.get_section(off)
        if s is None:
            return False

        self.add_xref(ad, off)
        if not self.mem.exists(off):
            self.mem.add(off, 1, MEM_UNK)

        self.__undefine(ad, sz)
        self.mem.add(ad, sz, MEM_OFFSET)

        if self.__analyzer.first_inst_are_code(off):
            self.__analyzer.msg.put(
                (off, self.__analyzer.has_prolog(off), False, True,
                 self.__queue_wait))
            self.__queue_wait.get()

        return True


    def is_string(self, ad, section=None, min_bytes=2):
        """
        Check if an ascii string can be found at ad.

        The parameter section is the section where ad is. It's just use for
        optimization and used to not recall get_section.
        """
        # It must contains at least one character and the null byte.
        sz = self.__binary.is_string(ad, min_bytes, s=section)
        if not sz:
            return False
        return True


    def get_string(self, ad, section=None):
        """
        Returns the string at ad (str type). If the buffer is not
        null-terminated or contains non ascii chars, it returns None.

        The parameter section is the section where ad is. It's just use for
        optimization and used to not recall get_section.
        """
        return self.__binary.get_string(ad, s=section)


    def read_byte(self, ad, section=None):
        """
        Read a byte, it returns None if ad is not an address.
        The parameter section is the section where ad is. It's just use for
        optimization and used to not recall get_section.
        """
        if section is None:
            section = self.__binary.get_section(ad)
            if section is None:
                return None
        return section.read_byte(ad)


    def read_word(self, ad, section=None):
        """
        Read a word, it returns None if ad is not an address.
        The parameter section is the section where ad is. It's just use for
        optimization and used to not recall get_section.
        """
        if section is None:
            section = self.__binary.get_section(ad)
            if section is None:
                return None
        return section.read_word(ad)


    def read_dword(self, ad, section=None):
        """
        Read a double word, it returns None if ad is not an address.

        The parameter section is the section where ad is. It's just use for
        optimization and used to not recall get_section.
        """
        if section is None:
            section = self.__binary.get_section(ad)
            if section is None:
                return None
        return section.read_dword(ad)


    def read_qword(self, ad, section=None):
        """
        Read a qword, it returns None if ad is not an address.

        The parameter section is the section where ad is. It's just use for
        optimization and used to not recall get_section.
        """
        if section is None:
            section = self.__binary.get_section(ad)
            if section is None:
                return None
        return section.read_qword(ad)


    def get_section(self, ad):
        """
        Returns a section or None if ad is not an address.
        """
        return self.__binary.get_section(ad)


    def add_section(self, start_address, name, virt_size, real_size,
                    is_exec, is_data, data):
        """
        Create a new section at start_address. name is a string and data
        is a bytes. The real_size should be less than virt_size, but nothing
        will be done if virt_size is less than real_size.
        """
        if virt_size < real_size:
            return
        self.__binary.add_section(start_address, name, virt_size,
                real_size, is_exec, is_data, data)


    def iter_sections(self):
        """
        Iterates over sections.
        """
        return self.__binary.iter_sections()


    def read_array(self, ad, nb_entries, size_word, section=None):
        """
        Returns a list of words at the address ad. size_word must be in
        [1, 2, 4, 8] otherwise the function returns None. The returned
        list could be less than nb_entries if it's at the end of a
        section.
        
        The parameter section is the section where ad is. It's just use for
        optimization and used to not recall get_section.
        """
        if size_word != 1 and size_word != 2 and size_word != 4 and size_word != 8:
            return None

        if section is None:
            section = self.__binary.get_section(ad)

        array = []
        l = 0

        while l < nb_entries:
            val = section.read_int(ad, size_word)
            if val is None:
                return array
            array.append(val)
            ad += size_word
            l += 1
        return array


    def xrefsto(self, ad):
        """
        Returns a list of all xrefs to ad.
        """
        if ad in self.__dis.xrefs:
            return list(self.__dis.xrefs[ad])
        return []


    def add_symbol(self, ad, name, force=False):
        """
        Match the symbol name to ad. If ad has already a symbol
        or if name is already defined, it's erased first.

        force could be set to True if the name starts with a
        reserved prefix (sub_, loc_, ret_, loop_, ...). Use it if
        you are sure.

        returns True if ok
        """
        if not force and self.is_reserved_prefix(name):
            return False

        if name in self.__db.symbols:
            last = self.__db.symbols[name]
            del self.__db.reverse_symbols[last]

        if ad in self.__db.reverse_symbols:
            last = self.__db.reverse_symbols[ad]
            del self.__db.symbols[last]

        self.__db.symbols[name] = ad
        self.__db.reverse_symbols[ad] = name

        if not self.mem.exists(ad):
            self.mem.add(ad, 1, MEM_UNK)

        return True


    def rm_symbol(self, ad):
        """
        Remove the symbol matched by the address ad.
        """
        if ad in self.__db.reverse_symbols:
            name = self.__db.reverse_symbols[ad]
            del self.__db.reverse_symbols[ad]

        if name in self.__db.symbols:
            del self.__db.symbols[name]


    def create_jmptable(self, inst_addr, table_addr, entry_size, nb_entries):
        """
        Create a jump table.
        inst_addr: address of the jump
        table_addr: address of the table
        entry_size: size of each address in the table
        nb_entries: number of entries to read

        returns True if ok
        """

        table = self.read_array(table_addr, nb_entries, entry_size)
        if not table:
            return False

        name = "jmptable_%x" % table_addr
        self.add_symbol(table_addr, name, force=True)
        self.__db.jmptables[inst_addr] = Jmptable(inst_addr, table_addr, table, name)
        self.__db.internal_inline_comments[inst_addr] = "switch statement %s" % name

        all_cases = {}
        for ad in table:
            all_cases[ad] = []

        case = 0
        for ad in table:
            all_cases[ad].append(case)
            case += 1

        for ad in all_cases:
            self.__db.internal_previous_comments[ad] = \
                ["case %s  %s" % (
                    ", ".join(map(str, all_cases[ad])),
                    name
                )]

        # If it's inside a function, the analysis is done on the entire function
        func_id = self.mem.get_func_id(inst_addr)
        if func_id == -1:
            self.__analyzer.msg.put((inst_addr, False, True, False, self.__queue_wait))
        else:
            ad = self.__db.func_id[func_id]
            self.__analyzer.msg.put((ad, True, True, False, self.__queue_wait))

        self.__queue_wait.get()


    def add_xref(self, from_ad, to_ad):
        if isinstance(to_ad, list):
            for x in to_ad:
                if x in self.__db.xrefs:
                    if from_ad not in self.__db.xrefs[x]:
                        self.__db.xrefs[x].append(from_ad)
                else:
                    self.__db.xrefs[x] = [from_ad]
        else:
            if to_ad in self.__db.xrefs:
                if from_ad not in self.__db.xrefs[to_ad]:
                    self.__db.xrefs[to_ad].append(from_ad)
            else:
                self.__db.xrefs[to_ad] = [from_ad]


    def rm_xrefs(self, from_ad, to_ad):
        if isinstance(to_ad, list):
            for x in to_ad:
                if from_ad in self.__db.xrefs[x]:
                    self.__db.xrefs[x].remove(from_ad)
                if not self.__db.xrefs[x]:
                    del self.__db.xrefs[x]
        elif to_ad in self.__db.xrefs:
            if from_ad in self.__db.xrefs[to_ad]:
                self.__db.xrefs[to_ad].remove(from_ad)
            if not self.__db.xrefs[to_ad]:
                del self.__db.xrefs[to_ad]


    def rm_xrefs_range(self, start, end):
        while start < end:
            if start in self.xrefs:
                del self.xrefs[start]
            start += 1


    def is_reserved_prefix(self, name):
        for n in RESERVED_PREFIX:
            if name.startswith(n):
                return True
        return False


    def get_addr_from_symbol(self, name):
        """
        From the given symbol, this function returns the corresponding
        address. If name starts with a reserved prefix, the hexa string
        is converted in decimal.
        """
        if self.is_reserved_prefix(name):
            try:
                return int(name[name.index("_") + 1:], 16)
            except:
                return -1
        return self.__db.symbols.get(name, -1)


    def get_symbol(self, ad):
        """
        Returns a string from an address ad. It returns None if ad is not
        defined as UNK, FUNC, CODE, *WORD, ... and if it's not a defined
        symbol. If the mangling is activated it returns the demangled string.
        """
        if ad in self.__db.reverse_symbols:
            if self.__gctx.show_mangling:
                s = self.__db.reverse_demangled.get(ad, None)
                if s is not None:
                    return s
            return self.__db.reverse_symbols[ad]

        ty = self.mem.get_type(ad)
        if ty == MEM_FUNC:
            return "sub_%x" % ad
        if ty == MEM_CODE:
            if ad in self.__db.xrefs:
                return "loc_%x" % ad
            return None
        if ty == MEM_DWORD:
            return "dword_%x" % ad
        if ty == MEM_BYTE:
            return "byte_%x" % ad
        if ty == MEM_QWORD:
            return "qword_%x" % ad
        if ty == MEM_UNK:
            return "unk_%x" % ad
        if ty == MEM_WORD:
            return "word_%x" % ad
        if ty == MEM_ASCII:
            return "asc_%x" % ad
        if ty == MEM_OFFSET:
            return "off_%x" % ad

        return None


    def disasm(self, ad):
        """
        Returns a capstone instruction object.
        """
        return self.__dis.lazy_disasm(ad)
