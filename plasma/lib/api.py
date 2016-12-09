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
        self.arch = gctx.dis.binary.arch
        self.is_big_endian = gctx.dis.binary.is_big_endian()


    def entry_point(self):
        """
        Returns the address of the entry point.
        """
        return self.__binary.get_entry_point()


    # This function remove all xrefs for arrays and offsets.
    # It's called only from set_* functions to create data
    # For security, we must run explicitly the "undefine" function
    # on code and function to create bytes or something else.
    def __undefine(self, ad, force=False):
        # TODO: remove comments

        if not force and self.mem.is_code(ad):
            return False

        # Remove xrefs if we erased offsets.

        if self.mem.is_array(ad):
            entry_type = self.mem.get_array_entry_type(ad)
            if MEM_WOFFSET <= entry_type <= MEM_QOFFSET:
                entry_size = self.mem.get_size_from_type(entry_type)
                total_size = self.mem.get_size(ad)
                i = ad
                s = self.__binary.get_section(ad)
                end = min(ad + total_size, s.end + 1)
                while i < end:
                    off = s.read_int(i, entry_size)
                    if off is not None and off in self.__db.xrefs:
                        self.rm_xref(i, off)
                    i += entry_size

        elif self.mem.is_offset(ad):
            entry_size = self.mem.get_size(ad)
            s = self.__binary.get_section(ad)
            off = s.read_int(ad, entry_size)
            if off is not None and off in self.__db.xrefs:
                self.rm_xref(ad, off)

        return True


    def undefine(self, ad):
        """
        Undefine data/code/function.
        returns True if ok
        """
        self.__undefine(ad, force=True)
        entry = ad

        # Clear all instructions
        fid = self.mem.get_func_id(ad)
        is_code = self.mem.is_code(ad)

        if fid != -1:
            entry = self.__db.func_id[fid]
            func_obj = self.__db.functions[entry]
            del self.__db.functions[entry]
            if func_obj is not None:
                del self.__db.end_functions[func_obj[FUNC_END]]
                del self.__db.func_id[fid]

        self.mem.rm_range(entry, max(self.mem.get_size(entry), 1))
        if entry in self.__db.xrefs:
            self.mem.add(entry, 1, MEM_BYTE)

        if is_code:
            # TODO: manage overlapping by calling mem.rm_range ?
            gph, _ = self.__dis.get_graph(entry)
            del gph.nodes[entry]
            for n in gph.nodes:
                self.mem.rm_range(n, max(self.mem.get_size(n), 1))
                if entry in self.__db.xrefs:
                    self.mem.add(entry, 1, MEM_BYTE)

        return True


    def set_code(self, ad):
        """
        Analyze and create instructions at the address ad.
        TODO: check if nothing is erased before.
        returns True if ok
        """
        if self.mem.is_overlapping(ad):
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
        if self.mem.is_func(ad) or self.mem.get_func_id(ad) != -1 or \
                self.mem.is_overlapping(ad):
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
        if not self.__undefine(ad):
            return False
        if ad in self.__db.xrefs:
            self.mem.add(ad, 1, MEM_BYTE)
        else:
            # not useful to store it in the database
            self.mem.rm_range(ad, max(self.mem.get_size(ad), 1))
        return True


    def set_word(self, ad):
        """
        Define a word at ad (2 bytes).
        returns True if ok
        """
        if not self.__undefine(ad):
            return False
        self.mem.add(ad, 2, MEM_WORD)
        return True


    def set_dword(self, ad):
        """
        Define a double word at ad (4 bytes).
        returns True if ok
        """
        if not self.__undefine(ad):
            return False
        self.mem.add(ad, 4, MEM_DWORD)
        return True


    def set_qword(self, ad):
        """
        Define a qword at ad (8 bytes).
        returns True if ok
        """
        if not self.__undefine(ad):
            return False
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
        if not self.__undefine(ad):
            return False
        self.mem.add(ad, sz, MEM_ASCII)
        return True


    def set_offset(self, ad, ty=None, async_analysis=True, dont_analyze=False):
        """
        Define ad as an offset. If the value is an address to a
        code location, an analysis will be done. ty should be in
        [WORD, DWORD, QWORD], if not set the type at the address
        ad is retrieved.
        async_analysis and dont_analyze should be used internally ONLY.

        returns True if ok
        """
        if ty is None:
            ty = self.mem.get_type(ad)
            sz = self.mem.get_size(ad)
        else:
            sz = self.mem.get_size_from_type(ty)

        if ty == -1 or ty < MEM_WORD or ty > MEM_QWORD:
            return False

        s = self.__binary.get_section(ad)
        off = s.read_int(ad, sz)
        if off is None:
            return False

        s = self.__binary.get_section(off)
        if s is None:
            return False

        head = self.mem.get_head_addr(off)
        if not self.mem.exists(head):
            self.mem.add(off, 1, MEM_UNK)

        self.add_xref(ad, off)

        if not self.__undefine(ad):
            return False

        if ty == MEM_WORD:
            self.mem.add(ad, sz, MEM_WOFFSET)
        elif ty == MEM_DWORD:
            self.mem.add(ad, sz, MEM_DOFFSET)
        elif ty == MEM_QWORD:
            self.mem.add(ad, sz, MEM_QOFFSET)

        if dont_analyze:
            return True

        if self.__analyzer.first_inst_are_code(off):
            if async_analysis:
                self.__analyzer.msg.put(
                    (off, self.__analyzer.has_prolog(off), False, True,
                     self.__queue_wait))
                self.__queue_wait.get()
            else:
                self.__analyzer.analyze_flow(
                    off, self.__analyzer.has_prolog(off), False, True)

        return True


    def set_array(self, ad, nb_entries, entry_type, dont_analyze=False):
        """
        returns True if ok.
        dont_analyze should be used internally ONLY.
        """
        if entry_type < MEM_BYTE or entry_type > MEM_QOFFSET or nb_entries <= 0:
            return False

        entry_size = self.mem.get_size_from_type(entry_type)
        sz = entry_size * nb_entries

        s = self.__binary.get_section(ad)
        if ad + sz > s.end + 1:
            return False

        if MEM_WOFFSET <= entry_type <= MEM_QOFFSET:
            end = ad + sz
            i = ad
            while i < end:
                ty = self.mem.get_type(i)
                if not (MEM_WOFFSET <= ty <= MEM_QOFFSET):
                    self.set_offset(i, self.mem.get_type_from_size(entry_size), dont_analyze=dont_analyze)
                i += entry_size
        elif not self.__undefine(ad):
            return False

        self.mem.add(ad, sz, MEM_ARRAY, entry_type)
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
        lst = []
        if ad in self.__db.data_sub_xrefs:
            for x in self.__db.data_sub_xrefs[ad]:
                lst += self.__db.xrefs[x]
            for i, x in enumerate(lst):
                ad = self.__db.mem.get_head_addr(x)
                if ad != x:
                    lst[i] = ad
            return set(lst)

        if ad in self.__db.xrefs:
            lst = set(self.__db.xrefs[ad])
        return lst


    def add_symbol(self, ad, name, force=False):
        """
        Match the symbol name to ad. If ad has already a symbol, it's
        renamed. If name exists, a suffix '_counter' is added.

        force could be set to True if the name starts with a
        reserved prefix (sub_, loc_, ret_, loop_, ...). Use it if
        you are sure.

        returns True if ok
        """
        if not force and self.is_reserved_prefix(name):
            return False

        if name in self.__db.symbols:
            i = 0
            while 1:
                name = "%s_%d" % (name, i)
                i += 1
                if name not in self.__db.symbols:
                    break

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


    def create_jmptable(self, inst_addr, table_addr, nb_entries, entry_size, dont_analyze=False):
        """
        Create a jump table.
        inst_addr: address of the jump
        table_addr: address of the table
        nb_entries: number of entries to read
        entry_size: size of each address in the table
        dont_analyze should be used internally ONLY.

        returns True if ok
        """

        table = self.read_array(table_addr, nb_entries, entry_size)
        if not table:
            return False

        if entry_size == 2:
            entry_type = MEM_WOFFSET
        elif entry_size == 4:
            entry_type = MEM_DOFFSET
        elif entry_size == 8:
            entry_type = MEM_QOFFSET

        self.set_array(table_addr, nb_entries, entry_type, dont_analyze=True)

        name = "jmptable_%x" % table_addr
        self.add_symbol(table_addr, name, force=True)
        self.__db.jmptables[inst_addr] = Jmptable(inst_addr, table_addr, table, name)
        self.__db.internal_inline_comments[inst_addr] = \
            "switch statement %s[%d]" % (name, nb_entries)

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

        if dont_analyze:
            return True

        # If it's inside a function, the analysis is done on the entire function
        func_id = self.mem.get_func_id(inst_addr)
        if func_id == -1:
            self.__analyzer.msg.put((inst_addr, False, True, True, self.__queue_wait))
        else:
            ad = self.__db.func_id[func_id]
            self.__analyzer.msg.put((ad, True, True, True, self.__queue_wait))

        self.__queue_wait.get()

        return True


    def add_xref(self, from_ad, to_ad):
        if to_ad in self.__db.xrefs:
            if from_ad not in self.__db.xrefs[to_ad]:
                self.__db.xrefs[to_ad].append(from_ad)
        else:
            self.__db.xrefs[to_ad] = [from_ad]

        head = self.mem.get_head_addr(to_ad)
        if head in self.__db.data_sub_xrefs:
            self.__db.data_sub_xrefs[head][to_ad] = True
            if head != to_ad:
                end = head + self.mem.get_size(head)
                self.mem.mm[to_ad] = [end - to_ad, MEM_HEAD, head]


    def add_xrefs_table(self, from_ad, to_ad_list):
        for x in to_ad_list:
            self.add_xref(from_ad, x)


    def rm_xref(self, from_ad, to_ad):
        if to_ad in self.__db.xrefs:
            if from_ad in self.__db.xrefs[to_ad]:
                self.__db.xrefs[to_ad].remove(from_ad)
            if not self.__db.xrefs[to_ad]:
                del self.__db.xrefs[to_ad]

        head = self.mem.get_head_addr(to_ad)
        if head in self.__db.data_sub_xrefs:
            del self.__db.data_sub_xrefs[head][to_ad]


    def rm_xrefs_table(self, from_ad, to_ad_list):
        for x in to_ad_list:
            self.rm_xref(from_ad, x)


    def rm_xrefs_range(self, start, size):
        end = start + size
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
        ctx = self.__gctx.get_addr_context(name, quiet=True)
        if ctx is None:
            return -1
        return ctx.entry


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

        if ty == MEM_ARRAY:
            ty = self.mem.mm[ad][2]

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
        if MEM_WOFFSET <= ty <= MEM_QOFFSET:
            return "off_%x" % ad

        return None


    def disasm(self, ad):
        """
        Returns a capstone instruction object.
        """
        return self.__dis.lazy_disasm(ad)


    def dump_asm(self, ad, nb_lines=10, until=-1):
        """
        Returns an Output object. You can then call the function print.
        until is an end address, if it's set nb_lines is ignored.
        """
        ctx = self.__gctx.get_addr_context(ad)
        return ctx.dump_asm(lines=nb_lines, until=until)


    def decompile(self, ad):
        """
        Returns an Output object. You can then call the function print.
        until is an end address, if it's set nb_lines is ignored.
        """
        ctx = self.__gctx.get_addr_context(ad)
        return ctx.decompile()


    def get_func_addr(self, ad):
        """
        Returns the function address where ad is. It returns None if
        ad is not in a function.
        """
        func_id = self.mem.get_func_id(ad)
        if func_id == -1:
            return None
        return self.__db.func_id[func_id]


    def set_frame_size(self, func_ad, frame_size):
        """
        Set a new frame size for the function at address `func_ad'.
        frame_size must be >= 0
        """
        if frame_size < 0 or func_ad not in self.__db.functions:
            return False
        self.__db.functions[func_ad][FUNC_FRAME_SIZE] = frame_size
        self.__analyzer.msg.put((func_ad, True, True, False, self.__queue_wait))
        self.__queue_wait.get()
        return True


    def set_noreturn(self, func_ad, val):
        """
        val is a boolean. It sets the function as noreturn or not
        TODO: reload the analyzer
        """
        if func_ad not in self.__db.functions:
            return False
        if val:
            self.__db.functions[func_ad][FUNC_FLAGS] |= FUNC_FLAG_NORETURN
        else:
            self.__db.functions[func_ad][FUNC_FLAGS] &= ~FUNC_FLAG_NORETURN
