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

##############################################################################
#                                                                            #
# This file is inspired/copied and adapted from the project                  #
# https://github.com/angr/cle/. You can find the LICENSE in the directory    #
# relocations/.                                                              #
#                                                                            #
##############################################################################

# FIXME : The code from CLE was just ported to work. Some function in
# relocations/generic may fail, because not every relocators have been ported.

import struct
import bisect

from elftools.elf.elffile import (ELFFile, SymbolTableSection,
        StringTableSection, RelocationSection)
from elftools.elf.sections import NullSection
from elftools.elf.constants import SH_FLAGS, P_FLAGS

from plasma.lib.utils import warning, die
from plasma.lib.fileformat.binary import SegmentAbs, Binary
from plasma.lib.exceptions import ExcElf
from plasma.lib.fileformat.relocations import get_relocation
from plasma.lib.fileformat.relocations.generic import MipsGlobalReloc, MipsLocalReloc


# SHF_WRITE=0x1
# SHF_ALLOC=0x2
# SHF_EXECINSTR=0x4
# SHF_MERGE=0x10
# SHF_STRINGS=0x20
# SHF_INFO_LINK=0x40
# SHF_LINK_ORDER=0x80
# SHF_OS_NONCONFORMING=0x100
# SHF_GROUP=0x200
# SHF_TLS=0x400
# SHF_MASKOS=0x0ff00000
# SHF_EXCLUDE=0x80000000
# SHF_MASKPROC=0xf0000000



class ELF(Binary):
    def __init__(self, db, filename):
        Binary.__init__(self)

        fd = open(filename, "rb")
        self.elf = ELFFile(fd)
        self.db = db

        self.__parsed_reloc_tables = set()
        self.dtags = {}
        self.jmprel = []
        self.dynamic_seg = None

        self.set_arch_name()

        if self.arch == "MIPS32":
            self.dynamic_tag_translation = {
                0x70000001: "DT_MIPS_RLD_VERSION",
                0x70000005: "DT_MIPS_FLAGS",
                0x70000006: "DT_MIPS_BASE_ADDRESS",
                0x7000000a: "DT_MIPS_LOCAL_GOTNO",
                0x70000011: "DT_MIPS_SYMTABNO",
                0x70000012: "DT_MIPS_UNREFEXTNO",
                0x70000013: "DT_MIPS_GOTSYM",
                0x70000016: "DT_MIPS_RLD_MAP",
                0x70000032: "DT_MIPS_PLTGOT"
            }
        elif self.arch == "MIPS64":
            self.dynamic_tag_translation = {
                0x70000001: "DT_MIPS_RLD_VERSION",
                0x70000005: "DT_MIPS_FLAGS",
                0x70000006: "DT_MIPS_BASE_ADDRESS",
                0x7000000a: "DT_MIPS_LOCAL_GOTNO",
                0x70000011: "DT_MIPS_SYMTABNO",
                0x70000012: "DT_MIPS_UNREFEXTNO",
                0x70000013: "DT_MIPS_GOTSYM",
                0x70000016: "DT_MIPS_RLD_MAP"
            }
        else:
            self.dynamic_tag_translation = {}

        reloc = 0

        # Load sections
        for s in self.elf.iter_sections():
            if not s.name:
                continue

            # Keep only sections R|W|X
            # TODO : is it sufficiant ?
            if s.header.sh_flags & 0xf == 0:
                continue

            name = s.name.decode()
            start = s.header.sh_addr

            if start == 0:
                start = reloc
                reloc += s.header.sh_size

            data = s.data()

            self.add_section(
                start,
                s.name.decode(),
                s.header.sh_size,
                len(data),
                self.__section_is_exec(s),
                self.__section_is_data(s),
                data)

        # Load segments
        rename_counter = 1
        seen = set()
        for seg in self.elf.iter_segments():
            if seg.header.p_type == "PT_DYNAMIC":
                self.dynamic_seg = seg

            if seg.header.p_type != "PT_LOAD":
                continue

            name = seg.header.p_type
            if name in seen:
                name += "_%d" % rename_counter
                rename_counter += 1

            seen.add(name)
            start = seg.header.p_vaddr
            bisect.insort_left(self._sorted_segments, start)

            is_data = self.__segment_is_data(seg)
            is_exec = self.__segment_is_exec(seg)
            data = seg.data()

            self._abs_segments[start] = SegmentAbs(
                    name,
                    start,
                    seg.header.p_memsz,
                    len(data),
                    is_exec,
                    is_data,
                    data,
                    seg.header.p_offset,
                    not self.elf.little_endian)

        # No section headers, we add segments in sections
        if len(self._abs_sections) == 0:
            self._abs_sections = self._abs_segments
            self._sorted_sections = self._sorted_segments


    def read_addr_at(self, ad):
        seg = self.get_segment(ad)
        if self.wordsize == 4:
            return seg.read_dword(ad)
        else:
            return seg.read_qword(ad)


    def __translate_dynamic_tag(self, tag):
        if isinstance(tag, int):
            return self.dynamic_tag_translation[tag]
        return tag


    def __get_offset(self, ad):
        seg = self.get_segment(ad)
        return seg.file_offset + ad - seg.start


    def load_dyn_sym(self):
        if self.dynamic_seg is None:
            return

        self.dtags = {}

        for tag in self.dynamic_seg.iter_tags():
            # Create a dictionary, mapping DT_* strings to their values
            tagstr = self.__translate_dynamic_tag(tag.entry.d_tag)
            self.dtags[tagstr] = tag.entry.d_val

        # None of the following things make sense without a string table
        if "DT_STRTAB" not in self.dtags:
            return

        # To handle binaries without section headers, we need to hack around
        # pyreadelf's assumptions make our own string table
        fakestrtabheader = {
            "sh_offset": self.__get_offset(self.dtags["DT_STRTAB"]),
        }
        strtab = StringTableSection(
                fakestrtabheader, "strtab_plasma", self.elf.stream)

        # ...
        # Here in CLE was checked the DT_SONAME 
        # ...

        # None of the following structures can be used without a symbol table
        if "DT_SYMTAB" not in self.dtags or "DT_SYMENT" not in self.dtags:
            return

        # Construct our own symbol table to hack around pyreadelf
        # assuming section headers are around
        fakesymtabheader = {
            "sh_offset": self.__get_offset(self.dtags["DT_SYMTAB"]),
            "sh_entsize": self.dtags["DT_SYMENT"],
            "sh_size": 0
        } # bogus size: no iteration allowed
        self.dynsym = SymbolTableSection(
                fakesymtabheader, "symtab_plasma", self.elf.stream,
                self.elf, strtab)

        # mips' relocations are absolutely screwed up, handle some of them here.
        self.__relocate_mips()

        # perform a lot of checks to figure out what kind of relocation
        # tables are around
        rela_type = None
        if "DT_PLTREL" in self.dtags:
            if self.dtags["DT_PLTREL"] == 7:
                rela_type = "RELA"
                relentsz = self.elf.structs.Elf_Rela.sizeof()
            elif self.dtags["DT_PLTREL"] == 17:
                rela_type = "REL"
                relentsz = self.elf.structs.Elf_Rel.sizeof()
            else:
                raise ExcElf("DT_PLTREL is not REL or RELA?")
        else:
            if "DT_RELA" in self.dtags:
                rela_type = "RELA"
                relentsz = self.elf.structs.Elf_Rela.sizeof()
            elif "DT_REL" in self.dtags:
                rela_type = "REL"
                relentsz = self.elf.structs.Elf_Rel.sizeof()
            else:
                return

        # try to parse relocations out of a table of type DT_REL{,A}
        if "DT_" + rela_type in self.dtags:
            reloffset = self.dtags["DT_" + rela_type]
            relsz = self.dtags["DT_" + rela_type + "SZ"]
            fakerelheader = {
                "sh_offset": self.__get_offset(reloffset),
                "sh_type": "SHT_" + rela_type,
                "sh_entsize": relentsz,
                "sh_size": relsz
            }
            reloc_sec = RelocationSection(
                    fakerelheader, "reloc_plasma",
                    self.elf.stream, self.elf)
            self.__register_relocs(reloc_sec)

        # try to parse relocations out of a table of type DT_JMPREL
        if "DT_JMPREL" in self.dtags:
            jmpreloffset = self.dtags["DT_JMPREL"]
            jmprelsz = self.dtags["DT_PLTRELSZ"]
            fakejmprelheader = {
                "sh_offset": self.__get_offset(jmpreloffset),
                "sh_type": "SHT_" + rela_type,
                "sh_entsize": relentsz,
                "sh_size": jmprelsz
            }
            jmprel_sec = RelocationSection(
                    fakejmprelheader, "jmprel_plasma",
                    self.elf.stream, self.elf)

            self.jmprel = self.__register_relocs(jmprel_sec)

        self.__resolve_plt()


    def __relocate_mips(self):
        if 'DT_MIPS_BASE_ADDRESS' not in self.dtags:
            return
        # The MIPS GOT is an array of addresses, simple as that.
        # number of local GOT entries
        got_local_num = self.dtags['DT_MIPS_LOCAL_GOTNO']

        # a.k.a the index of the first global GOT entry
        # index of first symbol w/ GOT entry
        symtab_got_idx = self.dtags['DT_MIPS_GOTSYM']

        symbol_count = self.dtags['DT_MIPS_SYMTABNO']
        gotaddr = self.dtags['DT_PLTGOT']

        for i in range(2, got_local_num):
            symbol = self.dynsym.get_symbol(i)
            reloc = MipsLocalReloc(self, symbol, gotaddr + i * self.wordsize)
            self.__save_symbol(reloc, reloc.symbol.entry.st_value)

        for i in range(symbol_count - symtab_got_idx):
            symbol = self.dynsym.get_symbol(i + symtab_got_idx)
            reloc = MipsGlobalReloc(self, symbol,
                            gotaddr + (i + got_local_num) * self.wordsize)
            self.__save_symbol(reloc, reloc.symbol.entry.st_value)
            self.jmprel.append(reloc)


    def __resolve_plt(self):
        # For PPC32 and PPC64 the address to save is 'got'

        if self.arch in ('x86', 'x64'):
            for rel in self.jmprel:
                got = rel.addr
                # 0x6 is the size of the plt's jmpq instruction in x86_64
                ad = self.read_addr_at(got) - 6
                self.__save_symbol(rel, ad)

        elif self.arch in ('ARM', 'AARCH64', 'MIPS32', 'MIPS64'):
            for rel in self.jmprel:
                got = rel.addr
                ad = self.read_addr_at(got)
                self.__save_symbol(rel, ad)


    def __save_symbol(self, rel, ad):
        if ad == 0:
            return

        name = rel.symbol.name.decode()

        if name in self.symbols:
            name = self.rename_sym(name)

        if rel.is_import:
            self.imports[ad] = True

        if self.is_function(rel.symbol):
            self.db.functions[ad] = None

        self.reverse_symbols[ad] = name
        self.symbols[name] = ad


    def __register_relocs(self, section):
        if section.header["sh_offset"] in self.__parsed_reloc_tables:
            return
        self.__parsed_reloc_tables.add(section.header["sh_offset"])

        relocs = []
        for r in section.iter_relocations():
            # MIPS64 is just plain old fucked up
            # https://www.sourceware.org/ml/libc-alpha/2003-03/msg00153.html
            if self.arch == "MIPS64":
                # Little endian addionally needs one of its fields reversed... WHY
                if self.elf.little_endian:
                    r.entry.r_info_sym = r.entry.r_info & 0xFFFFFFFF
                    r.entry.r_info = struct.unpack(">Q", struct.pack("<Q",
                            r.entry.r_info))[0]

                type_1 = r.entry.r_info & 0xFF
                type_2 = r.entry.r_info >> 8 & 0xFF
                type_3 = r.entry.r_info >> 16 & 0xFF
                extra_sym = r.entry.r_info >> 24 & 0xFF
                if extra_sym != 0:
                    die("r_info_extra_sym is nonzero??? PLEASE SEND HELP")

                sym = self.dynsym.get_symbol(r.entry.r_info_sym)

                if type_1 != 0:
                    r.entry.r_info_type = type_1
                    reloc = self._make_reloc(r, sym)
                    if reloc is not None:
                        relocs.append(reloc)
                        self.__save_symbol(reloc, reloc.symbol.entry.st_value)
                if type_2 != 0:
                    r.entry.r_info_type = type_2
                    reloc = self._make_reloc(r, sym)
                    if reloc is not None:
                        relocs.append(reloc)
                        self.__save_symbol(reloc, reloc.symbol.entry.st_value)
                if type_3 != 0:
                    r.entry.r_info_type = type_3
                    reloc = self._make_reloc(r, sym)
                    if reloc is not None:
                        relocs.append(reloc)
                        self.__save_symbol(reloc, reloc.symbol.entry.st_value)
            else:
                if "sh_link" in section.header:
                    symtab = self.reader.get_section(section.header["sh_link"])
                    sym = symtab.get_symbol(r.entry.r_info_sym)
                else:
                    sym = self.dynsym.get_symbol(r.entry.r_info_sym)

                reloc = self._make_reloc(r, sym)
                if reloc is not None:
                    relocs.append(reloc)
                    self.__save_symbol(reloc, reloc.symbol.entry.st_value)
        return relocs


    def _make_reloc(self, reloc_sec, symbol):
        addend = reloc_sec.entry.r_addend if reloc_sec.is_RELA() else None
        RelocClass = get_relocation(self.arch,
                                    reloc_sec.entry.r_info_type)
        if RelocClass is None:
            return None
        return RelocClass(self, symbol, reloc_sec.entry.r_offset, addend)


    def load_static_sym(self):
        symtab = self.elf.get_section_by_name(b".symtab")
        if symtab is None:
            return
        dont_save = [b"$a", b"$t", b"$d"]
        is_arm = self.arch == "ARM"

        for sy in symtab.iter_symbols():
            if is_arm and sy.name in dont_save:
                continue

            ad = sy.entry.st_value
            if ad != 0 and sy.name != b"":
                name = sy.name.decode()

                if self.is_address(ad):
                    if name in self.symbols:
                        name = self.rename_sym(name)

                    self.reverse_symbols[ad] = name
                    self.symbols[name] = ad

                    if self.is_function(sy):
                        self.db.functions[ad] = None


    def __section_is_data(self, s):
        mask = SH_FLAGS.SHF_WRITE | SH_FLAGS.SHF_ALLOC
        return s.header.sh_flags & mask and not self.__section_is_exec(s)


    def __section_is_exec(self, s):
        return s.header.sh_flags & SH_FLAGS.SHF_EXECINSTR


    def __segment_is_data(self, s):
        mask = P_FLAGS.PF_W | P_FLAGS.PF_R
        return s.header.p_flags & mask and not self.__segment_is_exec(s)


    def __segment_is_exec(self, s):
        return s.header.p_flags & P_FLAGS.PF_X


    def is_function(self, sy):
        return sy.entry.st_info.type == "STT_FUNC"


    def set_arch_name(self):
        arch = self.elf.get_machine_arch()

        if arch == "MIPS":
            if self.elf.elfclass == 32:
                arch += "32"
            elif self.elf.elfclass == 64:
                arch += "64"

        self.arch = arch


    def is_big_endian(self):
        return not self.elf.little_endian


    def get_entry_point(self):
        return self.elf.header['e_entry']
