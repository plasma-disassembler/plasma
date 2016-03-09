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

import os
from argparse import ArgumentParser

import plasma
import plasma.lib.utils
import plasma.lib.colors
from plasma.lib.database import Database
from plasma.lib.disassembler import Disassembler, NB_LINES_TO_DISASM
from plasma.lib.utils import die, error, debug__
from plasma.lib.generate_ast import generate_ast
from plasma.lib.exceptions import ExcArch, ExcFileFormat, ExcIfelse, ExcPEFail


#
# The global context variable is always named as gctx
#
class GlobalContext():
    def __init__(self):
        # TODO : let globally ?
        plasma.lib.utils.gctx  = self
        plasma.lib.colors.gctx = self

        self.comments = True # always True, will be removed

        # For info() messages
        self.quiet = False

        self.is_interactive = False

        # Command line options
        self.sectionsname = False
        self.print_andif = True
        self.color = True
        self.max_data_size = 30
        self.filename = None
        self.syms = False
        self.calls_in_section = None
        self.entry = None # string : symbol | EP | 0xNNNN
        self.do_dump = False
        self.vim = False
        self.nb_lines = 30
        self.graph = False # Print graph != gph -> object
        self.interactive_mode = False
        self.debug = False
        self.raw_base = 0
        self.raw_big_endian = False
        self.list_sections = False
        self.print_bytes = False
        self.raw_type = None
        self.print_data = False
        self.capstone_string = 0 # See lib.ui.visual.main_cmd_inst_output
        self.show_mangling = True
        self.autoanalyzer = True

        # Built objects
        self.dis = None # Disassembler
        self.libarch = None # module lib.arch.<BIN_ARCH>
        self.db = None # Database
        self.api = None # Api


    def parse_args(self):
        parser = ArgumentParser(description=
            'Reverse engineering for x86/ARM/MIPS binaries. Generation of pseudo-C. '
            'Supported formats : ELF, PE. More commands available in the interactive'
            ' mode.    https://github.com/joelpx/plasma')
        parser.add_argument('filename', nargs='?', metavar='FILENAME')
        parser.add_argument('-nc', '--nocolor', action='store_true')
        parser.add_argument('-g', '--graph', action='store_true',
                help='Generate a file graph.dot.')
        parser.add_argument('--noandif', action='store_true',
                help="Print normal 'if' instead of 'andif'")
        parser.add_argument('--datasize', type=int, default=30, metavar='N',
                help='default 30, maximum of chars to display for strings or bytes array.')
        parser.add_argument('-x', '--entry', metavar='SYMBOLNAME|0xXXXXX|EP',
                help='Pseudo-decompilation, default is main. EP stands for entry point.')
        parser.add_argument('--vim', action='store_true',
                help='Generate syntax colors for vim')
        parser.add_argument('-s', '--symbols', action='store_true',
                help='Print all symbols')
        parser.add_argument('--sections', action='store_true',
                help='Print all sections')
        parser.add_argument('--dump', action='store_true',
                help='Dump asm without decompilation')
        parser.add_argument('-l', '--lines', type=int, default=30, metavar='N',
                help='Max lines used with --dump')
        parser.add_argument('--nbytes', type=int, default=0, metavar='N',
                help='Print n bytes.')
        parser.add_argument('-i', '--interactive', action='store_true',
                help='Interactive mode')
        parser.add_argument('-d', '--opt_debug', action='store_true')
        parser.add_argument('-ns', '--nosectionsname', action='store_true')
        parser.add_argument('--raw', metavar='x86|x64|arm|mips|mips64',
                help='Consider the input file as a raw binary')
        parser.add_argument('--rawbase', metavar='0xXXXXX',
                help='Set base address of a raw file (default=0)')
        parser.add_argument('--rawbe', action='store_true',
                help='If not set it\'s in little endian')
        parser.add_argument('-na', '--noautoanalyzer', action='store_true',
                help='Disable analysis on the entry point / symbols and don\'t scan memmory. You can force it with the command push_analyze_symbols.')

        args = parser.parse_args()

        self.debug           = args.opt_debug
        self.print_andif     = not args.noandif
        self.color           = not args.nocolor
        self.sectionsname    = not args.nosectionsname
        self.max_data_size   = args.datasize
        self.filename        = args.filename
        self.raw_type        = args.raw
        self.raw_base        = args.rawbase
        self.syms            = args.symbols
        self.entry           = args.entry
        self.do_dump         = args.dump
        self.vim             = args.vim
        self.interactive_mode = args.interactive
        self.nb_lines        = args.lines
        self.graph           = args.graph
        self.raw_big_endian  = args.rawbe
        self.list_sections   = args.sections
        self.autoanalyzer    = not args.noautoanalyzer

        if args.nbytes == 0:
            self.nbytes = 4
            self.print_bytes = False
        else:
            self.nbytes = int(args.nbytes)
            self.print_bytes = True

        if self.raw_base is not None:
            try:
                self.raw_base = int(self.raw_base, 16)
            except:
                error("--rawbase must be in hex format")
                die()
        else:
            self.raw_base = 0


    def load_file(self, filename=None):
        if filename is None:
            filename = self.filename

        if not os.path.exists(filename):
            error("file {self.filename} doesn't exist".format(self=self))
            if self.interactive_mode:
               return False
            die()

        if not os.path.isfile(filename):
            error("this is not a file".format(self=self))
            if self.interactive_mode:
               return False
            die()

        self.db = Database()
        self.db.load(filename)

        if self.raw_base != 0:
            self.db.raw_base = self.raw_base

        if self.raw_type is not None:
            self.db.raw_type = self.raw_type

        if self.raw_big_endian is not None:
            self.db.raw_is_big_endian = self.raw_big_endian

        if self.db.loaded:
            self.raw_base = self.db.raw_base
            self.raw_type = self.db.raw_type
            self.raw_big_endian = self.db.raw_is_big_endian

        try:
            dis = Disassembler(filename, self.raw_type,
                               self.raw_base, self.raw_big_endian,
                               self.db)
        except ExcArch as e:
            error("arch %s is not supported" % e.arch)
            if self.interactive_mode:
                return False
            die()
        except ExcFileFormat:
            error("the file is not PE or ELF binary")
            if self.interactive_mode:
                return False
            die()
        except ExcPEFail as e:
            error(str(e.e))
            error("it seems that there is a random bug in pefile, you shoul retry.")
            error("please report here https://github.com/joelpx/plasma/issues/16")
            if self.interactive_mode:
                return False
            die()

        self.dis = dis
        self.libarch = dis.load_arch_module()

        return True


    def get_addr_context(self, ad):
        adctx = AddrContext(self)
        if isinstance(ad, int):
            adctx.entry = self.db.mem.get_head_addr(ad)
            return adctx
        ret = adctx.init_address(ad) # here ad is a string
        if not ret:
            return None
        adctx.entry = self.db.mem.get_head_addr(adctx.entry)
        return adctx


#
# This is a context for a disassembling at a specific address, it contains
# the graph, the output... It's always named as "ctx"
#
class AddrContext():
    def __init__(self, gctx):
        # TODO : let globally ?
        plasma.lib.colors.ctx = self

        self.gctx = gctx # Global context
        self.entry = 0
        self.addr_color = {}
        self.color_counter = 112
        self.seen = set()
        # If an address of an instruction cmp is here, it means that we
        # have fused with an if, so don't print this instruction.
        self.all_fused_inst = set()
        self.is_dump = False
        self.gph = None
        self.ast = None


    def init_address(self, entry):
        if isinstance(entry, int):
            self.entry = entry
            return True

        if entry == "EP":
            self.entry = self.gctx.dis.binary.get_entry_point()
            return True

        if entry is None:
            if self.gctx.raw_type is not None:
                self.entry = 0
                return True

            self.entry = self.gctx.db.symbols.get("main", None) or \
                         self.gctx.db.symbols.get("_main", None)

            if self.entry is None:
                error("symbol main or _main not found")
                if self.gctx.interactive_mode:
                    return False
                die()
            return True

        is_hexa = entry.startswith("0x")

        if not is_hexa and self.gctx.api.is_reserved_prefix(entry):
            entry = entry[entry.index("_") + 1:]
            is_hexa = True

        if is_hexa:
            try:
                self.entry = int(entry, 16)
            except:
                error("bad hexa string %s" % entry)
                if self.gctx.interactive_mode:
                    return False
                die()
            return True

        self.entry = self.gctx.db.demangled.get(entry, None) or \
                     self.gctx.db.symbols.get(entry, None) or \
                     self.gctx.dis.binary.section_names.get(entry, None)

        if self.entry is None:
            error("symbol %s not found" % entry)
            if self.gctx.interactive_mode:
                return False
                die()

        return True


    def decompile(self):
        self.is_dump = False
        self.gph, pe_nb_new_syms = self.gctx.dis.get_graph(self.entry)

        if self.gph is None:
            error("capstone can't disassemble here")
            return None
        self.gph.simplify()

        if self.gctx.db.loaded and pe_nb_new_syms:
            self.gctx.db.modified = True
        
        try:
            self.gph.loop_detection(self.entry)
            ast, correctly_ended = generate_ast(self)
            if not correctly_ended:
                debug__("Second try...")
                self.gph.loop_detection(self.entry, True)
                ast, _ = generate_ast(self)

            self.ast = ast
        except ExcIfelse as e:
            error("can't have a ifelse here     %x" % e.addr)
            if self.gctx.interactive_mode:
                return None
            die()

        o = self.gctx.libarch.output.Output(self)
        o._ast(self.entry, ast)
        self.output = o
        return o


    def dump_asm(self, lines=NB_LINES_TO_DISASM, until=-1):
        self.is_dump = True
        o = self.gctx.dis.dump_asm(self, lines, until=until)
        self.output = o
        return o


    def dump_xrefs(self):
        self.is_dump = True
        o = self.gctx.dis.dump_xrefs(self, self.entry)
        self.output = o
        return o
