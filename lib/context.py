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

import lib.utils
import lib.colors


class Context():
    def __init__(self):
        self.update()
        self.reset_all()

        # For info() messages
        self.quiet = False

        # Parameter options
        self.comments = True
        self.sectionsname = False
        self.print_andif = True
        self.color = True
        self.max_data_size = 30
        self.filename = None
        self.syms = False
        self.calls_in_section = None
        self.entry = None # string : symbol | EP | 0xNNNN
        self.dump = False
        self.vim = False
        self.lines = 30
        self.graph = False # Print graph != gph -> object
        self.interactive_mode = False
        self.debug = False
        self.raw_base = 0
        self.raw_big_endian = False
        self.list_sections = False
        self.print_bytes = False
        self.print_data = False


    def reset_all(self):
        # Built objects
        self.dis = None
        self.gph = None
        self.libarch = None
        self.raw_type = None
        self.db = None
        self.reset_vars()


    def reset_vars(self):
        # Other variables
        self.entry_addr = 0 # address where we disassemble,
                            # same as self.entry but it's an int
        self.addr_color = {}
        self.reverse_labels = {} # label -> addr
        self.labels = {} # addr -> label
        self.color_counter = 112
        self.local_vars_idx = {}
        self.local_vars_size = []
        self.local_vars_name = []
        self.vars_counter = 1
        self.seen = set()

        # If an address of an instruction cmp is here, it means that we
        # have fused with an if, so don't print this instruction.
        self.all_fused_inst = set()


    def update(self):
        # TODO : let globally ?
        lib.utils.ctx  = self
        lib.colors.ctx = self
