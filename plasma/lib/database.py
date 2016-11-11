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
import gc
import sys
import zlib

try:
    import msgpack
except:
    print("error: you need to install msgpack")
    print("pip3 install msgpack-python")
    sys.exit(0)

import json

from plasma.lib.api import Jmptable
from plasma.lib.utils import info, warning, die
from plasma.lib.memory import Memory


VERSION = 2.7


class Database():
    def __init__(self):
        self.__init_vars()

        if msgpack.version < (0, 4, 6):
            warning("your version of msgpack is less than 0.4.6")


    def __init_vars(self):
        self.history = []
        self.symbols = {} # name -> addr
        self.demangled = {} # name -> addr
        self.user_inline_comments = {}
        self.internal_inline_comments = {}
        self.user_previous_comments = {}
        self.internal_previous_comments = {}
        self.jmptables = {}
        self.mips_gp = 0
        self.modified = False
        self.loaded = False
        self.mem = None # see lib.memory
        # func address ->
        #  [ end addr,
        #    flags,
        #    dict vars_off -> [type, name],
        #    func_id,
        #    dict inst.address -> vars_off,
        #    frame_size,
        #    args_restore,
        #  ]
        self.functions = {}
        self.func_id = {} # id -> func address
        self.xrefs = {} # addr -> list addr
        # For big data (arrays/strings) we save all addresses with an xrefs
        self.data_sub_xrefs = {} # data_address -> {addresses_with_xrefs: True}
        self.imports = {} # ad -> True (the bool is just for msgpack to save the database)
        self.immediates = {} # insn_ad -> immediate result

        self.raw_base = 0
        self.raw_type = None
        self.raw_is_big_endian = None

        # Computed variables
        self.func_id_counter = 0
        self.end_functions = {}
        self.reverse_symbols = {} # addr -> name
        self.reverse_demangled = {} # addr -> name
        self.version = VERSION


    def load(self, filename):
        gc.disable()

        dirname = os.path.dirname(filename)
        self.path = dirname + "/" if dirname != "" else ""
        self.path +=  "." + os.path.basename(filename) + ".db"

        if os.path.exists(self.path):
            info("open database %s" % self.path)

            fd = open(self.path, "rb")

            data = fd.read()
            if data.startswith(b"ZLIB"):
                data = zlib.decompress(data[4:])
            data = msgpack.unpackb(data, encoding="utf-8")
            fd.close()

            self.__load_meta(data)
            self.__load_memory(data)
            self.__load_symbols(data)
            self.__load_jmptables(data)
            self.__load_comments(data)
            self.__load_functions(data)
            self.__load_history(data)
            self.__load_xrefs(data)
            self.__load_imports(data)
            self.__load_immediates(data)

            if self.version <= 1.5:
                self.__load_labels(data)

            if self.version < VERSION:
                die("your version of plasma is too old")
            elif self.version != VERSION:
                warning("the database version is old, some information may be missing")

            self.loaded = True

        gc.enable()


    def save(self, history):
        data = {
            "version": VERSION,
            "symbols": self.symbols,
            "demangled": self.demangled,
            "history": history,
            "user_inline_comments": self.user_inline_comments,
            "internal_inline_comments": self.internal_inline_comments,
            "user_previous_comments": self.user_previous_comments,
            "internal_previous_comments": self.internal_previous_comments,
            "jmptables": [],
            "mips_gp": self.mips_gp,
            "mem": self.mem.mm,
            "functions": self.functions,
            "func_id_counter": self.func_id_counter,
            "func_id": self.func_id,
            "xrefs": self.xrefs,
            "data_sub_xrefs": self.data_sub_xrefs,
            "raw_base": self.raw_base,
            "raw_type": self.raw_type,
            "raw_is_big_endian": self.raw_is_big_endian,
            "imports": self.imports,
            "immediates": self.immediates,
        }

        for j in self.jmptables.values():
            o = {
                "inst_addr": j.inst_addr,
                "table_addr": j.table_addr,
                "table": j.table,
                "name": j.name,
            }
            data["jmptables"].append(o)

        fd = open(self.path, "wb+")
        fd.write(b"ZLIB")
        fd.write(zlib.compress(msgpack.packb(data, use_bin_type=True)))
        fd.close()


    def __load_symbols(self, data):
        self.symbols = data["symbols"]

        if self.version >= 1.9:
            self.demangled = data["demangled"]

            for name, ad in self.demangled.items():
                self.reverse_demangled[ad] = name

        if self.version <= 1.4 and self.version != -1:
            for name, a in self.symbols.items():
                self.reverse_symbols[a[0]] = name
                self.symbols[name] = a[0]
                self.mem.add(a[0], 1, a[1])
            return

        for name, ad in self.symbols.items():
            self.reverse_symbols[ad] = name
            self.symbols[name] = ad


    def __load_labels(self, data):
        for name, ad in self.labels.items():
            self.reverse_symbols[ad] = name
            self.symbols[name] = ad


    def __load_comments(self, data):
        self.user_inline_comments = data["user_inline_comments"]
        self.internal_inline_comments = data["internal_inline_comments"]
        self.user_previous_comments = data["user_previous_comments"]
        self.internal_previous_comments = data["internal_previous_comments"]


    def __load_jmptables(self, data):
        for j in data["jmptables"]:
            self.jmptables[j["inst_addr"]] = \
                Jmptable(j["inst_addr"], j["table_addr"], j["table"], j["name"])


    def __load_meta(self, data):
        self.mips_gp = data["mips_gp"]
        self.version = data["version"]


    def __load_memory(self, data):
        self.mem = Memory()
        self.mem.mm = data["mem"]


    def __load_history(self, data):
        self.history = data["history"]


    def __load_immediates(self, data):
        self.immediates = data["immediates"]


    def __load_xrefs(self, data):
        self.xrefs = data["xrefs"]
        self.data_sub_xrefs = data["data_sub_xrefs"]


    def __load_imports(self, data):
        self.imports = data["imports"]


    def __load_functions(self, data):
        self.functions = data["functions"]

        for fad, value in self.functions.items():
            # end of the function
            if value is not None:
                e = value[0]
                if e in self.end_functions:
                    self.end_functions[e].append(fad)
                else:
                    self.end_functions[e] = [fad]

        self.func_id = data["func_id"]

        try:
            self.func_id_counter = data["func_id_counter"]
        except:
            self.func_id_counter = max(self.func_id.keys()) + 1
