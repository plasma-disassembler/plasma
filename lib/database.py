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

import os
import gc
import sys

try:
    import msgpack
except:
    print("error: you need to install msgpack")
    print("pip3 install msgpack-python")
    sys.exit(0)

import json

from lib.disassembler import Jmptable
from lib.utils import info, error, die, warning
from lib.fileformat.binary import SYM_UNK, SYM_FUNC
from lib.memory import Memory


VERSION = 1.1


class Database():
    def __init__(self):
        self.__init_vars()

        if msgpack.version < (0, 4, 6):
            warning("your version of msgpack is less than 0.4.6")


    def __init_vars(self):
        self.history = []
        self.symbols = {}
        self.user_inline_comments = {}
        self.internal_inline_comments = {}
        self.user_previous_comments = {}
        self.internal_previous_comments = {}
        self.jmptables = {}
        self.mips_gp = -1
        self.modified = False
        self.loaded = False
        self.mem = None
        self.functions = {}

        # Computed variables
        self.func_id_counter = 0
        self.func_id = {} # id -> func address
        self.end_functions = {}
        self.reverse_symbols = {}
        self.version = VERSION


    def load(self, filename):
        gc.disable()

        self.__init_vars()

        dirname = os.path.dirname(filename)
        self.path = dirname + "/" if dirname != "" else ""
        self.path +=  "." + os.path.basename(filename) + ".db"

        if os.path.exists(self.path):
            info("open database %s" % self.path)

            fd = open(self.path, "rb")

            data = self.__check_old_json_db(fd)
            if data is None:
                data = msgpack.unpackb(fd.read(), encoding="utf-8")
                fd.close()

            self.__load_meta(data)
            self.__load_symbols(data)
            self.__load_jmptables(data)
            self.__load_comments(data)
            self.__load_memory(data)
            self.__load_functions(data)
            self.__load_history(data)

            self.loaded = True

        gc.enable()


    def save(self, history):
        data = {
            "symbols": self.symbols,
            "history": history,
            "user_inline_comments": self.user_inline_comments,
            "internal_inline_comments": self.internal_inline_comments,
            "user_previous_comments": self.user_previous_comments,
            "internal_previous_comments": self.internal_previous_comments,
            "jmptables": [],
            "mips_gp": self.mips_gp,
            "mem_code": self.mem.code,
            "functions": self.functions,
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
        fd.write(msgpack.packb(data, use_bin_type=True))
        fd.close()


    def __load_symbols(self, data):
        self.symbols = data["symbols"]
        for name, a in self.symbols.items():
            self.reverse_symbols[a[0]] = [name, a[1]]
            self.symbols[name] = [a[0], a[1]]


    def __load_comments(self, data):
        self.user_inline_comments = data["user_inline_comments"]
        self.internal_inline_comments = data["internal_inline_comments"]
        self.user_previous_comments = data["user_previous_comments"]
        self.internal_previous_comments = data["internal_previous_comments"]


    def __load_jmptables(self, data):
        try:
            for j in data["jmptables"]:
                self.jmptables[j["inst_addr"]] = \
                    Jmptable(j["inst_addr"], j["table_addr"], j["table"], j["name"])
        except:
            # Not available in previous versions, this try will be
            # removed in the future
            pass


    def __load_meta(self, data):
        try:
            self.mips_gp = data["mips_gp"]
        except:
            # Not available in previous versions, this try will be
            # removed in the future
            pass

        try:
            self.version = data["version"]
        except:
            # Not available in previous versions, this try will be
            # removed in the future
            pass


    def __load_memory(self, data):
        self.mem = Memory()

        try:
            self.mem.code = data["mem_code"]
        except:
            # Not available in previous versions, this try will be
            # removed in the future
            pass


    def __load_history(self, data):
        self.history = data["history"]


    def __load_functions(self, data):
        try:
            self.functions = data["functions"]

            if self.version == 1.0:
                self.end_functions = data["end_functions"]

                tmp_rev_func_id = {}

                for fad in self.functions:
                    self.func_id[self.func_id_counter] = fad
                    self.tmp_rev_func_id[fad] = self.func_id_counter
                    self.func_id_counter += 1

                for e in self.end_functions:
                    for fad in e:
                        self.functions[fad] = [e, self.tmp_rev_func_id[fad]]

                return

            for fad, value in self.functions.items():
                # end of the function
                e = value[0]
                if e in self.end_functions:
                    self.end_functions[e].append(fad)
                else:
                    self.end_functions[e] = [fad]

                # function id
                id = value[1]
                self.func_id[id] = fad

            self.func_id_counter = max(self.func_id) + 1

        except:
            # Not available in previous versions, this try will be
            # removed in the future
            pass


    def __check_old_json_db(self, fd):
        c = fd.read(1)
        fd.seek(0)
        if c == b"{":
            fd = open(self.path, "r")
            data = json.loads(fd.read())
            fd.close()

            try:
                data["user_inline_comments"] = data["inline_comments"]
                data["user_previous_comments"] = data["previous_comments"]
                del data["inline_comments"]
                del data["previous_comments"]
            except:
                data["user_inline_comments"] = {}
                data["user_previous_comments"] = {}

            data["internal_inline_comments"] = {}
            data["internal_previous_comments"] = {}

            ptr = data["symbols"]
            for name, ad in ptr.items():
                ptr[name] = [ad, SYM_UNK]

            return data
        return None
