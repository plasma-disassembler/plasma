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
from lib.utils import info, error, die


VERSION = 1.0


class Database():
    def __init__(self):
        self.__init_vars()


    def __init_vars(self):
        self.history = []
        self.symbols = {}
        self.reverse_symbols = {}
        self.inline_comments = {}
        self.previous_comments = {}
        self.jmptables = {}
        self.mips_gp = -1
        self.modified = False
        self.loaded = False


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

            self.__load_symbols(data)
            self.__load_jmptables(data)
            self.__load_comments(data)
            self.__load_meta(data)

            self.loaded = True

        gc.enable()


    def save(self, history):
        data = {
            "symbols": self.symbols,
            "history": history,
            "inline_comments": self.inline_comments,
            "previous_comments": self.previous_comments,
            "jmptables": [],
            "mips_gp": self.mips_gp,
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
        for name, addr in data["symbols"].items():
            self.reverse_symbols[addr] = name


    def __load_comments(self, data):
        try:
            for ad, comm in data["inline_comments"].items():
                self.inline_comments[int(ad)] = comm
            for ad, comm in data["previous_comments"].items():
                self.previous_comments[int(ad)] = comm

        except:
            # Not available in previous versions, this try will be
            # removed in the future
            pass


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
            version = data["version"]
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
            return data
        return None
