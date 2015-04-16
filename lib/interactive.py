#!/usr/bin/env python3
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

import os
import sys
import shlex

from lib.utils import error
from lib.readline import ReadLine
from lib.reverse import load_file, init_addr, disasm


class Command():
    def __init__(self, max_args, callback_exec, callback_complete, desc):
        self.max_args = max_args
        self.callback_complete = callback_complete
        self.callback_exec = callback_exec
        self.desc = desc


class Interactive():
    COMMANDS = None
    TAB = " " * 10

    def __init__(self, ctx):
        self.ctx = ctx
        ctx.vim = False

        self.COMMANDS = {
            "help": Command(
                0,
                self.__exec_help,
                None,
                "Display this help"
            ),

            "load": Command(
                1,
                self.__exec_load,
                self.__complete_load,
                "Load a new file"
            ),

            "x": Command(
                1,
                self.__exec_x,
                self.__complete_x,
                "Disassemble at a symbol or address, if no arguments are\n" +
                self.TAB + "given it's main.\n" +
                self.TAB + "x [symbol|0xNNNN|EP]"
            ),

            "dump": Command(
                1,
                None,
                None,
                "Dump"
            ),

            "set": Command(
                3,
                None,
                None,
                "Set options"
            ),

            "sym": Command(
                3,
                None,
                None,
                "Symbol"
            ),

            "call": Command(
                3,
                None,
                None,
                "Call"
            ),

            "exit": Command(
                0,
                self.__exec_exit,
                None,
                "Exit"
            ),
        }

        rl = ReadLine(self.exec_command, self.complete, self.send_control_c)
        self.rl = rl

        if ctx.filename is not None:
            self.__exec_load(["", ctx.filename])

        if ctx.entry is not None:
            self.__exec_x(["", ctx.entry])

        rl.restore_history()
        rl.loop()
        rl.save_history()


    def send_control_c(self):
        return


    def complete(self, line):
        # If last_word == "_" it means that there was spaces before
        # and we want to complete a new arg
        tmp_line = line + "_"
        tokens = shlex.split(tmp_line)
        last_tok = tokens[-1][:-1] # remove the _
        tmp_line = tmp_line[:-1]

        # Complete a command name
        if len(tokens) == 1:
            all_cmd = []
            for cmd in self.COMMANDS:
                if cmd.startswith(last_tok):
                    # To keep spaces
                    all_cmd.append(tmp_line + cmd[len(last_tok):] + " ")
            return all_cmd

        try:
            first_tok = tokens[0]
            f = self.COMMANDS[first_tok].callback_complete
            if f is not None:
                return f(tmp_line, len(tokens)-1, last_tok)
        except KeyError:
            pass

        return []


    def __complete_load(self, tmp_line, nth_arg, last_tok):
        if nth_arg != 1:
            return []

        comp = []
        
        basename = os.path.basename(last_tok)
        dirname = os.path.dirname(last_tok)

        if not dirname:
            dirname = "."

        try:
            for f in os.listdir(dirname):
                if f.startswith(basename):
                    if os.path.isdir(os.path.join(dirname, f)):
                        comp.append(f + "/")
                    else:
                        comp.append(f + " ")
            if len(comp) == 1:
                return [tmp_line + comp[0][len(basename):]]
            return comp
        except FileNotFoundError:
            return []


    def __complete_x(self, tmp_line, nth_arg, last_tok):
        if nth_arg != 1 or self.ctx.dis is None:
            return []

        comp = []

        for sym in self.ctx.dis.binary.symbols:
            if sym.startswith(last_tok):
                comp.append(sym + " ")

        if len(comp) == 1:
            return [tmp_line + comp[0][len(last_tok):]]

        return comp


    def exec_command(self, line):
        args = line.split()
        if args[0] not in self.COMMANDS:
            error("unknown command")
            return
        c = self.COMMANDS[args[0]]

        if len(args)-1 > c.max_args:
            error("%s takes max %d args" % (args[0], c.max_args))
            return

        if c.callback_exec is not None:
            c.callback_exec(args)


    def __exec_exit(self, args):
        sys.exit(0)


    def __exec_load(self, args):
        if len(args) != 2:
            error("filename requirred")
            return
        self.ctx.filename = args[1]
        if not load_file(self.ctx):
            error("file doesn't exists")
        self.rl.print("file loaded\n")


    def __exec_x(self, args):
        if self.ctx.dis is None:
            error("load a file before")
            return
        if len(args) == 1:
            self.ctx.entry = None
        else:
            self.ctx.entry = args[1]
        if init_addr(self.ctx):
            disasm(self.ctx)
            self.ctx.entry = None
            self.ctx.addr = 0


    def __exec_help(self, args):
        for name, cmd in self.COMMANDS.items():
            if cmd.callback_exec is not None:
                self.rl.print(name)
                self.rl.print(" " * (10 - len(name)))
                self.rl.print(cmd.desc)
                self.rl.print("\n")
