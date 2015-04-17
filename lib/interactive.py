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

from lib.colors import color
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
    TAB = "      "
    MAX_PRINT_COMPLETE = 80

    def __init__(self, ctx):
        self.ctx = ctx
        ctx.vim = False

        self.COMMANDS_ALPHA = [
            "dump",
            "exit",
            "help",
            "load",
            "sym",
            "x",
        ]

        self.COMMANDS = {
            "help": Command(
                0,
                self.__exec_help,
                None,
                [
                "",
                "Display this help"
                ]
            ),

            "load": Command(
                1,
                self.__exec_load,
                self.__complete_load,
                [
                "filename",
                "Load a new binary file.",
                ]
            ),

            "x": Command(
                1,
                self.__exec_x,
                self.__complete_x,
                [
                "[symbol|0xXXXX|EP]",
                "Disassemble. By default it will be main.",
                ]
            ),

            # TODO add second args for the number of lines
            # by default it will be ctx.lines
            "dump": Command(
                2,
                self.__exec_dump,
                self.__complete_x,
                [
                "SYMBOL|0xXXXX|EP [NB_LINES]",
                "Dump asm.",
                ]
            ),

            "set": Command(
                3,
                None,
                None,
                [
                "",
                "Set options"
                ]
            ),

            "sym": Command(
                3,
                self.__exec_sym,
                self.__complete_x,
                [
                "[SYMBOL 0xXXXX]",
                "Print all symbols or set a new symbol."
                ]
            ),

            "calls": Command(
                3,
                self.__exec_calls,
                None,
                ["Print all Calls."]
            ),

            "exit": Command(
                0,
                self.__exec_exit,
                None,
                [
                "",
                "Exit"
                ]
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
            i = 0
            for cmd in self.COMMANDS:
                if cmd.startswith(last_tok):
                    # To keep spaces
                    all_cmd.append(tmp_line + cmd[len(last_tok):] + " ")
                    i += 1
                    if i == self.MAX_PRINT_COMPLETE:
                        print("\ntoo much possibilities")
                        return None
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
            i = 0
            for f in os.listdir(dirname):
                if f.startswith(basename):
                    f_backslahed = f.replace(" ", "\\ ")
                    if os.path.isdir(os.path.join(dirname, f)):
                        comp.append(f_backslahed + "/")
                    else:
                        comp.append(f_backslahed + " ")
                    i += 1
                    if i == self.MAX_PRINT_COMPLETE:
                        print("\ntoo much possibilities")
                        return None

            if len(comp) == 1:
                return [tmp_line + comp[0][len(basename):]]

            return comp
        except FileNotFoundError:
            return []


    def __complete_x(self, tmp_line, nth_arg, last_tok):
        if nth_arg != 1 or self.ctx.dis is None:
            return []
        return self.__find_symbol(tmp_line, nth_arg, last_tok)


    def __find_symbol(self, tmp_line, nth_arg, last_tok):
        comp = []
        i = 0
        for sym in self.ctx.dis.binary.symbols:
            if sym.startswith(last_tok):
                comp.append(sym + " ")
                i += 1
                if i == self.MAX_PRINT_COMPLETE:
                    print("\ntoo much possibilities")
                    return None

        if len(comp) == 1:
            return [tmp_line + comp[0][len(last_tok):]]
        return comp


    def exec_command(self, line):
        args = shlex.split(line)
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


    def __exec_dump(self, args):
        if self.ctx.dis is None:
            error("load a file before")
            return
        lines = self.ctx.lines
        if len(args) == 1:
            self.ctx.entry = None
        else:
            if len(args) == 3:
                lines = int(args[2])
            self.ctx.entry = args[1]
        if init_addr(self.ctx):
            self.ctx.dis.dump(self.ctx, self.ctx.addr, lines)
            self.ctx.entry = None
            self.ctx.addr = 0


    def __exec_load(self, args):
        if len(args) != 2:
            error("filename required")
            return
        self.ctx.reset()
        self.ctx.filename = args[1]
        load_file(self.ctx)


    def __exec_calls(self, args):
        if self.ctx.dis is None:
            error("load a file before")
            return
        if len(args) != 1:
            error("this command takes no args")
            return
        init_addr(self.ctx)
        self.ctx.dis.print_calls(self.ctx)


    def __exec_sym(self, args):
        if self.ctx.dis is None:
            error("load a file before")
            return
        if len(args) == 2:
            error("an address is required")
            return
        if len(args) == 1:
            self.ctx.dis.print_symbols(self.ctx.sectionsname)
            return

        addr = int(args[2], 16)
        self.ctx.dis.binary.symbols[args[1]] = addr
        self.ctx.dis.binary.reverse_symbols[addr] = args[1]


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
        for name in self.COMMANDS_ALPHA:
            cmd = self.COMMANDS[name]
            if cmd.callback_exec is not None:
                self.rl.print(color(name, 2))
                self.rl.print(" ")
                for i, line in enumerate(cmd.desc):
                    if i > 0:
                        self.rl.print(self.TAB)
                    self.rl.print(line)
                    # else:
                        # self.rl.print(color(line, 2))
                    self.rl.print("\n")
