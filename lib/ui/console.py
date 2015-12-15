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
import sys
import shlex
import json
import code

from lib import load_file, init_entry_addr, disasm
from lib.colors import color
from lib.utils import error, print_no_end, info
from lib.fileformat.binary import T_BIN_ELF, T_BIN_PE, T_BIN_RAW
from lib.ui.readline import ReadLine
from lib.ui.visual import Visual
from lib.disassembler import NB_LINES_TO_DISASM
from lib.analyzer import Analyzer
from lib.fileformat.binary import SYM_FUNC


class Command():
    def __init__(self, max_args, callback_exec, callback_complete, desc):
        self.max_args = max_args
        self.callback_complete = callback_complete
        self.callback_exec = callback_exec
        self.desc = desc


class Console():
    COMMANDS = None
    TAB = "      "
    MAX_PRINT_COMPLETE = 80

    def __init__(self, ctx):
        self.ctx = ctx
        ctx.vim = False

        self.COMMANDS_ALPHA = [
            "calls",
            "da",
            "db",
            "dd",
            "dw",
            "dq",
            "dump",
            "exit",
            "functions",
            "help",
            "history",
            "info",
            "jmptable",
            "load",
            "lrawarm",
            "lrawmips",
            "lrawmips64",
            "lrawx86",
            "lrawx64",
            "mips_set_gp",
            "py",
            "save",
            "sections",
            "sym",
            "x",
            "v",
            "display.print_section",
            "display.print_comments",
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

            "history": Command(
                0,
                self.__exec_history,
                None,
                [
                "",
                "Display the command history",
                ]
            ),

            "save": Command(
                0,
                self.__exec_save,
                None,
                [
                "",
                "Save the database (only symbols and history currently).",
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

            "lrawx86": Command(
                1,
                self.__exec_lrawx86,
                self.__complete_load,
                [
                "filename",
                "Load a x86 raw file.",
                ]
            ),

            "lrawx64": Command(
                1,
                self.__exec_lrawx64,
                self.__complete_load,
                [
                "filename",
                "Load a x64 raw file.",
                ]
            ),

            "lrawarm": Command(
                1,
                self.__exec_lrawarm,
                self.__complete_load,
                [
                "filename",
                "Load a ARM raw file.",
                ]
            ),

            "lrawmips": Command(
                1,
                self.__exec_lrawmips,
                self.__complete_load,
                [
                "filename",
                "Load a MIPS raw file.",
                ]
            ),

            "lrawmips64": Command(
                1,
                self.__exec_lrawmips64,
                self.__complete_load,
                [
                "filename",
                "Load a MIPS64 raw file.",
                ]
            ),

            "x": Command(
                1,
                self.__exec_x,
                self.__complete_x,
                [
                "[SYMBOL|0xXXXX|EP]",
                "Decompile and print on stdout. By default it will be main.",
                "The decompilation is forced, it dosn't check if addresses",
                "are defined as code."
                ]
            ),

            "v": Command(
                1,
                self.__exec_v,
                self.__complete_x,
                [
                "[SYMBOL|0xXXXX|EP]",
                "Visual mode",
                "Shortcuts:",
                "c       create code",
                "p       create function",
                "g       top",
                "G       bottom",
                "z       set current line on the middle",
                "q       quit",
                ";       edit inline comment (enter/escape to validate/cancel)",
                "%       goto next bracket",
                "*       highlight current word (ctrl-k to clear)",
                "{ }     previous/next paragraph",
                "tab     switch between dump/decompilation",
                "enter   follow address",
                "escape  go back",
                "u       re-enter (for undo)",
                ]
            ),

            "da": Command(
                2,
                self.__exec_data,
                self.__complete_x,
                [
                "SYMBOL|0xXXXX|EP [NB_LINES]",
                "Print data in ascii, it stops when the end of the section is found",
                ]
            ),

            "db": Command(
                2,
                self.__exec_data,
                self.__complete_x,
                [
                "SYMBOL|0xXXXX|EP [NB_LINES]",
                "Print data in bytes, it stops when the end of the section is found",
                ]
            ),

            "dd": Command(
                2,
                self.__exec_data,
                self.__complete_x,
                [
                "SYMBOL|0xXXXX|EP [NB_LINES]",
                "Print data in dwords, it stops when the end of the section is found",
                ]
            ),

            "dw": Command(
                2,
                self.__exec_data,
                self.__complete_x,
                [
                "SYMBOL|0xXXXX|EP [NB_LINES]",
                "Print data in words, it stops when the end of the section is found",
                ]
            ),

            "dq": Command(
                2,
                self.__exec_data,
                self.__complete_x,
                [
                "SYMBOL|0xXXXX|EP [NB_LINES]",
                "Print data in qwords, it stops when the end of the section is found",
                ]
            ),

            # by default it will be ctx.lines
            "dump": Command(
                2,
                self.__exec_dump,
                self.__complete_x,
                [
                "SYMBOL|0xXXXX|EP [NB_LINES]",
                "Disassemble only.",
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
                "[SYMBOL 0xXXXX] [| FILTER]",
                "Print all symbols or set a new symbol.",
                "You can filter symbols by searching the word FILTER.",
                "If FILTER starts with -, the match is inversed."
                ]
            ),

            "calls": Command(
                1,
                self.__exec_calls,
                self.__complete_x,
                [
                "[SECTION_NAME]",
                "Print all calls which are in the given section"
                ]
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

            "sections": Command(
                0,
                self.__exec_sections,
                None,
                [
                "",
                "Print all sections",
                ]
            ),

            "info": Command(
                0,
                self.__exec_info,
                None,
                [
                "",
                "Information about the current binary"
                ]
            ),

            "display.print_section": Command(
                0,
                self.__exec_display_print_section,
                None,
                [
                "",
                "Print or not section when an address is found"
                ]
            ),

            "display.print_comments": Command(
                0,
                self.__exec_display_print_comments,
                None,
                [
                "",
                "Print or not comments"
                ]
            ),

            "jmptable": Command(
                4,
                self.__exec_jmptable,
                None,
                [
                "INST_ADDR TABLE_ADDR NB_ENTRIES SIZE_ENTRY",
                "Create a jump table referenced at TABLE_ADDR and called",
                "from INST_ADDR."
                ]
            ),

            "py": Command(
                0,
                self.__exec_py,
                None,
                [
                "",
                "Run an interactive python shell."
                ]
            ),

            "mips_set_gp": Command(
                1,
                self.__exec_mips_set_gp,
                None,
                [
                "ADDR",
                "Set the register $gp to a fixed value."
                ]
            ),

            "functions": Command(
                1,
                self.__exec_functions,
                None,
                [
                "",
                "Print the function list."
                ]
            ),
        }

        self.analyzer = Analyzer()
        self.analyzer.start()
        info("analyzer is running in background...")

        rl = ReadLine(self.exec_command, self.complete, self.send_control_c)
        self.rl = rl

        if ctx.filename is not None:
            self.__exec_load(["", ctx.filename])

        if ctx.entry is not None:
            self.__exec_x(["", ctx.entry])

        rl.reload_cursor_line()

        while 1:
            rl.loop()
            if not self.check_db_modified():
                break

        self.analyzer.msg.put("exit")


    def check_db_modified(self):
        if self.ctx.db is not None and self.ctx.db.modified:
            print("the database was modified, run save or exit to force")
            return True
        return False


    def send_control_c(self):
        return


    #
    # Returns tuple :
    # - list of completed string (i.e. rest of the current token)
    # - string: the beginning of the current token
    # - if len(list) > 1: it contains the common string between
    #        all possibilities
    #
    # Each sub-complete functions returns only the list.
    #
    def complete(self, line):
        # If last_word == "_" it means that there was spaces before
        # and we want to complete a new arg
        tmp_line = line + "_"
        tokens = shlex.split(tmp_line)
        last_tok = tokens[-1][:-1] # remove the _
        tmp_line = tmp_line[:-1]

        comp = []

        # Complete a command name
        if len(tokens) == 1:
            i = 0
            for cmd in self.COMMANDS_ALPHA:
                if cmd.startswith(last_tok):
                    # To keep spaces
                    comp.append(cmd[len(last_tok):] + " ")
                    i += 1
                    if i == self.MAX_PRINT_COMPLETE:
                        comp = None
                        break
        else:
            try:
                first_tok = tokens[0]
                f = self.COMMANDS[first_tok].callback_complete
                if f is not None:
                    comp = f(tmp_line, len(tokens)-1, last_tok)
            except KeyError:
                pass

        if comp is None:
            print("\ntoo much possibilities")
            return None, None, None

        if len(comp) <= 1:
            return comp, last_tok, None

        common = []
        words_idx = {len(word):i for i, word in enumerate(comp)}
        min_len = min(words_idx)
        ref = words_idx[min_len]

        # Recreate because we have maybe removed words with same length
        words_idx = set(range(len(comp)))
        words_idx.remove(ref)

        for i, char in enumerate(comp[ref]):
            found = True
            for j in words_idx:
                if comp[j][i] != char:
                    found = False
                    break
            if not found:
                break
            common.append(char)

        return comp, last_tok, "".join(common)


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
                        s = f_backslahed + "/"
                    else:
                        s = f_backslahed + " "
                    comp.append(s[len(basename):])
                    i += 1
                    if i == self.MAX_PRINT_COMPLETE:
                        return None
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
        for sect in self.ctx.dis.binary.section_names:
            if sect.startswith(last_tok):
                comp.append((sect + " ")[len(last_tok):])
                i += 1
                if i == self.MAX_PRINT_COMPLETE:
                    return None
        for sym in self.ctx.dis.binary.symbols:
            if sym.startswith(last_tok):
                comp.append((sym + " ")[len(last_tok):])
                i += 1
                if i == self.MAX_PRINT_COMPLETE:
                    return None
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
        self.analyzer.msg.put("exit")
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
        self.ctx.reset_vars()
        if init_entry_addr(self.ctx):
            self.ctx.dump = True
            self.ctx.dis.dump_asm(self.ctx, lines).print()
            self.ctx.dump = False
            self.ctx.entry = None
            self.ctx.entry_addr = 0


    def __exec_data(self, args):
        if self.ctx.dis is None:
            error("load a file before")
            return
        lines = self.ctx.lines
        if len(args) <= 1:
            self.ctx.entry = None
            error("no address in parameter")
            return
        self.ctx.entry = args[1]
        if len(args) == 3:
            lines = int(args[2])
        self.ctx.print_data = True
        if init_entry_addr(self.ctx):
            if args[0] == "da":
                self.ctx.dis.dump_data_ascii(self.ctx, lines)
            elif args[0] == "db":
                self.ctx.dis.dump_data(self.ctx, lines, 1)
            elif args[0] == "dw":
                self.ctx.dis.dump_data(self.ctx, lines, 2)
            elif args[0] == "dd":
                self.ctx.dis.dump_data(self.ctx, lines, 4)
            elif args[0] == "dq":
                self.ctx.dis.dump_data(self.ctx, lines, 8)
            self.ctx.entry = None
            self.ctx.entry_addr = 0
            self.ctx.print_data = False


    def push_analyze_symbols(self):
        self.analyzer.set(self.ctx.dis, self.ctx.db)
        for ad, (name, ty) in self.ctx.db.reverse_symbols.items():
            if ty == SYM_FUNC:
                self.analyzer.msg.put((ad, True, None))


    def __exec_load(self, args):
        if self.check_db_modified():
            return
        if len(args) != 2:
            error("filename required")
            return
        self.ctx.reset_all()
        self.ctx.filename = args[1]
        load_file(self.ctx)
        if self.ctx.db is not None:
            self.rl.history = self.ctx.db.history
            self.push_analyze_symbols()


    def __exec_lrawx86(self, args):
        if self.check_db_modified():
            return
        if len(args) != 2:
            error("filename required")
            return
        self.ctx.reset_all()
        self.ctx.raw_type = "x86"
        self.ctx.raw_big_endian = False
        self.ctx.filename = args[1]
        load_file(self.ctx)
        self.analyzer.set(self.ctx.dis, self.ctx.db)


    def __exec_lrawx64(self, args):
        if self.check_db_modified():
            return
        if len(args) != 2:
            error("filename required")
            return
        self.ctx.reset_all()
        self.ctx.raw_type = "x64"
        self.ctx.raw_big_endian = False
        self.ctx.filename = args[1]
        load_file(self.ctx)
        self.analyzer.set(self.ctx.dis, self.ctx.db)


    def __exec_lrawarm(self, args):
        if self.check_db_modified():
            return
        if len(args) != 2:
            error("filename required")
            return
        self.ctx.reset_all()
        self.ctx.raw_type = "arm"
        self.ctx.filename = args[1]
        load_file(self.ctx)
        self.analyzer.set(self.ctx.dis, self.ctx.db)


    def __exec_lrawmips(self, args):
        if self.check_db_modified():
            return
        if len(args) != 2:
            error("filename required")
            return
        self.ctx.reset_all()
        self.ctx.raw_type = "mips"
        self.ctx.filename = args[1]
        load_file(self.ctx)
        self.analyzer.set(self.ctx.dis, self.ctx.db)


    def __exec_lrawmips64(self, args):
        if self.check_db_modified():
            return
        if len(args) != 2:
            error("filename required")
            return
        self.ctx.reset_all()
        self.ctx.raw_type = "mips64"
        self.ctx.filename = args[1]
        load_file(self.ctx)
        self.analyzer.set(self.ctx.dis, self.ctx.db)


    def __exec_calls(self, args):
        if len(args) != 2:
            error("section required")
            return
        if self.ctx.dis is None:
            error("load a file before")
            return
        self.ctx.calls_in_section = args[1]
        if init_entry_addr(self.ctx):
            self.ctx.dis.print_calls(self.ctx)
            self.ctx.entry = None
            self.ctx.entry_addr = 0
        self.ctx.calls_in_section = None


    def __exec_sym(self, args):
        if self.ctx.dis is None:
            error("load a file before")
            return

        if len(args) == 1:
            self.ctx.dis.print_symbols(self.ctx.sectionsname)
            return

        if args[1][0] == "|":
            if len(args) == 2 or len(args) > 3:
                error("bad arguments (warn: need spaces between |)")
                return
            self.ctx.dis.print_symbols(self.ctx.sectionsname, args[2])
            return

        if len(args) > 3:
            error("bad arguments")
            return

        if len(args) == 2:
            error("an address is required to save the symbol")
            return

        if not args[2].startswith("0x"):
            error("the address should starts with 0x")
            return

        # Save new symbol
        try:
            addr = int(args[2], 16)
            self.ctx.db.modified = True
            self.ctx.dis.add_symbol(addr, args[1])
        except:
            error("there was an error when creating a symbol")


    def __exec_x(self, args):
        if self.ctx.dis is None:
            error("load a file before")
            return
        if len(args) == 1:
            self.ctx.entry = None
        else:
            self.ctx.entry = args[1]
        self.ctx.reset_vars()
        if init_entry_addr(self.ctx):
            o = disasm(self.ctx)
            if o is not None:
                o.print()
            self.ctx.entry = None
            self.ctx.entry_addr = 0


    def __exec_v(self, args):
        if self.ctx.dis is None:
            error("load a file before")
            return
        if len(args) == 1:
            self.ctx.entry = None
        else:
            self.ctx.entry = args[1]
        self.ctx.reset_vars()
        if init_entry_addr(self.ctx):
            self.ctx.dump = True
            o = self.ctx.dis.dump_asm(self.ctx, NB_LINES_TO_DISASM)
            self.ctx.dump = False
            if o is not None:
                Visual(self, self.ctx.dis, o)
            self.ctx.entry = None
            self.ctx.entry_addr = 0


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
                    self.rl.print("\n")


    def __exec_history(self, args):
        for line in reversed(self.rl.history):
            print(line)


    def __exec_sections(self, args):
        if self.ctx.dis is None:
            error("load a file before")
            return

        self.rl.print("NAME".ljust(20))
        self.rl.print(" [ START - END - VIRTUAL_SIZE - RAW_SIZE ]\n")

        for s in self.ctx.dis.binary.iter_sections():
            s.print_header()


    def __exec_info(self, args):
        if self.ctx.filename is None:
            print("no file loaded")
            return
        print("File:", self.ctx.filename)

        statinfo = os.stat(self.ctx.filename)
        print("Size: %.2f ko" % (statinfo.st_size/1024.))

        print_no_end("Type: ")

        ty = self.ctx.dis.binary.type
        if ty == T_BIN_PE:
            print("PE")
        elif ty == T_BIN_ELF:
            print("ELF")
        elif ty == T_BIN_RAW:
            print("RAW")

        import capstone as CAPSTONE

        arch, mode = self.ctx.dis.binary.get_arch()

        print_no_end("Arch: ")

        if arch == CAPSTONE.CS_ARCH_X86:
            if mode & CAPSTONE.CS_MODE_32:
                print("x86")
            elif mode & CAPSTONE.CS_MODE_64:
                print("x64")
        elif arch == CAPSTONE.CS_ARCH_ARM:
            print("arm")
        elif arch == CAPSTONE.CS_ARCH_MIPS:
            if mode & CAPSTONE.CS_MODE_32:
                print("mips")
            elif mode & CAPSTONE.CS_MODE_64:
                print("mips64 (octeon)")
        else:
            print("not supported")

        if mode & CAPSTONE.CS_MODE_BIG_ENDIAN:
            print("Endianess: big endian")
        else:
            print("Endianess: little endian")


    def __exec_display_print_section(self, args):
        if self.ctx.sectionsname:
            print("now it's off")
            self.ctx.sectionsname = False
        else:
            print("now it's on")
            self.ctx.sectionsname = True


    def __exec_display_print_comments(self, args):
        if self.ctx.comments:
            print("now it's off")
            self.ctx.comments = False
        else:
            print("now it's on")
            self.ctx.comments = True


    def __exec_save(self, args):
        if self.ctx.dis is None:
            error("load a file before")
            return
        self.ctx.db.save(self.rl.history)
        print("database saved to", self.ctx.db.path)
        self.ctx.db.modified = False


    def __exec_jmptable(self, args):
        if self.ctx.dis is None:
            error("load a file before")
            return
        try:
            inst_addr = int(args[1], 16)
            table_addr = int(args[2], 16)
            nb_entries = int(args[3])
            entry_size = int(args[4])
        except:
            error("one parameter is invalid, be sure that addresses start with 0x")
            return

        if entry_size not in [2, 4, 8]:
            error("error the entry size should be in [2, 4, 8]")
            return

        self.ctx.db.modified = True
        self.ctx.dis.add_jmptable(inst_addr, table_addr, entry_size, nb_entries)

        # TODO: it will be better to start from the beginning of the function
        # end-function may differ.
        # Re-run the analyzer
        self.analyzer.msg.put((inst_addr, False, None))


    def __exec_py(self, args):
        code.interact(local=locals())


    def __exec_mips_set_gp(self, args):
        if self.ctx.dis is None:
            error("load a file before")
            return

        try:
            self.ctx.dis.mips_gp = int(args[1], 16)
            self.ctx.db.mips_gp = self.ctx.dis.mips_gp
        except:
            error("bad address")

        self.ctx.db.modified = True


    def __exec_functions(self, args):
        if self.ctx.dis is None:
            error("load a file before")
            return
        self.ctx.dis.print_symbols(self.ctx.sectionsname, only_func=True)
