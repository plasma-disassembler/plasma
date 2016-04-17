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
import sys
import shlex
import code
import traceback
import readline, rlcompleter

from plasma.lib.colors import color, bold
from plasma.lib.utils import error, print_no_end
from plasma.lib.fileformat.binary import T_BIN_ELF, T_BIN_PE, T_BIN_RAW
from plasma.lib.consts import NB_LINES_TO_DISASM
from plasma.lib.ui.visual import Visual
from plasma.lib.api import Api
from plasma.lib.analyzer import Analyzer


MAX_PRINT_COMPLETE = 300

SHOULD_EXIT = False


COMMANDS_ALPHA = [
    "analyzer",
    "dump",
    "exit",
    "functions",
    "help",
    "hexdump",
    "history",
    "info",
    "jmptable",
    "mips_set_gp",
    "py",
    "push_analyze_symbols",
    "rename",
    "save",
    "sections",
    "sym",
    "x",
    "v",
    "display.print_section",
    "xrefs",
]


def yellow(text):
    return "\x1b[;33m" + text + "\x1b[0m"


class Command():
    def __init__(self, max_args, callback_exec, callback_complete, desc):
        self.max_args = max_args
        self.callback_complete = callback_complete
        self.callback_exec = callback_exec
        self.desc = desc


class Completer():
    def __init__(self, con):
        readline.set_completer_delims(' \t\n;')
        readline.set_history_length(100)
        readline.set_completer(self.complete)
        readline.parse_and_bind("tab: complete")
        self.con = con


    def get_history(self):
        hist = []
        for i in range(readline.get_current_history_length()):
             hist.append(readline.get_history_item(i + 1))
        return hist


    def set_history(self, hist):
        for h in hist:
            readline.add_history(h)


    def complete(self, text, state):
        line = readline.get_line_buffer()
        line = line[:readline.get_endidx()]

        # If last_word == "_" it means that there was spaces before
        # and we want to complete a new arg
        tmp_line = line + "_"
        tokens = shlex.split(tmp_line)
        last_tok = tokens[-1][:-1] # remove the _ on the last token

        much = False

        if state == 0:
            if len(tokens) == 1:
                i = 0
                self.matches = []
                for cmd in COMMANDS_ALPHA:
                    if cmd.startswith(last_tok):
                        self.matches.append(cmd + " ")
                        i += 1
                        if i == MAX_PRINT_COMPLETE:
                            much = True
                            break

            else:
                cmd = tokens[0]
                if cmd in self.con.COMMANDS:
                    f = self.con.COMMANDS[cmd].callback_complete
                    if f is not None:
                        self.matches = f(len(tokens)-1, last_tok)
                        if self.matches is None:
                            much = True

        if much:
            print("\ntoo much possibilities")
            return None

        return self.matches[state]


    def loop(self):
        while 1:
            if SHOULD_EXIT:
                break
            try:
                line = input(bold(color("plasma> ", 11)))
                if line:
                    self.con.exec_command(line)

            except KeyboardInterrupt:
                print()
                pass

            except EOFError:
                print()
                break


class Console():
    COMMANDS = None
    TAB = "      "

    def __init__(self, gctx):
        self.gctx = gctx
        self.db = gctx.db
        gctx.vim = False


        self.COMMANDS = {
            "analyzer": Command(
                0,
                self.__exec_analyzer,
                None,
                [
                "",
                "Analyzer information",
                ]
            ),

            "push_analyze_symbols": Command(
                0,
                self.push_analyze_symbols,
                None,
                [
                "",
                "Force to analyze the entry point, symbols and a memory scan will be done.",
                ]
            ),

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
                "b/w/d/Q create byte/word/dword/qword",
                "a       create ascii string",
                "p       create function",
                "o       set [d|q]word as an offset",
                "x       show xrefs",
                "r       rename",
                "/       binary search: if the first char is ! you can put an",
                "        hexa string example: /!ab 13 42",
                "n/N     next/previous search occurence",
                "I       switch to traditional instruction string output",
                "M       show/hide mangling",
                "B       show/hide bytes",
                "g       top",
                "G       bottom",
                "z       set current line on the middle",
                "Q       quit",
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

            "hexdump": Command(
                2,
                self.__exec_hexdump,
                self.__complete_x,
                [
                "SYMBOL|0xXXXX|EP [NB_LINES]",
                "Dump memory in hexa."
                ]
            ),

            # by default it will be gctx.nb_lines
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

            "rename": Command(
                2,
                self.__exec_rename,
                self.__complete_x,
                [
                "OLD_SYM NEW_SYM",
                "Rename a symbol."
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
                1,
                self.__exec_py,
                self.__complete_file,
                [
                "[FILE]",
                "Run an interactive python shell or execute a script.",
                "The global variable 'api' will be accessible."
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

            "xrefs": Command(
                1,
                self.__exec_xrefs,
                self.__complete_x,
                [
                "SYMBOL|0xXXXX|EP",
                "Print all xrefs."
                ]
            ),
        }

        if gctx.dis.is_x86:
            import plasma.lib.arch.x86.analyzer as arch_analyzer
        elif gctx.dis.is_mips:
            import plasma.lib.arch.mips.analyzer as arch_analyzer
        elif gctx.dis.is_arm:
            import plasma.lib.arch.arm.analyzer as arch_analyzer

        self.analyzer = Analyzer()
        self.analyzer.init()
        self.analyzer.start()
        self.api = Api(gctx, self.analyzer)
        gctx.api = self.api
        self.analyzer.set(gctx, arch_analyzer)

        if gctx.dis.is_mips and gctx.dis.mips_gp == -1:
            print("please run first these commands :")
            print("mips_set_gp 0xADDRESS")
            print("push_analyze_symbols")
        else:
            # If false it means that the first analysis was already done
            if gctx.autoanalyzer and len(self.db.mem) == 0:
                self.push_analyze_symbols(None)

        self.comp = Completer(self)
        self.comp.set_history(self.db.history)

        while 1:
            self.comp.loop()
            if SHOULD_EXIT:
                break
            if not self.check_db_modified():
                break

        self.analyzer.msg.put("exit")


    def check_db_modified(self):
        if self.db is not None and self.db.modified:
            print("the database was modified, run save or exit to force")
            return True
        return False


    def __complete_file(self, nth_arg, last_tok):
        if nth_arg != 1:
            return []

        results = []
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
                        s = "%s/%s/" % (dirname, f_backslahed)
                    else:
                        s = "%s/%s " % (dirname, f_backslahed)
                    results.append(s)
                    i += 1
                    if i == MAX_PRINT_COMPLETE:
                        return None
            return results
        except FileNotFoundError:
            return []


    def __complete_x(self, nth_arg, last_tok):
        if nth_arg != 1 or self.gctx.dis is None:
            return []
        return self.__find_symbol(nth_arg, last_tok)


    def __find_symbol(self, nth_arg, last_tok):
        results = []
        i = 0
        for sect in self.gctx.dis.binary.section_names:
            if sect.startswith(last_tok):
                results.append((sect + " "))
                i += 1
                if i == MAX_PRINT_COMPLETE:
                    return None
        for sym in self.db.symbols:
            if sym.startswith(last_tok):
                results.append((sym + " "))
                i += 1
                if i == MAX_PRINT_COMPLETE:
                    return None
        for sym in self.db.demangled:
            if sym.startswith(last_tok):
                results.append((sym + " "))
                i += 1
                if i == MAX_PRINT_COMPLETE:
                    return None
        return results


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
            try:
                c.callback_exec(args)
            except:
                traceback.print_exc()


    def __exec_exit(self, args):
        global SHOULD_EXIT
        self.analyzer.msg.put("exit")
        SHOULD_EXIT = True


    def __exec_dump(self, args):
        nb_lines = self.gctx.nb_lines
        if len(args) == 3:
            try:
                nb_lines = int(args[2])
            except:
                pass
        ad = None if len(args) == 1 else args[1]
        ctx = self.gctx.get_addr_context(ad)
        if ctx:
            ctx.dump_asm(nb_lines).print()


    def __exec_hexdump(self, args):
        nb_lines = self.gctx.nb_lines
        if len(args) <= 1:
            self.gctx.entry = None
            error("no address in parameter")
            return

        if len(args) == 3:
            try:
                nb_lines = int(args[2])
            except:
                pass

        ctx = self.gctx.get_addr_context(args[1])
        if ctx:
            self.gctx.dis.hexdump(ctx, nb_lines)


    def push_analyze_symbols(self, args):
        # Analyze all imports (it checks if functions return or not)
        for ad in self.db.imports:
            if ad in self.db.functions and self.db.functions[ad] is None:
                self.analyzer.msg.put((ad, True, True, False, None))

        # Analyze entry point
        ep = self.gctx.dis.binary.get_entry_point()
        if ep is not None:
            self.analyzer.msg.put((ep, False, True, False, None))

        # Analyze static functions
        for ad in self.db.reverse_symbols:
            if ad not in self.db.imports and \
                    ad in self.db.functions and self.db.functions[ad] is None:
                self.analyzer.msg.put((ad, True, False, False, None))

        self.analyzer.msg.put("pass_scan_mem")


    def __exec_rename(self, args):
        if args[1] == args[2]:
            return
        ad = self.api.get_addr_from_symbol(args[1])
        if ad == -1:
            print("symbol %s not found" % args[1])
            return
        self.api.add_symbol(ad, args[2])
        self.db.modified = True


    def __exec_sym(self, args):
        if len(args) == 1:
            self.gctx.dis.print_symbols(self.gctx.sectionsname)
            return

        if args[1][0] == "|":
            if len(args) == 2 or len(args) > 3:
                error("bad arguments (warn: need spaces between |)")
                return
            self.gctx.dis.print_symbols(self.gctx.sectionsname, args[2])
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

        if args[1].startswith("loc_"):
            error("loc_ is a reserved prefix")
            return

        # Save new symbol
        try:
            if not self.api.add_symbol(int(args[2], 16), args[1]):
                error("cannot rename")
                return
            self.db.modified = True
        except:
            error("there was an error when creating a symbol")


    def __exec_x(self, args):
        ad = None if len(args) == 1 else args[1]
        ctx = self.gctx.get_addr_context(ad)
        if ctx:
            try:
                o = ctx.decompile()
                if o is not None:
                    o.print()
            except:
                traceback.print_exc()


    def __exec_v(self, args):
        ad = None if len(args) == 1 else args[1]
        ctx = self.gctx.get_addr_context(ad)
        if ctx:
            o = ctx.dump_asm(NB_LINES_TO_DISASM)
            if o is not None:
                Visual(self.gctx, ctx, self.analyzer, self.api)


    def __exec_help(self, args):
        for name in COMMANDS_ALPHA:
            cmd = self.COMMANDS[name]
            if cmd.callback_exec is not None:
                print_no_end(color(name, 2))
                print_no_end(" ")
                for i, line in enumerate(cmd.desc):
                    if i > 0:
                        print_no_end(self.TAB)
                    print(line)


    def __exec_history(self, args):
        for line in self.comp.get_history():
            print(line)


    def __exec_sections(self, args):
        print_no_end("NAME".ljust(20))
        print(" [ START - END - VIRTUAL_SIZE - RAW_SIZE ]")

        for s in self.gctx.dis.binary.iter_sections():
            s.print_header()


    def __exec_info(self, args):
        print("File:", self.gctx.filename)

        statinfo = os.stat(self.gctx.filename)
        print("Size: %.2f ko" % (statinfo.st_size/1024.))

        print_no_end("Type: ")

        ty = self.gctx.dis.binary.type
        if ty == T_BIN_PE:
            print("PE")
        elif ty == T_BIN_ELF:
            print("ELF")
        elif ty == T_BIN_RAW:
            print("RAW")

        print("Arch:", self.gctx.dis.binary.arch)

        if self.gctx.dis.binary.is_big_endian():
            print("Endianess: big endian")
        else:
            print("Endianess: little endian")


    def __exec_display_print_section(self, args):
        if self.gctx.sectionsname:
            print("now it's off")
            self.gctx.sectionsname = False
        else:
            print("now it's on")
            self.gctx.sectionsname = True


    def __exec_save(self, args):
        self.db.save(self.comp.get_history())
        print("database saved to", self.db.path)
        self.db.modified = False


    def __exec_jmptable(self, args):
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

        self.db.modified = True
        self.api.create_jmptable(inst_addr, table_addr, entry_size, nb_entries)


    def __exec_py(self, args):
        ns = {"api": self.api}
        if len(args) == 2:
            exec(open(args[1]).read(), ns)
        else:
            readline.set_completer(rlcompleter.Completer(ns).complete)
            code.interact(local=ns)
            readline.set_completer(self.comp.complete)


    def __exec_mips_set_gp(self, args):
        try:
            self.gctx.dis.mips_gp = int(args[1], 16)
            self.db.mips_gp = self.gctx.dis.mips_gp
        except:
            error("bad address")

        self.db.modified = True


    def __exec_functions(self, args):
        self.gctx.dis.print_functions(self.api)


    def __exec_xrefs(self, args):
        ad = None if len(args) == 1 else args[1]
        ctx = self.gctx.get_addr_context(ad)
        if ctx:
            if ctx.entry not in self.gctx.dis.xrefs:
                return
            ctx.dump_xrefs().print()


    def __exec_analyzer(self, args):
        n = self.analyzer.msg.qsize() + len(self.analyzer.pending)
        print("addresses remaining to analyze:", n)

        if self.analyzer.running_second_pass:
            print("scanning the whole memory...")
            ad = self.analyzer.where
            print("  -> %s: 0x%x" % (self.gctx.dis.binary.get_section(ad).name, ad))
