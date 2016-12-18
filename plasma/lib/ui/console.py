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

from plasma.lib.consts import *
from plasma.lib.colors import color, bold
from plasma.lib.utils import error, print_no_end
from plasma.lib.fileformat.binary import T_BIN_ELF, T_BIN_PE, T_BIN_RAW
from plasma.lib.ui.visual import Visual
from plasma.lib.api import Api
from plasma.lib.analyzer import Analyzer

import plasma
PLASMA_SCRIPTS_DIR = os.path.dirname(plasma.__file__) + "/scripts"

MAX_PRINT_COMPLETE = 300
SHOULD_EXIT = False

# Used for scripting
EXPORTED_SYMBOLS = {
    "MEM_UNK": MEM_UNK,
    "MEM_CODE": MEM_CODE,
    "MEM_FUNC": MEM_FUNC,
    "MEM_BYTE": MEM_BYTE,
    "MEM_WORD": MEM_WORD,
    "MEM_DWORD": MEM_DWORD,
    "MEM_QWORD": MEM_QWORD,
    "MEM_WOFFSET": MEM_WOFFSET,
    "MEM_DOFFSET": MEM_DOFFSET,
    "MEM_QOFFSET": MEM_QOFFSET,
    "MEM_ASCII": MEM_ASCII,
    "MEM_ARRAY": MEM_ARRAY,
    "MEM_HEAD": MEM_HEAD,
}

COMMANDS_ALPHA = [
    "analyzer",
    "dump",
    "exit",
    "frame_size",
    "functions",
    "help",
    "hexdump",
    "history",
    "info",
    "jmptable",
    "memmap",
    "mips_set_gp",
    "py",
    "push_analyze_symbols",
    "rename",
    "save",
    "sections",
    "sym",
    "x",
    "v",
    "xrefs",
]


def yellow(text):
    return "\x1b[;33m" + text + "\x1b[0m"


class Command():
    def __init__(self, max_args, min_args, callback_exec, callback_complete, desc):
        self.max_args = max_args
        self.min_args = min_args
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
        if sys.stdin.isatty():
            prompt = bold(color("plasma> ", 11))
        else:
            prompt = ""

        while 1:
            if SHOULD_EXIT:
                break
            try:
                line = input(prompt)
                if line:
                    self.con.exec_command(line)

            except KeyboardInterrupt:
                print()
                pass

            except EOFError:
                if sys.stdin.isatty():
                    print()
                break


class Console():
    COMMANDS = None
    TAB = "      "

    def __init__(self, gctx):
        self.gctx = gctx
        self.db = gctx.db
        gctx.vim = False

        self.visual_previous_idx = 0
        self.visual_last_widgets = []

        # A hack to allow window resizing
        os.environ['LINES']="blah"
        del os.environ['LINES']
        os.environ['COLUMNS']="blah"
        del os.environ['COLUMNS']

        self.COMMANDS = {
            "analyzer": Command(
                0, 0,
                self.__exec_analyzer,
                None,
                [
                "",
                "Analyzer status.",
                ]
            ),

            "push_analyze_symbols": Command(
                0, 0,
                self.push_analyze_symbols,
                None,
                [
                "",
                "Force to analyze the entry point, symbols and a memory scan will be done.",
                ]
            ),

            "help": Command(
                0, 0,
                self.__exec_help,
                None,
                [
                "",
                "Display this help."
                ]
            ),

            "history": Command(
                0, 0,
                self.__exec_history,
                None,
                [
                "",
                "Display the command history.",
                ]
            ),

            "save": Command(
                0, 0,
                self.__exec_save,
                None,
                [
                "",
                "Save the database.",
                ]
            ),

            "x": Command(
                1, 0,
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
                1, 0,
                self.__exec_v,
                self.__complete_x,
                [
                "[SYMBOL|0xXXXX|EP|%VISUAL]",
                "Visual mode: if no address is given, previous visual is",
                "reopen. You can keep up to 3 visuals. Use %1, %2 or %3",
                "to select the visual.",
                "",
                "Main shortcuts:",
                "c       create code",
                "b/w/d/Q create byte/word/dword/qword",
                "a       create ascii string",
                "p       create function",
                "o       set [d|q]word as an offset",
                "*       create an array",
                "x       show xrefs",
                "r       rename",
                "space   highlight current word (ctrl-k to clear)",
                ";       edit inline comment (enter/escape to validate/cancel)",
                "U       undefine",
                "",
                "Options:",
                "I       switch to traditional instruction string output (3 modes)",
                "M       show/hide mangling",
                "B       show/hide bytes",
                "",
                "Navigation:",
                "|       split the window",
                "j       jump to an address or a symbol",
                "/       binary search: if the first char is ! you can put an",
                "        hexa string example: /!ab 13 42",
                "        the search is case sensitive.",
                "n/N     next/previous search occurence",
                "g       top",
                "G       bottom",
                "z       set current line on the middle",
                "%       goto next bracket",
                "{ }     previous/next paragraph",
                "tab     switch between dump/decompilation",
                "enter   follow address",
                "escape  go back",
                "u       re-enter",
                "q       quit",
                ]
            ),

            "hexdump": Command(
                2, 1,
                self.__exec_hexdump,
                self.__complete_x,
                [
                "SYMBOL|0xXXXX|EP [NB_LINES]",
                "Dump memory in hexa."
                ]
            ),

            # by default it will be gctx.nb_lines
            "dump": Command(
                2, 1,
                self.__exec_dump,
                self.__complete_x,
                [
                "SYMBOL|0xXXXX|EP [NB_LINES]",
                "Print contents at the specified address.",
                ]
            ),

            "sym": Command(
                3, 0,
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
                2, 2,
                self.__exec_rename,
                self.__complete_x,
                [
                "OLD_SYM NEW_SYM",
                "Rename a symbol."
                ]
            ),

            "exit": Command(
                0, 0,
                self.__exec_exit,
                None,
                [
                "",
                "Exit"
                ]
            ),

            "sections": Command(
                0, 0,
                self.__exec_sections,
                None,
                [
                "",
                "Print all sections.",
                ]
            ),

            "info": Command(
                0, 0,
                self.__exec_info,
                None,
                [
                "",
                "Information about the current binary."
                ]
            ),

            "jmptable": Command(
                4, 4,
                self.__exec_jmptable,
                None,
                [
                "INST_ADDR TABLE_ADDR NB_ENTRIES SIZE_ENTRY",
                "Create a jump table referenced at TABLE_ADDR and called",
                "from INST_ADDR."
                ]
            ),

            "py": Command(
                -1, 0,
                self.__exec_py,
                self.__complete_file,
                [
                "[!][FILE]",
                "Run an interactive python shell or execute a script.",
                "Global variables api and args will be passed to the script.",
                "The character ! is an alias to the scripts directory."
                ]
            ),

            "mips_set_gp": Command(
                1, 1,
                self.__exec_mips_set_gp,
                None,
                [
                "ADDR",
                "Set the register $gp to a fixed value. Note that it will",
                "erase all defined memory."
                ]
            ),

            "functions": Command(
                0, 0,
                self.__exec_functions,
                None,
                [
                "",
                "Print the function list."
                ]
            ),

            "xrefs": Command(
                1, 1,
                self.__exec_xrefs,
                self.__complete_x,
                [
                "SYMBOL|0xXXXX|EP",
                "Print cross references to the specified address."
                ]
            ),

            "memmap": Command(
                0, 0,
                self.__exec_memmap,
                None,
                [
                "",
                "Open a qt window to display the memory."
                ]
            ),

            "frame_size": Command(
                2, 2,
                self.__exec_frame_size,
                self.__complete_x,
                [
                "[SYMBOL|0xXXXX|EP] frame_size",
                "Change the frame size of a function, the function will be re-analyzed."
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

        self.gctx.dis.binary.api = self.api

        if gctx.dis.is_mips and not gctx.dis.mips_gp:
            if sys.stdin.isatty():
                print("please run first these commands :")
                print("mips_set_gp 0xADDRESS")
                print("push_analyze_symbols")
        else:
            # If false it means that the first analysis was already done
            if gctx.autoanalyzer and len(self.db.mem) == 0:
                print("analyzer is running... check the command analyzer to see the status")
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

        if last_tok.startswith("!"):
            basename = last_tok[1:]
            dirname = PLASMA_SCRIPTS_DIR
        else:
            basename = os.path.basename(last_tok)
            dirname = os.path.dirname(last_tok)
            if not dirname:
                dirname = "."

        try:
            i = 0
            for f in os.listdir(dirname):
                if f.startswith(basename):
                    f_backslahed = f.replace(" ", "\\ ")

                    if last_tok.startswith("!"):
                        s = "!%s " % f_backslahed
                    else:
                        if os.path.isdir(os.path.join(dirname, f)):
                            if dirname == "/":
                                s = "/%s/" % f_backslahed
                            elif dirname == ".":
                                s = "%s/" % f_backslahed
                            else:
                                s = "%s/%s/" % (dirname, f_backslahed)
                        else:
                            if dirname == ".":
                                s = "%s " % f_backslahed
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
        try:
            args = shlex.split(line)
        except Exception as e:
            print("error:", e)
            return
        if not args:
            return
        if args[0] not in self.COMMANDS:
            error("unknown command")
            return
        c = self.COMMANDS[args[0]]

        if c.max_args != -1 and len(args) - 1 > c.max_args:
            error("%s takes max %d args" % (args[0], c.max_args))
            return

        if len(args) - 1 < c.min_args:
            error("%s takes at least %d args" % (args[0], c.min_args))
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
            self.analyzer.msg.put((ep, True, True, False, None))

        self.analyzer.msg.put("rename_entry_point")

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
            self.gctx.dis.print_symbols()
            return

        if args[1][0] == "|":
            if len(args) == 2 or len(args) > 3:
                error("bad arguments (warn: need spaces between |)")
                return
            self.gctx.dis.print_symbols(args[2])
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
        ad = 0
        if len(args) == 2:
            if args[1][0] == "%":
                if len(args[1]) != 2:
                    print("error: bad visual number")
                    return

                i = int(args[1][1]) - 1
                if i < 0 or i >= len(self.visual_last_widgets):
                    print("error: bad visual number, there are only %d opened visual" % len(self.visual_last_widgets))
                    return
                wdgt = self.visual_last_widgets[i]
            else:
                ad = args[1]
                wdgt = None
                i = None
        else:
            if not self.visual_last_widgets:
                ad = None # will open the visual at EP or main
                i = None
                wdgt = None
            else:
                i = self.visual_previous_idx
                wdgt = self.visual_last_widgets[i]

        v = Visual(self.gctx, ad, self.analyzer, self.api, wdgt)

        if v.error_occurs:
            return

        # Only %1, %2, %3 actually

        if i is None:
            self.visual_last_widgets.append(v.widgets)
            n = len(self.visual_last_widgets)
            print("visual saved to %%%d" % n)
            self.visual_previous_idx = n - 1
        else:
            self.visual_last_widgets[i] = v.widgets
            print("visual saved to %%%d" % (i + 1))
            self.visual_previous_idx = i

        if len(self.visual_last_widgets) == 4:
            self.visual_last_widgets = self.visual_last_widgets[1:]


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
        self.api.create_jmptable(inst_addr, table_addr, nb_entries, entry_size)


    def __exec_py(self, args):
        ns = {"api": self.api, "args": args[1:], "analyzer": self.analyzer}
        ns.update(EXPORTED_SYMBOLS)
        if len(args) > 1:
            if args[1].startswith("!"):
                args[1] = "%s/%s" % (PLASMA_SCRIPTS_DIR, args[1][1:])
            exec(open(args[1]).read(), ns)
        else:
            readline.set_completer(rlcompleter.Completer(ns).complete)
            code.interact(local=ns)
            readline.set_completer(self.comp.complete)


    def __exec_mips_set_gp(self, args):
        self.gctx.dis.mips_gp = int(args[1], 16)
        self.db.mips_gp = self.gctx.dis.mips_gp
        self.db.mem.mm.clear()
        self.db.xrefs.clear()
        self.db.data_sub_xrefs.clear()
        self.db.immediates.clear()
        self.db.modified = True


    def __exec_functions(self, args):
        self.gctx.dis.print_functions(self.api)


    def __exec_xrefs(self, args):
        ad = None if len(args) == 1 else args[1]
        ctx = self.gctx.get_addr_context(ad)
        if ctx and ctx.entry in self.gctx.db.xrefs or self.gctx.db.data_sub_xrefs:
            ctx.dump_xrefs().print()


    def __exec_analyzer(self, args):
        n = self.analyzer.msg.qsize() + len(self.analyzer.pending)
        print("addresses remaining to analyze:", n)

        if self.analyzer.running_second_pass:
            print("memory scan...")
            ad = self.analyzer.where
            s = self.gctx.dis.binary.get_section(ad)
            percent = int((ad - s.start) * 100 / s.real_size)
            print("  -> %s %d%%  (0x%x)" % (s.name, percent, ad))


    def __exec_memmap(self, args):
        from plasma.lib.memmap import ThreadMemoryMap
        t = ThreadMemoryMap(self.db, self.gctx.dis.binary)
        t.start()


    def __exec_frame_size(self, args):
        ctx = self.gctx.get_addr_context(args[1])
        frame_size = int(args[2])
        if ctx:
            self.api.set_frame_size(ctx.entry, frame_size)
