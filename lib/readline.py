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
import termios
import tty


def yellow(text):
    return "\x1b[;33m" + text + "\x1b[0m"


class ReadLine():
    def __init__(self, callback_enter, callback_complete, callback_ctrl_c):
        self.tty_fd = sys.stdin.fileno()
        self.tty_old_settings = termios.tcgetattr(self.tty_fd)
        self.tty_raw_set = False

        self.prompt = ">> "
        self.cursor_j = 0  # relative to prompt
        self.cursor_i = self.get_position()[0]
        self.line = ""
        self.callback_enter = callback_enter
        self.callback_complete = callback_complete
        self.callback_ctrl_c = callback_ctrl_c
        self.history = []
        self.idx_history = -1 # must be reinit at each modification on line
        self.saved_line = ""

        self.mapping = {
            "\x1b\x5b\x44": self.k_left,
            "\x1b\x5b\x43": self.k_right,
            "\x7f": self.k_backspace,
            "\x1b\x5b\x37\x7e": self.k_home,
            "\x1b\x5b\x38\x7e": self.k_end,
            "\x1b\x5b\x41": self.k_up,
            "\x1b\x5b\x42": self.k_down,
            "\x1b\x5b\x35\x7e": self.k_pageup,
            "\x1b\x5b\x36\x7e": self.k_pagedown,
            "\x1b\x5b\x33\x7e": self.k_delete,
            "\x17": self.k_ctrl_w,
            "\x15": self.k_ctrl_u,
            "\x0b": self.k_ctrl_k,
            "\x1b\x5b\x31\x3b\x35\x44": self.k_ctrl_left,
            "\x1b\x5b\x31\x3b\x35\x43": self.k_ctrl_right,
            "\x0d": self.k_enter,
            "\x0c": self.k_ctrl_l,
            "\x09": self.k_tab,
            "\x01": self.k_ctrl_a,
            "\x05": self.k_ctrl_e,
            "\x03": self.k_ctrl_c,
        }


    def print(self, txt):
        os.write(1, str.encode(txt))


    def save_history(self):
        fd = open(".reverse_history", "w+")
        for line in reversed(self.history):
            fd.write(line + "\n")
        fd.close()


    def restore_history(self):
        try:
            fd = open(".reverse_history", "r")
            for line in fd:
                self.history.insert(0, line[:-1])
            fd.close()
        except:
            pass


    def tty_set_raw(self):
        if not self.tty_raw_set:
            tty.setraw(self.tty_fd)
            self.tty_raw_set = True


    def tty_restore(self):
        termios.tcsetattr(self.tty_fd, termios.TCSADRAIN, self.tty_old_settings)
        self.tty_raw_set = False


    def getch(self):
        return


    def loop(self):
        self.print_prompt()
        self.tty_set_raw()

        while 1:
            # TODO for windows : return msvcrt.getch()
            # don't know the maximum of chars to read
            ch = os.read(self.tty_fd, 8).decode()
            # print(binascii.hexlify(ch))
            if ch == -1 or self.k_is_ctrl_d(ch):
                self.tty_restore()
                self.print("\n")
                break
            self.process_key(ch)


    def print_prompt(self):
        self.print("\x1b[" + str(self.cursor_i) + ";1H")
        self.print(yellow(self.prompt))


    def process_key(self, ch):
        if ch in self.mapping.keys():
            self.mapping[ch]()
        elif ord(ch[0]) >= 0x20:
            self.idx_history = -1
            self.insert_char(ch)


    def set_cursor(self):
        self.print("\x1b[" + str(self.cursor_i) + ";" +
                   str(1 + self.cursor_j + len(self.prompt)) + "H")


    def get_position(self):
        self.tty_set_raw()
        pos = [0,0]
        try:
            os.write(self.tty_fd, b"\x1b[6n")
            # don't know the maximum of chars to read
            ch = os.read(self.tty_fd, 16).decode()
            pos = ch[2:-1].split(";")
            pos[0] = int(pos[0])
            pos[1] = int(pos[1])
        finally:
            self.tty_restore()
        return pos


    def insert_char(self, ch):
        beginline = self.line[:self.cursor_j]
        endline = self.line[self.cursor_j:]
        self.print(ch)
        self.print("\x1b[K")
        self.print(endline)
        self.line = beginline + ch + endline
        self.cursor_j = len(beginline) + len(ch)
        self.set_cursor()


    def delete_end_line(self):
        self.print("\x1b[K")


    def new_prompt(self):
        self.tty_restore()
        self.print("\n")
        self.cursor_i += 1
        self.set_cursor()
        self.print_prompt()
        self.print(self.line)
        self.tty_set_raw()


    #######################################
    #          Mapping functions          #
    #######################################

    def k_is_ctrl_d(self, ch):
        return ch == "\x04"

    def k_ctrl_c(self):
        self.tty_restore()
        self.print("^C\n")
        self.cursor_i = self.get_position()[0]
        self.set_cursor()
        self.print_prompt()
        self.print(self.line)
        self.callback_ctrl_c()
        self.tty_set_raw()

    def k_left(self):
        if self.cursor_j > 0:
            self.cursor_j -= 1
            self.print("\x1b[1D")

    def k_right(self):
        if self.cursor_j < len(self.line):
            self.cursor_j += 1
            self.print("\x1b[1C")

    def k_backspace(self):
        if self.cursor_j == 0:
            return
        self.k_left()
        self.k_delete()
        self.idx_history = -1

    def k_home(self):
        self.cursor_j = 0
        self.set_cursor()

    def k_end(self):
        self.cursor_j = len(self.line)
        self.set_cursor()

    def k_ctrl_l(self):
        self.print("\x1b[2J")
        self.cursor_i = 1
        self.cursor_j = 0
        self.set_cursor()
        self.print_prompt()
        self.print(self.line)
        self.cursor_j = len(self.line)

    def k_up(self):
        if self.idx_history < len(self.history) - 1:
            if self.idx_history == -1:
                self.saved_line = self.line
            self.idx_history += 1
            self.cursor_j = 0
            self.set_cursor()
            self.delete_end_line()
            self.line = self.history[self.idx_history]
            self.print(self.line)
            self.cursor_j = len(self.line)

    def k_down(self):
        if self.idx_history >= 0:
            self.idx_history -= 1
            self.cursor_j = 0
            self.set_cursor()
            self.delete_end_line()
            if self.idx_history == -1:
                self.line = self.saved_line
            else:
                self.line = self.history[self.idx_history]
            self.print(self.line)
            self.cursor_j = len(self.line)

    def k_ctrl_w(self):
        j = self.cursor_j
        copy = self.cursor_j
        if self.cursor_j == 0:
            return
        j -= 1
        while j > 0 and self.line[j] == " ":
            j -= 1
        while j > 0 and self.line[j] != " ":
            j -= 1
        if j != 0:
            j += 1
        self.cursor_j = j
        self.set_cursor()
        self.delete_end_line()
        endline = self.line[copy:]
        self.line = self.line[:j] + endline
        self.cursor_j = j
        self.print(endline)
        self.set_cursor()
        self.idx_history = -1

    def k_ctrl_left(self):
        j = self.cursor_j
        if j == 0:
            return
        j -= 1
        while j > 0 and self.line[j] == " ":
            j -= 1
        while j > 0 and self.line[j] != " ":
            j -= 1
        if j != 0:
            j += 1
        self.cursor_j = j
        self.set_cursor()

    def k_ctrl_right(self):
        j = self.cursor_j
        while j < len(self.line) and self.line[j] == " ":
            j += 1
        while j < len(self.line) and self.line[j] != " ":
            j += 1
        self.cursor_j = j
        self.set_cursor()

    def k_enter(self):
        self.tty_restore()

        self.print("\n")

        if self.line != "":
            if self.idx_history != 0:
                self.history = [self.line] + self.history
            self.callback_enter(self.line)

        self.cursor_i = self.get_position()[0]
        self.set_cursor()
        self.line = ""
        self.idx_history = -1
        self.print_prompt()

        self.cursor_j = 0
        self.set_cursor()

        self.tty_set_raw()

    def k_ctrl_u(self):
        self.line = self.line[self.cursor_j:]
        self.cursor_j = 0
        self.set_cursor()
        self.delete_end_line()
        self.print(self.line)
        self.set_cursor()
        self.idx_history = -1

    def k_ctrl_k(self):
        self.line = self.line[:self.cursor_j]
        self.delete_end_line()
        self.idx_history = -1

    def k_pageup(self):
        if self.idx_history == -1:
            self.saved_line = self.line
        while self.idx_history < len(self.history) - 1:
            self.idx_history += 1
            copy = self.cursor_j
            if self.history[self.idx_history].find(self.line[:copy]) == 0:
              self.cursor_j = 0
              self.set_cursor()
              self.delete_end_line()
              self.line = self.history[self.idx_history]
              self.print(self.line)
              self.cursor_j = copy
              self.set_cursor()
              break

    def k_pagedown(self):
        found = False
        while self.idx_history >= 0:
            self.idx_history -= 1
            copy = self.cursor_j
            if self.idx_history == -1:
                self.line = self.saved_line
                found = True
            elif self.history[self.idx_history].find(self.line[:copy]) == 0:
                self.line = self.history[self.idx_history]
                found = True

            if found:
                self.cursor_j = 0
                self.set_cursor()
                self.delete_end_line()
                self.print(self.line)
                self.cursor_j = copy
                self.set_cursor()
                break

    def k_delete(self):
        if self.cursor_j == len(self.line):
            return
        beginline = self.line[:self.cursor_j]
        endline = self.line[self.cursor_j + 1:]
        self.delete_end_line()
        self.print(endline)
        self.line = beginline + endline
        self.set_cursor()
        self.idx_history = -1

    def k_tab(self):
        self.tty_restore()
        begin = self.line[:self.cursor_j]
        res, last_tok, common = self.callback_complete(begin)

        if res is None:
            self.print_prompt()
            self.print(self.line)
            self.tty_set_raw()
            return

        if len(res) == 0:
            self.tty_set_raw()
            return

        if len(res) == 1:
            completed = begin + res[0]
        else:
            completed = begin + common
            self.print("\n")
            for i in res:
                self.print(last_tok)
                self.print(i)
                self.print("\n")

        self.line = completed + self.line[self.cursor_j:]
        self.cursor_j = 0
        self.set_cursor()
        self.delete_end_line()

        if len(res) > 1:
            self.cursor_i = self.get_position()[0]
            self.print_prompt()

        self.print(self.line)
        self.cursor_j = len(completed)
        self.set_cursor()
        self.tty_set_raw()

    def k_ctrl_a(self):
        self.k_home()

    def k_ctrl_e(self):
        self.k_end()

