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

from curses import A_UNDERLINE, color_pair

from plasma.lib.custom_colors import *
from plasma.lib.ui.window import Window


# TODO: not very clean class...


class InlineEd(Window):
    def __init__(self, h, w, line, xbegin, idx_token, text,
                 color, tok_line):
        # The window class is only used for the read_escape_keys
        Window.__init__(self, None, has_statusbar=True)

        self.mapping = {
            b"\x1b\x5b\x44": self.k_left,
            b"\x1b\x5b\x43": self.k_right,
            b"\x7f": self.k_backspace,
            b"\x1b\x5b\x37\x7e": self.k_home,
            b"\x1b\x5b\x38\x7e": self.k_end,
            b"\x1b\x5b\x33\x7e": self.k_delete,
            b"\x15": self.k_ctrl_u,
            b"\x0b": self.k_ctrl_k,
            b"\x01": self.k_home, # ctrl-a
            b"\x05": self.k_end, # ctrl-e
        }

        self.xbegin = xbegin
        self.idx_token = idx_token
        self.text = list(text)
        self.line = line
        self.color = color
        self.tok_line = tok_line


    def start_view(self, screen):
        self.screen = screen
        y = self.cursor_y

        # index of the cursor in self.text
        i = len(self.text)
        self.cursor_x = self.xbegin + i

        while 1:
            (h, w) = screen.getmaxyx()

            if self.has_statusbar:
                h -= 1 # status bar

            self.screen.move(y, 0)
            self.screen.clrtoeol()
            self.print_line(w, y)

            if self.cursor_x >= w:
                self.cursor_x = w - 1
            screen.move(y, self.cursor_x)
            k = self.read_escape_keys()

            if k == b"\x1b": # escape = cancel
                self.text = "".join(self.text)
                break

            if k == b"\n":
                self.text = "".join(self.text)
                return True

            if k in self.mapping:
                i = self.mapping[k](i, w)

            # Ascii characters
            elif k and k[0] >= 32 and k[0] <= 126 and self.cursor_x < w - 1:
                # TODO: fix cursor_x >= w
                # TODO: utf-8
                c = chr(k[0])
                self.text.insert(i, c)
                i += 1
                self.cursor_x += 1

        self.text = "".join(self.text)

        return False


    def print_line(self, w, y):
        force_exit = False
        x = 0
        i = 0
        printed = False # the string currently edited

        while i < len(self.tok_line) or not printed:
            if not printed and i == self.idx_token:
                string = "".join(self.text)
                col = self.color
                is_bold = False
                printed = True
            else:
                (string, col, is_bold) = self.tok_line[i]
                i += 1

            if x + len(string) >= w:
                string = string[:w-x-1]
                force_exit = True

            c = color_pair(col)

            if is_bold:
                c |= curses.A_BOLD

            self.screen.addstr(y, x, string, c)

            x += len(string)
            if force_exit:
                break


    def k_left(self, i, w):
        if i != 0:
            i -= 1
            self.cursor_x -= 1
        return i

    def k_right(self, i, w):
        if i != len(self.text):
            i += 1
            self.cursor_x += 1
            # TODO: fix cursor_x >= w
            if self.cursor_x >= w:
                i -= self.cursor_x - w + 1
                self.cursor_x = w - 1
        return i

    def k_backspace(self, i, w):
        if i != 0:
            del self.text[i-1]
            i -= 1
            self.cursor_x -= 1
        return i

    def k_home(self, i, w):
        self.cursor_x = self.xbegin
        return 0

    def k_end(self, i, w):
        n = len(self.text)
        self.cursor_x = self.xbegin + n
        i = n
        # TODO: fix cursor_x >= w
        if self.cursor_x >= w:
            i -= self.cursor_x - w + 1
            self.cursor_x = w - 1
        return i

    def k_delete(self, i, w):
        if i != len(self.text):
            del self.text[i]
        return i

    def k_ctrl_u(self, i, w):
        self.text = self.text[i:]
        self.cursor_x = self.xbegin
        return 0

    def k_ctrl_k(self, i, w):
        self.text = self.text[:i]
        return i
