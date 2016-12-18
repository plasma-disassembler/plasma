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

from curses import color_pair

from plasma.lib.custom_colors import *


MOUSE_EVENT = [0x1b, 0x5b, 0x4d]
MOUSE_INTERVAL = 200


# TODO: not a very clean class...


class InlineEd():
    def __init__(self, line, xbegin, idx_token, text,
                 color, tok_line):
        self.set_key_timeout = True
        self.time_last_mouse_key = MOUSE_INTERVAL + 1
        self.cursor_y = 0
        self.cursor_x = 0

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


    # TODO : copied from lib.ui.window
    def read_escape_keys(self):
        if self.set_key_timeout:
            self.screen.timeout(-1)

        k = self.screen.getch()
        seq = []

        if k != -1:
            while k:
                seq.append(k & 0xff)
                k >>= 8

            self.screen.timeout(0)
            for i in range(8):
                k = self.screen.getch()
                if k == -1:
                    break
                seq.append(k)

                if seq == MOUSE_EVENT:
                    seq.append(self.screen.getch())
                    seq.append(self.screen.getch())
                    seq.append(self.screen.getch())
                    self.set_key_timeout = False
                    return bytes(seq)

        self.set_key_timeout = True
        return bytes(seq)



    def start_view(self, screen):
        screen.move(0, 1)
        self.screen = screen
        y = self.cursor_y

        # index of the cursor in self.text
        i = len(self.text)
        self.cursor_x = self.xbegin + i

        while 1:
            (h, w) = screen.getmaxyx()

            self.screen.move(y, 0)
            self.screen.clrtoeol()
            self.print_line(w, y)

            if self.cursor_x >= w:
                self.cursor_x = w - 1
            screen.move(y, self.cursor_x)

            keys = self.read_escape_keys()

            if keys == b"\x1b": # escape = cancel
                self.text = "".join(self.text)
                break

            if keys == b"\n":
                self.text = "".join(self.text)
                return True

            if keys in self.mapping:
                i = self.mapping[keys](i, w)

            else:
                # Ascii characters
                for k in keys:
                    if k >= 32 and k <= 126 and self.cursor_x < w - 1:
                        # TODO: fix cursor_x >= w
                        # TODO: utf-8
                        c = chr(k)
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
