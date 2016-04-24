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

import curses
from curses import A_UNDERLINE, color_pair
from time import time

from plasma.lib.custom_colors import *


MOUSE_EVENT = [0x1b, 0x5b, 0x4d]
MOUSE_INTERVAL = 200

MODE_DUMP = 1
MODE_DECOMPILE = 2
MODE_OTHER = 3


def popup_text(title, output, h_par, w_par):
    """
    It opens a centered popup. output is an instance of the class Output.
    Returns (bool, line number of the cursor)
    """
    h2 = int(h_par * 3 / 4)
    w2 = int(w_par * 6 / 7)

    x = int((w_par - w2)/2) - 1
    y = int((h_par - h2)/2) - 1

    # A background with borders
    borders = curses.newwin(h2 + 2, w2 + 2, y, x)
    borders.border()
    borders.addstr(0, int((w2 - len(title))/2), " %s " % title)
    borders.refresh()

    screen = curses.newwin(h2, w2, y + 1, x + 1)
    w = Window(output)
    ret = w.start_view(screen)
    return (ret, w.win_y + w.cursor_y)


def popup_inputbox(title, text, h_par, w_par):
    """
    It opens a centered popup and returns the text entered by the user.
    """
    h2 = 1
    w2 = int(w_par * 6 / 7)

    x = int((w_par - w2)/2) - 1
    y = int((h_par - h2)/2) - 1

    # A background with borders
    borders = curses.newwin(h2 + 2, w2 + 2, y, x)
    borders.border()
    borders.addstr(0, int((w2 - len(title))/2), " %s " % title)
    borders.refresh()

    return inputbox(text, x + 1, y + 1, w2, h2)


def inputbox(text, x, y, w, h):
    """
    It creates a surface for an inline editor.   
    """
    from plasma.lib.ui.inlineed import InlineEd
    ed = InlineEd(h, w, 0, 0, 0, text, 0, [])
    screen = curses.newwin(h, w, y, x)
    ret = ed.start_view(screen)
    if not ret:
        return ""
    return ed.text


class Window():
    def __init__(self, output, has_statusbar=False):
        self.mode = MODE_OTHER
        self.win_y = 0
        self.cursor_y = 0
        self.cursor_x = 0

        if output is not None:
            self.output = output
            self.token_lines = output.token_lines

        self.should_stop = False
        self.has_statusbar = has_statusbar

        self.search_hi = None
        self.search_bin = None
        self.word_accepted_chars = ["_", "@", ".", "$", ":"]

        self.time_last_mouse_key = MOUSE_INTERVAL + 1
        self.set_key_timeout = True

        self.mapping = {
            b"\x1b\x5b\x44": self.k_left,
            b"\x1b\x5b\x43": self.k_right,
            b"\x1b\x5b\x41": self.k_up,
            b"\x1b\x5b\x42": self.k_down,
            b"\x1b\x5b\x35\x7e": self.k_pageup,
            b"\x1b\x5b\x36\x7e": self.k_pagedown,
            b"g": self.k_top,
            b"G": self.k_bottom,
            b"\x01": self.k_home, # ctrl-a
            b"\x05": self.k_end, # ctrl-e
            b"\x1b\x5b\x37\x7e": self.k_home,
            b"\x1b\x5b\x38\x7e": self.k_end,
            b"*": self.cmd_highlight_current_word,
            b"\x0b": self.cmd_highlight_clear, # ctrl-k
            b"\x1b\x5b\x31\x3b\x35\x44": self.k_ctrl_left,
            b"\x1b\x5b\x31\x3b\x35\x43": self.k_ctrl_right,
            b"\n": self.k_enter,
        }


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


    def is_tok_var(self):
        num_line = self.win_y + self.cursor_y
        tokens = self.output.token_lines[num_line]

        x = self.cursor_x
        if x >= len(self.output.lines[num_line]):
            return None

        i = 0
        for (s, col, _) in tokens:
            i += len(s)
            if x < i:
                return col == COLOR_VAR.val

        return False


    def get_word_under_cursor(self):
        num_line = self.win_y + self.cursor_y
        line = self.output.lines[num_line]

        if len(line) == 0:
            return None

        x = self.cursor_x
        if x >= len(line):
            return None

        if not line[x].isalnum() and not line[x] in self.word_accepted_chars:
            return None

        curr = []
        while x >= 0 and (line[x].isalnum() or line[x] in self.word_accepted_chars):
            x -= 1
        x += 1

        while x < len(line) and (line[x].isalnum() or \
                line[x] in self.word_accepted_chars):
            curr.append(line[x])
            x += 1

        if curr[-1] == ":":
            return "".join(curr[:-1])

        if curr:
            return "".join(curr)
        return None


    def goto_line(self, new_line, h):
        curr_line = self.win_y + self.cursor_y
        diff = new_line - curr_line
        if diff > 0:
            self.scroll_down(h, diff, False)
        elif diff < 0:
            self.scroll_up(h, -diff, False)


    # If the address is already in the output, we only move the cursor.
    # Otherwise this address must be disassembled (it returns False).
    def goto_address(self, ad, h, w):
        if ad in self.output.addr_line:
            self.goto_line(self.output.addr_line[ad], h)
            if self.mode == MODE_DECOMPILE:
                self.cursor_x = 0
                self.k_home(h, w)
            return True
        return False


    def status_bar(self, s, h, refresh=False):
        self.screen.move(h, 0)
        self.screen.clrtoeol()
        self.screen.addstr(h, 0, s)
        if refresh:
            self.screen.refresh()


    def redraw(self, h, w):
        i = 0

        while i < h:
            if self.win_y + i < len(self.token_lines):
                self.print_line(w, i)
            else:
                # force to clear the entire line
                self.screen.move(i, 0)
            self.screen.clrtoeol()
            i += 1

        if self.has_statusbar:
            self.screen.move(h, 0)
            self.screen.clrtoeol()

        self.screen.refresh()


    def start_view(self, screen):
        self.screen = screen
        screen.clear()
        screen.keypad(False)
        refr = True

        while 1:
            (h, w) = screen.getmaxyx()

            if self.has_statusbar:
                h -= 1

            if refr:
                self.redraw(h, w)
                refr = False

            size_line = len(self.output.lines[self.win_y + self.cursor_y])
            if size_line == 0:
                x = 0
            elif self.cursor_x >= size_line:
                x = size_line - 1
            else:
                x = self.cursor_x

            screen.move(self.cursor_y, x)

            k = self.read_escape_keys()

            if k in self.mapping:
                refr = self.mapping[k](h, w)
            elif k.startswith(b"\x1b[M"):
                refr = self.mouse_event(k, h, w)
            elif k == b"q" or k == b"\x1b":
                break

            if self.should_stop:
                return True

        return False


    def print_line(self, w, i):
        num_line = self.win_y + i
        is_current_line = self.cursor_y == i
        force_exit = False
        x = 0

        for (string, col, is_bold) in self.token_lines[num_line]:
            if x + len(string) >= w:
                string = string[:w-x-1]
                force_exit = True
            
            c = color_pair(col)

            if is_current_line:
                c |= A_UNDERLINE

            if is_bold:
                c |= curses.A_BOLD

            self.screen.addstr(i, x, string, c)

            x += len(string)
            if force_exit:
                break

        if is_current_line and not force_exit:
            n = w - x - 1
            self.screen.addstr(i, x, " " * n, color_pair(0) | A_UNDERLINE)
            x += n

        self.highlight_search(i, w)
        self.screen.move(i, x)
            

    def highlight_search(self, i, w):
        if self.search_hi is None:
            return
        num_line = self.win_y + i
        start = 0
        while 1:
            idx = self.output.lines[num_line].find(self.search_hi, start)
            if idx == -1 or idx >= w:
                break
            self.screen.chgat(i, idx, len(self.search_hi), curses.color_pair(1))
            start = idx + 1


    def scroll_up(self, h, n, page_scroll):
        if page_scroll:
            wy = self.win_y - n
            y = self.cursor_y + n
            line = self.win_y + self.cursor_y

            wy = self.dump_update_up(wy, h)

            if wy >= 0:
                self.win_y = wy
                if y <= h - 3:
                    if line != len(self.token_lines):
                        self.cursor_y = y
                else:
                    self.cursor_y = h - 4
            else:
                self.win_y = 0
        else:
            # TODO: find another way
            for i in range(n):
                self.dump_update_up(self.win_y, h)

                if self.win_y == 0:
                    if self.cursor_y == 0:
                        break
                    self.cursor_y -= 1
                else:
                    if self.cursor_y == 3:
                        self.win_y -= 1
                    else:
                        self.cursor_y -= 1


    def scroll_down(self, h, n, page_scroll):
        if page_scroll:
            wy = self.win_y + n
            y = self.cursor_y - n

            self.dump_update_bottom(wy, h)

            if wy > len(self.token_lines) - h:
                if wy < len(self.token_lines) - 3:
                    self.win_y = wy
                else:
                    self.win_y = len(self.token_lines) - 3 - 1
                if y >= 3:
                    self.cursor_y = y
                else:
                    self.cursor_y = 3
            else:
                self.win_y = wy
                if y >= 3:
                    self.cursor_y = y
                else:
                    self.cursor_y = 3
        else:
            # TODO: find another way
            for i in range(n):
                self.dump_update_bottom(self.win_y, h)

                if self.win_y >= len(self.token_lines) - h:
                    if self.win_y + self.cursor_y == len(self.token_lines) - 1:
                        break
                    self.cursor_y += 1
                else:
                    if self.cursor_y == h - 4:
                        self.win_y += 1
                    else:
                        self.cursor_y += 1


    def dump_update_up(self, wy, h):
        return wy


    def dump_update_bottom(self, wy, h):
        return


    def check_cursor_x(self):
        size_line = len(self.output.lines[self.win_y + self.cursor_y])
        if size_line == 0:
            self.cursor_x = 0
        elif self.cursor_x >= size_line:
            self.cursor_x = size_line - 1


    def k_left(self, h, w):
        self.check_cursor_x()
        if self.cursor_x > 0:
            self.cursor_x -= 1
        return False

    def k_right(self, h, w):
        self.cursor_x += 1
        self.check_cursor_x()
        return False

    def k_down(self, h, w):
        self.scroll_down(h, 1, False)
        return True

    def k_up(self, h, w):
        self.scroll_up(h, 1, False)
        return True

    def k_pageup(self, h, w):
        self.scroll_up(h, h-1, True)
        return True

    def k_pagedown(self, h, w):
        self.scroll_down(h, h-1, True)
        return True

    def k_enter(self, h, w):
        self.should_stop = True
        return False

    def mouse_event(self, k, h, w):
        button = k[3]

        if button == 0x20:
            now = time()
            diff = now - self.time_last_mouse_key
            diff = int(diff * 1000)

            self.time_last_mouse_key = now

            if diff <= MOUSE_INTERVAL:
                # double left-click
                return self.mouse_double_left_click(h, w)

        if button == 0x20: # simple left-click
            x2, y2 = self.screen.getbegyx()

            x = k[4] - 33 - x2
            y = k[5] - 33 - y2

            if x < 0 or y < 0 or x >= w or y >= h:
                return False

            self.cursor_x = x
            self.goto_line(self.win_y + y, h)
            self.cmd_highlight_current_word(h, w)
            self.check_cursor_x()

        elif button == 0x60: # scroll up
            self.scroll_up(h, 3, True)
        elif button == 0x61: # scroll down
            self.scroll_down(h, 3, True)

        return True


    def mouse_double_left_click(self, h, w):
        return False


    def k_home(self, h, w):
        # TODO: fix self.cursor_x >= w
        if self.cursor_x == 0:
            line = self.output.lines[self.win_y + self.cursor_y]
            while self.cursor_x < len(line):
                if line[self.cursor_x] != " ":
                    break
                self.cursor_x += 1
        else:
            self.cursor_x = 0
        return False

    def k_end(self, h, w):
        # TODO: fix self.cursor_x >= w
        size_line = len(self.output.lines[self.win_y + self.cursor_y])
        if size_line >= w:
            self.cursor_x = w - 1
        elif size_line > 0:
            self.cursor_x = size_line - 1
        else:
            self.cursor_x = 0
        return False

    def k_ctrl_right(self, h, w):
        self.check_cursor_x()
        # TODO: fix self.cursor_x >= w
        line = self.output.lines[self.win_y + self.cursor_y]
        x = self.cursor_x
        while x < len(line) and line[x] == " " and x < w:
            x += 1
        while x < len(line) and line[x] != " " and x < w:
            x += 1
        self.cursor_x = x

    def k_ctrl_left(self, h, w):
        self.check_cursor_x()
        line = self.output.lines[self.win_y + self.cursor_y]
        x = self.cursor_x
        if x == 0:
            return
        x -= 1
        while x > 0 and line[x] == " ":
            x -= 1
        while x > 0 and line[x] != " ":
            x -= 1
        if x != 0:
            x += 1
        self.cursor_x = x

    def k_prev_paragraph(self, h, w):
        l = self.win_y + self.cursor_y - 1
        while l > 0 and len(self.output.lines[l]) != 0:
            l -= 1
        if l >= 0:
            self.goto_line(l, h)
            self.check_cursor_x()
        return True

    def k_next_paragraph(self, h, w):
        l = self.win_y + self.cursor_y + 1
        while l < len(self.output.lines)-1 and len(self.output.lines[l]) != 0:
            l += 1
        if l < len(self.output.lines):
            self.goto_line(l, h)
            self.check_cursor_x()
        return True


    def k_top(self, h, w):
        self.cursor_y = 0
        self.win_y = 0
        self.cursor_x = 0
        return True


    def k_bottom(self, h, w):
        self.cursor_x = 0
        if self.win_y >= len(self.token_lines) - h:
            self.cursor_y += len(self.token_lines) - \
                             self.win_y - self.cursor_y - 1
        else:
            self.cursor_y = h - 1
            self.win_y = len(self.token_lines) - h
        return True


    def cmd_highlight_current_word(self, h, w):
        w = self.get_word_under_cursor()
        if w is None:
            return False
        self.search_hi = w
        return True


    def cmd_highlight_clear(self, h, w):
        self.search_hi = None
        return True
