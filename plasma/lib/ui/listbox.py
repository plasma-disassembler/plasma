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
from curses import A_UNDERLINE, color_pair, A_REVERSE

from plasma.lib.custom_colors import *
from plasma.lib.consts import *
from plasma.lib.ui.widget import Widget


class Listbox(Widget):
    def __init__(self, x, y, w, h, output):
        Widget.__init__(self, x, y, w, h)

        # Coordinates of the cursor inside the box
        self.win_y = 0
        self.cursor_y = 0
        self.cursor_x = 0

        if output is not None:
            self.output = output
            self.token_lines = output.token_lines

        self.search_hi = None
        self.search_bin = None
        self.word_accepted_chars = ["_", "@", ".", "$", ":", "?"]

        # Note: all these functions should return a boolean. The value is true
        # if the screen must be refreshed (not re-drawn, in this case call
        # explictly self.draw or self.reload_asm if the output changed).

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
            b" ": self.cmd_highlight_current_word,
            b"\x0b": self.cmd_highlight_clear, # ctrl-k
            b"\x1b\x5b\x31\x3b\x35\x44": self.k_ctrl_left,
            b"\x1b\x5b\x31\x3b\x35\x43": self.k_ctrl_right,
            b"\n": self.k_enter,
            b"q": self.k_q,
            b"\x1b": self.k_q,
        }

        self.cursor_position_utf8 = {
            0: "█",
            1: "▇",
            2: "▆",
            3: "▅",
            4: "▄",
            5: "▃",
            6: "▂",
            7: "▁",
        }


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


    def goto_line(self, new_line):
        curr_line = self.win_y + self.cursor_y
        diff = new_line - curr_line
        if diff > 0:
            self.scroll_down(diff, False)
        elif diff < 0:
            self.scroll_up(-diff, False)


    def draw(self):
        i = 0
        while i < self.height:
            if self.win_y + i < len(self.token_lines):
                self.print_line(i)
            else:
                # force to clear the entire line
                self.screen.move(i, 0)
            self.screen.clrtoeol()
            i += 1

        # Print the scroll cursor on the right. It uses utf-8 block characters.

        y = self.get_y_scroll()
        i = y % 8
        y = y // 8

        self.screen.insstr(y, self.width - 1,
            self.cursor_position_utf8[i],
            color_pair(COLOR_SCROLL_CURSOR))

        if i != 0 and y + 1 < self.height:
            self.screen.insstr(y + 1, self.width - 1,
                self.cursor_position_utf8[i],
                color_pair(COLOR_SCROLL_CURSOR) | A_REVERSE)


    def draw_cursor(self):
        size_line = len(self.output.lines[self.win_y + self.cursor_y])
        if size_line == 0:
            x = 0
        elif self.cursor_x >= size_line:
            x = size_line - 1
        else:
            x = self.cursor_x

        self.screen.move(self.cursor_y, x)


    def print_line(self, i):
        num_line = self.win_y + i
        is_current_line = self.cursor_y == i and self.has_focus
        force_exit = False
        x = 0

        for (string, col, is_bold) in self.token_lines[num_line]:
            if x + len(string) >= self.width - 1:
                string = string[:self.width - x - 1]
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
            n = self.width - x - 1
            self.screen.addstr(i, x, " " * n, color_pair(0) | A_UNDERLINE)
            x += n

        self.highlight_search(i)
        self.screen.move(i, x)


    def get_y_scroll(self):
        # Because the scroll can have 8 states
        h8 = self.height * 8
        if len(self.token_lines) <= self.height:
            return 0
        y = self.win_y * h8 // (len(self.token_lines) - self.height)
        if y >= h8 - 8:
            return h8 - 8
        return y


    def callback_mouse_left(self, x, y):
        self.cursor_x = x
        self.goto_line(self.win_y + y)
        self.cmd_highlight_current_word(True)
        self.check_cursor_x()


    def callback_mouse_up(self):
        self.scroll_up(3, True)


    def callback_mouse_down(self):
        self.scroll_down(3, True)


    def callback_mouse_double_left(self):
        return False


    def highlight_search(self, i):
        if self.search_hi is None:
            return
        num_line = self.win_y + i
        start = 0
        while 1:
            idx = self.output.lines[num_line].find(self.search_hi, start)
            if idx == -1 or idx >= self.width:
                break
            self.screen.chgat(i, idx, len(self.search_hi), curses.color_pair(1))
            start = idx + 1


    def scroll_up(self, n, do_page_scroll):
        if do_page_scroll:
            wy = self.win_y - n
            y = self.cursor_y + n
            line = self.win_y + self.cursor_y

            wy = self.dump_update_up(wy)

            if wy >= 0:
                self.win_y = wy
                if y <= self.height - 3:
                    if line != len(self.token_lines):
                        self.cursor_y = y
                else:
                    self.cursor_y = self.height - 4
            else:
                self.win_y = 0
        else:
            # TODO: find another way
            for i in range(n):
                self.dump_update_up(self.win_y)

                if self.win_y == 0:
                    if self.cursor_y == 0:
                        break
                    self.cursor_y -= 1
                else:
                    if self.cursor_y == 3:
                        self.win_y -= 1
                    else:
                        self.cursor_y -= 1


    def scroll_down(self, n, do_page_scroll):
        if do_page_scroll:
            wy = self.win_y + n
            y = self.cursor_y - n

            self.dump_update_bottom(wy)

            if wy > len(self.token_lines) - self.height:
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
                self.dump_update_bottom(self.win_y)

                if self.win_y >= len(self.token_lines) - self.height:
                    if self.win_y + self.cursor_y == len(self.token_lines) - 1:
                        break
                    self.cursor_y += 1
                else:
                    if self.cursor_y == self.height - 4:
                        self.win_y += 1
                    else:
                        self.cursor_y += 1


    def dump_update_up(self, wy):
        return wy


    def dump_update_bottom(self, wy):
        return


    def check_cursor_x(self):
        size_line = len(self.output.lines[self.win_y + self.cursor_y])
        if size_line == 0:
            self.cursor_x = 0
        elif self.cursor_x >= size_line:
            self.cursor_x = size_line - 1


    # Commands / Mapping keys


    def k_left(self):
        self.check_cursor_x()
        if self.cursor_x > 0:
            self.cursor_x -= 1
        return False

    def k_right(self):
        self.cursor_x += 1
        self.check_cursor_x()
        return False

    def k_down(self):
        self.scroll_down(1, False)
        return True

    def k_up(self):
        self.scroll_up(1, False)
        return True

    def k_pageup(self):
        self.scroll_up(self.height - 1, True)
        return True

    def k_pagedown(self):
        self.scroll_down(self.height - 1, True)
        return True

    def k_enter(self):
        self.should_stop = True
        self.value_selected = True
        return False


    def k_q(self):
        self.should_stop = True
        self.value_selected = False
        return False


    def k_home(self):
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

    def k_end(self):
        # TODO: fix self.cursor_x >= w
        size_line = len(self.output.lines[self.win_y + self.cursor_y])
        if size_line >= self.width:
            self.cursor_x = self.width - 1
        elif size_line > 0:
            self.cursor_x = size_line - 1
        else:
            self.cursor_x = 0
        return False

    def k_ctrl_right(self):
        self.check_cursor_x()
        # TODO: fix self.cursor_x >= w
        line = self.output.lines[self.win_y + self.cursor_y]
        x = self.cursor_x
        while x < len(line) and line[x] == " " and x < self.width:
            x += 1
        while x < len(line) and line[x] != " " and x < self.width:
            x += 1
        self.cursor_x = x

    def k_ctrl_left(self):
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

    def k_prev_paragraph(self):
        l = self.win_y + self.cursor_y - 1
        while l > 0 and len(self.output.lines[l]) != 0:
            l -= 1
        if l >= 0:
            self.goto_line(l)
            self.check_cursor_x()
        return True

    def k_next_paragraph(self):
        l = self.win_y + self.cursor_y + 1
        while l < len(self.output.lines)-1 and len(self.output.lines[l]) != 0:
            l += 1
        if l < len(self.output.lines):
            self.goto_line(l)
            self.check_cursor_x()
        return True


    def k_top(self):
        self.cursor_y = 0
        self.win_y = 0
        self.cursor_x = 0
        return True


    def k_bottom(self):
        self.cursor_x = 0
        if self.win_y >= len(self.token_lines) - self.height:
            self.cursor_y += len(self.token_lines) - \
                             self.win_y - self.cursor_y - 1
        else:
            self.cursor_y = self.height - 1
            self.win_y = len(self.token_lines) - self.height
        return True


    def cmd_highlight_current_word(self, from_mouse_event=False):
        # When we click on a word with the mouse, we must be explicitly
        # on the word.
        if not from_mouse_event:
            num_line = self.win_y + self.cursor_y
            line = self.output.lines[num_line]
            if self.cursor_x >= len(line):
                self.cursor_x = len(line) - 1

        w = self.get_word_under_cursor()
        if w is None:
            return False
        self.search_hi = w
        return True


    def cmd_highlight_clear(self):
        self.search_hi = None
        return True
