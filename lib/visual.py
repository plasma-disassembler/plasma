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

import curses
from curses import A_UNDERLINE, color_pair

from custom_colors import *


class Visual():
    def __init__(self, interactive, disassembler, output):
        self.win_y = 0
        self.cursor_y = 0
        self.cursor_x = 0
        self.output = output
        self.token_lines = output.token_lines
        self.dis = disassembler
        self.interact = interactive

        self.main_mapping = {
            b"\x1b\x5b\x44": self.main_k_left,
            b"\x1b\x5b\x43": self.main_k_right,
            b"\x1b\x5b\x41": self.main_k_up,
            b"\x1b\x5b\x42": self.main_k_down,
            b"\x1b\x5b\x35\x7e": self.main_k_pageup,
            b"\x1b\x5b\x36\x7e": self.main_k_pagedown,
            b"z": self.main_cmd_line_middle,
            b"g": self.main_cmd_top,
            b"G": self.main_cmd_bottom,
            b";": self.view_inline_comment_editor,
            b"%": self.main_cmd_next_bracket,
        }

        self.inline_mapping = {
            b"\x1b\x5b\x44": self.inline_k_left,
            b"\x1b\x5b\x43": self.inline_k_right,
            b"\x7f": self.inline_k_backspace,
            b"\x1b\x5b\x37\x7e": self.inline_k_home,
            b"\x1b\x5b\x38\x7e": self.inline_k_end,
            b"\x1b\x5b\x33\x7e": self.inline_k_delete,
            b"\x15": self.inline_k_ctrl_u,
            b"\x0b": self.inline_k_ctrl_k,
            b"\n": self.inline_k_enter,
            b"\x01": self.inline_k_home, # ctrl-a
            b"\x05": self.inline_k_end, # ctrl-e
        }

        self.screen = curses.initscr()

        curses.noecho()
        curses.cbreak()
        curses.mousemask(curses.ALL_MOUSE_EVENTS | curses.REPORT_MOUSE_POSITION)
        curses.start_color()
        curses.use_default_colors()
        curses.mouseinterval(0)

        for i in range(0, curses.COLORS):
            curses.init_pair(i, i, -1)

        curses.wrapper(self.view_main)

        curses.nocbreak()
        curses.echo()
        curses.endwin()


    def read_escape_keys(self):
        self.screen.timeout(-1)
        k = self.screen.getch()
        seq = [k]
        self.screen.timeout(0)
        for i in range(8):
            k = self.screen.getch()
            if k == -1:
                break
            seq.append(k)
        return bytes(seq)


    def view_main_redraw(self, h, w):
        i = 0
        while i < h:
            if self.win_y + i < len(self.token_lines):
                self.print_line(w, i)
            else:
                # force to clear the entire line
                self.screen.move(i, 0)
            self.screen.clrtoeol()
            i += 1
        self.screen.refresh()


    def view_main(self, screen):
        screen.clear()
        self.screen.keypad(False)
        refr = True

        while 1:
            if refr:
                (h, w) = screen.getmaxyx()
                self.view_main_redraw(h, w)
                refr = False

            screen.move(self.cursor_y, self.cursor_x)

            k = self.read_escape_keys()

            if k == b"q":
                break

            if k in self.main_mapping:
                refr = self.main_mapping[k](h, w)
            elif k.startswith(b"\x1b[M"):
                refr = self.main_mouse_event(k, h)


    def view_inline_comment_editor(self, h, w):
        line = self.win_y + self.cursor_y
        if line not in self.output.line_addr:
            return True

        self.interact.database_modified = True

        addr = self.output.line_addr[line]

        # The same address can be repeated on multiple lines
        # With this we are sure to everytime on the same line
        # example for mips:
        #   # 0x4002bc: lui $gp, 0x19
        #   # 0x4002c0: addiu $gp, $gp, -0x63dc
        #   0x4002bc: li $gp, 0x189c24
        new_line = self.output.addr_line[addr]

        if new_line != line:
            diff = new_line - line
            if diff > 0:
                self.scroll_down(h, diff, False)
            elif diff < 0:
                self.scroll_up(h, -diff, False)
            line = new_line
            (h, w) = self.screen.getmaxyx()
            self.view_main_redraw(h, w)

        # xbegin is the first index just after all operands
        # So we need to add 1 to be at the index of ;
        xbegin, _ = self.output.index_end_inst[line]
        self.comm = []
        screen = self.screen
        y = self.cursor_y
        col_intern = color_pair(COLOR_INTERN_COMMENT.val) | A_UNDERLINE

        if addr in self.dis.inline_comments:
            self.comm = list(self.dis.inline_comments[addr])

        self.cursor_x = xbegin + 3
        i = 0 # index in the string comment

        while 1:
            (h, w) = screen.getmaxyx()
            x = xbegin
            screen.move(y, xbegin)
            if x + 3 < w:
                screen.addstr(y, x, " ; ", col_intern)
                x += 3
                if x + len(self.comm) >= w:
                    screen.addstr("".join(self.comm[:w - x - 1]), col_intern)
                else:
                    screen.addstr("".join(self.comm), col_intern)
            screen.clrtoeol()

            # Underline the rest of the line
            n = w - xbegin - len(self.comm) - 4
            self.screen.addstr(" " * n, color_pair(0) | curses.A_UNDERLINE)

            screen.move(y, self.cursor_x)
            k = self.read_escape_keys()

            if k == b"\x1b": # escape = cancel
                break

            if k in self.inline_mapping:
                i = self.inline_mapping[k](xbegin, i, w)
                if k == b"\n":
                    break
            elif k[0] >= 32 and k[0] <= 126 and self.cursor_x < w - 1:
                # TODO: fix self.cursor_x >= w
                # TODO: utf-8
                c = chr(k[0])
                self.comm.insert(i, c)
                i += 1
                self.cursor_x += 1

        return True


    def print_line(self, w, i):
        num_line = self.win_y + i
        is_current_line = self.cursor_y == i
        x = 0
        force_exit = False

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
                return

        if is_current_line:
            n = w - x - 1
            self.screen.addstr(i, x, " " * n, color_pair(0) | A_UNDERLINE)


    def scroll_up(self, h, n, page_scroll):
        if page_scroll:
            wy = self.win_y - n
            y = self.cursor_y + n
            line = self.win_y + self.cursor_y
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
            for i in range(n):
                if self.win_y == 0:
                    if self.cursor_y == 0:
                        break
                    self.cursor_y -= 1
                else:
                    if self.cursor_y == 3:
                        self.win_y -= 1
                    else:
                        self.cursor_y -= 1
        self.check_cursor_x()


    def scroll_down(self, h, n, page_scroll):
        if page_scroll:
            wy = self.win_y + n
            y = self.cursor_y - n
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
            for i in range(n):
                if self.win_y >= len(self.token_lines) - h:
                    if self.win_y + self.cursor_y == len(self.token_lines) - 1:
                        break
                    self.cursor_y += 1
                else:
                    if self.cursor_y == h - 4:
                        self.win_y += 1
                    else:
                        self.cursor_y += 1
        self.check_cursor_x()


    def check_cursor_x(self):
        line = self.output.lines[self.win_y + self.cursor_y]
        if self.cursor_x >= len(line):
            self.cursor_x = len(line) - 1


    # Main view : Keys mapping

    def main_k_left(self, h, w):
        if self.cursor_x > 0:
            self.cursor_x -= 1
        return False

    def main_k_right(self, h, w):
        line = self.output.lines[self.win_y + self.cursor_y]
        if self.cursor_x < len(line) - 1:
            self.cursor_x += 1
        return False

    def main_k_down(self, h, w):
        self.scroll_down(h, 1, False)
        return True

    def main_k_up(self, h, w):
        self.scroll_up(h, 1, False)
        return True

    def main_k_pageup(self, h, w):
        self.scroll_up(h, h-1, True)
        return True

    def main_k_pagedown(self, h, w):
        self.scroll_down(h, h-1, True)
        return True

    def main_mouse_event(self, k, h):
        button = k[3]
        if button == 0x20: # left-click
            self.cursor_x = k[4] - 33
            diff = k[5] - 33 - self.cursor_y
            if diff > 0:
                self.scroll_down(h, diff, False)
            elif diff < 0:
                self.scroll_up(h, -diff, False)
            else:
                self.check_cursor_x()
        elif button == 0x60: # scroll up
            self.scroll_up(h, 3, True)
        elif button == 0x61: # scroll down
            self.scroll_down(h, 3, True)
        return True

    def main_cmd_line_middle(self, h, w):
        mid = int(h/2)
        if self.cursor_y + self.win_y > mid:
            self.win_y += self.cursor_y - mid
            self.cursor_y = mid
        return True

    def main_cmd_top(self, h, w):
        self.cursor_y = 0
        self.win_y = 0
        return True

    def main_cmd_bottom(self, h, w):
        if self.win_y >= len(self.token_lines) - h:
            self.cursor_y += len(self.token_lines) - \
                             self.win_y - self.cursor_y - 1
        else:
            self.cursor_y = h - 1
            self.win_y = len(self.token_lines) - h
        return True


    def main_cmd_next_bracket(self, h, w):
        line = self.win_y + self.cursor_y
        x = self.cursor_x
        char = self.output.lines[line][x]
        diff = 0

        if char == "}":
            l = line - 1
            while l >= 0:
                if self.output.lines[l][x] != " ":
                    diff = line - l
                    break
                l -= 1

            if l != -1:
                x = 0
                while x < len(self.output.lines[l]):
                    if self.output.lines[l][x] == "{":
                        break
                    x += 1

            self.cursor_x = x
            self.scroll_up(h, diff, False)

        elif char == "{":
            x = 0
            while 1:
                if self.output.lines[line][x] != " ":
                    break
                x += 1

            l = line + 1
            while l < len(self.output.lines):
                if self.output.lines[l][x] != " ":
                    diff = l - line
                    break
                l += 1

            self.cursor_x = x
            self.scroll_down(h, diff, False)

        return True


    # Inline comment editor : keys mapping

    def inline_k_left(self, xbegin, i, w):
        if i != 0:
            i -= 1
            self.cursor_x -= 1
        return i

    def inline_k_right(self, xbegin, i, w):
        if i != len(self.comm):
            i += 1
            self.cursor_x += 1
            # TODO: fix self.cursor_x >= w
            if self.cursor_x >= w:
                i -= self.cursor_x - w + 1
                self.cursor_x = w - 1
        return i

    def inline_k_backspace(self, xbegin, i, w):
        if i != 0:
            del self.comm[i-1]
            i -= 1
            self.cursor_x -= 1
        return i

    def inline_k_home(self, xbegin, i, w):
        self.cursor_x = xbegin + 3 # 3 for " ; "
        return 0

    def inline_k_end(self, xbegin, i, w):
        n = len(self.comm)
        self.cursor_x = xbegin + 3 + n
        i = n
        # TODO: fix self.cursor_x >= w
        if self.cursor_x >= w:
            i -= self.cursor_x - w + 1
            self.cursor_x = w - 1
        return i

    def inline_k_delete(self, xbegin, i, w):
        if i != len(self.comm):
            del self.comm[i]
        return i

    def inline_k_enter(self, xbegin, i, w):
        line = self.win_y + self.cursor_y
        addr = self.output.line_addr[line]
        lines = self.output.lines

        xbegin, idx_token = self.output.index_end_inst[line]

        if addr in self.dis.inline_comments:
            is_new_comment = False
            # Extract the comment which starts by #
            instr_comm = lines[line][xbegin + 3 + len(self.comm) + 1:]
        else:
            is_new_comment = True
            instr_comm = lines[line][xbegin + 1:]

        if not self.comm:
            if not is_new_comment:
                del self.dis.inline_comments[addr]

                lines[line] = "".join([
                    lines[line][:xbegin],
                    " ",
                    instr_comm])

                # Remove space and comment
                del self.token_lines[line][idx_token]
                del self.token_lines[line][idx_token]
        else:
            self.comm = "".join(self.comm)
            self.dis.inline_comments[addr] = self.comm

            if is_new_comment:
                # Space token
                self.token_lines[line].insert(idx_token,
                        (" ", 0, False))

                # Insert the new token
                self.token_lines[line].insert(idx_token + 1,
                        ("; " + self.comm, COLOR_INTERN_COMMENT.val, False))

                self.output.index_end_inst[line] = \
                        (xbegin, idx_token)
            else:
                # Plus 1 for the space token
                self.token_lines[line][idx_token + 1] = \
                        ("; " + self.comm, COLOR_INTERN_COMMENT.val, False)

            lines[line] = "".join([
                lines[line][:xbegin],
                " ; ",
                self.comm,
                " ",
                instr_comm])
        return i

    def inline_k_ctrl_u(self, xbegin, i, w):
        self.comm = self.comm[i:]
        self.cursor_x = xbegin + 3 # 3 for " ; "
        return 0

    def inline_k_ctrl_k(self, xbegin, i, w):
        self.comm = self.comm[:i]
        return i
