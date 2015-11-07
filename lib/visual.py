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


CMD_g = 103
CMD_G = 71
CMD_q = 113
CMD_z = 122


class Visual():
    def __init__(self, output):
        self.win_y = 0
        self.cursor_y = 0
        self.cursor_x = 0
        self.output = output
        self.lines = output.lines

        self.screen = curses.initscr()

        curses.noecho()
        curses.cbreak()
        self.screen.keypad(True)
        curses.mousemask(curses.ALL_MOUSE_EVENTS | curses.REPORT_MOUSE_POSITION)
        curses.start_color()
        curses.use_default_colors()
        curses.mouseinterval(0)

        for i in range(0, curses.COLORS):
            curses.init_pair(i, i, -1)

        curses.wrapper(self.__main_loop)

        curses.nocbreak()
        self.screen.keypad(False)
        curses.echo()
        curses.endwin()


    def __main_loop(self, screen):
        screen.clear()

        refr = True
        chars = {CMD_g, CMD_G, CMD_q, CMD_z}

        while 1:
            if refr:

                (h, w) = screen.getmaxyx()
                (y, x) = screen.getyx()

                i = 0
                while i < h:
                    if self.win_y + i < len(self.lines):
                        self.print_line(w, i)
                    else:
                        # force to clear the entire line
                        screen.move(i, 0)
                    screen.clrtoeol()
                    i += 1

                screen.refresh()
                refr = False

            screen.move(self.cursor_y, self.cursor_x)
            res = screen.getch()
            refr = True

            if res in chars:
                if res == CMD_q:
                    return
                elif res == CMD_g:
                    self.cursor_y = 0
                    self.win_y = 0
                elif res == CMD_z:
                    mid = int(h/2)
                    if self.cursor_y + self.win_y > mid:
                        self.win_y += self.cursor_y - mid
                        self.cursor_y = mid
                elif res == CMD_G:
                    if self.win_y >= len(self.lines) - h:
                        self.cursor_y += len(self.lines) - self.win_y - self.cursor_y - 1
                    else:
                        self.cursor_y = h - 1
                        self.win_y = len(self.lines) - h
            else:
                if res == curses.KEY_UP:
                    self.scroll_up(h, 1, False)
                elif res == curses.KEY_DOWN:
                    self.scroll_down(h, 1, False)
                elif res == curses.KEY_LEFT:
                    if self.cursor_x > 0:
                        self.cursor_x -= 1
                elif res == curses.KEY_RIGHT:
                    if self.cursor_x < w - 1:
                        self.cursor_x += 1
                elif res == curses.KEY_PPAGE:
                    self.scroll_up(h, h-1, True)
                elif res == curses.KEY_NPAGE:
                    self.scroll_down(h, h-1, True)

                elif res == curses.KEY_MOUSE:
                    mouse = curses.getmouse()
                    mouse_state = mouse[4]
                    if mouse_state & curses.BUTTON4_PRESSED:
                        self.scroll_up(h, 3, True)
                    # mouse scroll down
                    elif mouse_state == 0x200000:
                        self.scroll_down(h, 3, True)
                    elif mouse_state == curses.BUTTON1_PRESSED:
                        self.cursor_x = mouse[1]
                        diff = mouse[2] - self.cursor_y
                        if diff > 0:
                            self.scroll_down(h, diff, False)
                        elif diff < 0:
                            self.scroll_up(h, -diff, False)


    def scroll_up(self, h, n, page_scroll):
        if page_scroll:
            wy = self.win_y - n
            y = self.cursor_y + n
            line = self.win_y + self.cursor_y
            if wy >= 0:
                self.win_y = wy
                if y <= h - 3:
                    if line != len(self.lines):
                        self.cursor_y = y
                else:
                    self.cursor_y = h - 4
            else:
                self.win_y = 0
        else:
            if self.cursor_y == 0 and self.win_y == 0:
                return
            wy = self.win_y - n
            y = self.cursor_y - n
            if self.win_y == 0:
                if y >= 0:
                    self.cursor_y = y
                else:
                    self.cursor_y = 0
            else:
                if y >= 3:
                    self.cursor_y = y
                else:
                    self.cursor_y = 3
                    if wy >= 0:
                        self.win_y = wy


    def scroll_down(self, h, n, page_scroll):
        if page_scroll:
            wy = self.win_y + n
            y = self.cursor_y - n
            if wy > len(self.lines) - h:
                if wy < len(self.lines) - 3:
                    self.win_y = wy
                else:
                    self.win_y = len(self.lines) - 3 - 1
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
            wy = self.win_y + n
            y = self.cursor_y + n
            line = self.win_y + self.cursor_y
            if line >= len(self.lines) - n:
                self.cursor_y += len(self.lines) - self.win_y - self.cursor_y - 1
                return
            if self.win_y >= len(self.lines) - h:
                if y < h:
                    self.cursor_y = y
                else:
                    self.cursor_y = h - 1
            else:
                if y < h - 3:
                    self.cursor_y = y
                else:
                    self.cursor_y = h - 3 - 1
                    if wy <= len(self.lines) - h:
                        self.win_y = wy


    def print_line(self, w, i):
        num_line = self.win_y + i
        is_current_line = self.cursor_y == i
        x = 0
        force_exit = False

        for (string, col, is_bold) in self.lines[num_line]:
            if x + len(string) >= w:
                string = string[:w-x-1]
                force_exit = True

            c = curses.color_pair(col)

            if is_current_line:
                c |= curses.A_UNDERLINE

            if is_bold:
                c |= curses.A_BOLD

            self.screen.addstr(i, x, string, c)

            x += len(string)
            if force_exit:
                return

        if is_current_line:
            n = w - x - 1
            self.screen.addstr(i, x, " " * n,
                        curses.color_pair(0) | curses.A_UNDERLINE)
