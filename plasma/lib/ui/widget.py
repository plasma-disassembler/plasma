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
from curses import color_pair, A_REVERSE
from time import time

from plasma.lib.custom_colors import COLOR_COMMENT


class Widget():
    def __init__(self, x, y, w, h):
        self.mapping = {}
        self.x = x
        self.y = y
        self.height = h
        self.width = w
        self.has_focus = False
        self.screen = curses.newwin(h, w, y, x)
        self.should_stop = False
        self.value_selected = False
        self.is_passive = False


    def draw(self):
        raise NotImplementedError


    def draw_cursor(self):
        raise NotImplementedError


    def callback_mouse_up(self):
        raise NotImplementedError


    def callback_mouse_down(self):
        raise NotImplementedError


    def callback_mouse_left(self):
        raise NotImplementedError


    def callback_mouse_double_left(self):
        raise NotImplementedError



class VertivalSep(Widget):
    def __init__(self, x, y, h):
        w = 2
        Widget.__init__(self, x, y, w, h)
        self.is_passive = True
        self.mapping = {}


    def draw(self):
        c = color_pair(COLOR_COMMENT.val) #| A_REVERSE
        for i in range(self.height):
            self.screen.addstr(i, 0, "▕", c)
