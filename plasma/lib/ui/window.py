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
from time import time

from plasma.lib.consts import *
from plasma.lib.ui.widget import VertivalSep


MOUSE_EVENT = [0x1b, 0x5b, 0x4d]
MOUSE_INTERVAL = 200


class Window():
    def __init__(self):
        self.screen = None
        self.widgets = []
        self.set_key_timeout = True
        self.time_last_mouse_key = MOUSE_INTERVAL + 1
        self.focus_widget_idx = 0
        self.cursor_x = 0
        self.cursor_y = 0


    # Returns True if we should refresh the screen
    def do_key(self, k):
        if k == b"|":
            self.split()
            return False

        w = self.widgets[self.focus_widget_idx]
        if k in w.mapping:
            return w.mapping[k]()
        if k.startswith(b"\x1b[M"):
            return self.mouse_event(k)
        return False


    def search_focus(self, x, y):
        for i, w in enumerate(self.widgets):
            if w.x <= x < w.x + w.width and w.y <= y < w.y + w.height and \
                      not w.is_passive:
                return i
        return -1


    def mouse_event(self, k):
        w = self.widgets[self.focus_widget_idx]

        x2, y2 = self.screen.getbegyx()
        x = k[4] - 33 - x2
        y = k[5] - 33 - y2

        idx = self.search_focus(x, y)
        if idx != -1 and idx != self.focus_widget_idx and not (x < 0 or y < 0):
            w.has_focus = False
            w.draw()
            w.screen.refresh()
            self.focus_widget_idx = idx
            w = self.widgets[idx]
            w.has_focus = True

        x -= w.x
        y -= w.y

        button = k[3]

        if button == 0x20 and idx == -1:
            return False

        # Double left click
        if button == 0x20:
            now = time()
            diff = now - self.time_last_mouse_key
            diff = int(diff * 1000)

            self.time_last_mouse_key = now

            if diff <= MOUSE_INTERVAL:
                return w.callback_mouse_double_left()

        # Simple left click
        if button == 0x20:
            w.callback_mouse_left(x, y)
        elif button == 0x60: # scroll up
            w.callback_mouse_up()
        elif button == 0x61: # scroll down
            w.callback_mouse_down()

        return True


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


    def refresh_all(self):
        for w in self.widgets:
            w.draw()

        for w in self.widgets:
            if w.has_focus:
                w.draw_cursor()
            w.screen.refresh()


    def start_view(self, screen):
        self.screen = screen
        screen.keypad(False)

        (last_h, last_w) = screen.getmaxyx()
        refr = False
        self.refresh_all()

        while 1:
            (h, w) = screen.getmaxyx()
            self.height = h
            self.width = w

            if h != last_h or w != last_w:
                # TODO : resizing
                screen.erase()
                curses.resizeterm(h, w)
                last_h = h
                last_w = w
                refr = True
                if self.cursor_y > h:
                    self.cursor_y = h - 5
                    if self.cursor_y < 0:
                        self.cursor_y = 0
                if self.cursor_x > w:
                    self.cursor_x = w - 3

            wdgt = self.widgets[self.focus_widget_idx]

            if refr:
                wdgt.draw()
                refr = False

            wdgt.draw_cursor()
            wdgt.screen.refresh()

            k = self.read_escape_keys()
            refr = self.do_key(k)

            if wdgt.should_stop:
                wdgt.should_stop = False # because the console saves widgets
                screen.erase()
                return wdgt.value_selected

        screen.erase()
        return wdgt.value_selected


    def split(self):
        from plasma.lib.ui.disasmbox import Disasmbox
        w = self.widgets[self.focus_widget_idx]

        if not isinstance(w, Disasmbox):
            return

        # Count  widgets
        n_dbox = 0
        n_sep = 0
        for w in self.widgets:
            if isinstance(w, Disasmbox):
                n_dbox += 1
            elif isinstance(w, VertivalSep):
                n_sep += 1

        n_sep += 1
        n_dbox += 1

        # Update widgets width
        height, width = self.screen.getmaxyx()

        w_dbox = (width - n_sep * 2) // n_dbox
        rest = (width - n_sep * 2) % n_dbox

        if w_dbox <= 20:
            return

        x = 0
        for i, w in enumerate(self.widgets):
            if isinstance(w, Disasmbox):
                w.width = w_dbox
                if i == len(self.widgets) - 1:
                    w.width += rest
                if w.cursor_x >= w.width:
                    w.cursor_x = w.width - 1
                # TODO : cleanest way, the height doesn't contain the status bar
                w.screen.resize(w.height + 1, w.width)
            w.x = x
            x += w.width
            w.screen.mvwin(w.y, w.x)

        # Add a vertical separator
        self.widgets.append(VertivalSep(x, 0, height))
        x += 2

        # Clone current Disasmbox, the width will be updated after
        until = w.last_addr if w.mode == MODE_DUMP else -1
        d = Disasmbox(x, 0, w_dbox, height,
                      w.gctx,
                      w.first_addr,
                      w.analyzer,
                      w.api,
                      mode=w.mode,
                      until=until,
                      update_position=False)

        for v in w.stack:
            d.stack.append(tuple(v))
        for v in w.saved_stack:
            d.saved_stack.append(tuple(v))

        d.cursor_x = w.cursor_x
        d.cursor_y = w.cursor_y
        d.win_y = w.win_y

        self.widgets.append(d)

        self.refresh_all()
