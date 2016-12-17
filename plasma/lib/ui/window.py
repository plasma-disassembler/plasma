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

from plasma.lib.ui.listbox import Listbox


MOUSE_EVENT = [0x1b, 0x5b, 0x4d]
MOUSE_INTERVAL = 200


def popup_text(title, output, par_widget):
    """
    It opens a centered popup. output is an instance of the class Output.
    Returns (bool, line number of the cursor)
    """
    h2 = par_widget.height * 3 // 4
    w2 = par_widget.width * 6 // 7

    x = (par_widget.width - w2) // 2 - 1
    y = (par_widget.height - h2) // 2 - 1

    # A background with borders
    borders = curses.newwin(h2 + 2, w2 + 2, par_widget.y + y, par_widget.x + x)
    borders.border()
    borders.addstr(0, (w2 - len(title)) // 2, " %s " % title)
    borders.refresh()

    w = Window()
    w.screen = borders

    w.widgets.append(Listbox(par_widget.x + x + 1, par_widget.y + y + 1,
                             w2, h2, output))
    ret = w.start_view(w.screen)

    return (ret, w.widgets[0].win_y + w.widgets[0].cursor_y)


def popup_inputbox(title, text, par_widget):
    """
    It opens a centered popup and returns the text entered by the user.
    """
    h2 = 1
    w2 = par_widget.width * 6 // 7

    x = (par_widget.width - w2) // 2 - 1 + par_widget.x
    y = (par_widget.height - h2) // 2 - 1 + par_widget.y

    # A background with borders
    borders = curses.newwin(h2 + 2, w2 + 2, y, x)
    borders.border()
    borders.addstr(0, (w2 - len(title)) // 2, " %s " % title)
    borders.refresh()

    return inputbox(text, x + 1, y + 1, w2, h2)


def inputbox(text, x, y, w, h):
    """
    It creates a surface for an inline editor.   
    """
    from plasma.lib.ui.inlineed import InlineEd
    ed = InlineEd(0, 0, 0, text, 0, [])
    ed.screen = curses.newwin(h, w, y, x)
    ret = ed.start_view(ed.screen)
    if not ret:
        return ""
    return ed.text


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
        wdgt = self.widgets[self.focus_widget_idx]
        if k in wdgt.mapping:
            return wdgt.mapping[k]()
        if k.startswith(b"\x1b[M"):
            return self.mouse_event(k)
        return False


    def search_focus(self, x, y):
        for i, w in enumerate(self.widgets):
            if w.x <= x < w.x + w.width and w.y <= y < w.y + w.height:
                return i
        return -1


    def mouse_event(self, k):
        wdgt = self.widgets[self.focus_widget_idx]

        x2, y2 = self.screen.getbegyx()
        x = k[4] - 33 - x2
        y = k[5] - 33 - y2

        idx = self.search_focus(x, y)
        if idx != -1 and not (x < 0 or y < 0):
            self.focus_widget_idx = idx
            wdgt = self.widgets[idx]
            x -= wdgt.x
            y -= wdgt.y

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
                return wdgt.callback_mouse_double_left()

        # Simple left click
        if button == 0x20:
            wdgt.callback_mouse_left(x, y)
        elif button == 0x60: # scroll up
            wdgt.callback_mouse_up()
        elif button == 0x61: # scroll down
            wdgt.callback_mouse_down()

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


    def start_view(self, screen):
        self.screen = screen
        screen.keypad(False)

        (last_h, last_w) = screen.getmaxyx()
        refr = True

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
                screen.erase()
                return wdgt.value_selected

        screen.erase()
        return wdgt.value_selected



