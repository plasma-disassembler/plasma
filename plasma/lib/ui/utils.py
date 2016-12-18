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
from plasma.lib.ui.listbox import Listbox
from plasma.lib.ui.window import Window
from plasma.lib.ui.inlineed import InlineEd


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

