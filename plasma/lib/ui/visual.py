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
import traceback
import binascii

from plasma.lib.utils import error, die
from plasma.lib.custom_colors import *
from plasma.lib.consts import *
from plasma.lib.ui.window import Window
from plasma.lib.ui.disasmbox import Disasmbox


class Visual(Window):
    def __init__(self, gctx, ad, analyzer, api, last_widgets=None):
        Window.__init__(self)

        saved_quiet = gctx.quiet
        gctx.quiet = True

        # Start curses

        self.screen = curses.initscr()
        curses.noecho()
        curses.cbreak()
        curses.mousemask(curses.ALL_MOUSE_EVENTS | curses.REPORT_MOUSE_POSITION)

        curses.start_color()
        curses.use_default_colors()

        if gctx.color:
            for i in range(0, curses.COLORS):
                curses.init_pair(i, i, -1)

            try:
                curses.init_pair(1, COLOR_SEARCH_FG, COLOR_SEARCH_BG)
            except:
                curses.nocbreak()
                curses.echo()
                curses.endwin()
                gctx.quiet = saved_quiet
                error("is your terminal supports 256 colours ? check the issue #58")
                return
        else:
            for i in range(0, curses.COLORS):
                curses.init_pair(i, 7, -1) # white


        # Init widgets

        (h, w) = self.screen.getmaxyx()

        if last_widgets is not None:
            self.widgets = last_widgets
            for wdgt in self.widgets:
                wdgt.has_focus = False
                if isinstance(wdgt, Disasmbox):
                    wdgt.reload_asm()
        else:
            self.widgets = [Disasmbox(0, 0, w, h, gctx, ad, analyzer, api, mode=MODE_DUMP)]
            if self.widgets[0].ctx is None:
                self.error_occurs = True
                curses.nocbreak()
                curses.echo()
                curses.endwin()
                gctx.quiet = saved_quiet
                print("error: bad address or symbol")
                return

        self.widgets[0].has_focus = True

        try:
            curses.wrapper(self.start_view)
        except:
            curses.nocbreak()
            curses.echo()
            curses.endwin()
            gctx.quiet = saved_quiet
            traceback.print_exc()
            self.error_occurs = True
            return

        self.error_occurs = False
        curses.nocbreak()
        curses.echo()
        curses.endwin()
        gctx.quiet = saved_quiet
