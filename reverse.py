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

from lib import reverse, parse_args
from lib.utils import info, die

# Generates the file custom_colors.py at the beginning
import lib.colors

if __name__ == '__main__':
    ctx = parse_args()

    if ctx.color and lib.colors.VERSION < 1.3:
        info("There is a new version of custom_colors.py. If it's wasn't")
        info("modified you can delete it. Otherwise you can copy it")
        info("somewhere, run again your command then merge the file at hand.")
        die()

    if ctx.interactive_mode:
        from lib.ui.console import Console
        i = Console(ctx)
    elif ctx.filename is not None:
        reverse(ctx)
