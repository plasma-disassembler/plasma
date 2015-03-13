#!/bin/python3
#
# Reverse : reverse engineering for x86 binaries
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


nocolor = False
color_counter = 112

addr_color = {}


def pick_color(addr):
    global color_counter

    if addr in addr_color:
        return

    if color_counter == 230:
        color_counter = 112
    else:
        color_counter += 2

    addr_color[addr] = color_counter



def color(text, c):
    if nocolor:
        return text
    return "\x1b[38;5;" + str(c) + "m" + text + "\x1b[0m"


def yellow(text):
    if nocolor:
        return text
    return "\x1b[;33m" + text + "\x1b[0m"


def red(text):
    if nocolor:
        return text
    return "\x1b[;31m" + text + "\x1b[0m"


def bold(text):
    if nocolor:
        return text
    return "\x1b[1m" + text + "\x1b[0m"


def color_keyword(text):
    if nocolor:
        return text
    return bold(color(text, 161))


def color_var(text):
    if nocolor:
        return text
    return bold(color(text, 208))


def color_comment(text):
    if nocolor:
        return text
    return color(text, 242)


def color_addr(text):
    if nocolor:
        return text
    return color(text, 242)


def color_string(text):
    if nocolor:
        return text
    return color(text, 144)
