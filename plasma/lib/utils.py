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

import sys

gctx = None


if sys.maxsize == 0x7fffffffffffffff:
    def unsigned(n):
        return n & 0xffffffffffffffff
else:
    def unsigned(n):
        return n & 0xffffffff


def print_no_end(text):
    print(text, end="")


def debug__(obj="", end="\n"):
    if gctx.debug:
        if isinstance(obj, str) or isinstance(obj, int):
            print(obj, end=end, file=sys.stderr)
        elif isinstance(obj, list):
            print_list(obj)
        elif isinstance(obj, dict):
            print_dict(obj)
        elif isinstance(obj, set):
            print_set(obj)
        elif isinstance(obj, tuple):
            print_tuple(obj)



# In each array nxt (from gph.link_out)
BRANCH_NEXT = 0        # or for the if part
BRANCH_NEXT_JUMP = 1   # or for the else part


# Here, I don't use string.printable because it contains \r \n \t
# and I want to print backslashed strings.
PRINTABLE = [r'\x{0:02x}'.format(i) for i in range(256)]
BYTES_PRINTABLE_SET = set()
for c in ("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLM"
        "NOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ \r\t\n"):
    PRINTABLE[ord(c)] = c
    BYTES_PRINTABLE_SET.add(ord(c))

PRINTABLE[0] = r'\0'
PRINTABLE[9] = r'\t'
PRINTABLE[10] = r'\n'
PRINTABLE[13] = r'\r'

get_char = PRINTABLE.__getitem__



def index(L, obj, k=0):
    try:
        return L.index(obj, k)
    except ValueError:
        return -1


def list_starts_with(l, prefix):
    if len(prefix) > len(l):
        return False
    i = 0
    for v in prefix:
        if v != l[i]:
            return False
        i += 1
    return True



def error(txt):
    if not gctx.quiet:
        print("error: " + txt, file=sys.stderr)


def warning(txt):
    if not gctx.quiet:
        print("warning: " + txt, file=sys.stderr)


def info(txt):
    if not gctx.quiet:
        print("info: " + txt, file=sys.stderr)


def die(txt=None):
    if txt is not None:
        print("error: " + txt, file=sys.stderr)
    sys.exit(1)


# Debug functions

def print_set(s, end="\n"):
    print("{", end="", file=sys.stderr)
    for i in s:
        if isinstance(i, tuple):
            print_tuple(i)
        else:
            print(" %x" % i, end="", file=sys.stderr)
    print(" }" + end, end="", file=sys.stderr)


def print_tuple(t, end="\n"):
    print("(", end="", file=sys.stderr)
    for i in t:
        if isinstance(i, set):
            print(" ", end="", file=sys.stderr)
            print_set(i)
        else:
            print(" %x" % i, end="", file=sys.stderr)
    print(")", end=" ", file=sys.stderr)


def print_dict(dic, end="\n"):
    print("[", file=sys.stderr)
    for i in dic:
        if isinstance(i, str):
            print("%s: " % i, end="", file=sys.stderr)
        elif isinstance(i, tuple):
            print_tuple(i, end="")
        else:
            print("%x: " % i, end="", file=sys.stderr)
        v = dic[i]
        if isinstance(v, list):
            print_list(v)
        elif isinstance(v, tuple):
            print_tuple(v)
            print(file=sys.stderr)
        elif isinstance(v, dict):
            print_dict(v)
        elif isinstance(v, set):
            print_set(v)
        elif isinstance(v, str):
            print("%s: " % v, file=sys.stderr)
        else:
            print("0x%x, " % v, end="", file=sys.stderr)

    print("]" + end, end="", file=sys.stderr)


def print_list(lst, end="\n"):
    print("[", end="", file=sys.stderr)
    for i in lst[:-1]:
        if isinstance(i, list):
            print_list(i, "")
            print(",\n ", end="", file=sys.stderr)
        elif isinstance(i, dict):
            print_dict(i)
            print(",\n ", end="", file=sys.stderr)
        elif isinstance(i, set):
            print_set(i)
        elif isinstance(i, tuple):
            print_tuple(i)
        else:
            print("0x%x, " % i, end="", file=sys.stderr)

    if len(lst) > 0:
        if isinstance(lst[-1], list):
            print_list(lst[-1], "")
        elif isinstance(lst[-1], dict):
            print_dict(lst[-1])
        elif isinstance(lst[-1], set):
            print_set(lst[-1])
        elif isinstance(lst[-1], tuple):
            print_tuple(lst[-1])
        else:
            print("0x%x" % lst[-1], end="", file=sys.stderr)

    print("]" + end, end="", file=sys.stderr)
