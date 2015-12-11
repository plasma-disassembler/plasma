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
from time import time

from lib import init_entry_addr, disasm
from custom_colors import *


MOUSE_EVENT = [0x1b, 0x5b, 0x4d]
MOUSE_INTERVAL = 200

MODE_DUMP = 1
MODE_DECOMPILE = 2

NB_LINES_TO_DISASM = 200


class Visual():
    def __init__(self, console, disassembler, output):
        self.mode = MODE_DUMP
        self.win_y = 0
        self.cursor_y = 0
        self.cursor_x = 0
        self.output = output
        self.dump_output = output
        self.token_lines = output.token_lines
        self.dis = disassembler
        self.console = console
        self.search = None

        # Last/first address printed (only in MODE_DUMP)
        self.last_addr = max(output.addr_line)
        self.first_addr = min(output.addr_line)

        self.stack = []
        self.saved_stack = [] # when we enter, go back, then re-enter

        self.word_accepted_chars = ["_", "@", ".", "$"]

        self.time_last_mouse_key = MOUSE_INTERVAL + 1
        self.set_key_timeout = True

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
            b"\x01": self.main_k_home, # ctrl-a
            b"\x05": self.main_k_end, # ctrl-e
            b"\x1b\x5b\x37\x7e": self.main_k_home,
            b"\x1b\x5b\x38\x7e": self.main_k_end,
            b"*": self.main_cmd_highlight_current_word,
            b"\x0b": self.main_cmd_highlight_clear, # ctrl-k
            b"\n": self.main_cmd_enter,
            b"\x1b": self.main_cmd_escape,

            # I wanted ctrl-enter but it cannot be mapped on my terminal
            b"u": self.main_cmd_reenter, # u for undo
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

        saved_quiet = self.console.ctx.quiet
        self.console.ctx.quiet = True

        self.screen = curses.initscr()

        curses.noecho()
        curses.cbreak()
        curses.mousemask(curses.ALL_MOUSE_EVENTS | curses.REPORT_MOUSE_POSITION)
        curses.start_color()
        curses.use_default_colors()

        for i in range(0, curses.COLORS):
            curses.init_pair(i, i, -1)

        curses.init_pair(1, 253, 66) # for the highlight search

        curses.wrapper(self.view_main)

        curses.nocbreak()
        curses.echo()
        curses.endwin()

        self.console.ctx.quiet = saved_quiet

        if self.stack:
            print("last address seen 0x%x" % self.console.ctx.entry_addr)


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


    def get_word_under_cursor(self):
        num_line = self.win_y + self.cursor_y
        line = self.output.lines[num_line]

        if len(line) == 0:
            return None

        x = self.cursor_x
        if x >= len(line):
            return None

        if not line[x].isalnum() and not line[x] in self.word_accepted_chars:
            return None

        curr = []
        while x >= 0 and (line[x].isalnum() or line[x] in self.word_accepted_chars):
            x -= 1
        x += 1

        while x < len(line) and (line[x].isalnum() or \
                line[x] in self.word_accepted_chars):
            curr.append(line[x])
            x += 1
        if curr:
            return "".join(curr)
        return None


    def goto_line(self, new_line, h):
        curr_line = self.win_y + self.cursor_y
        diff = new_line - curr_line
        if diff > 0:
            self.scroll_down(h, diff, False)
        elif diff < 0:
            self.scroll_up(h, -diff, False)


    # If the address is already in the output, we only move the cursor.
    # Otherwise this address must be disassembled (it returns False).
    def goto_address(self, ad, h, w):
        if ad in self.output.addr_line:
            self.goto_line(self.output.addr_line[ad], h)
            # double home moves the cursor at the beginning of the line
            self.main_k_home(h, w)
            self.main_k_home(h, w)
            return True
        return False


    def exec_disasm(self, addr):
        self.console.ctx.reset_vars()
        self.console.ctx.entry_addr = addr

        if self.mode == MODE_DUMP:
            self.console.ctx.dump = True
            o = self.dis.dump_asm(self.console.ctx, NB_LINES_TO_DISASM)
            self.console.ctx.dump = False

        elif self.mode == MODE_DECOMPILE:
            o = disasm(self.console.ctx)

        if o is not None:
            self.output = o
            self.token_lines = o.token_lines
            return True
        return False


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
            (h, w) = screen.getmaxyx()
            if refr:
                self.view_main_redraw(h, w)
                refr = False

            size_line = len(self.output.lines[self.win_y + self.cursor_y])
            if self.cursor_x >= size_line > 0:
                x = size_line - 1
            else:
                x = self.cursor_x

            screen.move(self.cursor_y, x)

            k = self.read_escape_keys()

            if k == b"q":
                break

            if k in self.main_mapping:
                refr = self.main_mapping[k](h, w)
            elif k.startswith(b"\x1b[M"):
                refr = self.main_mouse_event(k, h, w)


    def view_inline_comment_editor(self, h, w):
        line = self.win_y + self.cursor_y
        if line not in self.output.line_addr:
            return True

        self.console.ctx.db.modified = True

        addr = self.output.line_addr[line]

        # The same address can be repeated on multiple lines
        # With this we are sure to everytime on the same line
        # example for mips:
        #   # 0x4002bc: lui $gp, 0x19
        #   # 0x4002c0: addiu $gp, $gp, -0x63dc
        #   0x4002bc: li $gp, 0x189c24
        new_line = self.output.addr_line[addr]

        if new_line != line:
            self.goto_line(new_line, h)
            line = new_line
            (h, w) = self.screen.getmaxyx()
            self.view_main_redraw(h, w)

        # xbegin is the first index just after all operands
        # So we need to add 1 to be at the index of ;
        xbegin, _ = self.output.index_end_inst[line]
        self.comm = []
        screen = self.screen
        y = self.cursor_y
        col_intern = color_pair(COLOR_USER_COMMENT.val) | A_UNDERLINE

        if addr in self.dis.user_inline_comments:
            self.comm = list(self.dis.user_inline_comments[addr])

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

            if self.cursor_x >= w:
                self.cursor_x = w - 1
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
                break

        if is_current_line and not force_exit:
            n = w - x - 1
            self.screen.addstr(i, x, " " * n, color_pair(0) | A_UNDERLINE)
            x += n

        self.highlight_search(i, w)
        self.screen.move(i, x)
            

    def highlight_search(self, i, w):
        if self.search is None:
            return
        num_line = self.win_y + i
        start = 0
        while 1:
            idx = self.output.lines[num_line].find(self.search, start)
            if idx == -1 or idx >= w:
                break
            self.screen.chgat(i, idx, len(self.search), curses.color_pair(1))
            start = idx + 1


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
                self.dump_update_up(self.win_y, h)
                if self.win_y == 0:
                    if self.cursor_y == 0:
                        break
                    self.cursor_y -= 1
                else:
                    if self.cursor_y == 3:
                        self.win_y -= 1
                    else:
                        self.cursor_y -= 1


    def scroll_down(self, h, n, page_scroll):
        if page_scroll:
            wy = self.win_y + n
            y = self.cursor_y - n

            self.dump_update_bottom(wy, h)

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
                self.dump_update_bottom(self.win_y, h)

                if self.win_y >= len(self.token_lines) - h:
                    if self.win_y + self.cursor_y == len(self.token_lines) - 1:
                        break
                    self.cursor_y += 1
                else:
                    if self.cursor_y == h - 4:
                        self.win_y += 1
                    else:
                        self.cursor_y += 1


    def dump_update_up(self, wy, h):
        return
        if self.mode != MODE_DUMP:
            return

        if wy <= 10:
            # Compute NB_LINES_TO_DISASM (approximately) before the first address
            ad = self.first_addr - 1
            l = 0
            while l < 10:
                # Search the previous instruction
                found = False
                for i in range(64):
                    if ad - i in self.dis.mem.code_addr:
                        found = True
                        break

                if found:
                    inst = self.dis.capstone_inst[ad - i]
                    # `i' bytes + the instruction
                    l += i - inst.size
                else:
                    break
                    ad -= 64
                    l += 64

                break

            l = 10

            self.console.ctx.entry_addr = ad
            self.console.ctx.dump = True
            o = self.dis.dump_asm(self.console.ctx, l, True)
            self.console.ctx.dump = False

            if o is not None:
                nb_new_lines = o.lines
                self.output.lines = o.lines + self.output.lines
                self.output.token_lines = o.token_lines + self.output.lines
                self.first_addr = min(o.addr_line)

                for l in o.line_addr:
                    self.output.line_addr[end + l] = o.line_addr[l]
                    self.output.index_end_inst[end + l] = o.index_end_inst[l]

                for ad, l in self.output.addr_line:
                    self.output.addr_line[ad] = end + l

                self.output.line_addr.update(o.line_addr)
                self.output.addr_line.update(o.addr_line)
                self.output.index_end_inst.update(o.index_end_inst)


    def dump_update_bottom(self, wy, h):
        if self.mode != MODE_DUMP:
            return

        if wy >= len(self.token_lines) - h - 10:
            self.console.ctx.reset_vars()

            # TODO : if we delete capstone_inst when it's too big ??

            if self.dis.mem.is_code(self.last_addr):
                inst = self.dis.capstone_inst[self.last_addr]
                self.console.ctx.entry_addr = self.last_addr + inst.size
            else:
                self.console.ctx.entry_addr = self.last_addr + 1

            self.console.ctx.dump = True
            o = self.dis.dump_asm(self.console.ctx, NB_LINES_TO_DISASM, True)
            self.console.ctx.dump = False

            if o is not None:
                end = len(self.output.lines)

                self.output.lines += o.lines
                self.output.token_lines += o.token_lines
                self.last_addr = max(o.addr_line)

                for l in o.line_addr:
                    self.output.line_addr[end + l] = o.line_addr[l]
                    self.output.addr_line[o.line_addr[l]] = end + l
                    self.output.index_end_inst[end + l] = o.index_end_inst[l]


    def check_cursor_x(self):
        size_line = len(self.output.lines[self.win_y + self.cursor_y])
        if size_line == 0:
            self.cursor_x = 0
        elif self.cursor_x >= size_line:
            self.cursor_x = size_line - 1


    # Main view : Keys mapping

    def main_k_left(self, h, w):
        self.check_cursor_x()
        if self.cursor_x > 0:
            self.cursor_x -= 1
        return False

    def main_k_right(self, h, w):
        self.cursor_x += 1
        self.check_cursor_x()
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

    def main_mouse_event(self, k, h, w):
        button = k[3]

        if button == 0x20:
            now = time()
            diff = now - self.time_last_mouse_key
            diff = int(diff * 1000)

            self.time_last_mouse_key = now

            if diff <= MOUSE_INTERVAL:
                # double left-click
                return self. main_cmd_enter(h, w)

        if button == 0x20: # simple left-click
            self.cursor_x = k[4] - 33
            self.goto_line(self.win_y + k[5] - 33, h)
            self.main_cmd_highlight_current_word(h, w)
            self.check_cursor_x()
        elif button == 0x60: # scroll up
            self.scroll_up(h, 3, True)
        elif button == 0x61: # scroll down
            self.scroll_down(h, 3, True)

        return True

    def main_k_home(self, h, w):
        # TODO: fix self.cursor_x >= w
        if self.cursor_x == 0:
            line = self.output.lines[self.win_y + self.cursor_y]
            while self.cursor_x < len(line):
                if line[self.cursor_x] != " ":
                    break
                self.cursor_x += 1
        else:
            self.cursor_x = 0
        return False

    def main_k_end(self, h, w):
        # TODO: fix self.cursor_x >= w
        size_line = len(self.output.lines[self.win_y + self.cursor_y])
        if size_line >= w:
            self.cursor_x = w - 1
        elif size_line > 0:
            self.cursor_x = size_line - 1
        else:
            self.cursor_x = 0
        return False


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
        # TODO: fix self.cursor_x >= w
        line = self.win_y + self.cursor_y
        line_str = self.output.lines[line]
        x = self.cursor_x
        if x >= len(line_str):
            x = len(line_str) - 1
        char = line_str[x]
        new_line = -1

        if char == "}":
            l = line - 1
            while l >= 0:
                if self.output.lines[l][x] != " ":
                    new_line = l
                    break
                l -= 1

            if l != -1:
                x = 0
                while x < len(self.output.lines[l]):
                    if self.output.lines[l][x] == "{":
                        break
                    x += 1

            self.cursor_x = x

        elif char == "{":
            x = 0
            while 1:
                if self.output.lines[line][x] != " ":
                    break
                x += 1

            l = line + 1
            while l < len(self.output.lines):
                if self.output.lines[l][x] != " ":
                    new_line = l
                    break
                l += 1

            self.cursor_x = x

        if new_line != -1:
            self.goto_line(new_line, h)

        return True


    def main_cmd_highlight_current_word(self, h, w):
        w = self.get_word_under_cursor()
        if w is None:
            return False
        self.search = w
        return True


    def main_cmd_enter(self, h, w):
        word = self.get_word_under_cursor()
        if word is None:
            return False

        line = self.win_y + self.cursor_y
        x = self.cursor_x

        if word.startswith("0x"):
            try:
                ad = int(word, 16)
                if self.goto_address(ad, h, w):
                    self.saved_stack = []
                    self.stack.append((line, -1, -1, x, True))
                    return True
            except:
                return False

        elif word in self.console.ctx.labels:
            ad = self.console.ctx.labels[word]
            if self.goto_address(ad, h, w):
                self.saved_stack = []
                self.stack.append((line, -1, -1, x, True))
                return True

        self.console.ctx.entry = word
        last = self.console.ctx.entry_addr
        if not init_entry_addr(self.console.ctx):
            return False

        ret = self.exec_disasm(self.console.ctx.entry_addr)
        if ret:
            self.saved_stack = []
            self.stack.append((
                last,
                self.win_y,
                self.cursor_y,
                self.cursor_x,
                False
            ))
            self.win_y = 0
            self.cursor_y = 0
            self.cursor_x = 0
        return ret


    def main_cmd_escape(self, h, w):
        if not self.stack:
            return False

        value, wy, y, x, is_line = self.stack.pop(-1)

        if is_line:
            prev_x = self.cursor_x
            line = self.win_y + self.cursor_y
            self.goto_line(value, h)
            self.saved_stack.append((line, -1, -1, prev_x, True))
            self.cursor_x = x
            return True

        addr = value
        last = self.console.ctx.entry_addr

        self.saved_stack.append((
            last,
            self.win_y,
            self.cursor_y,
            self.cursor_x,
            False
        ))

        ret = self.exec_disasm(addr)
        if ret:
            self.win_y = wy
            self.cursor_y = y
            self.cursor_x = x
        return ret


    def main_cmd_reenter(self, h, w):
        if not self.saved_stack:
            return False

        value, wy, y, x, is_line = self.saved_stack.pop(-1)

        if is_line:
            line = self.win_y + self.cursor_y
            prev_x = self.cursor_x
            self.goto_line(value, h)
            self.stack.append((line, -1, -1, prev_x, True))
            self.cursor_x = x
            return True

        addr = value
        last = self.console.ctx.entry_addr

        self.stack.append((
            last,
            self.win_y,
            self.cursor_y,
            self.cursor_x,
            False
        ))

        ret = self.exec_disasm(addr)
        if ret:
            self.win_y = wy
            self.cursor_y = y
            self.cursor_x = x
        return ret



    def main_cmd_highlight_clear(self, h, w):
        self.search = None
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

        if addr in self.dis.user_inline_comments:
            is_new_comment = False
            # Extract the comment which starts by #
            instr_comm = lines[line][xbegin + 3 + len(self.comm) + 1:]
        else:
            is_new_comment = True
            instr_comm = lines[line][xbegin + 1:]

        if not self.comm:
            if not is_new_comment:
                del self.dis.user_inline_comments[addr]

                lines[line] = "".join([
                    lines[line][:xbegin],
                    " ",
                    instr_comm])

                # Remove space and comment
                del self.token_lines[line][idx_token]
                del self.token_lines[line][idx_token]
        else:
            self.comm = "".join(self.comm)
            self.dis.user_inline_comments[addr] = self.comm

            if is_new_comment:
                # Space token
                self.token_lines[line].insert(idx_token,
                        (" ", 0, False))

                # Insert the new token
                self.token_lines[line].insert(idx_token + 1,
                        ("; " + self.comm, COLOR_USER_COMMENT.val, False))

                self.output.index_end_inst[line] = \
                        (xbegin, idx_token)
            else:
                # Plus 1 for the space token
                self.token_lines[line][idx_token + 1] = \
                        ("; " + self.comm, COLOR_USER_COMMENT.val, False)

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
