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

from queue import Queue
import traceback

from custom_colors import *
from lib.disassembler import RESERVED_PREFIX

from lib.ui.window import *
from lib.ui.inlineed import InlineEd


class Visual(Window):
    def __init__(self, gctx, ctx, analyzer):
        Window.__init__(self, ctx.output, has_statusbar=True)

        self.ctx = ctx
        self.gctx = gctx
        self.mode = MODE_DUMP
        self.dis = gctx.dis
        self.analyzer = analyzer
        self.queue_wait_analyzer = Queue()

        # Last/first address printed (only in MODE_DUMP)
        self.last_addr = max(self.output.addr_line)
        self.first_addr = min(self.output.addr_line)

        self.stack = []
        self.saved_stack = [] # when we enter, go back, then re-enter

        new_mapping = {
            b"z": self.main_cmd_line_middle,
            b"g": self.main_k_top,
            b"G": self.main_k_bottom,
            b";": self.view_inline_comment_editor,
            b"%": self.main_cmd_next_bracket,
            b"\n": self.main_cmd_enter,
            b"\x1b": self.main_cmd_escape,
            b"\t": self.main_cmd_switch_mode,
            b"c": self.main_cmd_code,
            b"p": self.main_cmd_set_function,
            b"{": self.main_k_prev_paragraph,
            b"}": self.main_k_next_paragraph,
            b"x": self.main_cmd_xrefs,
            b"r": self.main_cmd_rename,
            b"I": self.main_cmd_inst_output,

            # I wanted ctrl-enter but it cannot be mapped on my terminal
            b"u": self.main_cmd_reenter, # u for undo
        }

        self.mapping.update(new_mapping)

        saved_quiet = self.gctx.quiet
        self.gctx.quiet = True

        self.screen = curses.initscr()

        (h, w) = self.screen.getmaxyx()
        h -= 1 # status bar
        self.goto_address(self.first_addr, h, w)

        curses.noecho()
        curses.cbreak()
        curses.mousemask(curses.ALL_MOUSE_EVENTS | curses.REPORT_MOUSE_POSITION)

        curses.start_color()
        curses.use_default_colors()

        if self.gctx.color:
            for i in range(0, curses.COLORS):
                curses.init_pair(i, i, -1)
            curses.init_pair(1, 253, 66) # for the highlight search
        else:
            for i in range(0, curses.COLORS):
                curses.init_pair(i, 7, -1) # white

        try:
            curses.wrapper(self.start_view)
        except:
            curses.nocbreak()
            curses.echo()
            curses.endwin()
            traceback.print_exc()
            return

        curses.nocbreak()
        curses.echo()
        curses.endwin()

        self.gctx.quiet = saved_quiet

        if self.stack:
            print(hex(self.ctx.entry))


    def exec_disasm(self, addr, h, dump_until=-1):
        self.ctx = self.gctx.get_addr_context(addr)

        if self.mode == MODE_DUMP:
            o = self.ctx.dump_asm(until=dump_until)

        elif self.mode == MODE_DECOMPILE:
            self.status_bar("decompiling...", h, True)
            o = self.ctx.decompile()

        if o is not None:
            self.output = o
            self.token_lines = o.token_lines
            self.last_addr = max(o.addr_line)
            self.first_addr = min(o.addr_line)
            return True
        return False


    def main_cmd_rename(self, h, w):
        h2 = 1
        w2 = int(w*6/7)

        x = int((w - w2)/2) - 1
        y = int((h - h2)/2) - 1

        # A background with borders
        scr_borders = curses.newwin(h2 + 2, w2 + 2, y, x)
        scr_borders.border()
        title = " rename "
        scr_borders.addstr(0, int((w2 - len(title))/2), title)
        scr_borders.refresh()

        # The message box
        scr = curses.newwin(h2, w2, y + 1, x + 1)

        w = Window(None)
        w.print_curr_line = False

        word = self.get_word_under_cursor()

        if word[:4] in RESERVED_PREFIX:
            try:
                ad = int(word[4:], 16)
            except:
                return True
            word = ""
        else:
            if word not in self.dis.binary.symbols:
                return True
            ad = self.dis.binary.symbols[word]

        text = w.open_textbox(scr, word)

        if word == text or not text or text[:4] in RESERVED_PREFIX:
            return True

        self.dis.add_symbol(ad, text)

        self.reload_output(h)
        self.gctx.db.modified = True

        return True


    def main_cmd_inst_output(self, h, w):
        self.gctx.capstone_string = not self.gctx.capstone_string
        self.reload_output(h)
        return True


    def view_inline_comment_editor(self, h, w):
        line = self.win_y + self.cursor_y
        if line not in self.output.line_addr:
            return True

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
        xbegin, idx_token = self.output.index_end_inst[line]

        self.status_bar("-- INLINE COMMENT --", h)

        if addr in self.dis.user_inline_comments:
            text = self.dis.user_inline_comments[addr]
        else:
            text = ""

        is_new_token = addr not in self.dis.user_inline_comments

        ed = InlineEd(self, h, w, line, xbegin, idx_token, text,
                      is_new_token, COLOR_USER_COMMENT.val,
                      self.token_lines[line], prefix="; ")

        ret = ed.start_view(self.screen)

        if ret:
            self.gctx.db.modified = True

            if ed.text:
                self.dis.user_inline_comments[addr] = ed.text
                if is_new_token:
                    self.output.index_end_inst[line] = \
                            (xbegin, idx_token)

            elif not is_new_token:
                del self.dis.user_inline_comments[addr]

        return True


    def dump_update_up(self, wy, h):
        if self.mode != MODE_DUMP or wy > 10:
            return wy

        if self.first_addr == self.dis.binary.get_first_addr():
            return wy

        ad = self.dis.find_addr_before(self.first_addr)

        self.ctx = self.gctx.get_addr_context(ad)
        o = self.ctx.dump_asm(until=self.first_addr)

        if o is not None:
            nb_new_lines = len(o.lines)

            if self.win_y == 0 and self.cursor_y < 3:
                if nb_new_lines >= 3:
                    diff = 3 - self.cursor_y
                    self.cursor_y = 3
                    wy -= diff
                    self.win_y -= diff
                else:
                    self.cursor_y = nb_new_lines

            if nb_new_lines >= 3:
                wy += nb_new_lines
                self.win_y += nb_new_lines

            # Update line counter on each line

            self.output.lines = o.lines + self.output.lines
            self.output.token_lines = o.token_lines + self.output.token_lines
            self.first_addr = min(o.addr_line)

            for ad, l in self.output.addr_line.items():
                o.line_addr[nb_new_lines + l] = ad
                o.index_end_inst[nb_new_lines + l] = self.output.index_end_inst[l]
                o.addr_line[ad] = nb_new_lines + l

            self.output.line_addr.clear()
            self.output.addr_line.clear()
            self.output.index_end_inst.clear()
            self.output.line_addr = o.line_addr
            self.output.addr_line = o.addr_line
            self.output.index_end_inst = o.index_end_inst
            self.token_lines = self.output.token_lines

        return wy


    def dump_update_bottom(self, wy, h):
        if self.mode != MODE_DUMP or wy < len(self.token_lines) - h - 10:
            return

        if self.last_addr == self.dis.binary.get_last_addr():
            return

        if self.dis.mem.is_code(self.last_addr):
            inst = self.dis.lazy_disasm(self.last_addr)
            ad = self.last_addr + inst.size
        else:
            ad = self.last_addr + 1

        self.ctx = self.gctx.get_addr_context(ad)
        o = self.ctx.dump_asm()

        if o is not None:
            nb_new_lines = len(self.output.lines)

            self.output.lines += o.lines
            self.output.token_lines += o.token_lines
            self.last_addr = max(o.addr_line)

            for l in o.line_addr:
                self.output.line_addr[nb_new_lines + l] = o.line_addr[l]
                self.output.addr_line[o.line_addr[l]] = nb_new_lines + l
                self.output.index_end_inst[nb_new_lines + l] = o.index_end_inst[l]


    # New mapping


    def main_k_prev_paragraph(self, h, w):
        l = self.win_y + self.cursor_y - 1
        while l > 0 and len(self.output.lines[l]) != 0:
            l -= 1
        if l >= 0:
            self.goto_line(l, h)
            self.check_cursor_x()
        return True

    def main_k_next_paragraph(self, h, w):
        l = self.win_y + self.cursor_y + 1
        while l < len(self.output.lines)-1 and len(self.output.lines[l]) != 0:
            l += 1
        if l < len(self.output.lines):
            self.goto_line(l, h)
            self.check_cursor_x()
        return True


    def main_cmd_line_middle(self, h, w):
        mid = int(h/2)
        if self.cursor_y + self.win_y > mid:
            self.win_y += self.cursor_y - mid
            self.cursor_y = mid
        return True


    def main_k_top(self, h, w):
        self.stack.append(self.__compute_curr_position())
        self.saved_stack.clear()

        if self.mode == MODE_DUMP:
            top = self.dis.binary.get_first_addr()
            if self.first_addr != top:
                self.exec_disasm(top, h)

        Window.k_top(self, h, w)
        return True


    def main_k_bottom(self, h, w):
        self.stack.append(self.__compute_curr_position())
        self.saved_stack.clear()

        self.cursor_x = 0

        if self.mode == MODE_DUMP:
            bottom = self.dis.binary.get_last_addr()
            if self.last_addr != bottom:
                ad = self.dis.find_addr_before(bottom)
                self.exec_disasm(ad, h)
                self.win_y = 0
                self.cursor_y = 0

        Window.k_bottom(self, h, w)
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


    def __compute_curr_position(self):
        line = self.win_y + self.cursor_y
        if self.mode == MODE_DECOMPILE:
            last = self.ctx.entry
            offset_y = (self.win_y, self.cursor_y)
        else:
            # We save only addresses on the stack, so if the cursor is
            # not on a line with an address, we search the nearest line
            # and save an offset to the original line.
            offset_y = 0
            while line not in self.output.line_addr:
                line += 1
                offset_y += 1
            last = self.output.line_addr[line]
        return (last, self.cursor_x, self.mode, offset_y)


    def main_cmd_enter(self, h, w):
        word = self.get_word_under_cursor()
        if word is None:
            return False

        topush = self.__compute_curr_position()

        ctx = self.gctx.get_addr_context(word)
        if not ctx:
            return False

        ad = ctx.entry
        self.cursor_x = 0

        if self.goto_address(ad, h, w):
            self.saved_stack.clear()
            self.stack.append(topush)
            return True

        self.ctx = ctx

        if self.mode == MODE_DECOMPILE and not self.dis.mem.is_code(ad):
            self.mode = MODE_DUMP

        ret = self.exec_disasm(ad, h)
        if ret:
            self.cursor_y = 0
            self.win_y = 0
            self.saved_stack.clear()
            self.stack.append(topush)
            self.goto_address(ad, h, w)
        return ret


    def __do_go_back(self, args, h, w):
        ad, x, mode, offset_y = args
        self.cursor_x = x

        if mode == MODE_DECOMPILE:
            line = offset_y[0] + offset_y[1]

            if self.mode == MODE_DECOMPILE and ad == self.ctx.entry:
                self.goto_line(line, h)
                self.cursor_x = x
                return True

            self.mode = mode
            ret = self.exec_disasm(ad, h)
            self.goto_line(line, h)

        else:
            if self.mode == MODE_DUMP and self.goto_address(ad, h, w):
                if offset_y != 0:
                    self.scroll_up(h, offset_y, False)
                return True

            self.mode = mode
            ret = self.exec_disasm(ad, h)

            if ret:
                self.goto_address(ad, h, w)
                if offset_y != 0:
                    self.scroll_up(h, offset_y, False)

        return ret


    def main_cmd_escape(self, h, w):
        if not self.stack:
            return False
        poped = self.stack.pop(-1)
        self.saved_stack.append(self.__compute_curr_position())
        return self.__do_go_back(poped, h, w)


    def main_cmd_reenter(self, h, w):
        if not self.saved_stack:
            return False
        poped = self.saved_stack.pop(-1)
        self.stack.append(self.__compute_curr_position())
        return self.__do_go_back(poped, h, w)


    def main_cmd_switch_mode(self, h, w):
        self.stack.append(self.__compute_curr_position())

        # Get a line with an address: the cursor is maybe on a comment
        l = self.win_y + self.cursor_y
        while l not in self.output.line_addr and l <= len(self.token_lines):
            l += 1

        ad = self.output.line_addr[l]

        if self.mode == MODE_DUMP:
            func_id = self.dis.mem.get_func_id(ad)

            if func_id == -1:
                self.status_bar("not in a function: create a function or use "
                                "the cmd x in the console", h, True)
                return False

            ad_disasm = self.dis.func_id[func_id]
            self.mode = MODE_DECOMPILE

        else:
            ad_disasm = self.ctx.entry
            self.mode = MODE_DUMP

        ret = self.exec_disasm(ad_disasm, h)

        if ret:
            self.cursor_x = 0
            self.win_y = 0
            self.cursor_y = 0
            self.goto_address(ad, h, w)

        return ret


    def reload_output(self, h):
        self.exec_disasm(self.first_addr, h, dump_until=self.last_addr)


    def main_cmd_code(self, h, w):
        if self.mode == MODE_DECOMPILE:
            return False

        line = self.win_y + self.cursor_y
        if line not in self.output.line_addr:
            return False

        ad = self.output.line_addr[line]

        if self.dis.mem.is_code(ad):
            return False

        self.analyzer.msg.put((ad, False, self.queue_wait_analyzer))
        self.queue_wait_analyzer.get()
        self.reload_output(h)
        self.gctx.db.modified = True
        return True


    def main_cmd_set_function(self, h, w):
        if self.mode == MODE_DECOMPILE:
            return False

        line = self.win_y + self.cursor_y
        if line not in self.output.line_addr:
            return False

        # TODO: check if the address is not already in a function

        ad = self.output.line_addr[line]
        self.analyzer.msg.put((ad, True, self.queue_wait_analyzer))
        self.queue_wait_analyzer.get()
        self.reload_output(h)
        self.gctx.db.modified = True
        self.goto_address(ad, h, w)
        return True


    def main_cmd_xrefs(self, h, w):
        word = self.get_word_under_cursor()
        if word is None:
            return False

        ctx = self.gctx.get_addr_context(word)
        if not ctx:
            return False

        if ctx.entry not in self.dis.xrefs:
            self.status_bar("no xrefs", h, True)
            return False

        h2 = int(h*3/4)
        w2 = int(w*6/7)

        x = int((w - w2)/2) - 1
        y = int((h - h2)/2) - 1

        # A background with borders
        scr_borders = curses.newwin(h2 + 2, w2 + 2, y, x)
        scr_borders.border()
        title = " xrefs for " + hex(ctx.entry)
        scr_borders.addstr(0, int((w2 - len(title))/2), title)
        scr_borders.refresh()

        # The message box with xrefs
        o = ctx.dump_xrefs()
        scr = curses.newwin(h2, w2, y + 1, x + 1)
        w = Window(o)
        ret = w.start_view(scr)

        if not ret:
            return True

        # Goto the selected xref

        ad = o.line_addr[w.win_y + w.cursor_y]
        topush = self.__compute_curr_position()
        self.cursor_x = 0

        if self.goto_address(ad, h, w):
            self.saved_stack.clear()
            self.stack.append(topush)
            return True

        ad_disasm = ad

        if self.mode == MODE_DECOMPILE:
            func_id = self.dis.mem.get_func_id(ad)
            if func_id == -1:
                self.mode = MODE_DUMP
            else:
                ad_disasm = self.dis.func_id[func_id]

        ret = self.exec_disasm(ad_disasm, h)
        if ret:
            self.cursor_y = 0
            self.win_y = 0
            self.saved_stack.clear()
            self.stack.append(topush)
            self.goto_address(ad, h, w)
        return ret


    def mouse_double_left_click(self, h, w):
        return self.main_cmd_enter(h, w)
