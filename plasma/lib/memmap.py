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

# quick & dirty
# TODO:
# - cleanup
# - communicate with the analyzer and the visual
# - self.width() instead of fixed size (1000)
# - zoom

import threading
from plasma.lib.consts import *
from PyQt4 import QtGui, QtCore


COLOR_BACKGROUND = QtGui.QColor(247, 245, 242)
COLOR_CODE = QtGui.QColor(213, 26, 26)
COLOR_UNK = QtGui.QColor(135, 255, 0)
COLOR_FUNC = QtGui.QColor(255, 237, 20)
COLOR_DATA = QtGui.QColor(255, 255, 215)
COLOR_SEP = QtGui.QColor(50, 50, 50)


is_open = False


class MemoryMap(QtGui.QWidget):
    def __init__(self, db, binary):
        QtGui.QWidget.__init__(self)

        self.db = db
        self.binary = binary
        self.update_sections_coords()

        p = self.palette()
        p.setColor(self.backgroundRole(), COLOR_BACKGROUND)
        self.setPalette(p)
        self.setGeometry(200, 300, 1000, 100)
        self.setWindowTitle("MEMORY MAP")
        self.show()


    def paintEvent(self, event):
        qp = QtGui.QPainter()
        qp.begin(self)
        self.draw_memory(event, qp)
        qp.end()


    def update_sections_coords(self):
        total = 0
        for s in self.binary.iter_sections():
            total += s.virt_size

        # width = self.width()
        width = 1000
        self.section_coords = {} # ad -> [coord_x, size_in_window]
        x = 0
        for s in self.binary.iter_sections():
            sz = int((s.virt_size * width) / total)
            self.section_coords[s.start] = [x, sz]
            x += sz


    def conv_ad_to_x(self, ad, nbytes):
        s = self.binary.get_section(ad)
        co = self.section_coords[s.start]
        x = (ad - s.start) * co[1] / s.virt_size + co[0]
        sz = int(nbytes * co[1] / s.virt_size)
        if sz == 0:
            sz = 1
        return (x, sz)


    def draw_memory(self, event, qp):
        # width = self.width()
        width = 1000
        qp.fillRect(0, 10, width, 80, COLOR_UNK)

        for ad, cont in self.db.mem.mm.items():
            if cont[1] == MEM_CODE or cont[1] == MEM_FUNC:
                if self.db.mem.get_func_id(ad) == -1:
                    col = COLOR_CODE
                else:
                    col = COLOR_FUNC
            elif MEM_BYTE <= cont[1] <= MEM_ARRAY:
                col = COLOR_DATA
            elif cont[1] == MEM_UNK or cont[1] == MEM_HEAD:
                continue

            (x, sz) = self.conv_ad_to_x(ad, cont[0])
            qp.fillRect(x, 10, sz + 1, 80, col)

        for s in self.binary.iter_sections():
         qp.fillRect(self.section_coords[s.start][0], 0, 1, 100, COLOR_SEP)



class ThreadMemoryMap(threading.Thread):
    def __init__(self, db, binary):
        self.db = db
        self.binary = binary
        threading.Thread.__init__(self)


    def run(self):
        global is_open
        if is_open:
            return
        is_open = True
        app = QtGui.QApplication([])
        ex = MemoryMap(self.db, self.binary)
        app.exec_()
        is_open = False
