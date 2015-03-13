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

import os
import os.path
import sys
from lib.utils import *


class Graph:
    def __init__(self, dis, entry_point_addr):
        # Each node contains a block (list) of instructions.
        self.nodes = {}

        # For each address block, we store a list of next blocks.
        # If there are 2 elements it means that the precedent instruction
        # was a conditional jump :
        # 1st : direct next instruction
        # 2nd : for conditional jump : address of the jump
        self.link_out = {}
        
        self.link_in = {}

        self.entry_point_addr = entry_point_addr
        self.loops = []
        self.dis = dis


    def add_node(self, inst):
        self.nodes[inst.address] = [inst]


    def set_next(self, curr, inst):
        self.nodes[curr.address] = [curr]
        self.link_out[curr.address] = [inst.address]
        if inst.address not in self.link_in:
            self.link_in[inst.address] = []
        self.link_in[inst.address].append(curr.address)


    def set_cond_next(self, curr, next_jump, direct_next):
        self.nodes[curr.address] = [curr]
        self.link_out[curr.address] = [direct_next.address, next_jump.address]

        if next_jump.address not in self.link_in:
            self.link_in[next_jump.address] = []

        if direct_next.address not in self.link_in:
            self.link_in[direct_next.address] = []

        self.link_in[next_jump.address].append(curr.address)
        self.link_in[direct_next.address].append(curr.address)


    def exists(self, inst):
        return inst.address in self.nodes


    # Concat instructions in single block
    # jumps are in separated blocks
    def simplify(self):
        fuse = []
        nodes = list(self.nodes.keys())

        for curr in nodes:
            inst = self.nodes[curr]
            if is_jump(inst[0]):
                continue

            if curr not in self.link_in or len(self.link_in[curr]) != 1:
                continue

            pred = self.link_in[curr][0]

            # don't fuse with jumps
            if is_jump(self.nodes[pred][0]):
                continue

            if pred not in self.link_out or len(self.link_out[pred]) != 1:
                continue

            if curr in self.link_out:
                self.link_out[pred] = self.link_out[curr]
            else:
                del self.link_out[pred]

            self.nodes[pred] += self.nodes[curr]

            if curr in self.link_out:
                del self.link_out[curr]

            del self.link_in[curr]
            del self.nodes[curr]

            # replace all addr wich refers to curr
            for k, lst_i in self.link_in.items():
                try:
                    lst_i[lst_i.index(curr)] = pred
                except:
                    pass


    # Check d3/index.html !
    def html_graph(self):
        revpath = os.path.dirname(os.path.abspath(os.path.expanduser(__file__)))
        output = open(revpath + "/../d3/graph.js", "w+")
        output.write("mygraph = \"digraph {\\\n")

        for k, lst_i in self.nodes.items():
            output.write("node_%x [label=\\\"" % k)

            for i in lst_i:
                output.write("0x%x: %s %s\\n" % (i.address, i.mnemonic, i.op_str))

            output.write("\\\"")

            if k not in self.link_out:
                output.write(" style=\\\"fill:#f77\\\"")
            elif k not in self.link_in:
                output.write(" style=\\\"fill:#B6FFDD\\\"")

            output.write("];\\\n")
        
        for k, i in self.link_out.items():
            if len(i) == 2:
                # true green branch (jump is taken)
                output.write("node_%x -> node_%x [" % (k, i[BRANCH_NEXT_JUMP]))
                output.write("style=\\\"stroke: #58DA9C; stroke-width: 3px;\\\" ")
                output.write("arrowheadStyle=\\\"fill: #58DA9C\\\"")
                output.write("];\\\n")

                # false red branch (jump is not taken)
                output.write("node_%x -> node_%x [" % (k, i[BRANCH_NEXT]))
                output.write("style=\\\"stroke: #f77; stroke-width: 3px;\\\" ")
                output.write("arrowheadStyle=\\\"fill: #f77\\\"")
                output.write("];\\\n")

            else:
                output.write("node_%x -> node_%x;\\\n" % (k, i[BRANCH_NEXT]))

        output.write("}\";\n")
        output.write("inputGraph.innerHTML = mygraph;")
        output.write("tryDraw();")


    def detect_loops(self):
        def rec_explore(path, curr):
            path = list(path) # copy

            while 1:
                idx = index(path, curr.address)
                if idx != -1:
                    loop = path[idx:]
                    if loop not in self.loops:
                        self.loops.append(path[idx:])
                    return
                if curr.address not in self.link_out:
                    return

                path.append(curr.address)
                nxt = self.link_out[curr.address]
                if len(nxt) == 2:
                    rec_explore(path, self.nodes[nxt[BRANCH_NEXT_JUMP]][0])
                curr = self.nodes[nxt[BRANCH_NEXT]][0]

        rec_explore([], self.nodes[self.entry_point_addr][0])
        
        self.nested_loops = {}
        
        for l in self.loops:
            self.nested_loops[l[0]] = []

        for l in self.loops:
            for addr in l[1:]:
                # check if addr is a beginning of a loop (we have inited 
                # nested_loops : all keys corresponds to a loop)
                if addr in self.nested_loops: 
                    # don't dupplicate addr in the list
                    if addr not in self.nested_loops[l[0]]:
                        self.nested_loops[l[0]].append(addr)

        self.nested_loops[-1] = []
        for l in self.loops:
            if l[0] not in self.nested_loops[-1]:
                self.nested_loops[-1].append(l[0])
