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
from lib.utils import *
from lib.paths import Paths, loop_contains


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
        self.dis = dis
        self.loops = []
        self.loops_set = []
        self.nested_loops_idx = {}
        self.direct_nested_idx = {}
        self.paths = None

        # If a loop is "marked" it means that there is an other equivalent
        # loop, and this must not be interpreted during the process. Generally
        # it will print a jmp. This can occurs if a goto jump inside a loop.
        self.marked = set()

        # address juste before the loop marked
        self.marked_addr = set()


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


    def init(self):
        self.__simplify()
        self.__explore(self.entry_point_addr)
        self.__search_equivalent_loops()
        self.__compute_nested()


    # Concat instructions in single block
    # jumps are in separated blocks
    def __simplify(self):
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
                except ValueError:
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
        output.o
        write("tryDraw();")


    def __explore(self, start):
        def save_step(k, addr, create):
            nonlocal new_paths, moved

            try:
                # This path is looping if index doesn't fail

                idx_node = self.paths.paths[k].index(addr)

                l = self.paths.paths[k][idx_node:]
                l_idx = index(self.loops, l)

                if l_idx == -1:
                    l_idx = len(self.loops)
                    self.loops.append(l)
                    self.loops_set.append(set(l))

                if create:
                    idx_new_path = len(self.paths.paths) + len(new_paths)
                    self.paths.looping[idx_new_path] = l_idx
                    new_paths.append(list(self.paths.paths[k]))
                else:
                    self.paths.looping[k] = l_idx

            except ValueError:
                moved = True
                if create:
                    new_paths.append(self.paths.paths[k] + [addr])
                else:
                    self.paths.paths[k].append(addr)

        moved = True
        self.paths = Paths()
        self.paths.paths = [[start]]

        while moved:
            new_paths = []
            moved = False

            # - Looping branchs will be detected
            # - Create a new branch if we are on cond jump
            #     only if it doesn't go outside the current loop
            for k, p in enumerate(self.paths.paths):
                last = p[-1]
                inst = self.dis.code[last]

                # The branch is finish or is looping
                if k in self.paths.looping or last not in self.link_out:
                    continue

                nxt = self.link_out[last]
                if is_cond_jump(inst):
                    save_step(k, nxt[BRANCH_NEXT_JUMP], True)
                save_step(k, nxt[BRANCH_NEXT], False)

            self.paths.paths += new_paths


    def __compute_nested(self):
        for k in range(len(self.loops)):
            self.nested_loops_idx[k] = set()
            self.direct_nested_idx[k] = set()

        has_parent_loop_idx = set()

        for k, l in enumerate(self.loops):
            self.nested_loops_idx[k] = set()
            self.direct_nested_idx[k] = set()

        for k1, l1 in enumerate(self.loops):
            if k1 in self.marked:
                continue
            for addr in l1[1:]:
                # check if addr is a beginning of another loop
                # found = -1
                for k2, l2 in enumerate(self.loops):
                    if k2 in self.marked or \
                            self.loops_set[k1] == self.loops_set[k2]:
                        continue
                    if l2[0] == addr:
                        self.direct_nested_idx[k1].add(k2) 
                        self.nested_loops_idx[k1].add(k2) 
                        has_parent_loop_idx.add(k2)

        # Warning : sometimes a sub-nested-loop didn't appear in a
        # parent-parent-loop. So we search for new nested.
        # See tests/nestedloop5 :
        # the path of the third loop is not in the first one

        while 1:
            moved = False
            for parent in self.nested_loops_idx:
                l_par = self.nested_loops_idx[parent]
                for nest in list(l_par):
                    for subnest in self.nested_loops_idx[nest]:
                        if subnest not in l_par:
                            l_par.add(subnest)
                            has_parent_loop_idx.add(subnest)
                            moved = True
            if not moved:
                break

        self.direct_nested_idx[-1] = set(range(len(self.loops))) - has_parent_loop_idx
        self.nested_loops_idx[-1] = set(range(len(self.loops)))


    def __search_equivalent_loops(self):

        # TODO : temporary algorithm while waiting a better one.
        #
        # Can occurs when a goto jumps into a loop. This will generate more
        # loops. For example :
        #
        # if {
        #    goto next
        # }
        # 
        # loop {
        #    next:
        #    ...
        # }
        #
        # Two loops are detected here, but they are equivalents, one is just
        # shifted. If each number is an address we can have for example these
        # two loops :
        # [1, 2, 3, 4, 5]
        # [2, 3, 4, 5, 6]
        #
        #
        # So to keep only the non-shifted loop, we keep the loop which have
        # the smallest address at the beginning (here 1).
        #
        # In fact it's false, because sometimes we can have this situation
        # For avoiding these we had a jmp for to be sure (see tests/gotoinloop3)
        #


        self.equiv = {}

        for k1, l1 in enumerate(self.loops_set):
            k2 = k1 + 1
            while k2 < len(self.loops_set):
                l2 = self.loops_set[k2]
                if l1 == l2:
                    k = k1 if self.loops[k1][0] < self.loops[k2][0] else k2
                    self.marked.add(k)
                    self.__mark_addr(k)
                    self.equiv[k1] = k2
                    self.equiv[k2] = k1
                k2 += 1

        # print(self.marked)
        # print_set(self.marked_addr)
        # print_list(self.loops)


    def __mark_addr(self, loop_idx):
        for k in self.paths.looping:
            if self.paths.looping[k] == loop_idx:
                idx_start_loop = self.paths.paths[k].index(self.loops[loop_idx][0])
                before = self.paths.paths[k][idx_start_loop-1]
                self.marked_addr.add(before)


    def __get_loop_set(self, k):
        s = self.loops_set[k]
        for i in self.nested_loops_idx[k]:
            s.update(self.loops_set[i])
        return s


    def __contains_nested(self, k):
        return len(self.nested_loops_idx[k]) != 0


    def __are_equiv(self, k1, k2):
        s1 = self.__get_loop_set(k1)
        s2 = self.__get_loop_set(k2)
        return s1 == s2
