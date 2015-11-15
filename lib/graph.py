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

import os
from time import time

from lib.utils import BRANCH_NEXT, BRANCH_NEXT_JUMP, debug__


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

        # For one loop : contains all address of the loop only
        self.loops_set = {}

        # For one loop : contains all address of the loop and sub-loops
        self.loops_all = {}

        # Rest of all address which are not in a loop
        self.not_in_loop = set()

        self.loops_start = set()

        # Optimization
        self.cond_jumps_set = set()
        self.uncond_jumps_set = set()

        self.equiv = {}
        self.false_loops = set()

        # Loop dependencies
        self.deps = {}
        self.rev_deps = {}

        self.cache_path_exists = {}

        # For each loop we search the last node that if we enter in it,
        # we are sure to return to the loop.
        self.last_loop_node = {}


    # A jump is normally alone in a block, but for some architectures
    # we save the prefetched instruction after.

    def new_node(self, curr, prefetch, nxt):
        ad = curr.address
        self.nodes[ad] = [curr]

        if nxt is not None:
            self.link_out[ad] = nxt

        if nxt is not None:
            for n in nxt:
                if n not in self.link_in:
                    self.link_in[n] = [ad]
                else:
                    self.link_in[n].append(ad)

        if prefetch is not None:
            self.nodes[ad].append(prefetch)


    def exists(self, inst):
        return inst.address in self.nodes


    def graph_init(self, ctx):
        self.__simplify()
        self.__loop_detection(ctx, self.entry_point_addr)


    # Concat instructions in single block
    # jumps are in separated blocks
    def __simplify(self):
        nodes = list(self.nodes.keys())
        start = time()

        for ad in nodes:
            if ad in self.uncond_jumps_set or ad in self.cond_jumps_set:
                continue

            if ad not in self.link_in or len(self.link_in[ad]) != 1 or \
                    ad == self.entry_point_addr:
                continue

            pred = self.link_in[ad][0]

            # don't fuse with jumps
            if pred in self.uncond_jumps_set or pred in self.cond_jumps_set:
                continue

            if pred not in self.link_out or len(self.link_out[pred]) != 1:
                continue

            if ad in self.link_out:
                self.link_out[pred] = self.link_out[ad]
            else:
                del self.link_out[pred]

            self.nodes[pred] += self.nodes[ad]

            if ad in self.link_out:
                del self.link_out[ad]

            del self.link_in[ad]
            del self.nodes[ad]

            # replace all addr wich refers to ad
            for k, lst_i in self.link_in.items():
                if ad in lst_i:
                    lst_i[lst_i.index(ad)] = pred

        elapsed = time()
        elapsed = elapsed - start
        debug__("Graph simplified in %fs (%d nodes)" % (elapsed, len(self.nodes)))


    # Check d3/index.html !
    def html_graph(self, jmptables):
        revpath = os.path.dirname(os.path.abspath(os.path.expanduser(__file__)))
        output = open(revpath + "/../d3/graph.js", "w+")
        output.write("mygraph = \"digraph {\\\n")

        keys = list(self.nodes.keys())
        keys.sort()

        for k in keys:
            lst_i = self.nodes[k]

            output.write("node_%x [label=\\\"" % k)

            for i in lst_i:
                output.write("0x%x: %s %s\\n" % (i.address, i.mnemonic, i.op_str))

            output.write("\\\"")

            if k in self.loops_start:
                output.write(" style=\\\"fill:#FFFCC4\\\"")
            elif k not in self.link_out:
                output.write(" style=\\\"fill:#f77\\\"")
            elif k not in self.link_in:
                output.write(" style=\\\"fill:#B6FFDD\\\"")

            output.write("];\\\n")
        
        for k, i in self.link_out.items():
            if k in jmptables:
                for ad in jmptables[k].table:
                    output.write("node_%x -> node_%x;\\\n" % (k, ad))
            elif len(i) == 2:
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


    def __search_last_loop_node(self, visited, l_prev_loop, l_start, l_set):
        def __rec_search(ad):
            for prev in self.link_in[ad]:
                nxt = self.link_out[prev]
                for n in nxt:
                    if n not in l_set:
                        if ad not in self.last_loop_node:
                            self.last_loop_node[ad] = set()
                        self.last_loop_node[ad].add((l_prev_loop, l_start))
                        return

            if ad in visited:
                return

            visited.add(ad)

            for prev in self.link_in[ad]:
                __rec_search(prev)

        # start from the end of the loop
        ad = l_start
        visited.add(ad)
        for prev in self.link_in[l_start]:
            if prev in l_set:
                __rec_search(prev)


    def __is_inf_loop(self, l_set):
        for ad in l_set:
            if ad in self.link_out:
                for nxt in self.link_out[ad]:
                    if nxt not in l_set:
                        return False
        return True


    def path_exists(self, from_addr, to_addr):
        def __rec_path_exists(curr, local_visited):
            if curr == to_addr:
                return True

            if curr in local_visited:
                return False

            local_visited.add(curr)

            if curr not in self.link_out:
                return False

            for n in self.link_out[curr]:
                found = __rec_path_exists(n, local_visited)
                if found:
                    return True
            return False

        if (from_addr, to_addr) in self.cache_path_exists:
            return self.cache_path_exists[(from_addr, to_addr)]

        local_visited = set()
        res = __rec_path_exists(from_addr, local_visited)
        self.cache_path_exists[(from_addr, to_addr)] = res
        return res


    # Returns a set containing every address which are in paths from
    # 'from_addr' to 'to_addr'.
    def find_paths(self, from_addr, to_addr, global_visited):
        def __rec_find_paths(curr, local_visited, path_set):
            nonlocal isfirst

            if curr == to_addr and not isfirst:
                path_set.add(curr)
                return

            isfirst = False

            if curr in local_visited:
                return

            local_visited.add(curr)

            if curr in global_visited or curr not in self.link_out:
                return

            for n in self.link_out[curr]:
                __rec_find_paths(n, local_visited, path_set)

                if n in path_set:
                    path_set.add(curr)

        isfirst = True
        path_set = set()
        local_visited = set()
        __rec_find_paths(from_addr, local_visited, path_set)
        return path_set


    def __try_find_loops(self, entry, waiting, par_loops, l_set, is_sub_loop):
        detected_loops = {}
        keys = set(waiting.keys())

        for ad in keys:
            if l_set is not None and ad not in l_set:
                continue

            if (entry, ad) in self.loops_set:
                continue

            l = self.find_paths(ad, ad, par_loops)

            # If the set is empty, it's not a loop
            if l:
                self.loops_set[(entry, ad)] = l
                is_sub_loop.add(ad)
                detected_loops[ad] = (entry, ad)

        return detected_loops


    def __manage_waiting(self, stack, visited, waiting, l_set, done):
        keys = set(waiting.keys())
        for ad in keys:
            if l_set is not None and ad not in l_set:
                continue
            if len(waiting[ad]) == 0:
                del waiting[ad]
                done.add(ad)
                stack.append((-1, ad))


    def __until_stack_empty(self, stack, waiting, visited,
                            par_loops, l_set, is_sub_loop, done):
        has_moved = False

        while stack:
            prev, ad = stack.pop(-1)

            if ad in self.link_in and ad not in done:
                l_in = self.link_in[ad]

                if len(l_in) > 1 or l_set is not None and ad not in l_set:
                    if ad in waiting:
                        if prev in waiting[ad]:
                            waiting[ad].remove(prev)
                    else:
                        unseen = set(l_in)
                        unseen.remove(prev)
                        waiting[ad] = unseen
                    continue

            if ad in visited:
                continue

            visited.add(ad)

            if ad in self.link_out:
                for n in self.link_out[ad]:
                    if n in par_loops:
                        continue
                    stack.append((ad, n))
                    has_moved = True

        return has_moved


    def __get_new_loops(self, waiting, detected_loops, l_set, is_sub_loop):
        new_loops = set()

        # Remove internal links to the beginning of the loop
        # If later we enter in the loop it means that len(waiting[ad]) == 0
        for ad, k in detected_loops.items():
            loop = self.loops_set[k]

            was_removed = False

            for rest in set(waiting[ad]):
                if rest in loop:
                    waiting[ad].remove(rest)
                    was_removed = True

            if was_removed:
                if len(waiting[ad]) == 0:
                    new_loops.add(ad)
                    del waiting[ad]

        # Remove external jumps which are outside the current loop
        for ad, unseen in waiting.items():
            if l_set is not None and ad not in l_set:
                continue
            for i in set(unseen):
                if l_set is not None and i not in l_set:
                    unseen.remove(i)

        return new_loops


    def __explore(self, entry, par_loops, visited, waiting, l_set, done):
        stack = []

        # Check if the first address (entry point of the function) is the
        # beginning of a loop.
        if not visited and entry in self.link_in:
            for p in self.link_in[entry]:
                stack.append((p, entry))
        else:
            if entry in self.link_out:
                for n in self.link_out[entry]:
                    stack.append((entry, n))
            visited.add(entry)

        is_sub_loop = set()

        while 1:
            if self.__until_stack_empty(
                    stack, waiting, visited, par_loops, l_set, is_sub_loop, done):
                self.__manage_waiting(stack, visited, waiting, l_set, done)
                continue

            detected_loops = self.__try_find_loops(
                    entry, waiting, par_loops, l_set, is_sub_loop)

            new_loops = self.__get_new_loops(
                    waiting, detected_loops, l_set, is_sub_loop)

            while new_loops:
                # Follow loops
                for ad in new_loops:
                    # TODO : optimize
                    v = set(visited)
                    v.add(ad)
                    pl = set(par_loops)
                    pl.add(ad)

                    l = self.loops_set[(entry, ad)]
                    self.__explore(ad, pl, v, waiting, l, set(done))

                detected_loops = self.__try_find_loops(
                        entry, waiting, par_loops, l_set, is_sub_loop)

                new_loops = self.__get_new_loops(
                        waiting, detected_loops, l_set, is_sub_loop)


            self.__manage_waiting(stack, visited, waiting, l_set, done)

            if not stack:
                break

        # Now for each current loop, we add the content of each sub-loops.
        # It means that a loop contains all sub-loops (which is not the case
        # in loops_set : in contains only the current loop).
        for ad in is_sub_loop:
            loop = set(self.loops_set[(entry, ad)])
            self.loops_all[(entry, ad)] = loop

            self.deps[(entry, ad)] = set()

            for (prev, start), l in self.loops_set.items():
                # Skip current loop
                if (prev, start) == (entry, ad):
                    continue

                # Is it a sub loop ?
                if prev == ad and start != entry and start in loop:
                    k1 = (entry, ad)
                    k2 = (prev, start)
                    if k2 not in self.rev_deps:
                        self.rev_deps[k2] = set()
                    self.rev_deps[k2].add(k1)
                    self.deps[k1].add(k2)
                    self.loops_all[(entry, ad)].update(self.loops_all[(prev, start)])


    def __search_equiv_loops(self):
        # optim: don't compare twice two loops
        keys = set(self.loops_set.keys())

        for (prev1, start1), l1 in self.loops_set.items():
            keys.remove((prev1, start1))

            for prev2, start2 in keys:
                l2 = self.loops_set[(prev2, start2)]

                if start1 in l2 and start2 in l1 and l1 == l2:
                    #
                    # Try to detect equivalent or shifted loops :
                    #
                    # example :
                    #
                    # if {
                    #   goto label
                    # }
                    #
                    # while {
                    #   statement_1
                    # label:
                    #   statement_2
                    # }
                    #
                    # There is one loop, but in reality there are two loops,
                    # which are :
                    # [statement_1, statement_2]
                    # [statement_2, statement_1]
                    #
                    # This is what I call an equivalent or shifted loop.
                    # We can't say which one is the original, during the
                    # generation of the ast, we will keep the loop where
                    # we entered first.
                    #

                    if (prev1, start1) not in self.equiv:
                        self.equiv[(prev1, start1)] = {(prev2, start2)}
                    else:
                        self.equiv[(prev1, start1)].add((prev2, start2))

                    if (prev2, start2) not in self.equiv:
                        self.equiv[(prev2, start2)] = {(prev1, start1)}
                    else:
                        self.equiv[(prev2, start2)].add((prev1, start1))


    def __search_false_loops(self):
        # Mark recursively parent loops
        def rec_false_loop_parent(k):
            if k in self.false_loops:
                return
            self.false_loops.add(k)
            if k not in self.rev_deps:
                return
            for par in self.rev_deps[k]:
                rec_false_loop_parent(par)

        # Mark recursively sub loops
        def rec_false_loop_sub(k):
            if k in self.false_loops:
                return
            self.false_loops.add(k)
            for sub in self.deps[k]:
                rec_false_loop_sub(sub)

        def rec_unset_false_loop(k):
            if k not in self.false_loops:
                return
            self.false_loops.remove(k)
            if k not in self.rev_deps:
                return
            for par in self.rev_deps[k]:
                rec_unset_false_loop(par)

        # optim: don't compare twice two loops
        keys = set(self.loops_set.keys())

        for (prev1, start1), l1 in self.loops_set.items():
            keys.remove((prev1, start1))

            if (prev1, start1) in self.false_loops:
                continue

            for prev2, start2 in keys:
                if (prev2, start2) in self.false_loops:
                    continue

                l2 = self.loops_set[(prev2, start2)]

                #
                # Try to detect "strange" loops:
                #
                # example :
                #
                # if {
                #   goto label
                # }
                #
                # while {
                #   if {
                #     statement_1
                # label:
                #     statement_2
                #   } else {
                #     statement_3
                #   }
                # }
                #
                # Here there are no equivalent loops. Check for example
                # gotoinloop6 to see the result.
                #

                if (prev2, start2) in self.equiv and \
                    (prev1, start1) in self.equiv[(prev2, start2)]:
                    continue

                if prev2 in l1 and \
                   start2 in l1 and \
                   start1 in l2:
                    if l2.issubset(l1):
                        rec_false_loop_parent((prev2, start2))
                        rec_false_loop_sub((prev2, start2))

                elif prev1 in l2 and \
                     start1 in l2 and \
                     start2 in l1:
                    if l1.issubset(l2):
                        rec_false_loop_parent((prev1, start1))
                        rec_false_loop_sub((prev1, start1))

        # Now remove false positive: with rec_add_false_loop we can
        # go up too much and add a parent loop which is not a "false loop".

        for k in self.deps:
            if len(self.deps[k]) == 0:
                rec_unset_false_loop(k)


    def __loop_detection(self, ctx, entry):
        start = time()

        self.__explore(entry, set(), set(), {}, None, set())

        self.__search_equiv_loops()

        elapsed = time()
        elapsed = elapsed - start
        debug__("Exploration: found %d loop(s) in %fs" %
                (len(self.loops_all), elapsed))

        self.html_graph([])

        self.__search_false_loops()

        for k in self.false_loops:
            del self.loops_all[k]
            del self.loops_set[k]

        # Compute all address which are not in a loop
        in_loop = set()
        for l in self.loops_set.items():
            in_loop.update(l[1])

        self.not_in_loop = self.nodes.keys() - in_loop

        # Search inifinite loops
        self.infinite_loop = set()
        for l_curr_loop, l_set in self.loops_all.items():
            if self.__is_inf_loop(l_set):
                self.infinite_loop.add(l_curr_loop)

        # Save first address of loops
        for _, l_start in self.loops_all:
            self.loops_start.add(l_start)

        # search last node which force to looping
        for (l_prev_loop, l_start), l_set in self.loops_all.items():
            self.last_loop_node[(l_prev_loop, l_start)] = set()
            self.__search_last_loop_node(set(), l_prev_loop, l_start, l_set)

        elapsed = time()
        elapsed = elapsed - start
        debug__("Exploration: found %d loop(s) in %fs" %
                (len(self.loops_all), elapsed))
