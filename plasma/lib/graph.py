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

from time import time

from plasma.lib.utils import BRANCH_NEXT, BRANCH_NEXT_JUMP, debug__, list_starts_with

# For the loop's analysis
MAX_NODES = 800


# This class is used only for the decompilation mode. The analyzer create
# also a graph but only on-the-fly.

class Graph:
    def __init__(self, dis, entry_point_addr):
        # Each node contains a block (list) of instructions.
        self.nodes = {} # ad -> [instruction, (prefetch)]

        # For each address block, we store a list of next blocks.
        # If there are 2 elements it means that the precedent instruction
        # was a conditional jump :
        # 1st : direct next instruction
        # 2nd : for conditional jump : address of the jump
        self.link_out = {} # ad -> [nxt1, nxt2]
        
        self.link_in = {} # ad -> [prev, ...]

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
        self.last_node_loop = {}

        self.all_deep_equiv = set()

        self.skipped_loops_analysis = False

        self.exit_or_ret = set()

        # Could be modified by AddrContext.decompile
        self.debug = False


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


    # Concat instructions in single block
    # jumps are in separated blocks
    def simplify(self):
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


    def dot_loop_deps(self):
        output = open("graph_loop_deps.dot", "w+")
        output.write('digraph {\n')
        output.write('node [fontname="liberation mono" style=filled fillcolor=white shape=box];\n')

        for k, dp in self.deps.items():
            output.write('node_%x_%x [label="(%x, %x)"' % (k[0], k[1], k[0], k[1]))

            if k in self.false_loops:
                output.write(' fillcolor="#B6FFDD"')

            if k in self.all_deep_equiv:
                output.write(' color="#ff0000"')

            output.write('];\n')

            for sub in dp:
                output.write('node_%x_%x -> node_%x_%x;\n'
                        % (k[0], k[1], sub[0], sub[1]))

        output.write('}\n')
        output.close()


    def dot_graph(self, jmptables):
        output = open("graph.dot", "w+")
        output.write('digraph {\n')
        # output.write('graph [bgcolor="#aaaaaa" pad=20];\n')
        # output.write('node [fontname="liberation mono" style=filled fillcolor="#333333" fontcolor="#d3d3d3" shape=box];\n')
        output.write('node [fontname="liberation mono" style=filled fillcolor=white shape=box];\n')

        keys = list(self.nodes.keys())
        keys.sort()

        for k in keys:
            lst_i = self.nodes[k]

            output.write('node_%x [label="' % k)

            for i in lst_i:
                output.write('0x%x: %s %s\\l' % (i.address, i.mnemonic, i.op_str))

            output.write('"')

            if k in self.loops_start:
                output.write(' fillcolor="#FFFCC4"')
            elif k not in self.link_out:
                output.write(' fillcolor="#ff7777"')
            elif k not in self.link_in:
                output.write(' fillcolor="#B6FFDD"')

            output.write('];\n')
        
        for k, i in self.link_out.items():
            if k in jmptables:
                for ad in jmptables[k].table:
                    output.write('node_%x -> node_%x;\n' % (k, ad))
            elif len(i) == 2:
                # true green branch (jump is taken)
                output.write('node_%x -> node_%x [color="#58DA9C"];\n'
                        % (k, i[BRANCH_NEXT_JUMP]))

                # false red branch (jump is not taken)
                output.write('node_%x -> node_%x [color="#ff7777"];\n'
                        % (k, i[BRANCH_NEXT]))
            else:
                output.write('node_%x -> node_%x;\n' % (k, i[BRANCH_NEXT]))

        output.write('}')
        output.close()


    def __search_last_node_loop(self, l_prev_loop, l_start, l_set):
        def __rec_branch_go_out(ad):
            stack = [ad]
            visited = set()
            while stack:
                ad = stack.pop(-1)
                if ad not in l_set:
                    return True
                if ad == l_start or ad in visited:
                    continue
                visited.add(ad)
                for n in self.link_out[ad]:
                    stack.append(n)
            return False

        # Start from the end of the loop

        stack = []
        visited = {l_start}
        for prev in self.link_in[l_start]:
            if prev in l_set:
                stack.append(prev)

        res = []

        while stack:
            ad = stack.pop(-1)
            if ad in visited or ad not in l_set:
                continue
            visited.add(ad)

            for prev in self.link_in[ad]:
                if prev == l_start:
                    continue

                go_out = False

                for n in self.link_out[prev]:
                    if n not in l_set:
                        res.append(ad)
                        go_out = True

                if not go_out:
                    stack.append(prev)

        for ad in res:
            if ad not in self.last_node_loop:
                self.last_node_loop[ad] = set()
            self.last_node_loop[ad].add((l_prev_loop, l_start))


    def __is_inf_loop(self, l_set):
        for ad in l_set:
            if ad in self.link_out:
                for nxt in self.link_out[ad]:
                    if nxt not in l_set:
                        return False
        return True


    def path_exists(self, from_addr, to_addr, loop_start):
        def __path_exists(curr, local_visited):
            stack = []
            for n in self.link_out[from_addr]:
                stack.append(n)
            while stack:
                curr = stack.pop(-1)
                if curr == to_addr:
                    return True
                if curr in local_visited:
                    continue
                local_visited.add(curr)
                if curr not in self.link_out or curr == loop_start:
                    continue
                for n in self.link_out[curr]:
                    stack.append(n)
            return False

        if from_addr == to_addr:
            return True

        if from_addr not in self.link_out:
            return False

        if (from_addr, to_addr) in self.cache_path_exists:
            return self.cache_path_exists[(from_addr, to_addr)]

        local_visited = set()
        res = __path_exists(from_addr, local_visited)
        self.cache_path_exists[(from_addr, to_addr)] = res
        return res


    # Returns a set containing every addresses which are in paths from
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

            # search a path from ad to ad, but don't return in pareent loops
            l = self.find_paths(ad, ad, par_loops)

            # If the set is empty, it's not a loop
            if l:
                self.loops_set[(entry, ad)] = l
                is_sub_loop.add(ad)
                detected_loops[ad] = (entry, ad)

        return detected_loops


    # This function removes entries in waiting list if we have seen
    # all previous nodes for one node.
    def __manage_waiting(self, stack, visited, waiting, l_set, done):
        keys = set(waiting.keys())
        for ad in keys:
            if l_set is not None and ad not in l_set:
                continue
            if len(waiting[ad]) == 0:
                del waiting[ad]
                done.add(ad)
                stack.append((-1, ad))


    # This function reads all nodes in the current stack.
    # Each node is added to the waiting list if all previous
    # nodes were not seen.
    # Then if there is an out-link, this new node is added to
    # the stack, and it returns True.
    def __until_stack_empty(self, stack, waiting, visited,
                            par_loops, l_set, is_sub_loop, done):
        has_moved = False

        while stack:
            prev, ad = stack.pop(-1)

            # if ad has parent nodes, check if we have seen all parents
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


    # It explores the graph and detects loops
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
            # first: manage pending nodes
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


    def all_false(self, loops_key):
        for k in loops_key:
            if k not in self.false_loops:
                return False
        return True


    # Mark recursively parent loops, all children of a loop must
    # have been set to false
    def __rec_mark_parent_false(self, k):
        self.false_loops.add(k)
        if k not in self.rev_deps:
            return

        for par in self.rev_deps[k]:
            if par in self.false_loops:
                continue

            if self.all_false(self.deps[par]):
                self.__rec_mark_parent_false(par)


    def __rec_mark_children(self, k, myset):
        myset.add(k)
        for sub in self.deps[k]:
            if sub not in self.false_loops:
                self.__rec_mark_children(sub, myset)


    def __yield_cmp_loops(self, keys1, not_in_false=True):
        # optim: don't compare twice two loops
        keys2 = set(keys1)
        for k1 in keys1:
            keys2.remove(k1)
            if not_in_false and k1 in self.false_loops:
                continue
            for k2 in keys2:
                if not_in_false and k2 in self.false_loops:
                    continue
                yield k1, k2


    # Some heuristics to detect false loops
    def __search_false_loops(self):
        # If all previous link of a loop start is inside the loop, this
        # is a false loop.
        for (prev, start), l_set in self.loops_all.items():
            if prev == start:
                # special case: see tests/entryloop1
                continue

            l_set_copy = set(l_set)
            l_set_copy.remove(start)
            lin = set(self.link_in[start])

            if lin.issubset(l_set):
                self.false_loops.add((prev, start))


        # Find loops at the last level (no loop inside)
        loops_to_check = set()
        for k in self.loops_all:
            if len(self.deps[k]) == 0:
                loops_to_check.add(k)


        # Now try to find other false loops...
        for (prev1, start1), (prev2, start2) in \
                    self.__yield_cmp_loops(self.loops_all.keys()):

            if (prev1, start1) not in loops_to_check:
                continue

            l1 = self.loops_set[(prev1, start1)]
            l2 = self.loops_set[(prev2, start2)]

            if start1 == start2:
                continue

            if prev1 in l2 and \
                 start1 in l2 and \
                 start2 in l1:
                if l1.issubset(l2):
                    self.__rec_mark_parent_false((prev1, start1))


        # Make a diff to keep only real loops (false loops will be
        # deleted by __update_loops)

        correct_loops = set()

        for k in self.roots:
            if k in self.false_loops:
                continue
            self.__rec_mark_children(k, correct_loops)

        self.false_loops = self.loops_all.keys() - correct_loops


    def __search_same_deep_equiv_loops(self):
        #
        # Search equivalent loops at the same deep, but compare with
        # 'loops_all' -> each item contains all sub-loops instead of
        # 'loops_set' wich contains only the loop.
        #
        # example:
        #
        #      loop1
        #     /     \
        #  loop2   loop3
        #
        # If loops_all[loop2] == loops_all[loop3], and if loop2 or loop3 is
        # in false_loops, we remove these loops.
        #

        def do_add(k1, k2):
            nonlocal idx_count, set_index, deep_equiv
            l1 = self.loops_all[k1]
            l2 = self.loops_all[k2]
            if l1 == l2:
                if k1 in set_index:
                    i = set_index[k1]
                    deep_equiv[i].add(k2)
                    self.all_deep_equiv.add(k2)
                    set_index[k2] = i
                elif k2 in set_index:
                    i = set_index[k2]
                    deep_equiv[i].add(k1)
                    self.all_deep_equiv.add(k1)
                    set_index[k1] = i
                else:
                    i = idx_count
                    idx_count += 1
                    deep_equiv[i] = {k1, k2}
                    set_index[k1] = i
                    set_index[k2] = i
                    self.all_deep_equiv.add(k1)
                    self.all_deep_equiv.add(k2)

        set_index = {}
        deep_equiv = {}
        idx_count = 0

        for k in self.deps:
            for k1, k2 in self.__yield_cmp_loops(self.deps[k], False):
                do_add(k1, k2)

        for k1, k2 in self.__yield_cmp_loops(self.roots, False):
            do_add(k1, k2)

        if not deep_equiv:
            return

        last_length = 0
        while last_length != len(self.false_loops):
            last_length = len(self.false_loops)

            for i, keys in deep_equiv.items():
                nb_false = 0
                for k in keys:
                    if k in self.false_loops:
                        nb_false += 1

                if nb_false > 0:
                    for k in set(keys):
                        if k in self.false_loops:
                            continue
                        subs = self.deps[k]
                        if len(subs) == 0 or self.all_false(subs):
                            keys.remove(k)
                            self.__rec_mark_parent_false(k)


    def __update_loops(self):
        def rec_remove(k):
            if k not in self.loops_all:
                return
            del self.loops_all[k]
            del self.loops_set[k]
            for sub in self.deps[k]:
                if sub in self.false_loops:
                    rec_remove(sub)
        for k in self.false_loops:
            if k not in self.rev_deps or k in self.all_deep_equiv:
                rec_remove(k)


    def loop_detection(self, entry, bypass_false_search=False):
        start = time()

        # Equivalent loops at a same deep in the loops dependencies tree
        self.deep_equiv = set()
        # For one loop : contains all address of the loop only
        self.loops_set = {}
        # For one loop : contains all address of the loop and sub-loops
        self.loops_all = {}
        # Loop dependencies
        self.deps = {}
        self.rev_deps = {}
        # Loops marked as "False"
        self.false_loops = set()

        if len(self.nodes) > MAX_NODES:
            self.skipped_loops_analysis = True
            return

        # Detect loops and compute loop dependencies on the fly
        self.__explore(entry, set(), set(), {}, None, set())

        # Keep only loops at the first level
        self.roots = self.loops_set.keys() - self.rev_deps.keys()

        # debug__(self.deps)
        # debug__(self.roots)
        # debug__(self.loops_all)

        # Detect 'strange loops'
        if not bypass_false_search:
            self.__search_false_loops()
            self.__search_same_deep_equiv_loops()

        # Remove recursively marked false loops
        self.__update_loops()

        # debug__(self.loops_all)

        # Compute all addresses which are not in a loop
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
        self.loops_start = set()
        for _, l_start in self.loops_all:
            self.loops_start.add(l_start)

        # For each loop we search the last node that if we enter in it,
        # we are sure to return to the loop.
        self.last_node_loop = {}
        for (l_prev_loop, l_start), l_set in self.loops_all.items():
            if (l_prev_loop, l_start) not in self.infinite_loop:
                self.__search_last_node_loop(l_prev_loop, l_start, l_set)

        if self.debug:
            self.dot_loop_deps()

        elapsed = time()
        elapsed = elapsed - start
        debug__("Exploration: found %d loop(s) in %fs" %
                (len(self.loops_all), elapsed))
