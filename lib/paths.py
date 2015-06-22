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

import sys
import copy

import lib.utils
from lib.utils import (index, BRANCH_NEXT, BRANCH_NEXT_JUMP, print_list)
from lib.ast import Ast_Goto


class Paths():
    def __init__(self, gph=None):
        self.looping = {}  # key_path -> idx_loop
        self.paths = {}
        self.gph = gph
        if gph != None:
            self.cache_obj()


    def cache_obj(self):
        # For avoiding sub-access
        self.gph_loops            = self.gph.loops
        self.gph_marked_addr      = self.gph.marked_addr
        self.gph_cond_jumps_set   = self.gph.cond_jumps_set
        self.gph_uncond_jumps_set = self.gph.uncond_jumps_set
        self.gph_link_out         = self.gph.link_out


    def copy(self):
        newp = Paths(self.gph)
        newp.looping = copy.deepcopy(self.looping)
        newp.paths = copy.deepcopy(self.paths)
        return newp


    def __contains__(self, addr):
        return any(addr in p for p in self.paths.values())


    def __is_in_curr_loop(self, loop):
        # Assume that current paths is a loop
        curr_loop = self.first()

        if loop[0] != curr_loop:
            return False

        # Check if all address of loop are in paths
        if not all(addr in self for addr in loop):
            return False

        # Check if the loop is in the right order
        for p in self.paths.values():
            last_idx = -1
            for addr in loop:
                idx = index(p, addr)
                if idx == -1:
                    break
                elif idx < last_idx:
                    return False
                else:
                    last_idx = idx

        return True


    def get_loop_start(self, curr_loop_idx):
        if not curr_loop_idx:
            return -1
        return self.gph_loops[next(iter(curr_loop_idx))][0]


    def get_loops_idx(self):
        return {k for k, l in enumerate(self.gph_loops) \
                      if self.__is_in_curr_loop(l)}


    def debug(self):
        if not lib.utils.ctx.debug:
          return
        print("paths :", file=sys.stderr)
        for k, p in self.paths.items():
            print(k, ": ", end="", file=sys.stderr)
            print_list(p)
                
        print("looping : ", end="", file=sys.stderr)
        print(self.looping, file=sys.stderr)
        print()


    def __is_looping(self, key_path, curr_loop_idx):
        if key_path not in self.looping:
            return False
        l_idx = self.looping[key_path]
        if l_idx not in curr_loop_idx:
            return True
        # If it's a loop but on the current, return False and keep the path
        return False


    #
    # Returns :
    # is_loop : true if path[i] is a beginning of a loop
    # force_stop : true if it's a loop but we need to stop here
    #
    # A "marked" loop is a loop which have an equivalent loop
    # It means that these loops are the same but one starts
    # in the middle of the second (see tests/gotoinloop*). So
    # we go on the loop which starts in the middle, we returns
    # force_stop = True.
    #
    def __enter_new_loop(self, curr_loop_idx, key_path, i):
        addr = self.paths[key_path][i]
        is_loop = key_path in self.looping

        # TODO not sure
        # tests/gotoinloop{6,7}
        if addr in self.gph_marked_addr:
            if not curr_loop_idx or not is_loop:
                return False, True

        if not is_loop:
            return False, False

        l_idx = self.looping[key_path]
        if addr != self.gph_loops[l_idx][0]:
            return False, False

        # TODO check if all conditions are really necessary
        if addr in self.gph_marked_addr: # and \
                # l_idx in gph.marked:
                # and \
                # l_idx in gph.equiv and \
                # gph.equiv[l_idx] not in curr_loop_idx:
            return False, True

        return True, False


    def are_all_looping(self, start, check_equal, curr_loop_idx):
        # TODO check len looping == len paths ?
        if check_equal:
            for k in self.paths:
                if self.paths[k][0] == start and \
                        not self.__is_looping(k, curr_loop_idx):
                    return False
        else:
            for k in self.paths:
                if self.paths[k][0] != start and \
                        not self.__is_looping(k, curr_loop_idx):
                    return False
        return True


    def add_path(self, key_path, new_path, loop_idx=-1):
        self.paths[key_path] = new_path
        if loop_idx != -1:
            self.looping[key_path] = loop_idx


    def __get_loop_idx(self, k):
        return self.looping.get(k, -1)


    def pop(self, n):
        if n == 0:
            return []
        # Assume that all paths pop the same value
        it = iter(self.paths.values())
        p = next(it)
        if n == 1:
            poped = [p[0]]
            del p[0]
            for p in it:
                del p[0]
        else:
            poped = p[:n]
            del p[:n]
            for p in it:
                del p[:n]
        return poped


    def __del_path(self, k):
        del self.paths[k]
        if k in self.looping:
            del self.looping[k]


    def rm_empty_paths(self):
        to_remove = [k for k, p in self.paths.items() if not p]
        for k in to_remove:
            self.__del_path(k)
        return len(self.paths) == 0


    def __longuest_path(self):
        key = 0
        max_len = 0
        # leng = {len(p):k for k, p in self.paths.items()}
        # return leng[max(leng)]
        for k, p in self.paths.items():
            if len(p) > max_len:
                max_len = len(p)
                key = k
        return key


    #
    # Returns tuple :
    #
    # nb_commons :  common addresses on each paths
    # is_loop (bool) : stopped on a begining loop
    # is_ifelse (bool) : stopped on a ifelse (found two differents address on paths)
    # force_stop_addr : return the address we have stopped the algorithm
    #                   see comments in paths.__enter_new_loop
    #
    def head_last_common(self, curr_loop_idx):
        # The path used as a reference (each value of this path is
        # compared all others paths). We need the longest, otherwise
        # if we have a too smal path, we can stop too early.
        # tests/nestedloop3
        refpath = self.__longuest_path()

        nb_commons = 0
        for i in range(len(self.paths[refpath])):
            addr0 = self.paths[refpath][i]

            # Searching if it's a loop or a ifelse must be in differents loops
            # because for a conditional jump can a loop or a ifelse. Priority
            # is for loops.

            # Check if addr0 is the beginning of a loop
            is_loop, force_stop = self.__enter_new_loop(curr_loop_idx, refpath, i)
            if is_loop or force_stop:
                return nb_commons, is_loop, False, (force_stop and addr0)

            # Compare with other paths
            for k, p in self.paths.items():
                if k == refpath:
                    continue

                if addr0 not in p:
                    return nb_commons, False, False, 0

                addr = p[i]

                is_loop, force_stop = self.__enter_new_loop(curr_loop_idx, k, i)
                if is_loop or force_stop:
                    return nb_commons, is_loop, False, (force_stop and addr)

            # Check if addr0 is a ifelse
            if addr0 in self.gph_cond_jumps_set:
                nxt = self.gph_link_out[addr0]
                c1 = self.loop_contains(curr_loop_idx, nxt[BRANCH_NEXT])
                c2 = self.loop_contains(curr_loop_idx, nxt[BRANCH_NEXT_JUMP])
                if c1 and c2:
                    return nb_commons, False, True, 0

            # Compare with other paths
            for k, p in self.paths.items():
                if k == refpath:
                    continue

                if addr0 not in p:
                    return nb_commons, False, False, 0

                addr = p[i]

                if addr in self.gph_cond_jumps_set:
                    nxt = self.gph_link_out[addr]
                    c1 = self.loop_contains(curr_loop_idx, nxt[BRANCH_NEXT])
                    c2 = self.loop_contains(curr_loop_idx, nxt[BRANCH_NEXT_JUMP])
                    if c1 and c2:
                        return nb_commons, False, True, 0

            nb_commons = i+1

        # We have to test here, because we can stop before with a loop
        # or a ifelse.
        if len(self.paths) == 1:
            p = next(iter(self.paths.values()))
            return len(p), False, False, 0

        return nb_commons, False, False, 0


    def first_common_ifelse(self, curr_loop_idx, else_addr):
        if len(self.paths) <= 1:
            return -1

        #
        # if () { 
        #   infiniteloop ...
        # } else {
        #   ...
        # }
        #
        # can be simplified by : (the endpoint is the else-part)
        #
        # if () { 
        #   infiniteloop ...
        # }
        # ...
        #

        all_looping_if = self.are_all_looping(else_addr, False, curr_loop_idx)
        all_looping_else = self.are_all_looping(else_addr, True, curr_loop_idx)

        if all_looping_if or all_looping_else:
            return else_addr

        return self.first_common(curr_loop_idx)


    def first_common(self, curr_loop_idx):
        # Take a non looping-path as a reference :
        # we want to search a common address between other paths
        refpath = -1
        for k in self.paths:
            if not self.__is_looping(k, curr_loop_idx):
                refpath = k
                break

        if refpath == -1:
            return -1

        # Compare refpath with other paths

        for val in self.paths[refpath]:
            found = True
            is_enter = False
            for k in self.paths:
                if k != refpath and not self.__is_looping(k, curr_loop_idx):
                    is_enter = True
                    if val not in self.paths[k]:
                        found = False
                        break

            if found and is_enter:
                return val

        return -1


    def split(self, ifaddr, endpoint):
        nxt = self.gph_link_out[ifaddr]
        nxt_br_next = nxt[BRANCH_NEXT]
        split = [Paths(self.gph), Paths(self.gph)]

        add_path_1 = split[BRANCH_NEXT].add_path
        add_path_2 = split[BRANCH_NEXT_JUMP].add_path
        get_loop_idx = self.__get_loop_idx

        for k, p in self.paths.items():
            if p:
                # idx == -1 means :
                # - p is looping so there is no endpoint with some other paths
                # - endpoint == -1
                try:
                    idx = p.index(endpoint)
                    if p[0] == nxt_br_next:
                        add_path_1(k, p[:idx])
                    else:
                        add_path_2(k, p[:idx])
                except:
                    if p[0] == nxt_br_next:
                        add_path_1(k, p, get_loop_idx(k))
                    else:
                        add_path_2(k, p, get_loop_idx(k))

        else_addr = nxt[BRANCH_NEXT_JUMP] \
                    if len(split[BRANCH_NEXT_JUMP].paths) > 0 else -1

        return split, else_addr


    def goto_addr(self, addr):
        to_remove = []
        for k, p in self.paths.items():
            idx = index(p, addr)
            if idx != -1:
                self.paths[k] = p[idx:]
            else:
                to_remove.append(k)

        all_removed = len(to_remove) == len(self.paths)

        for k in to_remove:
            self.__del_path(k)

        return all_removed


    def first(self):
        p = next(iter(self.paths.values()))
        return p[0]


    def loop_contains(self, loop_start_idx, addr):
        if not loop_start_idx:
            return True
        return any(addr in self.gph_loops[i] for i in loop_start_idx)
                    

    # For a loop : check if the path need to be kept (the loop 
    # contains the path). For this we see the last address of the path.
    # Otherwise it's an endloop
    def __keep_path(self, curr_loop_idx, path, key_path):
        last = path[-1]

        if self.loop_contains(curr_loop_idx, last):
            return True, False

        if key_path not in self.looping:
            return False, False

        l_idx = self.looping[key_path]

        if l_idx in curr_loop_idx:
            return True, False

        for i in curr_loop_idx:
            if l_idx in self.gph.nested_loops_idx[i]:
                return True, False

        if l_idx in self.gph.marked:
            return False, True

        return False, False


    # Returns :
    # loop_paths (Paths), endloop (list(Paths)), address_endloops
    def extract_loop_paths(self, curr_loop_idx, last_loop_idx, endif):
        # TODO optimize....

        loop_paths = Paths(self.gph)
        tmp_endloops = Paths(self.gph)


        # ------------------------------------------------------
        # Distinction of loop-paths / endloops
        # ------------------------------------------------------

        for k, p in self.paths.items():
            keep, ignore =  self.__keep_path(curr_loop_idx, p, k)
            if not ignore:
                if keep:
                    loop_paths.add_path(k, p, self.__get_loop_idx(k))
                else:
                    tmp_endloops.add_path(k, p, self.__get_loop_idx(k))

        # Remove the beginning of the loop to get only the endloop
        for k, el in tmp_endloops.paths.items():
            for i, addr in enumerate(el):
                if addr not in loop_paths:
                    p = el[i:]
                    if not p in tmp_endloops.paths.values():
                        tmp_endloops.paths[k] = p
                    else:
                        tmp_endloops.paths[k] = []
                    break

        tmp_endloops.rm_empty_paths()


        # ------------------------------------------------------
        # Regroup paths if they start with the same addr
        # ------------------------------------------------------

        grp_endloops = {}

        for k, el in tmp_endloops.paths.items():
            if el[0] not in grp_endloops:
                grp_endloops[el[0]] = Paths(self.gph)

            grp_endloops[el[0]].add_path(k, el, tmp_endloops.__get_loop_idx(k))


        # ------------------------------------------------------
        # Just store the beginning of each endloop. It will
        # be returned by the function. We need it for printing
        # a comment "endloop NUMBER". Later we add more endloops
        # due to common endpoints.
        # ------------------------------------------------------

        endloops_start = {ad for ad in grp_endloops}
        # debug__("endloops_start")
        # debug__(endloops_start)


        if len(grp_endloops) <= 1:
            return loop_paths, list(grp_endloops.values()), endloops_start


        # ------------------------------------------------------
        # Endpoints bruteforce between all paths
        # Searching an endpoint is used to avoid common address
        # between two paths. A path will be cut at this endpoint.
        # ------------------------------------------------------

        def search_first_common(loops_idx, p1, p2):
            # TODO hack...
            if p1.are_all_looping(-1, False, loops_idx) or \
                p2.are_all_looping(-1, False, loops_idx):
                return -1
            # TODO optimize
            tmp = Paths(self.gph)
            tmp.paths.update(p1.paths)
            tmp.paths.update(p2.paths)
            tmp.looping.update(p1.looping)
            tmp.looping.update(p2.looping)
            return tmp.first_common(loops_idx)

        # Check if the address n is the next address of g
        def has_next(g, n):
            for k, p in g.paths.items():
                nxt = self.gph_link_out[p[-1]]
                if len(nxt) == 1 and nxt[BRANCH_NEXT] == n:
                    return True
            return False


        grp2_keys = set(grp_endloops.keys())
        all_endpoints = {}

        for ad1, els1 in grp_endloops.items():
            # Optimization to not compare twice two sets (for
            # example g1 with g2 g2 with g1).
            grp2_keys.remove(ad1) 

            for ad2 in grp2_keys:
                els2 = grp_endloops[ad2]

                endpoint = search_first_common(last_loop_idx, els1, els2)
                # print("endpoint: ", hex(ad1), hex(ad2), "=", hex(endpoint))

                if endpoint != -1:
                    if endpoint not in all_endpoints:
                        all_endpoints[endpoint] = set()
                    all_endpoints[endpoint].add(ad1)
                    all_endpoints[endpoint].add(ad2)


        # If we have all endloops at the end of an if, there will
        # be no endpoints between them (the endpoints is outside)
        # So check all groups if the next is the "endif".
        if endif != -1 and endif not in grp_endloops:
            # Add a fake group
            for ad, els in grp_endloops.items():
                if has_next(els, endif):
                    if endif not in all_endpoints:
                        all_endpoints[endif] = set()
                    all_endpoints[endif].add(ad)

            grp_endloops[endif] = Paths(self.gph)
            grp_endloops[endif].paths[-1] = [endif]


        # ------------------------------------------------------
        # Compute endpoints dependencies
        # A path can contains multiple endpoints with multiple
        # paths. So we need to check which endpoint is the first.
        # ------------------------------------------------------

        rev_depends_on = {}
        edp2_keys = list(all_endpoints.keys())

        has_no_dep = set(all_endpoints.keys())

        for edp1, adset1 in all_endpoints.items():
            # Optimization to not compare twice two sets
            edp2_keys.remove(edp1)

            for edp2 in edp2_keys:
                adset2 = all_endpoints[edp2]

                if adset1.issubset(adset2):
                    all_endpoints[edp2] -= adset1

                    if edp1 not in rev_depends_on:
                        rev_depends_on[edp1] = {edp2}
                    else:
                        rev_depends_on[edp1].add(edp2)

                    if edp2 in has_no_dep:
                        has_no_dep.remove(edp2)

                elif adset2.issubset(adset1):
                    all_endpoints[edp1] -= adset2

                    if edp2 not in rev_depends_on:
                        rev_depends_on[edp2] = {edp1}
                    else:
                        rev_depends_on[edp2].add(edp1)

                    if edp1 in has_no_dep:
                        has_no_dep.remove(edp1)

        # Now remove indirect dependencies
        # For example if we have : e1 -> e2 -> e3
        # e1 has a dependence inverse with [e2,e3]
        # Here we just want to keep e2.
        e2_keys = list(rev_depends_on.keys())
        for e1, s1 in rev_depends_on.items():
            # Optimization to not compare twice two sets
            e2_keys.remove(e1)
            for e2 in e2_keys:
                s2 = rev_depends_on[e2]
                if s1.issubset(s2):
                    rev_depends_on[e2] -= s1
                elif s2.issubset(s1):
                    rev_depends_on[e1] -= s2

        # debug__("all_endpoints   endpoint: address")
        # debug__(all_endpoints)
        # debug__("endpoints without dependencies")
        # debug__(has_no_dep)
        # debug__("rev_depends_on")
        # debug__(rev_depends_on)


        # ------------------------------------------------------
        # Search which endpoints we must see first. A path can
        # contains multiple endpoint with other paths.
        # ------------------------------------------------------

        endpoints_sort = []
        seen = set()

        def rec(e):
            endpoints_sort.append(e)
            seen.add(e)
            if e not in rev_depends_on:
                return
            for rev_e in rev_depends_on[e]:
                if rev_e not in seen:
                    rec(rev_e)

        for e in has_no_dep:
            rec(e)

        # debug__("endpoints_sort")
        # debug__(endpoints_sort)


        # ------------------------------------------------------
        # Cut paths to avoid duplicate code and create new
        # groups. Paths are cut at each endpoints.
        # ------------------------------------------------------

        prev_cut_idx = {}
        for k in tmp_endloops.paths:
            prev_cut_idx[k] = 0

        # Function to cut each path of the group g. Because we can
        # have multiple endpoints in one path, prev_cut_idx is used 
        # to store the last index of the previous endpoint.
        # All paths are cut like this : [prev_cut_idx:endpoint]
        # or [index(force_start_e):next_endpoint]
        def cut_path(g, e, force_start_e=-1):
            els = grp_endloops[g]
            newp = Paths(self.gph)
            all_finish_by_jump = True

            for k, p in els.paths.items():

                if force_start_e != -1:
                    start = index(p, force_start_e)
                else:
                    start = prev_cut_idx[k]

                stop = -1 if e == -1 else index(p, e)
                if stop == -1: 
                    stop = len(p)

                if force_start_e == -1:
                    prev_cut_idx[k] = start

                loop_idx = -1
                if stop == len(p):
                    loop_idx = els.__get_loop_idx(k)

                if start == 0 and stop == len(p):
                    p2 = p
                else:
                    p2 = p[start:stop]

                if not p2:
                    continue

                newp.add_path(k, p2, loop_idx)

                # If it's an internal loop, we don't have to check
                # if the last instruction is a jump.
                if els.__is_looping(k, last_loop_idx):
                    continue

                # Check if the last instruction is a jump and
                # go to the endpoint.
                if p[stop-1] in self.gph_link_out:
                    nxt = self.gph_link_out[p[stop-1]]
                    # TODO need to check cond jumps ?
                    if not(len(nxt) == 1 and \
                            p[stop-1] in self.gph_uncond_jumps_set and \
                            nxt[BRANCH_NEXT] == e):
                        all_finish_by_jump = False
                else:
                    # It's a return, there is nothing after. It must be
                    # in the future dict 'next_no_jump'.
                    all_finish_by_jump = False

            return newp, all_finish_by_jump


        # List of group-Paths. All paths have a jump at the end.
        with_jump = []

        # Contains the next address of a group. These groups
        # must be sorted.
        next_no_jump = {} # group_addr -> next_address
        saved_paths = {}  # group_addr -> Paths

        seen_endloops = set()

        # All groups are recreated. They are copied to saved_paths
        # or with_jump.

        for i, e in enumerate(endpoints_sort):

            # Cut paths to get the beginning of the endpoint until
            # the end or the next endpoint.

            # Check if the next endpoint is a dependence of the
            # current. It means that these two endpoints are in
            # a same group.
            next_e = -1
            if i+1 < len(endpoints_sort):
                tmp_e = endpoints_sort[i+1]
                if e in rev_depends_on and tmp_e in rev_depends_on[e]:
                    next_e = tmp_e

            if e in grp_endloops:
                # TODO optimize by avoiding the copy of
                # grp_endloops[e] if next_e == -1
                # -> until the end
                newp, all_finish_by_jump = cut_path(e, next_e, force_start_e=e)
                seen_endloops.add(e)
            else:
                # Take one group it doesn't matter which one is it
                # If one group contains the endpoint e, all paths must
                # be in g.
                g = next(iter(all_endpoints[e]))

                # TODO optimize by avoiding the copy of
                # grp_endloops[e] if next_e == -1
                # -> until the end
                newp, all_finish_by_jump = cut_path(g, next_e, force_start_e=e)
                seen_endloops.add(g)

            if all_finish_by_jump:
                # print("4 ---->", hex(newp.first()), hex(e), hex(next_e))
                with_jump.append(newp)
            else:
                # print("3 ---->", hex(newp.first()), hex(e), hex(next_e))
                next_no_jump[e] = next_e
                saved_paths[e] = newp


            # Now cut all paths until the endpoint. If a previous
            # endpoints was in the group, we start to cut at this
            # one (see prev_cut_idx).
            for g in all_endpoints[e]:
                # This prevent to not duplicate endpoints which are at
                # the same time the beginning of a group.
                if g != e:
                    newp, all_finish_by_jump = cut_path(g, e)
                    if all_finish_by_jump:
                        # print("2 ---->", hex(newp.first()), hex(e))
                        with_jump.append(newp)
                    else:
                        # print("1 ---->", hex(newp.first()), hex(e))
                        head = newp.first()
                        next_no_jump[head] = e
                        saved_paths[head] = newp
                    seen_endloops.add(g)


        # ------------------------------------------------------
        # Sort endloops.
        # ------------------------------------------------------

        list_grp_endloops = []

        # It's possible that a path have no endpoints with others.
        # For example if we have an infinite loop in the loop.
        # Or if these paths are at the end of an if (tests/server).

        # debug__(endloops_start)
        # debug__(seen_endloops)

        other_paths = endloops_start - seen_endloops
        for ad in other_paths:
            list_grp_endloops.append(grp_endloops[ad])
            
        # Because all these paths finish with a jump, the order
        # is not important.
        for els in with_jump:
            if len(els.paths) > 0:
                list_grp_endloops.append(els)


        # Now we must order these paths. They have a direct access to
        # the next group (no jump), so must sort them.
        endloops_sort = []

        # Just for a better output, we sort the addresses. We want that
        # the last endloop is the "real last". get_ast_loop will return
        # endloops[-1]. We assume that the last in no_dep has the longuest
        # path than the first one.
        el_with_dep = {n for n in next_no_jump.values() if n != -1}
        el_no_dep = list(next_no_jump.keys() - el_with_dep)
        el_no_dep.sort()
            
        # debug__(el_no_dep)
        # debug__(next_no_jump)

        for ad in el_no_dep:
            n = ad
            while n != -1:
                if n != endif:
                    endloops_sort.append(n)
                n = next_no_jump[n]

        # debug__(endloops_sort)

        el_seen = set()

        for i, ad in enumerate(endloops_sort):
            # Sometimes it's not possible to merge endpoints due to some goto.
            # (tests/goto4). If a Path is duplicated it may crash the program
            # because a path is modified when a branch is traversed. The solution
            # is to make a copy of the object.
            if ad in el_seen:
                list_grp_endloops.append(saved_paths[ad].copy())
            else:
                list_grp_endloops.append(saved_paths[ad])

            el_seen.add(ad)

            # This is a HACK.
            # It's possible that endloops were not correclty sorted (due to
            # weird gotos). So check that and add a goto, if the next is not the
            # one expected. (tests/goto5)
            nxt = next_no_jump[ad]
            if nxt != -1 and i < len(endloops_sort)-1 and nxt != endloops_sort[i+1]:
                list_grp_endloops.append(Ast_Goto(nxt))

        return loop_paths, list_grp_endloops, endloops_start
