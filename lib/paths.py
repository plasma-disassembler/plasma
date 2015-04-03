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


from lib.utils import (debug__, index, is_cond_jump, is_uncond_jump,
        BRANCH_NEXT, BRANCH_NEXT_JUMP)

gph = None



def get_loop_start(curr_loop_idx):
    if not curr_loop_idx:
        return -1
    return gph.loops[curr_loop_idx[0]][0]


# TODO remove ?
def loop_contains(loop_start, addr):
    if loop_start == -1:
        return True
    for l in gph.loops:
        if l[0] == loop_start and addr in l:
            return True
    return False


# TODO remove ?
# Returns all loops starting with addr
def loop_exists_idx(addr):
    idx = []
    i = 0
    for l in gph.loops:
        if l[0] == addr:
            idx.append(i)
        i += 1
    return idx


# TODO remove ?
def loop_exists(addr):
    # normally addr != -1
    # nested_loops[-1] contains all sub-loops
    # return addr in gph.nested_loops
    for l in gph.loops:
        if addr == l[0]:
            return True
    return False


class Paths():
    def __init__(self):
        self.looping = {}  # key_path -> idx_loop
        self.paths = {}


    def __contains__(self, addr):
        return any(addr in i for i in self.paths.values())


    def contains_list(self, lst):
        return all(addr not in self for addr in lst)


    def __is_in_curr_loop(self, loop):
        # Assume that current paths is a loop
        curr_loop = self.first()

        if loop[0] != curr_loop:
            return False

        # Check if all address of loop are in paths
        for addr in loop:
            if addr not in self:
                return False

        # Check if the loop is in the right order
        for k in self.paths:
            p = self.paths[k]
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


    def get_loops_idx(self):
        idx = []
        for k, l in enumerate(gph.loops):
            if self.__is_in_curr_loop(l):
                idx.append(k)
        return idx


    def debug(self):
        debug__("\npaths :", end="")
        debug__(self.paths)
        debug__("looping :", end="")
        debug__(self.looping)


    def __is_looping(self, key_path, curr_loop_idx):
        if key_path not in self.looping:
            return False
        l_idx = self.looping[key_path]
        # If is a loop but on the current, return False and  keep the path
        if l_idx not in curr_loop_idx :
            return True
        return False


    def __enter_new_loop(self, curr_loop_idx, key_path, k):
        addr = self.paths[key_path][k]
        is_loop = key_path not in self.looping

        # TODO not sure
        # tests/gotoinloop{6,7}
        if addr in gph.marked_addr:
            if not curr_loop_idx or is_loop:
                return False, True

        if is_loop:
            return False, False

        l_idx = self.looping[key_path]
        if addr != gph.loops[l_idx][0]:
            return False, False

        # TODO check if all conditions are really necessary
        if addr in gph.marked_addr: # and \
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


    def add(self, key_path, new_path, loop_idx=-1):
        self.paths[key_path] = new_path
        if loop_idx != -1:
            self.looping[key_path] = loop_idx


    def __get_loop_idx(self, k):
        return self.looping.get(k, -1)


    def pop(self):
        # Assume that all paths pop the same value
        vals = set(pv.pop(0) for pv in self.paths.values())
        assert len(vals) == 1
        return next(iter(vals))


    def __del_path(self, k):
        del self.paths[k]
        if k in self.looping:
            del self.looping[k]
        return


    def rm_empty_paths(self):
        to_remove = []
        for k in self.paths:
            if not self.paths[k]:
                to_remove.append(k)

        for k in to_remove:
            del self.paths[k]
            if k in self.looping:
                del self.looping[k]

        return len(self.paths) == 0


    def __longuest_path(self):
        key = 0
        max_len = 0
        for k, p in self.paths.items():
            if len(p) > max_len:
                max_len = len(p)
                key = k
        return key


    # Returns tuple :
    #
    # until_address : found common address until this value
    # is_loop (bool) : stopped on a begining loop
    # is_ifelse (bool) : stopped on a ifelse (found two differents address on paths)
    # force_stop_addr : return the address we have stopped the algorithm
    #
    def head_last_common(self, curr_loop_idx):
        # The path used as a reference (each value of this path is
        # compared all others paths). We need the longest, otherwise
        # if we have a too smal path, we can stop too early.
        # tests/nestedloop3
        refpath = self.__longuest_path()

        last = -1
        i = 0
        while i < len(self.paths[refpath]):

            addr0 = self.paths[refpath][i]

            is_loop, force_stop = self.__enter_new_loop(curr_loop_idx, refpath, i)
            if is_loop or force_stop:
                return last, is_loop, False, (force_stop and addr0)

            # Check addr0
            if is_cond_jump(gph.nodes[addr0][0]):
                nxt = gph.link_out[addr0]
                c1 = self.loop_contains(curr_loop_idx, nxt[BRANCH_NEXT])
                c2 = self.loop_contains(curr_loop_idx, nxt[BRANCH_NEXT_JUMP])
                if c1 and c2:
                    return last, False, True, 0


            # Compare with other paths
            for k in self.paths:
                if k == refpath:
                    continue

                if index(self.paths[k], addr0) == -1:
                    return last, False, False, 0

                addr = self.paths[k][i]

                is_loop, force_stop = self.__enter_new_loop(curr_loop_idx, k, i)
                if is_loop or force_stop:
                    return last, is_loop, False, force_stop and addr


                if is_cond_jump(gph.nodes[addr][0]):
                    nxt = gph.link_out[addr]
                    c1 = self.loop_contains(curr_loop_idx, nxt[BRANCH_NEXT])
                    c2 = self.loop_contains(curr_loop_idx, nxt[BRANCH_NEXT_JUMP])
                    if c1 and c2:
                        return last, False, True, 0

            i += 1
            last = addr0

        # We have to test here, because we can stop before with a loop
        # or a ifelse.
        if len(self.paths) == 1:
            k = next(iter(self.paths.keys()))
            return self.paths[k][-1], False, False, 0

        return last, False, False, 0


    def first_common(self, curr_loop_idx, else_addr):
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

        # Take a non looping-path as a reference :
        # we want to search a common address between other paths
        refpath = -1
        for k in self.paths:
            if not self.__is_looping(k, curr_loop_idx):
                refpath = k
                break

        # Compare

        found = False
        i = 0
        val = -1
        while not found and i < len(self.paths[refpath]):
            val = self.paths[refpath][i]
            found = True
            for k in self.paths:
                if k != refpath:
                    if not self.__is_looping(k, curr_loop_idx):
                        if index(self.paths[k], val) == -1:
                            found = False
                            break
            i += 1

        if found:
            return val
        return -1


    def split(self, ifaddr, endpoint):
        nxt = gph.link_out[ifaddr]
        split = [Paths(), Paths()]
        else_addr = -1
        for k, p in self.paths.items():
            if p:
                if p[0] == nxt[BRANCH_NEXT]:
                    br = BRANCH_NEXT
                else:
                    br = BRANCH_NEXT_JUMP
                    else_addr = nxt[BRANCH_NEXT_JUMP]
                # idx == -1 means :
                # - p is looping so there is no endpoint with some other paths
                # - endpoint == -1
                idx = index(p, endpoint)
                if idx == -1:
                    split[br].add(k, p, self.__get_loop_idx(k))
                else:
                    split[br].add(k, p[:idx])
        return split, else_addr


    def goto_addr(self, addr):
        for k in self.paths:
            idx = index(self.paths[k], addr)
            self.paths[k] = [] if idx == -1 else self.paths[k][idx:]


    def first(self):
        k = next(iter(self.paths.keys()))
        return self.paths[k][0]


    def loop_contains(self, loop_start_idx, addr):
        if not loop_start_idx:
            return True
        for i in loop_start_idx:
            if addr in gph.loops[i]:
                return True
        return False
                    

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
            if l_idx in gph.nested_loops_idx[i]:
                return True, False

        if l_idx in gph.marked:
            return False, True

        return False, False

    # Returns :
    # loop_paths (Paths), endloop (list(Paths))
    def extract_loop_paths(self, curr_loop_idx):
        # TODO optimize....

        loop_paths = Paths()

        # temporary, it will be replaced later by an array of Paths
        endloop = Paths()

        # ------------------------------------------------------
        # Separation of loop-paths / endloops
        # ------------------------------------------------------

        for k, p in self.paths.items():
            keep, ignore =  self.__keep_path(curr_loop_idx, p, k)
            if not ignore:
                if keep:
                    loop_paths.add(k, p, self.__get_loop_idx(k))
                else:
                    endloop.add(k, p, self.__get_loop_idx(k))

        # Finalize endloops
        # Cut the path to get only the endloop
        for k, el in endloop.paths.items():
            for i, addr in enumerate(el):
                if addr not in loop_paths:
                    p = el[i:]
                    if not p in endloop.paths.values():
                        endloop.paths[k] = p
                    else:
                        endloop.paths[k] = []
                    break

        endloop.rm_empty_paths()


        # ------------------------------------------------------
        # Remove dupplicate code
        # ------------------------------------------------------

        common = {}

        # Search dupplicate address
        for k1, p in endloop.paths.items():
            for addr in p:
                for k2, el in endloop.paths.items():
                    if el[0] == p[0]:
                        continue
                    idx = index(el, addr)
                    if idx != -1:
                        common[addr] = True
                        break

        for dup in common:
            for k, el in endloop.paths.items():
                if el[0] == dup:
                    continue
                idx = index(el, dup)
                if idx != -1:
                    endloop.paths[k] = el[:idx]
                    if idx != len(el)-1 and k in self.looping:
                        del endloop.looping[k]

        endloop.rm_empty_paths()


        # ------------------------------------------------------
        # Regroup paths if they start with the same addr
        # ------------------------------------------------------

        grp_endloop = []
        seen = {}

        for k, el in endloop.paths.items():
            try:
                idx = seen[el[0]]
                grp_endloop[idx].add(k, el, endloop.__get_loop_idx(k))
            except:
                seen[el[0]] = len(grp_endloop) # save index
                p = Paths()
                p.add(k, el, endloop.__get_loop_idx(k))
                grp_endloop.append(p)


        # ------------------------------------------------------
        # Sort endloops
        # ------------------------------------------------------

        with_jump = []
        no_jump = {}
            
        # Search the next address of each endloops
        for i, els in enumerate(grp_endloop):
            all_jmp = True

            for k, el in els.paths.items():
                queue = el[-1]
                inst = gph.nodes[queue][0]
                if not is_uncond_jump(inst):
                    try:
                        # TODO
                        # is it possible to have a conditional jump here ?
                        # if true, need to check BRANCH_NEXT_JUMP
                        no_jump[i] = gph.link_out[queue][BRANCH_NEXT]
                    except:
                        no_jump[i] = -1
                    all_jmp = False

            if all_jmp:
                with_jump.append(i)

        # paths which not finish with a jump need to be sorted
        # contains idx in grp_endloop
        endloop_sort = []
        while no_jump:
            for i in no_jump:
                nxt = no_jump[i]
                if nxt == -1 or nxt not in no_jump:
                    endloop_sort.insert(0, i) 
                    del no_jump[i]
                    break

        # Recreate endloop
        new_grp_endloop = []
        for i in with_jump:
            new_grp_endloop.append(grp_endloop[i])
            
        for i in endloop_sort:
            new_grp_endloop.append(grp_endloop[i])

        return loop_paths, new_grp_endloop
