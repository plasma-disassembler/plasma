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


# WORK IN PROGRESS


from lib.utils import *

gph = None



def get_loop_start(curr_loop_idx):
    if not curr_loop_idx:
        return -1
    return gph.loops[curr_loop_idx[0]][0]


# TODO remove
def loop_contains(loop_start, addr):
    if loop_start == -1:
        return True
    for l in gph.loops:
        if l[0] == loop_start and addr in l:
            return True
    return False



# TODO remove
# Returns all loops starting with addr
def loop_exists_idx(addr):
    idx = []
    i = 0
    for l in gph.loops:
        if l[0] == addr:
            idx.append(i)
        i += 1
    return idx



# TODO remove
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
        self.looping = {}  # idx_path -> idx_loop
        self.paths = []


    def __contains__(self, addr):
        for p in self.paths:
            if addr in p:
                return True
        return False


    def contains_list(self, lst):
        for addr in lst:
            if addr not in self:
                return False
        return True


    def __is_in_curr_loop(self, loop, cond):
        # Assume that current paths is a loop

        curr_loop = self.first()

        if loop[0] != curr_loop:
            if cond:
                print("    false 1")
            return False

        # Check if all address of loop are in paths
        for addr in loop:
            if addr not in self:
                if cond:
                    print("    false 2")
                return False

        # Check if the loop is in the right order
        for p in self.paths:
            last_idx = -1
            for addr in loop:
                idx = index(p, addr)
                if idx == -1:
                    break
                    last_idx = 99999999
                elif idx < last_idx:
                    if cond:
                        print("    false 3")
                    return False
                else:
                  last_idx = idx

        if cond:
            print("    true 1")
        return True


    def get_loops_idx(self):
        # TODO cleanup
        idx = []
        cond = self.first() == 0x400530 and 0

        if cond:
            print_list(self.paths)
            print_dict(self.looping)
            print()

        for k, l in enumerate(gph.loops):
            if cond:
                print("check  %d  " % k, end="")
                print_list(l)
            if self.__is_in_curr_loop(l, cond):
                idx.append(k)

        if cond:
            print()
            print(idx)
            sys.exit(0)

        return idx


    def debug(self):
        debug__("\npaths :", end="")
        debug__(self.paths)
        debug__("looping :", end="")
        debug__(self.looping)


    def __is_looping(self, path_idx, curr_loop_idx):
        # TODO
        # print(" ####   %d   " % path_idx, end="")
        # print_list(self.paths[path_idx])
        if path_idx not in self.looping:
            # print(" ####   false 1")
            return False
        l_idx = self.looping[path_idx]
        # If is a loop but on the current, return False and  keep the path
        if l_idx not in curr_loop_idx :
            # print(" ####   true 1")
            return True
        # print(" ####   false 2")
        return False


    def __enter_new_loop(self, curr_loop_idx, path_idx, k):
        addr = self.paths[path_idx][k]

        if path_idx not in self.looping:
            return False, False
            
        l_idx = self.looping[path_idx]

        # if l_idx in gph.marked and l_idx in gph.equiv and gph.equiv[l_idx] not in curr_loop_idx and addr == gph.loops[l_idx][0]:
            # return False, True

        if addr != gph.loops[l_idx][0]:
            return False, False

        return True, False


    def are_all_looping(self, start, check_equal, curr_loop_idx):
        # TODO check len looping == len paths ?
        if check_equal:
            i = 0
            for p in self.paths:
                if p[0] == start and not self.__is_looping(i, curr_loop_idx):
                    return False
                i += 1
        else:
            i = 0
            for p in self.paths:
                if p[0] != start and not self.__is_looping(i, curr_loop_idx):
                    return False
                i += 1
        return True


    def add(self, new_path, loop_idx=-1):
        idx_new_path = len(self.paths)
        self.paths.append(new_path)
        if loop_idx != -1:
            self.looping[idx_new_path] = loop_idx


    def __get_loop_idx(self, k):
        return self.looping.get(k, -1)


    def pop(self):
        # Assume that all paths pop the same value
        for p in self.paths:
            val = p.pop(0)
        return val


    # TODO optimize suppression
    def __del_path(self, i):
        del self.paths[i]

        new = {}
        for k in self.looping:
            if k != i:
                if k > i:
                    new[k-1] = self.looping[k]
                else:
                    new[k] = self.looping[k]

        del self.looping
        self.looping = new


    def rm_empty_paths(self):
        i = len(self.paths) - 1
        while i >= 0:
            if not self.paths[i]:
                self.__del_path(i)
            i -= 1
        return len(self.paths) == 0


    def __longuest_path_idx(self):
        idx = 0
        max_len = len(self.paths[0])
        for k, p in enumerate(self.paths):
            if len(p) > max_len:
                max_len = len(p)
                idx = k
        return idx


    # The second value returned indicates if we have stop on a loop.
    # Stop on :
    # - first difference (ifelse), but not on jumps which are 
    #     conditions for loops
    # - beginning of a loop
    #
    # Returns :
    # until_address, is_loop, is_ifelse 
    #
    def head_last_common(self, curr_loop_idx):
        # The path used as a reference (each value of this path is
        # compared all others paths). We need the longest, otherwise
        # if we have a too smal path, we can stop too early.
        # tests/nestedloop3
        refpath = self.__longuest_path_idx()

        last = -1
        k = 0
        while k < len(self.paths[refpath]):

            addr0 = self.paths[refpath][k]

            is_loop, force_stop = self.__enter_new_loop(curr_loop_idx, refpath, k)
            if is_loop or force_stop:
                return last, is_loop, False, force_stop

            # Check addr0
            if is_cond_jump(gph.nodes[addr0][0]):
                nxt = gph.link_out[addr0]
                c1 = self.loop_contains(curr_loop_idx, nxt[BRANCH_NEXT])
                c2 = self.loop_contains(curr_loop_idx, nxt[BRANCH_NEXT_JUMP])
                # TODO
                # debug__("0_____ %x  %x  %d  %d" % (nxt[BRANCH_NEXT], nxt[BRANCH_NEXT_JUMP], c1, c2))
                if c1 and c2:
                    return last, False, True, False


            # Compare with other paths
            i = 0
            while i < len(self.paths):
                if i == refpath:
                    i += 1
                    continue

                if index(self.paths[i], addr0) == -1:
                    return last, False, False, False

                addr = self.paths[i][k]

                is_loop, force_stop = self.__enter_new_loop(curr_loop_idx, i, k)
                if is_loop or force_stop:
                    return last, is_loop, False, force_stop


                if is_cond_jump(gph.nodes[addr][0]):
                    nxt = gph.link_out[addr]
                    c1 = self.loop_contains(curr_loop_idx, nxt[BRANCH_NEXT])
                    c2 = self.loop_contains(curr_loop_idx, nxt[BRANCH_NEXT_JUMP])
                    # TODO
                    # debug__("1_____ %x  %x  %d  %d" % (nxt[BRANCH_NEXT], nxt[BRANCH_NEXT_JUMP], c1, c2))
                    if c1 and c2:
                        return last, False, True, False

                i += 1

            k += 1
            last = addr0

        # We have to test here, because we can stop before with a loop
        # or a ifelse.
        if len(self.paths) == 1:
            return self.paths[0][-1], False, False, False

        return last, False, False, False


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
        debug__("all looping : if %d   else %d" % (all_looping_if, all_looping_else))

        if all_looping_if or all_looping_else:
            return else_addr

        # Take a non looping-path as a reference :
        # we want to search a common address between other paths
        refpath = 0
        i = 0
        while i < len(self.paths):
            if not self.__is_looping(i, curr_loop_idx):
                refpath = i
                break
            i += 1

        # Compare

        debug__("refpath %d" % refpath)
        debug__(self.paths[refpath])
        debug__(curr_loop_idx)

        found = False
        k = 0
        val = -1
        while not found and k < len(self.paths[refpath]):
            val = self.paths[refpath][k]
            i = 0
            found = True
            while i < len(self.paths):
                if i != refpath:
                    if not self.__is_looping(i, curr_loop_idx):
                        if index(self.paths[i], val) == -1:
                            found = False
                            break
                i += 1
            k += 1

        if found:
            return val
        return -1


    def split(self, ifaddr, endpoint):
        nxt = gph.link_out[ifaddr]
        split = [Paths(), Paths()]
        else_addr = -1
        for k, p in enumerate(self.paths):
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
                    split[br].add(p, self.__get_loop_idx(k))
                else:
                    split[br].add(p[:idx])
        # debug__("split: ", end="")
        # debug__(split)
        debug__("else addr %x" % else_addr)
        return split, else_addr


    def goto_addr(self, addr):
        debug__("goto endpoint %x" % addr)
        i = 0
        while i < len(self.paths):
            idx = index(self.paths[i], addr)
            self.paths[i] = [] if idx == -1 else self.paths[i][idx:]
            i += 1


    def first(self):
        return self.paths[0][0]


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
    def __keep_path(self, curr_loop_idx, path, path_idx):
        last = path[-1]

        # debug__("curr %x   last  %x     " % (get_loop_start(curr_loop_idx), last), end="")
        # debug__(path)

        # if path_idx in self.looping:
            # l_idx = self.looping[path_idx]
            # if l_idx in curr_loop_idx or 

        if self.loop_contains(curr_loop_idx, last):
            debug__("     true 1")
            return True

        if path_idx not in self.looping:
            debug__("     false 1")
            return False

        l_idx = self.looping[path_idx]

        if l_idx in curr_loop_idx:
            return True

        for i in curr_loop_idx:
            if l_idx in gph.nested_loops_idx[i]:
                return True

        return False


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

        for k, p in enumerate(self.paths):
            is_in_curr = False
            if self.__keep_path(curr_loop_idx, p, k):
                loop_paths.add(p, self.__get_loop_idx(k))
                is_in_curr = True
            if not is_in_curr:
                endloop.add(p, self.__get_loop_idx(k))

        # Finalize endloops
        # Cut the path to get only the endloop
        for i, el in enumerate(endloop.paths):
            for k, addr in enumerate(el):
                if addr not in loop_paths:
                    p = el[k:]
                    if p not in endloop.paths:
                        endloop.paths[i] = p
                    else:
                        endloop.paths[i] = []
                    break

        endloop.rm_empty_paths()


        # ------------------------------------------------------
        # Remove dupplicate code
        # ------------------------------------------------------

        common = {}

        # Search dupplicate address
        for p in endloop.paths:
            for addr in p:
                for el in endloop.paths:
                    if el[0] == p[0]:
                        continue
                    idx = index(el, addr)
                    if idx != -1:
                        common[addr] = True
                        break

        for dup in common:
            for i, el in enumerate(endloop.paths):
                if el[0] == dup:
                    continue
                idx = index(el, dup)
                if idx != -1:
                    endloop.paths[i] = el[:idx]
                    if idx != len(el)-1 and i in self.looping:
                        del endloop.looping[i]

        endloop.rm_empty_paths()


        # ------------------------------------------------------
        # Regroup paths if they start with the same addr
        # ------------------------------------------------------

        grp_endloop = []
        seen = {}

        for k, el in enumerate(endloop.paths):
            try:
                idx = seen[el[0]]
                grp_endloop[idx].add(el, endloop.__get_loop_idx(k))
            except:
                seen[el[0]] = len(grp_endloop) # save index
                p = Paths()
                p.add(el, endloop.__get_loop_idx(k))
                grp_endloop.append(p)


        # ------------------------------------------------------
        # Sort endloops
        # ------------------------------------------------------

        with_jump = []
        no_jump = {}
            
        # Search the next address of each endloops
        for i, els in enumerate(grp_endloop):
            all_jmp = True

            for el in els.paths:
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
        endloop_sort = []
        while no_jump:
            for i in no_jump:
                nxt = no_jump[i]
                if nxt == -1 or nxt not in no_jump:
                    endloop_sort.insert(0, i) 
                    del no_jump[i]
                    break

        # Recreate endloop
        new_endloop = []
        for i in with_jump:
            new_endloop.append(grp_endloop[i])
            
        for i in endloop_sort:
            new_endloop.append(grp_endloop[i])

        grp_endloop = new_endloop

        # TODO
        debug__("loop paths: ", end="")
        loop_paths.debug()
        debug__("endloop: ", end="")
        for el in grp_endloop:
            el.debug()

        return loop_paths, grp_endloop
