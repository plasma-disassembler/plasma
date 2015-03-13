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

import sys
from lib.ast import *
from lib.utils import *


gph = None
dbg = False


def debug__(obj, end="\n"):
    if dbg:
        if isinstance(obj, str):
            print(obj, end=end)
        elif isinstance(obj, list):
            print_list(obj)
        elif isinstance(obj, dict):
            print_dict(obj)


def loop_start_by(addr):
    # normally addr != -1
    # nested_loops[-1] contains all sub-loops
    return addr in gph.nested_loops
    # for l in gph.loops:
        # if addr == l[0]:
            # return True
    # return False


def loop_contains(loop_start, addr):
    if loop_start == -1:
        return True
    for l in gph.loops:
        if l[0] == loop_start and addr in l:
            return True
    return False


# Returns all paths
def paths_explore(start_addr):
    def save_step(k, addr, create):
        nonlocal paths, looping, new_paths, moved
        # Prevent looping on seen node : the branch will be deleted later.
        if addr in paths[k]:
            if create:
                # Future path
                looping[len(paths) + len(new_paths)] = True
                new_paths.append(list(paths[k]))
            else:
                looping[k] = True
            return
        moved = True
        if create:
            new_paths.append(paths[k] + [addr])
        else:
            paths[k].append(addr)

    # Compute all paths to the end
    paths = [[start_addr]]
    moved = True
    looping = {}

    while moved:
        new_paths = []
        moved = False

        # Next step for each branch
        # - Looping branchs will be deleted
        # - Create a new branch if we are on cond jump
        #     only if it doesn't go outside the current loop
        for k, p in enumerate(paths):
            addr = p[-1]
            inst = gph.dis.code[addr]

            # The branch is finish or is looping
            if k in looping or addr not in gph.link_out:
                continue

            nxt = gph.link_out[addr]
            if is_cond_jump(inst):
                save_step(k, nxt[BRANCH_NEXT_JUMP], True)
            save_step(k, nxt[BRANCH_NEXT], False)

        paths += new_paths

    return paths


# Stop on first difference (ifelse)
# def head_last_common_simple(paths):
    # if len(paths) == 1:
        # return paths[0][-1]
    # k = 0
    # common = True
    # last = -1
    # while common and k < len(paths[0]):
        # addr = paths[0][k]
        # i = 1
        # while i < len(paths):
            # if index(paths[i], addr) == -1:
                # common = False
                # break
            # i += 1
        # k += 1
        # if common:
            # last = addr
    # return last


# The second value returned indicates if we have stop on a loop.
# Stop on :
# - first difference (ifelse), but not on jumps which are 
#     conditions for loops
# - beginning of a loop
def head_last_common(paths, curr_loop):
    last = -1

    # The path used as a reference (each value of this path is
    # compared all others paths). We need the longest, otherwise
    # if we have a too smal path, we can stop too early.
    # tests/nestedloop3
    refpath = 0
    max_len = len(paths[0])
    for k, p in enumerate(paths):
        if len(p) > max_len:
            max_len = len(p)
            refpath = k

    k = 0
    while k < len(paths[refpath]):

        addr0 = paths[refpath][k]

        # TODO cleanup

        # Check addr0
        if is_cond_jump(gph.nodes[addr0][0]):
            nxt = gph.link_out[addr0]
            c1 = loop_contains(curr_loop, nxt[BRANCH_NEXT])
            c2 = loop_contains(curr_loop, nxt[BRANCH_NEXT_JUMP])
            if c1 and c2:
                return last, False, True

        if loop_start_by(addr0):
            return last, True, False

        # Compare with other paths
        i = 0
        while i < len(paths):
            if i == refpath:
                i += 1
                continue

            if index(paths[i], addr0) == -1:
                return last, False, False

            addr = paths[i][k]
            if is_cond_jump(gph.nodes[addr][0]):
                nxt = gph.link_out[addr]
                c1 = loop_contains(curr_loop, nxt[BRANCH_NEXT])
                c2 = loop_contains(curr_loop, nxt[BRANCH_NEXT_JUMP])
                if c1 and c2:
                    return last, False, True

            if loop_start_by(addr):
                return last, True, False

            i += 1

        k += 1
        last = addr0

    if len(paths) == 1:
        return paths[0][-1], False, False

    return last, False, False


# Return True if the path is looping (it means that the next of the
# last address is a loop)
# 
# If curr_loop is given :
#       if the path is looping on the current loop, return False
#       tests/if3
def is_looping(path, curr_loop=None):
    last = path[-1]
    if last not in gph.link_out:
        return False
    
    nxt = gph.link_out[last]

    if not loop_start_by(nxt[BRANCH_NEXT]):
        return False

    if nxt[BRANCH_NEXT] == curr_loop:
        return False

    if len(nxt) == 2:
        if not loop_start_by(nxt[BRANCH_NEXT_JUMP]):
            return False

        if nxt[BRANCH_NEXT_JUMP] == curr_loop:
            return False

    return True


def are_all_looping(paths, curr_loop, start, check_equal):
    if check_equal:
        for p in paths:
            if p[0] == start and not is_looping(p, curr_loop):
                return False
    else:
        for p in paths:
            if p[0] != start and not is_looping(p, curr_loop):
                return False
    return True


def first_common(paths, curr_loop, else_addr, start=0):
    if len(paths) <= 1:
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

    all_looping_if = are_all_looping(paths, curr_loop, else_addr, True)
    all_looping_else = are_all_looping(paths, curr_loop, else_addr, False)

    if all_looping_if or all_looping_else:
        debug__("all looping : if %d   else %d" % (all_looping_if, all_looping_else))
        return else_addr


    found = False
    k = start
    val = -1
    while not found and k < len(paths[0]):
        val = paths[0][k]
        i = 0
        found = True
        while i < len(paths):
            if not is_looping(paths[i], curr_loop):
                if index(paths[i], val, start) == -1:
                    found = False
                    break
            i += 1
        k += 1

    if found:
        return val
    return -1


# For a loop : check if the path need to be kept (the loop 
# contains the path). For this we see the last address of the path.
def keep_path(curr_loop, path):
    addr = path[-1]

    if addr not in gph.link_out:
        return False 

    nxt = gph.link_out[addr]

    # may be a nested or current loop
    n = nxt[BRANCH_NEXT]
    if loop_start_by(n):
        if loop_contains(curr_loop, n) or loop_contains(curr_loop, addr):
            return True

    if len(nxt) == 1:
        return False

    n = nxt[BRANCH_NEXT_JUMP]
    if loop_start_by(n):
        if loop_contains(curr_loop, n) or loop_contains(curr_loop, addr):
            return True

    return False


def extract_loop_paths(paths):
    # TODO optimize....

    loop_paths = []
    endloop = []
    curr_loop = paths[0][0]

    # ------------------------------------------------------
    # Separation of loop-paths / endloops
    # ------------------------------------------------------

    for p in paths:
        looping = False
        if keep_path(curr_loop, p):
            loop_paths.append(p)
            looping = True
        if not looping:
            endloop.append(p)

    # Finalize endloops
    # Cut the path to get only the endloop
    for i, el in enumerate(endloop):
        for k, addr in enumerate(el):
            if not is_in_paths(loop_paths, addr):
                p = el[k:]
                if p not in endloop:
                    endloop[i] = p
                else:
                    endloop[i] = []
                break

    rm_empty_paths(endloop)


    # ------------------------------------------------------
    # Remove dupplicate code
    # ------------------------------------------------------

    common = {}

    # Search dupplicate address
    for path in endloop:
        for addr in path:
            for el in endloop:
                if el[0] == path[0]:
                    continue
                idx = index(el, addr)
                if idx != -1:
                    common[addr] = True
                    break

    for dup in common:
        for i, el in enumerate(endloop):
            if el[0] == dup:
                continue
            idx = index(el, dup)
            if idx != -1:
                endloop[i] = el[:idx]

    rm_empty_paths(endloop)


    # ------------------------------------------------------
    # Regroup paths if they start with the same addr
    # ------------------------------------------------------

    group_endloop = []
    seen = {}

    for el in endloop:
        try:
            idx = seen[el[0]]
            group_endloop[idx].append(el)
        except:
            seen[el[0]] = len(group_endloop)
            group_endloop.append([el])

    endloop = group_endloop


    # ------------------------------------------------------
    # Sort endloops
    # ------------------------------------------------------

    with_jump = []
    no_jump = {}
        
    # Search the next address of each endloops
    for i, els in enumerate(endloop):
        all_jmp = True

        for el in els:
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

    # print("no jump ", end=""); print_dict(no_jump)
    # print("with jump ", end=""); print_list(with_jump)

    # paths which not finish with a jump need to be sorted
    endloop_sort = []
    while no_jump:
        for i in no_jump:
            head = endloop[i][0]
            nxt = no_jump[i]
            if nxt == -1 or nxt not in no_jump:
                endloop_sort.insert(0, i) 
                del no_jump[i]
                break

    # print_list(endloop_sort)

    # Recreate endloop
    new_endloop = []
    for i in with_jump:
        new_endloop.append(endloop[i])
        
    for i in endloop_sort:
        new_endloop.append(endloop[i])

    endloop = new_endloop
    # print_list(endloop)

    debug__("loop paths: ", end="")
    debug__(loop_paths)
    debug__("endloop: ", end="")
    debug__(endloop)

    return loop_paths, endloop


def is_in_paths(paths, addr):
    for p in paths:
        if index(p, addr) != -1:
            return True
    return False


def get_index_path(paths, addr):
    for k, p in enumerate(paths):
        if index(p, addr) != -1:
            return k
    return -1


def pop(paths):
    # Assume that all paths pop the same value
    for p in paths:
        val = p.pop(0)
    return val


def paths_goto_addr(paths, addr):
    debug__("goto endpoint %x" % addr)
    i = 0
    while i < len(paths):
        idx = index(paths[i], addr)
        paths[i] = [] if idx == -1 else paths[i][idx:]
        i += 1


def rm_empty_paths(paths):
    for i in reversed(range(len(paths))):
        if not paths[i]:
            del paths[i]


def cut_paths(paths, start, end):
    cut = []
    for p in paths:
        if not p:
            continue
        idx_s = index(p, start)
        if idx_s != -1:
            idx_e = index(p, end)
            if idx_e != -1:
                cut.append(p[idx_s:idx_e-1])
            else:
                cut.append(p[idx_s:])
    return cut


def get_ast_branch(paths, curr_loop=-1, last_else=-1):
    ast = Ast_Branch()

    while 1:
        rm_empty_paths(paths)
        if not paths:
            break

        debug__("\nbranch %x     loop=%x" % (paths[0][0], curr_loop))
        debug__("nb paths %d" % len(paths))
        debug__(paths)

        # Stop on the first split or is_loop
        until, is_loop, is_ifelse = head_last_common(paths, curr_loop)
        debug__("until %x   loop=%d   ifelse=%d" % (until, is_loop, is_ifelse))

        # Add code to the branch, and update paths
        # until == -1 if there is no common point at the begining
        last = -1
        while last != until:
            blk = gph.nodes[paths[0][0]]
            inst = blk[0] # first inst

            # Here if we have conditional jump, it's not a ifelse,
            # it's a condition for a loop. It will be replaced by a
            # goto. ifgoto are skipped by head_last_common.
            if is_cond_jump(inst):
                nxt = gph.link_out[inst.address]
                c1 = loop_contains(curr_loop, nxt[BRANCH_NEXT])
                c2 = loop_contains(curr_loop, nxt[BRANCH_NEXT_JUMP])
                if c1 and c2:
                    die("can't have a ifelse here     %x" % inst.address)

                # If the address of the jump is inside the loop, we
                # invert the conditions. example :
                #
                # jmp conditions
                # loop:
                #    code ...
                # conditions:
                #    cmp ...
                #    jg endloop
                #    cmp ...
                #    jne loop
                # endloop:
                #
                # Here the last jump point inside the loop. We want to
                # replace by this : 
                #
                # loop {
                #    cmp ...
                #    jg endloop
                #    cmp ...
                #    je endloop
                #    code ...
                # } # here there is an implicit jmp to loop
                # endloop:
                #
                cond_id = inst.id
                if c2:
                    (nxt[BRANCH_NEXT], nxt[BRANCH_NEXT_JUMP]) = \
                        (nxt[BRANCH_NEXT_JUMP], nxt[BRANCH_NEXT])
                    cond_id = invert_cond(cond_id)
                ast.add(Ast_IfGoto(inst, cond_id, nxt[BRANCH_NEXT_JUMP]))
            else:
                ast.add(blk)

            last = pop(paths)

        rm_empty_paths(paths)
        if not paths:
            break

        if is_loop:
            a, endpoint = get_ast_loop(paths, curr_loop, last_else)
            ast.add(a)
        elif is_ifelse:
            a, endpoint = get_ast_ifelse(paths, curr_loop, last_else)
            ast.add(a)
        else:
            endpoint = paths[0][0]

        if endpoint == -1:
            break

        paths_goto_addr(paths, endpoint)

    return ast


# Assume that the beginning of paths is the beginning of a loop
def paths_is_infinite(paths):
    for p in paths:
        for addr in p:
            inst = gph.nodes[addr][0]
            if is_cond_jump(inst):
                nxt = gph.link_out[addr]
                if not is_in_paths(paths, nxt[BRANCH_NEXT]) \
                or not is_in_paths(paths, nxt[BRANCH_NEXT_JUMP]):
                    return False
    return True


def get_ast_loop(paths, last_loop, last_else):
    debug__("\nloop %x" % paths[0][0])
    debug__(paths)
    ast = Ast_Loop()
    curr_loop = paths[0][0]
    ast.add(gph.nodes[curr_loop])
    loop_paths, endloop = extract_loop_paths(paths)

    # Checking if endloop == [] to determine if it's an 
    # infinite loop is not sufficient
    # tests/nestedloop2
    ast.set_infinite(paths_is_infinite(loop_paths))

    pop(paths)
    ast.add(get_ast_branch(loop_paths, curr_loop, last_else))

    if not endloop:
        return ast, -1

    epilog = Ast_Branch()
    if len(endloop) > 1:
        epilog.add(Ast_Comment("warning not sure multi endloop is correct !!"))
        i = 1
        for el in endloop[:-1]:
            epilog.add(Ast_Comment("endloop " + str(i)))
            debug__("\nendloop " + str(i))
            epilog.add(get_ast_branch(el, last_loop, last_else))
            i += 1
        epilog.add(Ast_Comment("endloop " + str(i)))

        ast.set_epilog(epilog)

    return ast, endloop[-1][0][0]


def get_ast_ifelse(paths, curr_loop, last_else):
    debug__("\nifelse %x" % paths[0][0])
    debug__("last else %x" % last_else)
    addr = pop(paths)
    rm_empty_paths(paths)
    debug__(paths)
    jump_inst = gph.nodes[addr][0]
    nxt = gph.link_out[addr]

    if_addr = nxt[BRANCH_NEXT]
    else_addr = nxt[BRANCH_NEXT_JUMP] if len(nxt) == 2 else -1

    # If endpoint == -1, it means we are in a sub-if and the endpoint 
    # is after. When we create_split, only address inside current
    # if and else are kept.
    endpoint = first_common(paths, curr_loop, else_addr)
    debug__("endpoint %x" % endpoint)
    split, else_addr = create_split(addr, paths, endpoint)


    # last_else allows to not repeat the else part when there are some 
    # and in the If. example :
    #
    # if (i > 0 && i == 1) {
    #     part 1
    # } else {
    #     part 2
    # }
    #
    #
    # output without this "optimization" :
    #
    # ...
    # if > {
    #     ...
    #     if == {
    #         part 1
    #     } else != {
    #         part 2
    #     }
    # } else <= {
    #     part 2
    # }
    # 
    #
    # output with "optimization" :
    #
    # ...
    # if > {
    #     ...
    #     and if ==    means that if the condition is false, goto else
    #     part 1
    # } else <= {
    #     part 2
    # }
    #

    if last_else != -1:
        # TODO not sure about endpoint == -1
        # tests/or4
        if if_addr == last_else and endpoint == -1:
            return (Ast_AndIf(jump_inst, jump_inst.id), else_addr)

        if else_addr == -1 or else_addr == last_else:
            endpoint = gph.link_out[addr][BRANCH_NEXT]
            return (Ast_AndIf(jump_inst, invert_cond(jump_inst.id)), endpoint)

    if else_addr == -1:
        else_addr = last_else

    a1 = get_ast_branch(split[BRANCH_NEXT_JUMP], curr_loop, -1)
    a2 = get_ast_branch(split[BRANCH_NEXT], curr_loop, else_addr)

    return (Ast_Ifelse(jump_inst, a1, a2), endpoint)


def create_split(ifaddr, paths, endpoint):
    nxt = gph.link_out[ifaddr]
    split = [[], []]
    else_addr = -1
    for p in paths:
        if p:
            if p[0] == nxt[BRANCH_NEXT]:
                k = BRANCH_NEXT
            else:
                k = BRANCH_NEXT_JUMP
                else_addr = nxt[BRANCH_NEXT_JUMP]
            # idx == -1 means :
            # - p is looping so there is no endpoint with some other paths
            # - endpoint == -1
            idx = index(p, endpoint)
            if idx == -1:
                split[k].append(p)
            else:
                split[k].append(p[:idx])
    debug__("split: ", end="")
    debug__(split)
    debug__("else addr %x" % else_addr)
    return split, else_addr


def generate_ast(graph, debug):
    global gph, dbg
    gph = graph
    dbg = debug
    paths = paths_explore(gph.entry_point_addr)
    debug__(paths)
    return get_ast_branch(paths)
