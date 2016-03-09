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

import sys
from time import time

from plasma.lib.ast import (Ast_Branch, Ast_Goto, Ast_Loop, Ast_If_cond,
                            Ast_IfGoto, Ast_Ifelse, Ast_AndIf, Ast_Comment)
from plasma.lib.utils import BRANCH_NEXT, BRANCH_NEXT_JUMP, debug__
from plasma.lib.exceptions import ExcIfelse
from plasma.lib.colors import pick_color


class Endpoint():
    def __init__(self, ast, unseen, l_start):
        self.ast = [ast]
        self.unseen = unseen
        self.loop_start = [l_start]

    def rendezvous(self, ast, prev, l_start):
        self.ast.append(ast)
        self.loop_start.append(l_start)
        if prev in self.unseen:
            self.unseen.remove(prev)


def assign_colors(libarch, ctx, ast):
    if isinstance(ast, Ast_Branch):
        for n in ast.nodes:
            if isinstance(n, list):
                if libarch.utils.is_uncond_jump(n[0]) and \
                        n[0].operands[0].type == libarch.utils.OP_IMM and \
                        n[0].address in ctx.gph.link_out:
                    nxt = ctx.gph.link_out[n[0].address][BRANCH_NEXT]
                    pick_color(nxt)
            else: # ast
                assign_colors(libarch, ctx, n)

    elif isinstance(ast, Ast_IfGoto) or isinstance(ast, Ast_Goto):
        pick_color(ast.addr_jump)

    elif isinstance(ast, Ast_Ifelse):
        assign_colors(libarch, ctx, ast.br_next_jump)
        assign_colors(libarch, ctx, ast.br_next)

    elif isinstance(ast, Ast_Loop):
        assign_colors(libarch, ctx, ast.branch)



def get_first_addr(ast):
    # Assume that there are no Ast_Comment

    if isinstance(ast, list):
        return ast[0].address

    if isinstance(ast, Ast_Branch):
        if len(ast.nodes) > 0:
            return get_first_addr(ast.nodes[0])

    if isinstance(ast, Ast_Ifelse):
        # Any instructions at the moment so we can use the jump inst
        return ast.jump_inst.address

    if isinstance(ast, Ast_Loop):
        if len(ast.branch.nodes) > 0:
            return get_first_addr(ast.branch.nodes[0])

    if isinstance(ast, Ast_Goto):
        return ast.addr_jump

    if isinstance(ast, Ast_IfGoto):
        return ast.orig_jump.address

    if isinstance(ast, Ast_AndIf):
        return ast.orig_jump.address

    if isinstance(ast, Ast_If_cond):
        if len(ast.br.nodes) > 0:
            return get_first_addr(ast.br.nodes[0])

    return -1


def get_next_addr(ast):
    par = ast.parent
    if par is None:
        return -1
    i = ast.idx_in_parent + 1

    # Get the next address of the parent ast
    if i == len(par.nodes):
        return get_next_addr(par)

    return get_first_addr(par.nodes[i])


# Returns the first address of the current loop only if the i th ast
# is the last in the parent ast.
def is_last_in_loop(ast, i):
    par = ast.parent
    if par is None:
        return -1

    is_last = i == len(ast.nodes) - 1
    a = ast.parent.nodes[ast.idx_in_parent]
    if isinstance(a, Ast_Loop) and is_last:
        return get_first_addr(a)

    if not is_last:
        return -1

    return is_last_in_loop(par, ast.idx_in_parent)


def remove_all_unnecessary_goto(ast):
    if isinstance(ast, Ast_Branch):
        # Remove all last Ast_Goto, only if the previous is not an andif
        if len(ast.nodes) > 0 and isinstance(ast.nodes[-1], Ast_Goto):
            if len(ast.nodes) <= 1 or not isinstance(ast.nodes[-2], Ast_AndIf):
                if not ast.nodes[-1].dont_remove:
                    nxt = get_next_addr(ast)
                    if ast.nodes[-1].addr_jump == nxt:
                        del ast.nodes[-1]

        for n in ast.nodes:
            if not isinstance(n, list):
                remove_all_unnecessary_goto(n)

    elif isinstance(ast, Ast_Ifelse):
        remove_all_unnecessary_goto(ast.br_next)
        remove_all_unnecessary_goto(ast.br_next_jump)

    elif isinstance(ast, Ast_Loop):
        if isinstance(ast.branch.nodes[-1], Ast_Goto):
            if get_first_addr(ast) == ast.branch.nodes[-1].addr_jump:
                del ast.branch.nodes[-1]
        remove_all_unnecessary_goto(ast.branch)


def fix_non_consecutives(ctx, ast):
    if isinstance(ast, Ast_Branch):
        idx_to_add = {}

        for i, n in enumerate(ast.nodes):
            if isinstance(n, list):
                ad = n[0].address
                if ad in ctx.gph.uncond_jumps_set or ad not in ctx.gph.link_out:
                    continue

                nxt1 = ctx.gph.link_out[ad][BRANCH_NEXT]

                if i == len(ast.nodes) - 1:
                    loop_start = is_last_in_loop(ast, i)
                    if loop_start != -1:
                        if nxt1 != loop_start:
                            idx_to_add[i + 1] = nxt1
                        continue
                    nxt2 = get_next_addr(ast)
                else:
                    nxt2 = get_first_addr(ast.nodes[i + 1])

                if nxt1 != nxt2:
                    idx_to_add[i + 1] = nxt1
            else:
                fix_non_consecutives(ctx, n)

        if not idx_to_add:
            return

        # Add from the end of the nodes list
        lst = list(idx_to_add.keys())
        lst.sort()
        for i in reversed(lst):
            ast.nodes.insert(i, Ast_Goto(idx_to_add[i]))

    elif isinstance(ast, Ast_Ifelse):
        fix_non_consecutives(ctx, ast.br_next)
        fix_non_consecutives(ctx, ast.br_next_jump)

    elif isinstance(ast, Ast_Loop):
        fix_non_consecutives(ctx, ast.branch)


def search_endpoint(ctx, stack, ast, entry, l_set, l_prev_loop, l_start):
    endp = __search_endpoint(ctx, stack, ast, entry, l_set, l_prev_loop, l_start)

    if endp == -1:
        return -1

    # Check if we found an endpoint in a subloop : for a "if" it's not possible
    # that the end goes in a loop, so we return -1 if this is the case.

    if l_prev_loop == -1:
        l = ctx.gph.not_in_loop
    else:
        # l_set contains also subloops, here we just want the current loop
        l = ctx.gph.loops_set[(l_prev_loop, l_start)]

    if endp not in l:
        return -1

    return endp


def __search_endpoint(ctx, stack, ast, entry, l_set, l_prev_loop, l_start):
    waiting = {}
    visited = set()
    done = set()

    stack = []
    for n in ctx.gph.link_out[entry]:
        stack.append((entry, n))

    while 1:
        while stack:
            prev, ad = stack.pop(-1)

            # Don't go outside the current loop : we want to search
            # an if-endpoint.
            if l_prev_loop != -1 and ad not in l_set:
                continue

            # If "ad" is in last_loop_node we are sure that the path
            # will loop. So don't keep it if it's a subloop.

            if ad in ctx.gph.last_loop_node and \
                    (l_prev_loop, l_start) not in ctx.gph.last_loop_node[ad]:
                continue

            # If endpoint == loop : maybe the endpoint is at the end of the loop
            # If we have multiple link in, and if it's not a new loop, wait

            if ad not in done:
                lkin = ctx.gph.link_in[ad]

                if ad == l_start or len(lkin) > 1:
                    unseen = get_unseen_links_in(ad, l_set, l_prev_loop, l_start)
                    if len(unseen) > 1:
                        if ad in waiting:
                            if prev in waiting[ad]:
                                waiting[ad].remove(prev)
                        else:
                            unseen.remove(prev)
                            waiting[ad] = unseen
                        continue

            if ad in visited:
                continue

            visited.add(ad)

            if ad in ctx.gph.link_out:
                for n in ctx.gph.link_out[ad]:
                    stack.append((ad, n))

        if not waiting:
            return -1

        if len(waiting) == 1:
            ad = next(iter(waiting.keys()))
            return ad

        stack = []

        restart = True
        while restart:
            restart = False

            for ad in list(waiting):
                if len(waiting[ad]) > 0:
                    continue

                del waiting[ad]
                done.add(ad)
                stack.append((-1, ad))

            # If the stack is still empty but if we have still some waiting
            # nodes, search if paths are really possible. If not, delete
            # a dependence.

            if not stack and waiting:
                for ad in set(waiting):
                    for i in set(waiting[ad]):
                        if not ctx.gph.path_exists(entry, i):
                            waiting[ad].remove(i)
                            if len(waiting[ad]) > 0:
                                restart = True
                            else:
                                del waiting[ad]

                if len(waiting) == 1:
                    ad = next(iter(waiting.keys()))
                    return ad

        if not stack:
            return -1


def get_unseen_links_in(ad, l_set, l_prev_loop, l_start):
    unseen = set(ctx.gph.link_in[ad])

    # Is it the beginning of a loop ?
    # Remove internal links to the beginning of the loop
    if (l_start, ad) in ctx.gph.loops_all:
        sub_loop = ctx.gph.loops_all[(l_start, ad)]
        for prev in ctx.gph.link_in[ad]:
            if prev in sub_loop and prev in unseen:
                unseen.remove(prev)

    if l_set is None:
        return unseen

    # Remove external jumps which are outside the current loop
    for prev in ctx.gph.link_in[ad]:
        if prev not in l_set and prev in unseen:
            unseen.remove(prev)

    return unseen


def remove_unnecessary_goto(ast, ad):
    if len(ast.nodes) > 1:
        if isinstance(ast.nodes[-1], Ast_Goto) and \
                ast.nodes[-1].addr_jump == ad:
            ast.nodes.pop(-1)


def rm_waiting(ctx, waiting, ad):
    # Get the ast which has the smallest level

    min_level_idx = -1
    list_ast = waiting[ad].ast
    list_loop_start = waiting[ad].loop_start

    for i, a in enumerate(list_ast):
        if (list_loop_start[i], ad) in ctx.gph.false_loops:
            continue
        if min_level_idx == -1 or a.level < list_ast[min_level_idx].level:
            min_level_idx = i

    if min_level_idx == -1:
        print("errorD: this is a bug, please report")
        sys.exit(1)

    ast = list_ast[min_level_idx]

    # Add goto on each other ast
    # If they are finally unuseful, they will be deleted with
    # remove_unnecessary_goto or in remove_unnecessary_goto
    for i, a in enumerate(list_ast):
        if i == min_level_idx:
            continue
        if len(a.nodes) == 0:
            a.add(Ast_Goto(ad))
            continue
        # The previous instruction has not `ad` as the next instruction
        if isinstance(a.nodes[-1], list):
            prev = a.nodes[-1][0].address
            if prev in ctx.gph.uncond_jumps_set:
                continue
            if prev in ctx.gph.link_out:
                n = ctx.gph.link_out[prev][BRANCH_NEXT]
                if n != ad:
                    a.add(Ast_Goto(n))
                    continue
        # The previous is a goto, skip it
        if isinstance(a.nodes[-1], Ast_Goto):
            continue
        a.add(Ast_Goto(ad))

    waiting[ad].ast.clear()
    del waiting[ad]

    return ast


def manage_endpoint(ctx, waiting, ast, prev, ad, l_set, l_prev_loop,
                    l_start, ad_is_visited):
    if ad not in ctx.gph.link_in or len(ctx.gph.link_in[ad]) <= 1:
        return ast

    # If ad_is_visited is False it means this is a prevision for a future
    # visit on this node. Here prev has no sense.

    if not ad_is_visited:
        if ad not in waiting:
            unseen = get_unseen_links_in(ad, l_set, l_prev_loop, l_start)
            waiting[ad] = Endpoint(ast, unseen, l_start)
        return None

    if ad in waiting:
        waiting[ad].rendezvous(ast, prev, l_start)

        if len(waiting[ad].unseen) != 0:
            return None

        ast = rm_waiting(ctx, waiting, ad)
        return ast

    unseen = get_unseen_links_in(ad, l_set, l_prev_loop, l_start)

    if len(unseen) > 1:
        unseen.remove(prev)
        waiting[ad] = Endpoint(ast, unseen, l_start)
        return None

    return ast


def generate_ast(ctx__):
    global ctx
    ctx = ctx__

    start = time()

    ast = Ast_Branch()
    ast.parent = None
    stack = [(ast, [], -1, ctx.entry, -1)]
    visited = set()
    waiting = {}

    ast_head = ast

    fake_br = Ast_Branch()
    fake_br.level = sys.maxsize

    while stack or waiting:

        if not stack and waiting:
            if not ctx.gph.skipped_loops_analysis:
                break
            for ad in set(waiting):
                waiting[ad].unseen.clear()
                stack.append((fake_br, [], -1, ad, -1))

        ast, loops_stack, prev, curr, else_addr = stack.pop(-1)

        # Check if we enter in a false loop (see gotoinloop*)
        if loops_stack:
            _, _, l_start = loops_stack[-1]
        else:
            l_start = ctx.entry

        if (l_start, curr) in ctx.gph.false_loops:
            continue

        blk = ctx.gph.nodes[curr]

        # Exit the current loop
        while loops_stack:
            l_ast, l_prev_loop, l_start = loops_stack[-1]
            l_set = ctx.gph.loops_all[(l_prev_loop, l_start)]
            if curr not in l_set:
                loops_stack.pop(-1)
                ast = l_ast.parent
            else:
                break

        if not loops_stack:
            l_prev_loop = -1
            l_start = ctx.entry
            l_set = None

        level = ast.level

        if curr not in visited:
            # Check if we need to stop and wait on a node
            a = manage_endpoint(ctx, waiting, ast, prev, curr, l_set,
                                l_prev_loop, l_start, True)
            if a is None:
                continue

            ast = a
            remove_unnecessary_goto(ast, curr)

            # Check if we enter in a new loop
            if (l_start, curr) in ctx.gph.loops_all:
                if curr not in ctx.gctx.db.reverse_symbols:
                    name = "loop_0x%x" % curr
                    ctx.gctx.db.symbols[name] = curr
                    ctx.gctx.db.reverse_symbols[curr] = name
                    ctx.gctx.db.modified = True

                level += 1
                a = Ast_Loop()
                a.level = level
                a.parent = ast
                a.idx_in_parent = len(ast.nodes)
                a.branch.parent = ast
                a.branch.level = level
                a.branch.idx_in_parent = len(ast.nodes)
                ast.add(a)
                ast = a.branch
                loops_stack.append((a, l_start, curr))
                else_addr = -1
                l_ast = a
                l_set = ctx.gph.loops_all[(l_start, curr)]
                l_prev_loop = l_start
                l_start = curr
                if (l_prev_loop, l_start) in ctx.gph.infinite_loop:
                    a.is_infinite = True
            # Here curr may has changed

        if curr in visited:
            if curr == l_start:
                continue
            if len(ast.nodes) > 0:
                if isinstance(ast.nodes[-1], list):
                    prev = ast.nodes[-1][0].address
                    if prev not in ctx.gph.uncond_jumps_set:
                        ast.add(Ast_Goto(curr))
            else:
                ast.add(Ast_Goto(curr))
            continue

        visited.add(curr)

        # Return instruction
        if curr not in ctx.gph.link_out:
            if curr != ctx.entry and curr not in ctx.gctx.db.reverse_symbols:
                name = "ret_0x%x" % curr
                ctx.gctx.db.symbols[name] = curr
                ctx.gctx.db.reverse_symbols[curr] = name
                ctx.gctx.db.modified = True
            ast.add(blk)
            continue

        nxt = ctx.gph.link_out[curr]

        if curr in ctx.gctx.dis.jmptables:
            ast.add(blk)
            for n in nxt:
                stack.append((ast, loops_stack, curr, n, else_addr))

        elif len(nxt) == 2:
            # We are on a conditional jump

            prefetch = blk[1] if len(blk) == 2 else None

            if loops_stack:
                goto_set = False

                c1 = nxt[BRANCH_NEXT] not in l_set
                c2 = nxt[BRANCH_NEXT_JUMP] not in l_set

                if c1 and c2:
                    raise ExcIfelse(curr)

                if c1:
                    exit_loop = nxt[BRANCH_NEXT]
                    nxt_node_in_loop = nxt[BRANCH_NEXT_JUMP]
                    cond_id = ctx.gctx.libarch.utils.invert_cond(blk[0])
                    goto_set = True

                if c2:
                    exit_loop = nxt[BRANCH_NEXT_JUMP]
                    nxt_node_in_loop = nxt[BRANCH_NEXT]
                    cond_id = ctx.gctx.libarch.utils.get_cond(blk[0])
                    goto_set = True

                # goto to exit a loop
                if goto_set:
                    stack.append((ast.parent, list(loops_stack), curr,
                                  exit_loop, else_addr))
                    stack.append((ast, list(loops_stack), curr,
                                  nxt_node_in_loop, else_addr))
                    a = Ast_IfGoto(blk[0], cond_id, exit_loop, prefetch)
                    a.parent = ast
                    a.level = level
                    a.idx_in_parent = len(ast.nodes)
                    ast.add(a)
                    continue

            # and-if
            if ctx.gctx.print_andif:
                if else_addr == nxt[BRANCH_NEXT_JUMP]:
                    cond_id = ctx.gctx.libarch.utils.invert_cond(blk[0])
                    a = Ast_AndIf(blk[0], cond_id, nxt[BRANCH_NEXT], prefetch)
                    a.parent = ast
                    a.idx_in_parent = len(ast.nodes)
                    ast.add(a)
                    ast.add(Ast_Goto(nxt[BRANCH_NEXT]))

                    # Add a fake branch, with this in the manage function
                    # all gotos to the else_addr will be invisible.
                    stack.append((fake_br, list(loops_stack), curr,
                                  nxt[BRANCH_NEXT_JUMP], else_addr))

                    stack.append((ast, list(loops_stack), curr,
                                  nxt[BRANCH_NEXT], else_addr))
                    continue

                # and-if
                if else_addr == nxt[BRANCH_NEXT]:
                    cond_id = ctx.gctx.libarch.utils.get_cond(blk[0])
                    a = Ast_AndIf(blk[0], cond_id, nxt[BRANCH_NEXT_JUMP], prefetch)
                    a.parent = ast
                    a.idx_in_parent = len(ast.nodes)
                    ast.add(a)
                    ast.add(Ast_Goto(nxt[BRANCH_NEXT_JUMP]))

                    stack.append((fake_br, list(loops_stack), curr,
                                  nxt[BRANCH_NEXT], else_addr))

                    stack.append((ast, list(loops_stack), curr,
                                  nxt[BRANCH_NEXT_JUMP], else_addr))
                    continue

            # if-else

            endpoint = search_endpoint(ctx, stack, ast, curr,
                                       l_set, l_prev_loop, l_start)

            ast_if = Ast_Branch()
            ast_if.parent = ast
            ast_if.level = level + 1
            ast_if.idx_in_parent = len(ast.nodes)

            ast_else = Ast_Branch()
            ast_else.parent = ast
            ast_else.level = level + 1
            ast_else.idx_in_parent = len(ast.nodes)

            else_addr = nxt[BRANCH_NEXT_JUMP]

            if endpoint != -1:
                if (l_start, endpoint) not in ctx.gph.false_loops:
                    # If we have already seen this address (for example the
                    # endpoint is the beginning of the current loop) we don't
                    # re-add in the waiting list.
                    if endpoint not in visited:
                        manage_endpoint(ctx, waiting, ast, -1, endpoint, l_set,
                                        l_prev_loop, l_start, False)
                else:
                    endpoint = -1

            stack.append((ast_if, list(loops_stack), curr,
                          nxt[BRANCH_NEXT], else_addr))

            if endpoint == -1:
                # No endpoint, so it's not useful to have an else-branch
                # -> the stack will continue on `ast`
                a = Ast_Ifelse(blk[0], ast_else, ast_if, else_addr, prefetch)
                stack.append((ast, list(loops_stack), curr,
                              nxt[BRANCH_NEXT_JUMP], else_addr))

                a.parent = ast
                a.level = level + 1
                a.idx_in_parent = len(ast.nodes)
                ast.add(a)
                ast.add(Ast_Goto(else_addr))

            elif endpoint == else_addr:
                # Branch ast_else will be empty
                a = Ast_Ifelse(blk[0], ast_else, ast_if, endpoint, prefetch)
                stack.append((ast, list(loops_stack), curr,
                              nxt[BRANCH_NEXT_JUMP], else_addr))

                a.parent = ast
                a.level = level + 1
                a.idx_in_parent = len(ast.nodes)
                ast.add(a)
                ast.add(Ast_Goto(else_addr))

            else:
                a = Ast_Ifelse(blk[0], ast_else, ast_if, endpoint, prefetch)
                stack.append((ast_else, list(loops_stack), curr,
                              nxt[BRANCH_NEXT_JUMP], else_addr))

                a.parent = ast
                a.level = level + 1
                a.idx_in_parent = len(ast.nodes)
                ast.add(a)
                ast.add(Ast_Goto(endpoint))

        else:
            ast.add(blk)
            stack.append((ast, loops_stack, curr,
                          nxt[BRANCH_NEXT], else_addr))

    ast = ast_head

    remove_all_unnecessary_goto(ast)
    fix_non_consecutives(ctx, ast)

    elapsed = time()
    elapsed = elapsed - start
    debug__("Ast generated in %fs" % elapsed)

    # Process ast

    start = time()

    for func in ctx.gctx.libarch.registered:
        func(ctx, ast)

    elapsed = time()
    elapsed = elapsed - start
    debug__("Functions for processing ast in %fs" % elapsed)

    if ctx.gctx.color:
        assign_colors(ctx.gctx.libarch, ctx, ast)

    if waiting:
        ast_head.nodes.insert(0, Ast_Comment(""))
        ast_head.nodes.insert(0, Ast_Comment(""))
        ast_head.nodes.insert(0,
            Ast_Comment("WARNING: there is a bug, the output is incomplete !"))
        ast_head.nodes.insert(0, Ast_Comment(""))
        ast_head.nodes.insert(0, Ast_Comment(""))
        return ast, False

    return ast, True
