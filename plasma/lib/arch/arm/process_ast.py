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

from capstone.arm import ARM_OP_IMM, ARM_INS_CMP, ARM_CC_AL, ARM_INS_TST

from plasma.lib.ast import (Ast_Branch, Ast_Loop, Ast_IfGoto, Ast_Ifelse,
                            Ast_AndIf, Ast_If_cond)
from plasma.lib.arch.arm.output import ASSIGNMENT_OPS


FUSE_OPS = set(ASSIGNMENT_OPS)
FUSE_OPS.add(ARM_INS_CMP)
FUSE_OPS.add(ARM_INS_TST)


def fuse_inst_with_if(ctx, ast):
    if isinstance(ast, Ast_Branch):
        types_ast = (Ast_Ifelse, Ast_IfGoto, Ast_AndIf, Ast_If_cond)
        for i, n in enumerate(ast.nodes):
            # TODO : try to do the same thing as x86
            if isinstance(n, list):
                if n[-1].id in FUSE_OPS and i+1 < len(ast.nodes) and \
                        isinstance(ast.nodes[i+1], types_ast):
                    ast.nodes[i+1].fused_inst = n[-1]
                    ctx.all_fused_inst.add(n[-1].address)
            else: # ast
                fuse_inst_with_if(ctx, n)

    # elif isinstance(ast, Ast_If_cond):
        # fuse_inst_with_if(ctx, ast.br)

    elif isinstance(ast, Ast_Ifelse):
        fuse_inst_with_if(ctx, ast.br_next)
        fuse_inst_with_if(ctx, ast.br_next_jump)

    elif isinstance(ast, Ast_Loop):
        fuse_inst_with_if(ctx, ast.branch)


def convert_cond_to_if(ctx, ast):
    def add_node(i, last_cond, br_lst):
        if br_lst:
            if last_cond == ARM_CC_AL:
                added_nodes[i].append(br_lst)
            else:
                br = Ast_Branch()
                br.add(br_lst)
                added_nodes[i].append(Ast_If_cond(last_cond, br))

    if isinstance(ast, Ast_Branch):
        # Temporary dict, because we can't modify nodes while we are
        # looping, we store new nodes here with the corresponding index
        added_nodes = {}

        for i, n in enumerate(ast.nodes):
            if isinstance(n, list):
                # This will split the current block in other branch if
                # we found conditional instructions.

                blk = n
                added_nodes[i] = []
                last_cond = blk[0].cc
                br = []

                # Fuse instructions with same condition in a same branch
                for inst in blk:
                    if inst.cc == last_cond:
                        br.append(inst)
                    else:
                        add_node(i, last_cond, br)
                        br = [inst]
                    last_cond = inst.cc
                add_node(i, last_cond, br)

            else: # ast
                convert_cond_to_if(ctx, n)

        # Now we update the nodes list. If we have split a block n
        # we remove it, and add new nodes.
        idx_keys = list(added_nodes.keys())
        idx_keys.sort()
        for i in reversed(idx_keys):
            if len(added_nodes[i]) > 1:
                del ast.nodes[i]
                # node is a list (blk of instructions) or Ast_If_cond
                for k, node in enumerate(added_nodes[i]):
                    ast.nodes.insert(i+k, node)

    elif isinstance(ast, Ast_Ifelse):
        convert_cond_to_if(ctx, ast.br_next_jump)
        convert_cond_to_if(ctx, ast.br_next)

    elif isinstance(ast, Ast_Loop):
        convert_cond_to_if(ctx, ast.branch)
