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

from capstone.x86 import (X86_INS_CMP, X86_INS_MOV, X86_INS_TEST, X86_OP_IMM,
        X86_OP_INVALID, X86_OP_REG, X86_REG_EBP, X86_REG_RBP)

from reverse.lib.colors import pick_color
from reverse.lib.utils import BRANCH_NEXT
from reverse.lib.ast import (Ast_Branch, Ast_Goto, Ast_Loop, Ast_IfGoto, Ast_Ifelse,
                             Ast_AndIf)
from reverse.lib.arch.x86.output import ASSIGNMENT_OPS
from reverse.lib.arch.x86.utils import is_uncond_jump, is_call


FUSE_OPS = set(ASSIGNMENT_OPS)
FUSE_OPS.add(X86_INS_CMP)


def inv(n):
    return n == X86_OP_INVALID


def assign_colors(ctx, ast):
    if isinstance(ast, Ast_Branch):
        for n in ast.nodes:
            if isinstance(n, list):
                if is_uncond_jump(n[0]) and n[0].operands[0].type == X86_OP_IMM and \
                        n[0].address in ctx.gph.link_out:
                    nxt = ctx.gph.link_out[n[0].address][BRANCH_NEXT]
                    pick_color(nxt)
            else: # ast
                assign_colors(ctx, n)

    elif isinstance(ast, Ast_IfGoto) or isinstance(ast, Ast_Goto):
        pick_color(ast.addr_jump)

    elif isinstance(ast, Ast_Ifelse):
        assign_colors(ctx, ast.br_next_jump)
        assign_colors(ctx, ast.br_next)

    elif isinstance(ast, Ast_Loop):
        assign_colors(ctx, ast.branch)


def fuse_inst_with_if(ctx, ast):
    if isinstance(ast, Ast_Branch):
        types_ast = (Ast_Ifelse, Ast_IfGoto, Ast_AndIf)
        for i, n in enumerate(ast.nodes):
            if isinstance(n, list):
                if ((n[-1].id in FUSE_OPS or (n[-1].id == X86_INS_TEST and
                    all(op.type == X86_OP_REG for op in n[-1].operands) and
                    len(set(op.value.reg for op in n[-1].operands)) == 1))
                    and i+1 < len(ast.nodes)
                            and isinstance(ast.nodes[i+1], types_ast)):
                    ast.nodes[i+1].fused_inst = n[-1]
                    ctx.all_fused_inst.add(n[-1].address)
            else: # ast
                fuse_inst_with_if(ctx, n)

    elif isinstance(ast, Ast_Ifelse):
        fuse_inst_with_if(ctx, ast.br_next)
        fuse_inst_with_if(ctx, ast.br_next_jump)

    elif isinstance(ast, Ast_Loop):
        fuse_inst_with_if(ctx, ast.branch)
