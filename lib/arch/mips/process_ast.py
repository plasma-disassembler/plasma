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

from capstone.mips import (MIPS_OP_IMM, MIPS_INS_ADDIU, MIPS_INS_ORI, 
        MIPS_INS_LUI, MIPS_OP_REG, MIPS_REG_ZERO)

from lib.colors import pick_color
from lib.utils import BRANCH_NEXT
from lib.ast import (Ast_Branch, Ast_Goto, Ast_Loop, Ast_IfGoto, Ast_Ifelse,
        Ast_AndIf, Ast_If_cond)
from lib.arch.mips.output import ASSIGNMENT_OPS
from lib.arch.mips.utils import is_uncond_jump, PseudoInst, NopInst


FUSE_OPS = set(ASSIGNMENT_OPS)
# FUSE_OPS.add(ARM_INS_CMP)
# FUSE_OPS.add(ARM_INS_TST)


def assign_colors(ctx, ast):
    if isinstance(ast, Ast_Branch):
        for n in ast.nodes:
            if isinstance(n, list):
                if is_uncond_jump(n[0]) and n[0].operands[0].type == MIPS_OP_IMM:
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

    elif isinstance(ast, Ast_If_cond):
        assign_colors(ctx, ast.br)


# TODO !!
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


LI_INST = [MIPS_INS_ADDIU, MIPS_INS_ORI]


def __blk_search_li(blk):
    prev_k = -1
    prev_i = None
    prev_op = None

    for k, i in enumerate(blk):
        if i.id in LI_INST:
            op = i.operands

            if prev_k != -1 and prev_i.id == MIPS_INS_LUI:
                if op[0].type == MIPS_OP_REG and \
                    op[1].type == MIPS_OP_REG and \
                    op[2].type == MIPS_OP_IMM and \
                    op[0].value.reg == op[1].value.reg and \
                    prev_op[0].type == MIPS_OP_REG and \
                    prev_op[1].type == MIPS_OP_IMM and \
                    prev_op[0].value.reg == op[0].value.reg:

                    blk[k] = PseudoInst("li $%s, %s" % (
                            i.reg_name(op[0].value.reg),
                            hex((prev_op[1].value.imm << 16) + op[2].value.imm)),
                            [prev_i, i])

                    blk[prev_k] = NopInst()

            else:
                if op[0].type == MIPS_OP_REG and \
                    op[1].type == MIPS_OP_REG and \
                    op[2].type == MIPS_OP_IMM and \
                    op[1].value.reg == MIPS_REG_ZERO:

                    blk[k] = PseudoInst("li $%s, %s" % (
                            i.reg_name(op[0].value.reg),
                            op[2].value.imm),
                            [i])

        prev_k = k
        prev_i = i
        prev_op = i.operands


def search_li(ctx, ast):
    if isinstance(ast, Ast_Branch):
        for n in ast.nodes:
            if isinstance(n, list):
                __blk_search_li(n)
            else: # ast
                search_li(ctx, n)

    elif isinstance(ast, Ast_Ifelse):
        search_li(ctx, ast.br_next_jump)
        search_li(ctx, ast.br_next)

    elif isinstance(ast, Ast_Loop):
        search_li(ctx, ast.branch)
