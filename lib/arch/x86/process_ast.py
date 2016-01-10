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

from lib.colors import pick_color
from lib.utils import BRANCH_NEXT
from lib.ast import (Ast_Branch, Ast_Goto, Ast_Loop, Ast_IfGoto, Ast_Ifelse,
        Ast_AndIf)
from lib.arch.x86.output import ASSIGNMENT_OPS
from lib.arch.x86.utils import is_uncond_jump, is_call


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


def search_local_vars(ctx, ast):
    def save_vars(ctx, i):
        for op in i.operands:
            mm = op.mem
            if not inv(mm.base) and mm.disp != 0 \
                    and inv(mm.segment) and inv(mm.index) \
                    and (mm.base == X86_REG_RBP or mm.base == X86_REG_EBP):
                if mm.disp not in ctx.local_vars_idx:
                    ctx.local_vars_idx[mm.disp] = len(ctx.local_vars_name)
                    ctx.local_vars_name.append("var%d" % ctx.vars_counter)
                    ctx.local_vars_size.append(op.size)
                    ctx.vars_counter += 1


    if isinstance(ast, Ast_Branch):
        for i, n in enumerate(ast.nodes):
            if isinstance(n, list):
                for inst in n:
                    save_vars(ctx, inst)
            else: # ast
                search_local_vars(ctx, n)

    elif isinstance(ast, Ast_Ifelse):
        if ast.fused_inst != None:
            save_vars(ctx, ast.fused_inst)
        search_local_vars(ctx, ast.br_next)
        search_local_vars(ctx, ast.br_next_jump)

    elif isinstance(ast, Ast_IfGoto):
        if ast.fused_inst != None:
            save_vars(ctx, ast.fused_inst)

    elif isinstance(ast, Ast_Loop):
        search_local_vars(ctx, ast.branch)


def search_canary_plt(ctx, ast):
    fname = "__stack_chk_fail@plt"
    if fname not in ctx.gctx.dis.binary.symbols:
        return
    faddr = ctx.gctx.dis.binary.symbols[fname]
    __rec_search_canary_plt(faddr, ctx, ast, [])


def get_var_canary(ctx, last_block):
    # Try to get VAR
    #
    # rax = VAR # mov rax, qword ptr [rbp - 8]
    # xor rax, [fs + 40]
    # je 0x400714
    # if != {
    #     call 0x4004f0 <__stack_chk_fail@plt>
    # }
    #

    # Search in the last four instructions
    for i in reversed(last_block[-4:]):
        if i.id != X86_INS_MOV:
            continue

        mm = i.operands[1].mem
        if mm.disp != 0  and inv(mm.segment) and inv(mm.index) and \
                mm.base in [X86_REG_RBP, X86_REG_EBP] and \
                mm.disp in ctx.local_vars_idx:
            ctx.local_vars_name[ctx.local_vars_idx[mm.disp]] += "_canary"
            break


def __rec_search_canary_plt(faddr, ctx, ast, last_block):
    if isinstance(ast, Ast_Branch):
        for n in ast.nodes:
            if isinstance(n, list):
                for i in n:
                    if not is_call(i):
                        continue
                    op = i.operands[0]
                    if op.type == X86_OP_IMM and op.value.imm == faddr:
                        get_var_canary(ctx, last_block)

                last_block = n

            else: # ast
                __rec_search_canary_plt(faddr, ctx, n, last_block)

    elif isinstance(ast, Ast_Ifelse):
        __rec_search_canary_plt(faddr, ctx, ast.br_next_jump, last_block)
        __rec_search_canary_plt(faddr, ctx, ast.br_next, last_block)

    elif isinstance(ast, Ast_Loop):
        __rec_search_canary_plt(faddr, ctx, ast.branch, last_block)
