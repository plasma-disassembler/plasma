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

from capstone.mips import (MIPS_OP_IMM, MIPS_INS_ADDIU, MIPS_INS_ORI, 
        MIPS_INS_LUI, MIPS_OP_REG, MIPS_REG_ZERO, MipsOpValue)

from plasma.lib.ast import (Ast_Branch, Ast_Loop, Ast_IfGoto, Ast_Ifelse,
                            Ast_AndIf)
from plasma.lib.arch.mips.output import ASSIGNMENT_OPS
from plasma.lib.arch.mips.utils import PseudoInst, NopInst, PseudoOp


FUSE_OPS = set(ASSIGNMENT_OPS)
# FUSE_OPS.add(ARM_INS_CMP)
# FUSE_OPS.add(ARM_INS_TST)

LI_INST = [MIPS_INS_ADDIU, MIPS_INS_ORI]


def __blk_search_li(blk):
    prev_k = -1
    prev_i = None
    prev_op = None

    for k, i in enumerate(blk):
        if i.id in LI_INST:
            op = i.operands

            if prev_k != -1 and prev_i.id == MIPS_INS_LUI:
                if prev_op is not None and \
                    op[0].type == MIPS_OP_REG and \
                    op[1].type == MIPS_OP_REG and \
                    op[2].type == MIPS_OP_IMM and \
                    op[0].value.reg == op[1].value.reg and \
                    prev_op[0].type == MIPS_OP_REG and \
                    prev_op[1].type == MIPS_OP_IMM and \
                    prev_op[0].value.reg == op[0].value.reg:

                    op1 = op[0]
                    op2 = PseudoOp(MIPS_OP_IMM, 
                            (prev_op[1].value.imm << 16) + op[2].value.imm)

                    op_str = "$%s, %s" % (
                            i.reg_name(op[0].value.reg),
                            hex(op2.value.imm))

                    new_i = PseudoInst(i.address, "li", op_str, [prev_i, i])
                    new_i.operands = [op1, op2]

                    blk[k] = new_i
                    blk[prev_k] = NopInst()

            else:
                if op[0].type == MIPS_OP_REG and \
                    op[1].type == MIPS_OP_REG and \
                    op[2].type == MIPS_OP_IMM and \
                    op[1].value.reg == MIPS_REG_ZERO:

                    op1 = op[0]
                    op2 = PseudoOp(MIPS_OP_IMM, op[2].value.imm)

                    op_str = "$%s, %s" % (
                            i.reg_name(op[0].value.reg),
                            hex(op2.value.imm))

                    new_i = PseudoInst(i.address, "li", op_str, [i])
                    new_i.operands = [op1, op2]

                    blk[k] = new_i

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
