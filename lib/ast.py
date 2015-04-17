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

from capstone.x86 import (X86_INS_CMP, X86_INS_MOV, X86_INS_TEST, X86_OP_IMM,
        X86_OP_INVALID, X86_OP_REG, X86_REG_EBP, X86_REG_RBP)

from lib.utils import is_call, is_uncond_jump, BRANCH_NEXT, invert_cond
from lib.colors import pick_color, color_addr, color_keyword
from lib.output import (print_comment, print_no_end, print_tabbed,
        print_tabbed_no_end, ASSIGNMENT_OPS)


FUSE_OPS = set(ASSIGNMENT_OPS)
FUSE_OPS.add(X86_INS_CMP)


class Ast_Branch:
    def __init__(self):
        self.nodes = []

    def add(self, node):
        if isinstance(node, Ast_Branch):
            self.nodes += node.nodes
        else:
            self.nodes.append(node)

    def print(self, o, tab=0):
        for n in self.nodes:
            if isinstance(n, list):
                o.print_block(n, tab)
            else: # ast
                n.print(o, tab)


class Ast_IfGoto:
    def __init__(self, orig_jump, cond_id, addr_jump):
        self.orig_jump = orig_jump
        self.cond_id = cond_id
        self.addr_jump = addr_jump
        self.fused_inst = None

    def print(self, o, tab=0):
        o.print_commented_jump(self.orig_jump, self.fused_inst, tab)
        print_tabbed_no_end(color_keyword("if "), tab)
        o.print_if_cond(self.cond_id, self.fused_inst)
        print_no_end(color_keyword("  goto "))
        print(color_addr(self.addr_jump, False))


class Ast_AndIf:
    def __init__(self, orig_jump, cond_id):
        self.orig_jump = orig_jump
        self.cond_id = cond_id
        self.fused_inst = None

    def print(self, o, tab=0):
        o.print_commented_jump(self.orig_jump, self.fused_inst, tab)
        print_tabbed_no_end(color_keyword("and ") + color_keyword("if "), tab)
        o.print_if_cond(self.cond_id, self.fused_inst)
        print()


class Ast_Ifelse:
    def __init__(self, jump_inst, br_next_jump, br_next):
        self.jump_inst = jump_inst
        self.br_next = br_next
        self.br_next_jump = br_next_jump
        self.fused_inst = None

    def print(self, o, tab=0, print_else_keyword=False):
        #
        # if cond {
        # } else {
        #   ...
        # }
        #
        # become
        #
        # if !cond {
        #   ...
        # }
        #

        br_next = self.br_next
        br_next_jump = self.br_next_jump
        inv_if = False

        if len(self.br_next.nodes) == 0:
            br_next, br_next_jump = br_next_jump, br_next
            inv_if = True
            
        o.print_commented_jump(self.jump_inst, self.fused_inst, tab)

        if print_else_keyword:
            print_tabbed_no_end(color_keyword("else if "), tab)
        else:
            print_tabbed_no_end(color_keyword("if "), tab)

        # jump_inst is the condition to go to the else-part
        if inv_if:
            o.print_if_cond(self.jump_inst.id, self.fused_inst)
        else:
            o.print_if_cond(invert_cond(self.jump_inst.id), self.fused_inst)

        print(" {")

        # if-part
        br_next.print(o, tab+1)

        # else-part
        if len(br_next_jump.nodes) > 0:
            print_tabbed_no_end("} ", tab)
            
            # 
            # if {
            #   ...
            # } else {
            #   if {
            #     ...
            #   }
            # }
            #
            # become :
            #
            # if {
            #   ...
            # }
            # else if {
            #   ...
            # }
            #

            br = br_next_jump

            if len(br.nodes) == 1 and isinstance(br.nodes[0], Ast_Ifelse):
                print()
                br.nodes[0].print(o, tab, True)
                return

            if len(br.nodes) == 2 and isinstance(br.nodes[0], list) and \
                  len(br.nodes[0]) == 1 and br.nodes[0][0].id == X86_INS_CMP and \
                  isinstance(br.nodes[1], Ast_Ifelse):
                print()
                br.nodes[1].print(o, tab, True)
                return

            print(color_keyword("else ") + "{")
            br.print(o, tab+1)

        print_tabbed("}", tab)


class Ast_Jmp:
    def __init__(self, addr):
        self.addr_jump = addr

    def print(self, o, tab=0):
        print_tabbed_no_end("jmp ", tab)
        print(color_addr(self.addr_jump, False))


class Ast_Loop:
    def __init__(self):
        self.branch = Ast_Branch()
        self.epilog = None
        self.is_infinite = False

    def add(self, node):
        self.branch.add(node)

    def set_epilog(self, epilog):
        self.epilog = epilog

    def set_infinite(self, v):
        self.is_infinite = v

    def set_branch(self, b):
        self.branch = b

    def print(self, o, tab=0):
        if self.is_infinite:
            print_tabbed(color_keyword("infiniteloop") + " {", tab)
        else:
            print_tabbed(color_keyword("loop") + " {", tab)
        self.branch.print(o, tab+1)
        print_tabbed("}", tab)
        if self.epilog != None:
            self.epilog.print(o, tab)


class Ast_Comment:
    def __init__(self, text):
        self.text = text

    def print(self, o, tab=0):
        if o.ctx.comments:
            print_comment("# " + self.text, tab)


# Functions for processing ast

def assign_colors(ctx, ast):
    if isinstance(ast, Ast_Branch):
        for n in ast.nodes:
            if isinstance(n, list):
                if is_uncond_jump(n[0]) and n[0].operands[0].type == X86_OP_IMM:
                    nxt = ctx.gph.link_out[n[0].address][BRANCH_NEXT]
                    pick_color(nxt)
            else: # ast
                assign_colors(ctx, n)

    elif isinstance(ast, Ast_IfGoto) or isinstance(ast, Ast_Jmp):
        pick_color(ast.addr_jump)

    elif isinstance(ast, Ast_Ifelse):
        assign_colors(ctx, ast.br_next_jump)
        assign_colors(ctx, ast.br_next)

    elif isinstance(ast, Ast_Loop):
        assign_colors(ctx, ast.branch)
        if ast.epilog != None:
            assign_colors(ctx, ast.epilog)


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
        if ast.epilog != None:
            fuse_inst_with_if(ctx, ast.epilog)


def search_local_vars(ctx, ast):
    def inv(n):
        return n == X86_OP_INVALID

    def save_vars(ctx, i):
        for op in inst.operands:
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
        if ast.epilog != None:
            search_local_vars(ctx, ast.epilog)


def search_canary_plt(ctx):
    def inv(n):
        return n == X86_OP_INVALID

    fname = "__stack_chk_fail@plt"
    if fname not in ctx.dis.binary.symbols:
        return

    faddr = ctx.dis.binary.symbols[fname]

    k = 0
    for idx in ctx.dis.code_idx:
        i = ctx.dis.code[idx]
        if is_call(i):
            op = i.operands[0]
            if op.type == X86_OP_IMM and op.value.imm == faddr:
                # Try to get VAR
                #
                # rax = VAR # mov rax, qword ptr [rbp - 8]
                # xor rax, [fs + 40]
                # je 0x400714
                # if != {
                #     call 0x4004f0 <__stack_chk_fail@plt>
                # }
                #

                kk = k - 1
                while kk > 0 and kk > k - 4:
                    inst = ctx.dis.code[ctx.dis.code_idx[kk]]

                    if inst.id == X86_INS_MOV:
                        mm = inst.operands[1].mem
                        if mm.disp != 0  and inv(mm.segment) and inv(mm.index) and \
                                mm.base in [X86_REG_RBP, X86_REG_EBP] and \
                                mm.disp in ctx.local_vars_idx:
                            ctx.local_vars_name[ctx.local_vars_idx[mm.disp]] += "_canary"
                            break

                    kk -= 1

                break

        k += 1
