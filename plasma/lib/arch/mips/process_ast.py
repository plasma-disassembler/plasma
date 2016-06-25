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


FUSE_OPS = set(ASSIGNMENT_OPS)
# FUSE_OPS.add(ARM_INS_CMP)
# FUSE_OPS.add(ARM_INS_TST)
