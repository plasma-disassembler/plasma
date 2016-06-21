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


# Type of data in Memory

MEM_UNK = 1
MEM_CODE = 2
MEM_FUNC = 3

MEM_BYTE = 4
MEM_WORD = 5
MEM_DWORD = 6
MEM_QWORD = 7
MEM_WOFFSET = 8
MEM_DOFFSET = 9
MEM_QOFFSET = 10
MEM_ASCII = 11
MEM_ARRAY = 12
MEM_STRUCT = 13

# For big strings or data we put a MEM_HEAD every BLOCK_SIZE bytes and at
# the end of the data. It allows to scroll up correctly in the visual mode.
# BLOCK_SIZE should not be too big otherwise performance will decrease.
MEM_HEAD = 50
BLOCK_SIZE = 64 # should be a power of 2
BLOCK_SIZE_MASK = 64-1


# Index of values for each Database.functions[i]
FUNC_END = 0
FUNC_FLAGS = 1
FUNC_OFF_VARS = 2
FUNC_ID = 3
FUNC_INST_ADDR = 4
FUNC_FRAME_SIZE = 5

# Index of values for each Database.functions[i][FUNC_OFF_VARS][offset]
VAR_TYPE = 0
VAR_NAME = 1


# List of flags, in Database.functions[i][FUNC_FLAGS]
FUNC_FLAG_NORETURN = 0x1
FUNC_FLAG_CDECL = 0x2


# Known functions which never returns
NORETURN_ELF = {
    "exit", "_exit", "__stack_chk_fail", "err", "verr", "errx", "verrx",
    "abort", "__assert_fail", "__libc_start_main", "perror", "__cxa_rethrow",
    "__cxa_throw", "__cxa_call_terminate", "__cxa_bad_cast", "__cxa_call_unexpected",
    "__cxa_call_unexpected", "__terminate", "__unexpected",
}

NORETURN_PE = {
    "exit", "ExitProcess", "_exit", "quick_exit", "_Exit", "abort",
    "_CxxThrowException", "quick_exit", "RaiseException",
}


# This is the number of lines to disassemble (without comments and newlines:
# it counts only lines which start with an address). Note: an array or a string
# on multi-lines is counted for 1.
NB_LINES_TO_DISASM = 150

# Save disassembled instructions in a cache
CAPSTONE_CACHE_SIZE = 60000


RESERVED_PREFIX = ["loc_", "sub_", "unk_", "byte_", "word_",
                   "dword_", "qword_", "asc_", "off_", "ret_", "loop_",
                   "var_"]
