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

from capstone.x86 import (X86_REG_EBX, X86_REG_ECX, X86_REG_EDX, X86_REG_ESI,
        X86_INS_INT, X86_OP_IMM, X86_REG_AL, X86_REG_AX, X86_REG_EAX,
        X86_REG_RAX, X86_REG_BL, X86_REG_CL, X86_REG_DL, X86_REG_BX,
        X86_REG_CX, X86_REG_DX, X86_REG_RBX, X86_REG_RCX, X86_REG_RDX,
        X86_INS_MOV, X86_INS_XOR, X86_OP_REG, X86_REG_RSI, X86_REG_RDI,
        X86_REG_EDI)

from plasma.lib.ast import Ast_Branch, Ast_Loop, Ast_Ifelse


ARGS_ORDER = {
    0: [X86_REG_EBX, X86_REG_RBX, X86_REG_BL, X86_REG_BX],
    1: [X86_REG_ECX, X86_REG_ECX, X86_REG_CL, X86_REG_CX],
    2: [X86_REG_EDX, X86_REG_EDX, X86_REG_DL, X86_REG_DX],
    3: [X86_REG_ESI, X86_REG_RSI],
    4: [X86_REG_EDI, X86_REG_RDI],
}


# TYPES ARE CURRENTLY UNUSED !

ARG_INT = 0
ARG_LONG = 1
ARG_PTR = 2
ARG_CHAR = 3
ARG_SHORT = 4

# Registers are in the right order, example:
# if we want the register of the second arg for a syscall and the type
# is a char, the register is CL.
ARG_REG_TYPE = {
    ARG_CHAR: [X86_REG_BL, X86_REG_CL, X86_REG_DL],
    ARG_SHORT: [X86_REG_BX, X86_REG_CX, X86_REG_DX],
    ARG_INT: [X86_REG_EBX, X86_REG_ECX, X86_REG_EDX, X86_REG_ESI, X86_REG_EDI],
    ARG_LONG: [X86_REG_RBX, X86_REG_RCX, X86_REG_RDX, X86_REG_RSI, X86_REG_RDI],
}


# http://docs.cs.up.ac.za/programming/asm/derick_tut/syscalls.html

SYSCALL = {
    1: {"name": "exit", "args_type": [ARG_INT]},
    # 2: {"name": "fork", "args_type": ['struct pt_regs']},
    2: {"name": "fork", "args_type": []},
    3: {"name": "read", "args_type": [ARG_INT, ARG_PTR, ARG_INT]},
    4: {"name": "write", "args_type": [ARG_INT, ARG_PTR, ARG_INT]},
    5: {"name": "open", "args_type": [ARG_PTR, ARG_INT, ARG_INT]},
    6: {"name": "close", "args_type": [ARG_INT]},
    7: {"name": "waitpid", "args_type": [ARG_INT, ARG_INT, ARG_INT]},
    8: {"name": "creat", "args_type": [ARG_PTR, ARG_INT]},
    9: {"name": "link", "args_type": [ARG_PTR, ARG_PTR]},
    10: {"name": "unlink", "args_type": [ARG_PTR]},
    # 11: {"name": "execve", "args_type": ['struct pt_regs']},
    11: {"name": "execve", "args_type": [ARG_PTR, ARG_PTR, ARG_PTR]},
    12: {"name": "chdir", "args_type": [ARG_PTR]},
    13: {"name": "time", "args_type": [ARG_PTR]},
    14: {"name": "mknod", "args_type": [ARG_PTR, ARG_INT, ARG_INT]},
    15: {"name": "chmod", "args_type": [ARG_PTR, ARG_SHORT]},
    16: {"name": "lchown", "args_type": [ARG_PTR, ARG_INT, ARG_INT]},
    18: {"name": "stat", "args_type": [ARG_PTR, ARG_PTR]},
    19: {"name": "lseek", "args_type": [ARG_INT, ARG_LONG, ARG_INT]},
    20: {"name": "getpid", "args_type": []},
    21: {"name": "mount", "args_type": [ARG_PTR, ARG_PTR, ARG_PTR]},
    22: {"name": "oldumount", "args_type": [ARG_PTR]},
    23: {"name": "setuid", "args_type": [ARG_INT]},
    24: {"name": "getuid", "args_type": []},
    25: {"name": "stime", "args_type": [ARG_PTR]},
    26: {"name": "ptrace", "args_type": [ARG_LONG, ARG_LONG, ARG_LONG, ARG_LONG]},
    27: {"name": "alarm", "args_type": [ARG_INT]},
    28: {"name": "fstat", "args_type": [ARG_INT, ARG_PTR]},
    29: {"name": "pause", "args_type": []},
    30: {"name": "utime", "args_type": [ARG_PTR, ARG_PTR]},
    33: {"name": "access", "args_type": [ARG_PTR, ARG_INT]},
    34: {"name": "nice", "args_type": [ARG_INT]},
    36: {"name": "sync", "args_type": []},
    37: {"name": "kill", "args_type": [ARG_INT, ARG_INT]},
    38: {"name": "rename", "args_type": [ARG_PTR, ARG_PTR]},
    39: {"name": "mkdir", "args_type": [ARG_PTR, ARG_INT]},
    40: {"name": "rmdir", "args_type": [ARG_PTR]},
    41: {"name": "dup", "args_type": [ARG_INT]},
    42: {"name": "pipe", "args_type": [ARG_PTR]},
    43: {"name": "times", "args_type": [ARG_PTR]},
    45: {"name": "brk", "args_type": [ARG_LONG]},
    46: {"name": "setgid", "args_type": [ARG_INT]},
    47: {"name": "getgid", "args_type": []},
    48: {"name": "signal", "args_type": [ARG_INT, ARG_PTR]},
    49: {"name": "geteuid", "args_type": []},
    50: {"name": "getegid", "args_type": []},
    51: {"name": "acct", "args_type": [ARG_PTR]},
    52: {"name": "umount", "args_type": [ARG_PTR, ARG_INT]},
    54: {"name": "ioctl", "args_type": [ARG_INT, ARG_INT, ARG_LONG]},
    55: {"name": "fcntl", "args_type": [ARG_INT, ARG_INT, ARG_LONG]},
    57: {"name": "setpgid", "args_type": [ARG_INT, ARG_INT]},
    59: {"name": "olduname", "args_type": [ARG_PTR]},
    60: {"name": "umask", "args_type": [ARG_INT]},
    61: {"name": "chroot", "args_type": [ARG_PTR]},
    62: {"name": "ustat", "args_type": [ARG_INT, ARG_PTR]},
    63: {"name": "dup2", "args_type": [ARG_INT, ARG_INT]},
    64: {"name": "getppid", "args_type": []},
    65: {"name": "getpgrp", "args_type": []},
    66: {"name": "setsid", "args_type": []},
    67: {"name": "sigaction", "args_type": [ARG_INT, ARG_PTR, ARG_PTR]},
    68: {"name": "sgetmask", "args_type": []},
    69: {"name": "ssetmask", "args_type": [ARG_INT]},
    70: {"name": "setreuid", "args_type": [ARG_INT, ARG_INT]},
    71: {"name": "setregid", "args_type": [ARG_INT, ARG_INT]},
    72: {"name": "sigsuspend", "args_type": [ARG_INT, ARG_INT, ARG_LONG]},
    73: {"name": "sigpending", "args_type": [ARG_PTR]},
    74: {"name": "sethostname", "args_type": [ARG_PTR, ARG_INT]},
    75: {"name": "setrlimit", "args_type": [ARG_INT, ARG_PTR]},
    76: {"name": "getrlimit", "args_type": [ARG_INT, ARG_PTR]},
    77: {"name": "getrusage", "args_type": [ARG_INT, ARG_PTR]},
    78: {"name": "gettimeofday", "args_type": [ARG_PTR, ARG_PTR]},
    79: {"name": "settimeofday", "args_type": [ARG_PTR, ARG_PTR]},
    80: {"name": "getgroups", "args_type": [ARG_INT, ARG_PTR]},
    81: {"name": "setgroups", "args_type": [ARG_INT, ARG_PTR]},
    82: {"name": "old_select", "args_type": [ARG_PTR]},
    83: {"name": "symlink", "args_type": [ARG_PTR, ARG_PTR]},
    84: {"name": "lstat", "args_type": [ARG_PTR, ARG_PTR]},
    85: {"name": "readlink", "args_type": [ARG_PTR, ARG_PTR, ARG_INT]},
    86: {"name": "uselib", "args_type": [ARG_PTR]},
    87: {"name": "swapon", "args_type": [ARG_PTR, ARG_INT]},
    88: {"name": "reboot", "args_type": [ARG_INT, ARG_INT, ARG_INT, ARG_PTR]},
    89: {"name": "old_readdir", "args_type": [ARG_INT, ARG_PTR, ARG_INT]},
    90: {"name": "old_mmap", "args_type": [ARG_PTR]},
    91: {"name": "munmap", "args_type": [ARG_LONG, ARG_INT]},
    92: {"name": "truncate", "args_type": [ARG_PTR, ARG_LONG]},
    93: {"name": "ftruncate", "args_type": [ARG_INT, ARG_LONG]},
    94: {"name": "fchmod", "args_type": [ARG_INT, ARG_SHORT]},
    95: {"name": "fchown", "args_type": [ARG_INT, ARG_INT, ARG_INT]},
    96: {"name": "getpriority", "args_type": [ARG_INT, ARG_INT]},
    97: {"name": "setpriority", "args_type": [ARG_INT, ARG_INT, ARG_INT]},
    99: {"name": "statfs", "args_type": [ARG_PTR, ARG_PTR]},
    100: {"name": "fstatfs", "args_type": [ARG_INT, ARG_PTR]},
    101: {"name": "ioperm", "args_type": [ARG_LONG, ARG_LONG, ARG_INT]},
    102: {"name": "socketcall", "args_type": [ARG_INT, ARG_PTR]},
    103: {"name": "syslog", "args_type": [ARG_INT, ARG_PTR, ARG_INT]},
    104: {"name": "setitimer", "args_type": [ARG_INT, ARG_PTR, ARG_PTR]},
    105: {"name": "getitimer", "args_type": [ARG_INT, ARG_PTR]},
    106: {"name": "newstat", "args_type": [ARG_PTR, ARG_PTR]},
    107: {"name": "newlstat", "args_type": [ARG_PTR, ARG_PTR]},
    108: {"name": "newfstat", "args_type": [ARG_INT, ARG_PTR]},
    109: {"name": "uname", "args_type": [ARG_PTR]},
    110: {"name": "iopl", "args_type": [ARG_LONG]},
    111: {"name": "vhangup", "args_type": []},
    112: {"name": "idle", "args_type": []},
    113: {"name": "vm86old", "args_type": [ARG_LONG, ARG_PTR]},
    114: {"name": "wait4", "args_type": [ARG_INT, ARG_PTR, ARG_INT, ARG_PTR]},
    115: {"name": "swapoff", "args_type": [ARG_PTR]},
    116: {"name": "sysinfo", "args_type": [ARG_PTR]},
    117: {"name": "ipc (*Note)", "args_type": [ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_PTR]},
    118: {"name": "fsync", "args_type": [ARG_INT]},
    119: {"name": "sigreturn", "args_type": [ARG_LONG]},
    120: {"name": "clone", "args_type": ['struct pt_regs']},
    121: {"name": "setdomainname", "args_type": [ARG_PTR, ARG_INT]},
    122: {"name": "newuname", "args_type": [ARG_PTR]},
    123: {"name": "modify_ldt", "args_type": [ARG_INT, ARG_PTR, ARG_LONG]},
    124: {"name": "adjtimex", "args_type": [ARG_PTR]},
    125: {"name": "mprotect", "args_type": [ARG_LONG, ARG_INT, ARG_LONG]},
    126: {"name": "sigprocmask", "args_type": [ARG_INT, ARG_PTR, ARG_PTR]},
    127: {"name": "create_module", "args_type": [ARG_PTR, ARG_INT]},
    128: {"name": "init_module", "args_type": [ARG_PTR, ARG_PTR]},
    129: {"name": "delete_module", "args_type": [ARG_PTR]},
    130: {"name": "get_kernel_syms", "args_type": [ARG_PTR]},
    131: {"name": "quotactl", "args_type": [ARG_INT, ARG_PTR, ARG_INT, ARG_PTR]},
    132: {"name": "getpgid", "args_type": [ARG_INT]},
    133: {"name": "fchdir", "args_type": [ARG_INT]},
    134: {"name": "bdflush", "args_type": [ARG_INT, ARG_LONG]},
    135: {"name": "sysfs", "args_type": [ARG_INT, ARG_LONG, ARG_LONG]},
    136: {"name": "personality", "args_type": [ARG_LONG]},
    138: {"name": "setfsuid", "args_type": [ARG_INT]},
    139: {"name": "setfsgid", "args_type": [ARG_INT]},
    140: {"name": "llseek", "args_type": [ARG_INT, ARG_LONG, ARG_LONG, ARG_PTR, ARG_INT]},
    141: {"name": "getdents", "args_type": [ARG_INT, ARG_PTR, ARG_INT]},
    142: {"name": "select", "args_type": [ARG_INT, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR]},
    143: {"name": "flock", "args_type": [ARG_INT, ARG_INT]},
    144: {"name": "msync", "args_type": [ARG_LONG, ARG_INT, ARG_INT]},
    145: {"name": "readv", "args_type": [ARG_LONG, ARG_PTR, ARG_LONG]},
    146: {"name": "writev", "args_type": [ARG_LONG, ARG_PTR, ARG_LONG]},
    147: {"name": "getsid", "args_type": [ARG_INT]},
    148: {"name": "fdatasync", "args_type": [ARG_INT]},
    149: {"name": "sysctl", "args_type": [ARG_PTR]},
    150: {"name": "mlock", "args_type": [ARG_LONG, ARG_INT]},
    151: {"name": "munlock", "args_type": [ARG_LONG, ARG_INT]},
    152: {"name": "mlockall", "args_type": [ARG_INT]},
    153: {"name": "munlockall", "args_type": []},
    154: {"name": "sched_setparam", "args_type": [ARG_INT, ARG_PTR]},
    155: {"name": "sched_getparam", "args_type": [ARG_INT, ARG_PTR]},
    156: {"name": "sched_setscheduler", "args_type": [ARG_INT, ARG_INT, ARG_PTR]},
    157: {"name": "sched_getscheduler", "args_type": [ARG_INT]},
    158: {"name": "sched_yield", "args_type": []},
    159: {"name": "sched_get_priority_max", "args_type": [ARG_INT]},
    160: {"name": "sched_get_priority_min", "args_type": [ARG_INT]},
    161: {"name": "sched_rr_get_interval", "args_type": [ARG_INT, ARG_PTR]},
    162: {"name": "nanosleep", "args_type": [ARG_PTR, ARG_PTR]},
    163: {"name": "mremap", "args_type": [ARG_LONG, ARG_LONG, ARG_LONG, ARG_LONG]},
    164: {"name": "setresuid", "args_type": [ARG_INT, ARG_INT, ARG_INT]},
    165: {"name": "getresuid", "args_type": [ARG_PTR, ARG_PTR, ARG_PTR]},
    166: {"name": "vm86", "args_type": [ARG_PTR]},
    167: {"name": "query_module", "args_type": [ARG_PTR, ARG_INT, ARG_PTR, ARG_INT, 'size_t *']},
    168: {"name": "poll", "args_type": [ARG_PTR, ARG_INT, ARG_LONG]},
    169: {"name": "nfsservctl", "args_type": [ARG_INT, ARG_PTR, ARG_PTR]},
    170: {"name": "setresgid", "args_type": [ARG_INT, ARG_INT, ARG_INT]},
    171: {"name": "getresgid", "args_type": [ARG_PTR, ARG_PTR, ARG_PTR]},
    172: {"name": "prctl", "args_type": [ARG_INT, ARG_LONG, ARG_LONG, ARG_LONG, ARG_LONG]},
    173: {"name": "rt_sigreturn", "args_type": [ARG_LONG]},
    174: {"name": "rt_sigaction", "args_type": [ARG_INT, ARG_PTR, ARG_PTR, ARG_INT]},
    175: {"name": "rt_sigprocmask", "args_type": [ARG_INT, ARG_PTR, ARG_PTR, ARG_INT]},
    176: {"name": "rt_sigpending", "args_type": [ARG_PTR, ARG_INT]},
    177: {"name": "rt_sigtimedwait", "args_type": [ARG_PTR, ARG_PTR, ARG_PTR, ARG_INT]},
    178: {"name": "rt_sigqueueinfo", "args_type": [ARG_INT, ARG_INT, ARG_PTR]},
    179: {"name": "rt_sigsuspend", "args_type": [ARG_PTR, ARG_INT]},
    180: {"name": "pread", "args_type": [ARG_INT, ARG_PTR, ARG_INT, ARG_LONG]},
    181: {"name": "pwrite", "args_type": [ARG_INT, ARG_PTR, ARG_INT, ARG_LONG]},
    182: {"name": "chown", "args_type": [ARG_PTR, ARG_INT, ARG_INT]},
    183: {"name": "getcwd", "args_type": [ARG_PTR, ARG_LONG]},
    # Don't know for these structures
    # 184: {"name": "capget", "args_type": ['cap_user_header_t', 'cap_user_data_t']},
    # 185: {"name": "capset", "args_type": ['cap_user_header_t', 'const cap_user_data_t']},
    186: {"name": "sigaltstack", "args_type": [ARG_PTR, ARG_PTR]},
    187: {"name": "sendfile", "args_type": [ARG_INT, ARG_INT, ARG_PTR, ARG_INT]},
    190: {"name": "vfork", "args_type": ['struct pt_regs']},
}



def reg_write(inst, reg_id):
    if len(inst.operands) == 0:
        return False
    op = inst.operands[0]
    return op.type == X86_OP_REG and op.value.reg == reg_id


def search_backward(blk, since, lst_reg_id):
    i = since
    while i >= 0:
        for reg_id in lst_reg_id:
            if reg_write(blk[i], reg_id):
                return i
        i -= 1
    return -1


def get_value_written(inst):
    # Only few instructions are supported
    if inst.id == X86_INS_MOV:
        op = inst.operands[1]
        if op.type == X86_OP_IMM:
            return op.value.imm
    elif inst.id == X86_INS_XOR:
        return 0
    return None


def read_block(ctx, blk):
    inline_comm = ctx.gctx.dis.internal_inline_comments
    for i, inst in enumerate(blk):
        if inst.id != X86_INS_INT:
            continue

        # Search the syscall number

        idx_wr_al = search_backward(blk, i, [X86_REG_AL, X86_REG_AX,
                                             X86_REG_EAX, X86_REG_RAX])

        if idx_wr_al == -1:
            continue

        inst_wr_al = blk[idx_wr_al]
        sysnum = get_value_written(inst_wr_al)

        if sysnum is None:
            inline_comm[inst.address] = "?"
            continue

        inline_comm[inst.address] = SYSCALL[sysnum]["name"] + "("

        # Search values for each args, otherwise print the register

        args_type = SYSCALL[sysnum]["args_type"]
        for j in range(len(args_type)):
            idx_wr_reg = search_backward(blk, i, ARGS_ORDER[j])

            if idx_wr_reg == -1:
                # TODO: we take the first register which is in 32 bits
                # we need to check the architecture before
                inline_comm[inst.address] += inst.reg_name(ARGS_ORDER[j][0])
            else:
                inst_wr_reg = blk[idx_wr_reg]
                val = get_value_written(inst_wr_reg)
                if val is None:
                    # TODO: we take the first register which is in 32 bits
                    # we need to check the architecture before
                    inline_comm[inst.address] += inst.reg_name(ARGS_ORDER[j][0])
                else:
                    inline_comm[inst.address] += hex(val)

            if j != len(args_type)-1:
                inline_comm[inst.address] += ", "
            
        inline_comm[inst.address] += ")"


def int80(ctx, ast):
    if isinstance(ast, Ast_Branch):
        for n in ast.nodes:
            if isinstance(n, list):
                read_block(ctx, n)
            else: # ast
                int80(ctx, n)

    elif isinstance(ast, Ast_Ifelse):
        int80(ctx, ast.br_next_jump)
        int80(ctx, ast.br_next)

    elif isinstance(ast, Ast_Loop):
        int80(ctx, ast.branch)
