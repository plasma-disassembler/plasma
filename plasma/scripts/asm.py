#!/usr/bin/env python3

from keystone import *


arch_lookup = {
    "x86": KS_ARCH_X86,
    "x64": KS_ARCH_X86,
    "ARM": KS_ARCH_ARM,
    "MIPS32": KS_ARCH_MIPS,
    "MIPS64": KS_ARCH_MIPS,
}

mode_lookup = {
    "x86": KS_MODE_32,
    "x64": KS_MODE_64,
    "ARM": KS_ARCH_ARM,
    "MIPS32": KS_MODE_MIPS32,
    "MIPS64": KS_MODE_MIPS64,
}

endianness = {
    True: KS_MODE_BIG_ENDIAN,
    False: KS_MODE_LITTLE_ENDIAN,
}


if len(args) != 2:
    print("usage: asm.py 'multi line asm code with \\n'")
else:
    code = args[1].replace("\\n", "\n")

    flags = mode_lookup[api.arch] | endianness[api.is_big_endian]
    ks = Ks(arch_lookup[api.arch], flags)

    buf, nb_stmts = ks.asm(code.encode())

    for b in buf:
        print("%02x " % b, end="")

    print()
