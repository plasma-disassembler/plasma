#!/usr/bin/env python3

import binascii
from capstone import *


arch_lookup = {
    "x86": CS_ARCH_X86,
    "x64": CS_ARCH_X86,
    "ARM": CS_ARCH_ARM,
    "MIPS32": CS_ARCH_MIPS,
    "MIPS64": CS_ARCH_MIPS,
}

mode_lookup = {
    "x86": CS_MODE_32,
    "x64": CS_MODE_64,
    "ARM": CS_ARCH_ARM,
    "MIPS32": CS_MODE_MIPS32,
    "MIPS64": CS_MODE_MIPS64,
}

endianness = {
    True: CS_MODE_BIG_ENDIAN,
    False: CS_MODE_LITTLE_ENDIAN,
}


if len(args) != 2:
    print("usage: diasm.py HEX_FORMAT")
    print("HEX_FORMAT can contain spaces or not")
    print("example disasm.py '80 3d 24 e9 04 08 00'")
else:
    buf = binascii.unhexlify(args[1].replace(" ", ""))
    flags = mode_lookup[api.arch] | endianness[api.is_big_endian]
    cs = Cs(arch_lookup[api.arch], flags)

    for i in cs.disasm(buf, 0):
        print(i.mnemonic, i.op_str)
