from . import generic

arch = 'MIPS32'

R_MIPS_32 = generic.GenericAbsoluteAddendReloc
R_MIPS_REL32 = generic.GenericRelativeReloc
R_MIPS_TLS_DTPMOD32 = generic.GenericTLSModIdReloc
R_MIPS_TLS_TPREL32 = generic.GenericTLSOffsetReloc
R_MIPS_TLS_DTPREL32 = generic.GenericTLSDoffsetReloc
R_MIPS_JUMP_SLOT = generic.GenericAbsoluteReloc
R_MIPS_GLOB_DAT = generic.GenericAbsoluteReloc
