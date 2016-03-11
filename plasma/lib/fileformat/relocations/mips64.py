from . import generic

arch = 'MIPS64'

R_MIPS_64 = generic.GenericAbsoluteAddendReloc
R_MIPS_REL32 = generic.GenericRelativeReloc
R_MIPS_COPY = generic.GenericCopyReloc
R_MIPS_TLS_DTPMOD64 = generic.GenericTLSModIdReloc
R_MIPS_TLS_DTPREL64 = generic.GenericTLSDoffsetReloc
R_MIPS_TLS_TPREL64 = generic.GenericTLSOffsetReloc
