from . import generic

arch = 'x64'

R_X86_64_64 = generic.GenericAbsoluteAddendReloc
R_X86_64_COPY = generic.GenericCopyReloc
R_X86_64_GLOB_DAT = generic.GenericJumpslotReloc
R_X86_64_JUMP_SLOT = generic.GenericJumpslotReloc
R_X86_64_RELATIVE = generic.GenericRelativeReloc
R_X86_64_IRELATIVE = generic.GenericIRelativeReloc

R_X86_64_DTPMOD64 = generic.GenericTLSModIdReloc
R_X86_64_DTPOFF64 = generic.GenericTLSDoffsetReloc
R_X86_64_TPOFF64 = generic.GenericTLSOffsetReloc
