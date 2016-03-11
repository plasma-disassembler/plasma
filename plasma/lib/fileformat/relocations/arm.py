from . import generic

# http://infocenter.arm.com/help/topic/com.arm.doc.ihi0044e/IHI0044E_aaelf.pdf
arch = 'ARM'

R_ARM_COPY = generic.GenericCopyReloc
R_ARM_GLOB_DAT = generic.GenericJumpslotReloc
R_ARM_JUMP_SLOT = generic.GenericJumpslotReloc
R_ARM_RELATIVE = generic.GenericRelativeReloc
R_ARM_ABS32 = generic.GenericAbsoluteAddendReloc

R_ARM_TLS_DTPMOD32 = generic.GenericTLSModIdReloc
R_ARM_TLS_DTPOFF32 = generic.GenericTLSDoffsetReloc
R_ARM_TLS_TPOFF32 = generic.GenericTLSOffsetReloc
