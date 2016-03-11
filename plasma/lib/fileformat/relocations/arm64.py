from . import generic

# http://infocenter.arm.com/help/topic/com.arm.doc.ihi0056b/IHI0056B_aaelf64.pdf
arch = 'AARCH64'

R_AARCH64_ABS64 = generic.GenericAbsoluteAddendReloc
R_AARCH64_COPY = generic.GenericCopyReloc
R_AARCH64_GLOB_DAT = generic.GenericJumpslotReloc
R_AARCH64_JUMP_SLOT = generic.GenericJumpslotReloc
R_AARCH64_RELATIVE = generic.GenericRelativeReloc
R_AARCH64_IRELATIVE = generic.GenericIRelativeReloc
R_AARCH64_TLS_DTPREL = generic.GenericTLSDoffsetReloc
R_AARCH64_TLS_DTPMOD = generic.GenericTLSModIdReloc
R_AARCH64_TLS_TPREL = generic.GenericTLSOffsetReloc
