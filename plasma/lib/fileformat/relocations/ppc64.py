from . import generic

# http://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64abi-1.9.pdf
arch = 'PPC64'

class R_PPC64_JMP_SLOT(generic.Relocation):
    def relocate(self, solist):
        if not self.resolve_symbol(solist):
            return False

        if self.owner_obj.is_ppc64_abiv1:
            # R_PPC64_JMP_SLOT
            # http://osxr.org/glibc/source/sysdeps/powerpc/powerpc64/dl-machine.h?v=glibc-2.15#0405
            # copy an entire function descriptor struct
            addr = self.resolvedby.owner_obj.memory.read_addr_at(self.resolvedby.addr)
            toc = self.resolvedby.owner_obj.memory.read_addr_at(self.resolvedby.addr + 8)
            aux = self.resolvedby.owner_obj.memory.read_addr_at(self.resolvedby.addr + 16)
            self.owner_obj.memory.write_addr_at(self.addr, addr)
            self.owner_obj.memory.write_addr_at(self.addr + 8, toc)
            self.owner_obj.memory.write_addr_at(self.addr + 16, aux)
        else:
            self.owner_obj.memory.write_addr_at(self.addr, self.resolvedby.rebased_addr)
        return True

R_PPC64_DTPMOD64 = generic.GenericTLSModIdReloc
R_PPC64_DTPREL64 = generic.GenericTLSDoffsetReloc
R_PPC64_TPREL64 = generic.GenericTLSOffsetReloc
R_PPC64_RELATIVE = generic.GenericRelativeReloc
R_PPC64_IRELATIVE = generic.GenericIRelativeReloc
R_PPC64_ADDR64 = generic.GenericAbsoluteAddendReloc
R_PPC64_GLOB_DAT = generic.GenericJumpslotReloc
