class Relocation(object):
    """
    A representation of a relocation in a binary file. Smart enough to
    relocate itself.

    Properties you may care about:
    - owner_obj: the binary this relocation was originaly found in, as a cle object
    - symbol: the Symbol object this relocation refers to
    - addr: the address in owner_obj this relocation would like to write to
    - rebased_addr: the address in the global memory space this relocation would like to write to
    - resolvedby: If the symbol this relocation refers to is an import symbol and that import has been resolved,
                  this attribute holds the symbol from a different binary that was used to resolve the import.
    - resolved: Whether the application of this relocation was succesful
    """
    def __init__(self, owner, symbol, addr, addend=None):
        super(Relocation, self).__init__()
        self.owner_obj = owner
        self.symbol = symbol
        self.addr = addr
        self.is_rela = addend is not None
        self._addend = addend
        self.resolvedby = None
        self.resolved = False

    @property
    def is_import(self):
        return self.__is_import(self.symbol)


    def __is_import(self, symbol):
        return symbol.entry.st_info.type == 'STB_GLOBAL' or \
               symbol.entry.st_info.type == 'STB_WEAK' or \
               symbol.entry.st_info.type == 'STT_FUNC'

    def __is_export(self, symbol):
        return symbol.entry.st_info.type == 'STB_GLOBAL' or \
               symbol.entry.st_info.type == 'STB_WEAK'


    @property
    def addend(self):
        if self.is_rela:
            return self._addend
        else:
            return self.owner_obj.memory.read_addr_at(self.addr)

    def resolve_symbol(self, solist):
        weak_result = None
        for so in solist:
            symbol = so.get_symbol(self.symbol.name)
            if symbol is not None and symbol.is_export(symbol):
                if symbol.entry.st_info.type == 'STB_GLOBAL':
                    self.resolve(symbol)
                    return True
                elif weak_result is None:
                    weak_result = symbol
            elif symbol is not None and not self.__is_import(symbol) and \
                        so is self.owner_obj:
                if not symbol.is_weak:
                    self.resolve(symbol)
                    return True
                elif weak_result is None:
                    weak_result = symbol

        if weak_result is not None:
            self.resolve(weak_result)
            return True

        return False

    def resolve(self, obj):
        self.resolvedby = obj
        self.resolved = True
        if self.symbol is not None:
            self.symbol.resolve(obj)

    @property
    def rebased_addr(self):
        return self.addr + self.owner_obj.rebase_addr

    @property
    def dest_addr(self):
        return self.addr

    @property
    def value(self):    # pylint: disable=no-self-use
        l.error('Value property of Relocation must be overridden by subclass!')
        return 0

    def relocate(self, solist):
        """
        Applies this relocation. Will make changes to the memory object of the
        object it came from.

        This implementation is a generic version that can be overridden in subclasses.

        @param solist       A list of objects from which to resolve symbols
        """
        if not self.resolve_symbol(solist):
            return False

        self.owner_obj.memory.write_addr_at(self.dest_addr, self.value)


class GenericAbsoluteReloc(Relocation):
    @property
    def value(self):
        return self.resolvedby.rebased_addr

class GenericAbsoluteAddendReloc(Relocation):
    @property
    def value(self):
        return self.resolvedby.rebased_addr + self.addend

class GenericJumpslotReloc(Relocation):
    @property
    def value(self):
        if self.is_rela:
            return self.resolvedby.rebased_addr + self.addend
        else:
            return self.resolvedby.rebased_addr

class GenericRelativeReloc(Relocation):
    @property
    def value(self):
        return self.owner_obj.rebase_addr + self.addend

    def resolve_symbol(self, solist):   # pylint: unused-argument
        self.resolve(None)
        return True

class GenericCopyReloc(Relocation):
    @property
    def value(self):
        return self.resolvedby.owner_obj.memory.read_addr_at(self.resolvedby.addr)

class GenericTLSModIdReloc(Relocation):
    def relocate(self, solist):
        if self.symbol.type == 'STT_NOTYPE':
            self.owner_obj.memory.write_addr_at(self.addr, self.owner_obj.tls_module_id)
            self.resolve(None)
        else:
            if not self.resolve_symbol(solist):
                return False
            self.owner_obj.memory.write_addr_at(self.addr, self.resolvedby.owner_obj.tls_module_id)
        return True

class GenericTLSDoffsetReloc(Relocation):
    @property
    def value(self):
        return self.addend + self.symbol.addr

    def resolve_symbol(self, solist):   # pylint: disable=unused-argument
        self.resolve(None)
        return True

class GenericTLSOffsetReloc(Relocation):
    def relocate(self, solist):
        if self.symbol.type == 'STT_NOTYPE':
            self.owner_obj.memory.write_addr_at(self.addr, self.owner_obj.tls_block_offset + self.addend + self.symbol.addr)
            self.resolve(None)
        else:
            if not self.resolve_symbol(solist):
                return False
            self.owner_obj.memory.write_addr_at(self.addr, self.resolvedby.owner_obj.tls_block_offset + self.addend + self.symbol.addr)
        return True

class GenericIRelativeReloc(Relocation):
    def relocate(self, solist):
        if self.symbol.type == 'STT_NOTYPE':
            self.owner_obj.irelatives.append((self.owner_obj.rebase_addr + self.addend, self.addr))
            self.resolve(None)
            return True

        if not self.resolve_symbol(solist):
            return False

        self.owner_obj.irelatives.append((self.resolvedby.rebased_addr, self.addr))

class MipsGlobalReloc(GenericAbsoluteReloc):
    pass

class MipsLocalReloc(Relocation):
    def relocate(self, solist): # pylint: disable=unused-argument
        if self.owner_obj.rebase_addr == 0:
            self.resolve(None)
            return True                     # don't touch local relocations on the main bin
        delta = self.owner_obj.rebase_addr - self.owner_obj._dynamic['DT_MIPS_BASE_ADDRESS']
        if delta == 0:
            self.resolve(None)
            return True
        elif delta < 0:
            raise Exception("We are relocating a MIPS object at a lower address than"
                            " its static base address. This is weird.")
        val = self.owner_obj.memory.read_addr_at(self.addr)
        newval = val + delta
        self.owner_obj.memory.write_addr_at(self.addr, newval)
        self.resolve(None)
        return True

