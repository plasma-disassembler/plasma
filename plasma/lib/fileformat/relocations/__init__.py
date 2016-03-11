import sys

from .generic import Relocation
from .defines import defines
from plasma.lib.utils import warning
from . import arm64, i386, mips64, ppc64, amd64, arm, mips, ppc

ALL_RELOCATIONS = {}
complaint_log = set()


def load_relocations():
    for module in [arm64, i386, mips64, ppc64, amd64, arm, mips, ppc]:
        try:
            arch_name = module.arch
        except AttributeError:
            continue

        for item_name in dir(module):
            if item_name not in defines:
                continue
            item = getattr(module, item_name)
            if not isinstance(item, type) or not issubclass(item, Relocation):
                continue

            if arch_name not in ALL_RELOCATIONS:
                ALL_RELOCATIONS[arch_name] = {}
            ALL_RELOCATIONS[arch_name][defines[item_name]] = item


def get_relocation(arch, r_type):
    if r_type == 0:
        return None
    try:
        return ALL_RELOCATIONS[arch][r_type]
    except KeyError:
        if (arch, r_type) not in complaint_log:
            complaint_log.add((arch, r_type))
            warning("Unknown reloc %d on %s" % (r_type, arch))
        return None


load_relocations()
