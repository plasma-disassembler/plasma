#!/usr/bin/env python3
ep = api.entry_point()
api.set_code(ep)
ad = api.get_addr_from_symbol(".text")
s = api.get_section(ad)
api.dump_asm(ad, until=s.end+1).print()
