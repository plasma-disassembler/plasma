#!/usr/bin/env python3

ep = api.entry_point()
api.set_code(ep)

s = api.get_section(ep)
api.dump_asm(ep, until=s.end+1).print()
