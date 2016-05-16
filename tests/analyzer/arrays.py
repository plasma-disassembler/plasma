#!/usr/bin/env python3
ep = api.entry_point()
api.set_code(ep)

ad = api.get_addr_from_symbol("global_array")
api.set_array(ad, 10, MEM_DWORD)

ad = api.get_addr_from_symbol("global_ptr")
api.set_array(ad, 3, MEM_QOFFSET)

ad = api.get_addr_from_symbol(".text")
s = api.get_section(ad)
api.dump_asm(ad, until=s.end+1).print()

ad = api.get_addr_from_symbol(".data")
s = api.get_section(ad)
api.dump_asm(ad, until=s.end+1).print()
