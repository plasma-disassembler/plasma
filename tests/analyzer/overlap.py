#!/usr/bin/env python3
ep = api.entry_point()
api.set_code(ep)

ad = api.get_addr_from_symbol("overlap_1")
api.decompile(ad).print()

ad = api.get_addr_from_symbol("overlap_2")
api.decompile(ad).print()
