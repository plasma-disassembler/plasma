#!/usr/bin/env python3
ep = api.entry_point()
api.set_code(ep)
ad = api.get_addr_from_symbol("main")
api.decompile(ad).print()
