#!/usr/bin/env python3
main = api.get_addr_from_symbol("main")
func1 = api.get_addr_from_symbol("func1")
func2 = api.get_addr_from_symbol("func2")

api.set_function(main)

api.decompile(main).print()
api.decompile(func1).print()
api.decompile(func2).print()

jumps = [0x6f2, 0x6f8, 0x6fe, 0x696, 0x6c9]

for ad in jumps:
    api.invert_cond(ad)

api.decompile(main).print()
api.decompile(func1).print()
api.decompile(func2).print()
