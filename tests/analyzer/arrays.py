#!/usr/bin/env python3


def check(boolean):
    if boolean:
        print("ok")
    else:
        print("error")


# Check some xrefs

global_string = api.get_addr_from_symbol("global_string")
global_ptr = api.get_addr_from_symbol("global_ptr")

# in this order the xrefs failed before
api.set_ascii(global_string)
api.set_offset(global_ptr + 8, MEM_QWORD) # there is an address to global_string
check(api.xrefsto(global_string) == {global_ptr + 8})

api.set_byte(global_ptr + 8)
check(api.xrefsto(global_string) == set())

api.set_offset(global_ptr + 8, MEM_QWORD)
check(api.xrefsto(global_string) == {global_ptr + 8})

api.set_byte(global_string)
api.set_byte(global_ptr + 8)
api.set_ascii(global_string)
api.set_offset(global_ptr + 8, MEM_QWORD)
check(api.xrefsto(global_string) == {global_ptr + 8})


# now analyze the code

ep = api.entry_point()
api.set_code(ep)

ad = api.get_addr_from_symbol("global_array")
api.set_array(ad, 10, MEM_DWORD)

api.set_array(global_ptr, 3, MEM_QOFFSET)

ad = api.get_addr_from_symbol(".text")
s = api.get_section(ad)
api.dump_asm(ad, until=s.end+1).print()

ad = api.get_addr_from_symbol(".data")
s = api.get_section(ad)
api.dump_asm(ad, until=s.end+1).print()
