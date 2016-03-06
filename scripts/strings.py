#!/usr/bin/env python3

import pydoc

buf = []

for s in api.iter_sections():
    ad = s.start
    while ad < s.end:
        if api.is_string(ad, s):
            string = api.get_string(ad, s)
            if len(string) >= 3:
                buf.append("0x%x  \"%s\"\n" % (ad, string))
            ad += len(string) + 1
        else:
            ad += 1

pydoc.pager("".join(buf)) 
