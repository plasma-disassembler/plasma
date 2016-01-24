VERSION = 1.5

class COLOR:
    def __init__(self, val, bold):
        self.val  = val
        self.bold = bold

COLOR_SECTION        = COLOR(81, False)
COLOR_KEYWORD        = COLOR(161, True)

# Don't reuse this color for other tokens
# COLOR_VAR is also used to detect if a token has the type VAR
# FIXME: lib.ui.window.get_tok_type_under_cursor
COLOR_VAR            = COLOR(214, False)

COLOR_TYPE           = COLOR(81, False)
COLOR_COMMENT        = COLOR(242, False)
COLOR_ADDR           = COLOR(242, False)
COLOR_SYMBOL         = COLOR(144, False)
COLOR_RETCALL        = COLOR(161, False)
COLOR_INTERN_COMMENT = COLOR(217, False)
COLOR_CODE_ADDR      = COLOR(226, False)
COLOR_USER_COMMENT   = COLOR(38, False)
COLOR_UNK            = COLOR(154, False)
COLOR_DATA           = COLOR(230, False)
COLOR_STRING         = COLOR(154, False)
COLOR_OFFSET_NOT_FOUND = COLOR(196, False)
