VERSION = 1.4

class COLOR:
    def __init__(self, val, bold):
        self.val  = val
        self.bold = bold

COLOR_SECTION        = COLOR(81, False)
COLOR_KEYWORD        = COLOR(161, True)
COLOR_VAR            = COLOR(208, True)
COLOR_TYPE           = COLOR(81, False)
COLOR_COMMENT        = COLOR(242, False)
COLOR_ADDR           = COLOR(242, False)
COLOR_SYMBOL         = COLOR(144, False)
COLOR_RETCALL        = COLOR(161, False)
COLOR_INTERN_COMMENT = COLOR(217, False)
COLOR_CODE_ADDR      = COLOR(220, False)
COLOR_USER_COMMENT   = COLOR(38, False)
COLOR_UNK            = COLOR(154, False)
COLOR_DATA           = COLOR(230, False)
# COLOR_STRING         = COLOR(144, False)
COLOR_STRING         = COLOR(154, False)
