TESTS_DIR = tests
SRC = $(shell ls -d $(TESTS_DIR)/*.c)
REV = $(patsubst $(TESTS_DIR)/%.c, $(TESTS_DIR)/%.rev, $(SRC))
BIN = $(patsubst $(TESTS_DIR)/%.c, $(TESTS_DIR)/%.bin, $(SRC))
.PHONY : all check compile FORCE clean

FLAGS[tests/server.c] = "-lpthread"
FLAGS[tests/canary_plt.c] = "-fstack-protector"
FLAGS[tests/strlen.c] = "-Os"
FLAGS[tests/andor5.c] = "-O3"
FLAGS[tests/andor6.c] = "-O3"

SYMBOLS[tests/server.rev] = "main" "connection_handler"
SYMBOLS[tests/pendu.rev] = "_main" "___main" "__imp___cexit"
SYMBOLS[tests/shellcode.rev] = "0x0"
SYMBOLS[tests/malloc.rev] = "malloc"
SYMBOLS[tests/entryloop1.rev] = "0x4041b0"

OPTIONS[tests/shellcode.rev] = "--raw x86"
OPTIONS[tests/malloc.rev] = "--raw x64 --rawbase 0x77110"
OPTIONS[tests/entryloop1.rev] = "--raw x64 --rawbase 0x4041b0"

all: check


check:
	@python3 test_reverse.py


# Verbose : print the diff at each test
# set the variable V=1 on the commande line


# Don't rebuild. We want to keep the original rev file.
# You need to recreate the file .rev at hand (with the options -nc -ns)
# Or you can use the file regen.sh
oldcheck: $(REV)
FORCE:
$(TESTS_DIR)/%.rev: FORCE
	@./diff.sh $@ ${OPTIONS[$@]} ${V} $(SYMBOLS[$@])


clean:
	@rm -f tmp*


compile: $(BIN)
$(TESTS_DIR)/%.bin: $(TESTS_DIR)/%.c
	gcc $< $(FLAGS[$^]) -o $@
