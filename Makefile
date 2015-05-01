TESTS_DIR = tests
SRC = $(shell ls -d $(TESTS_DIR)/*.c)
REV = $(patsubst $(TESTS_DIR)/%.c, $(TESTS_DIR)/%.rev, $(SRC))
BIN = $(patsubst $(TESTS_DIR)/%.c, $(TESTS_DIR)/%.bin, $(SRC))
.PHONY : all check compile FORCE clean

FLAGS[tests/server.c] = "-lpthread"
FLAGS[tests/canary_plt.c] = "-fstack-protector"
FLAGS[tests/strlen.c] = "-Os"

SYMBOLS[tests/server.rev] = "main" "connection_handler"
SYMBOLS[tests/pendu.rev] = "_main" "___main"
SYMBOLS[tests/shellcode.rev] = "0x0"

OPTIONS[tests/shellcode.rev] = "--raw x86"

all: check


# Verbose : print the diff at each test
# set the variable V=1 on the commande line


# Don't rebuild. We want to keep the original rev file.
# You need to recreate the file .rev at hand (with the options -nc -ns)
# Or you can use the file regen.sh
check: $(REV)
FORCE:
$(TESTS_DIR)/%.rev: FORCE
	@./diff.sh $@ ${OPTIONS[$@]} ${V} $(SYMBOLS[$@])


clean:
	@rm -f tmp*


compile: $(BIN)
$(TESTS_DIR)/%.bin: $(TESTS_DIR)/%.c
	gcc $< $(FLAGS[$^]) -o $@
