TESTS_DIR = tests
SRC = $(shell ls -d $(TESTS_DIR)/*.c)
REV = $(patsubst $(TESTS_DIR)/%.c, $(TESTS_DIR)/%.rev, $(SRC))
BIN = $(patsubst $(TESTS_DIR)/%.c, $(TESTS_DIR)/%.bin, $(SRC))
.PHONY : all check compile FORCE

FLAGS[tests/server.c] = "-lpthread"
FLAGS[tests/canary_plt.c] = "-fstack-protector"
SYMBOLS[tests/server.rev] = "main" "connection_handler"

all: check


# Don't rebuild. We want to keep original rev file.
# You need to recreate the file .rev at hand (with the option --nocolor|-nc)
# Or you can use the file regen.sh
check: $(REV)
FORCE:
$(TESTS_DIR)/%.rev: FORCE
	@./diff.sh $@ $(SYMBOLS[$@])

# @./diff.sh $@ verbose $(SYMBOLS[$@])
	

compile: $(BIN)
$(TESTS_DIR)/%.bin: $(TESTS_DIR)/%.c
	gcc $< $(FLAGS[$^]) -o $@
